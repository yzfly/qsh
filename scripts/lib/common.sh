# shellcheck shell=bash
# Shared helpers of scripts/local-test.sh: results, logging, the build queue and the disk check.
# Sourced, not run.

# Every check appends `STATUS<TAB>STEP<TAB>NAME<TAB>SECONDS<TAB>DETAIL` to $QSHL_RESULTS
# (STATUS: PASS, FAIL, WARN, SKIP); the summary table at the end is made from it.
: "${QSHL_RESULTS:?}" "${QSHL_LOG_DIR:?}"

QSHL_VERBOSE=${QSHL_VERBOSE:-0}
# Free space (GiB) a build needs on the target's file system and on /
QSHL_MIN_FREE_GB=${QSHL_MIN_FREE_GB:-3}

qshl_say() {
    printf '%s local-test: %s\n' "$(date +%H:%M:%S)" "$*" >&2
}

qshl_result() { # STATUS STEP NAME SECONDS DETAIL
    local detail=${5//$'\t'/ }
    detail=${detail//$'\n'/ }
    printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "${detail:0:400}" >>"$QSHL_RESULTS"
    qshl_say "$1 [$2] $3 (${4} s)${detail:+: ${detail:0:200}}"
}

qshl_slug() {
    local s=${1,,}
    s=${s//[^a-z0-9]/-}
    printf '%s' "$s"
}

# Free GiB on the file system of PATH
qshl_free_gb() {
    df -Pk "$1" | awk 'NR == 2 { printf "%d", $4 / 1048576 }'
}

# Make sure a build has room: at least QSHL_MIN_FREE_GB on / and on the target directory. When
# short, remove the target's incremental caches (ours, safe to rebuild) and look again.
qshl_disk_ok() {
    local target=$1 free_root free_target
    free_root=$(qshl_free_gb /)
    free_target=$(qshl_free_gb "$target")
    if [ "$free_root" -ge "$QSHL_MIN_FREE_GB" ] && [ "$free_target" -ge "$QSHL_MIN_FREE_GB" ]; then
        return 0
    fi
    qshl_say "low disk (/ ${free_root} GiB, target ${free_target} GiB free): removing $target/*/incremental"
    rm -rf "$target"/debug/incremental "$target"/release/incremental
    free_root=$(qshl_free_gb /)
    free_target=$(qshl_free_gb "$target")
    if [ "$free_root" -ge "$QSHL_MIN_FREE_GB" ] && [ "$free_target" -ge "$QSHL_MIN_FREE_GB" ]; then
        return 0
    fi
    qshl_say "still under ${QSHL_MIN_FREE_GB} GiB free (/ ${free_root} GiB, target ${free_target} GiB): not building"
    return 1
}

# The build queue of this machine: one heavy job at a time, at low priority (AGENTS.md)
qshl_heavy() {
    flock /tmp/heavy.lock nice -n 10 "$@"
}

# qshl_check STEP NAME [--heavy] [--warn] -- CMD...: run CMD with its output in a log file
# (streamed too with -v), record PASS or FAIL (WARN with --warn), print the log's tail when it
# fails. --heavy queues it on the build lock after the disk check. Returns CMD's status.
qshl_check() {
    local step=$1 name=$2 heavy=0 bad=FAIL
    shift 2
    while [ $# -gt 0 ]; do
        case $1 in
            --heavy) heavy=1 ;;
            --warn) bad=WARN ;;
            --) shift; break ;;
            *) break ;;
        esac
        shift
    done
    local log
    log="$QSHL_LOG_DIR/$(qshl_slug "$step-$name").log"
    local start=$SECONDS rc=0
    if [ "$heavy" = 1 ]; then
        if ! qshl_disk_ok "${CARGO_TARGET_DIR:-$QSHL_REPO/target}"; then
            qshl_result FAIL "$step" "$name" 0 "not enough free disk space"
            return 1
        fi
        set -- qshl_heavy "$@"
    fi
    qshl_say "[$step] $name: $*"
    if [ "$QSHL_VERBOSE" = 1 ]; then
        "$@" 2>&1 | tee "$log"
        rc=${PIPESTATUS[0]}
    else
        "$@" >"$log" 2>&1 || rc=$?
    fi
    local took=$((SECONDS - start))
    if [ "$rc" = 0 ]; then
        qshl_result PASS "$step" "$name" "$took" ""
    else
        if [ "$QSHL_VERBOSE" != 1 ]; then
            tail -n 25 "$log" | sed 's/^/    | /' >&2
        fi
        qshl_result "$bad" "$step" "$name" "$took" "exit $rc; log $log"
    fi
    return "$rc"
}

# The summary table, worst first within each step's order of appearance
qshl_summary() {
    local width=${COLUMNS:-120}
    [ "$width" -lt 80 ] && width=80
    printf '\n%-5s %-7s %-34s %7s  %s\n' STATUS STEP CHECK SECONDS DETAIL
    printf '%s\n' "$(printf '%*s' "$width" '' | tr ' ' '-')"
    local status step name secs detail
    while IFS=$'\t' read -r status step name secs detail; do
        printf '%-5s %-7s %-34s %7s  %s\n' "$status" "$step" "${name:0:34}" "$secs" \
            "${detail:0:$((width - 58))}"
    done <"$QSHL_RESULTS"
    printf '%s\n' "$(printf '%*s' "$width" '' | tr ' ' '-')"
    local pass fail warn skip
    pass=$(grep -c '^PASS' "$QSHL_RESULTS" || true)
    fail=$(grep -c '^FAIL' "$QSHL_RESULTS" || true)
    warn=$(grep -c '^WARN' "$QSHL_RESULTS" || true)
    skip=$(grep -c '^SKIP' "$QSHL_RESULTS" || true)
    printf '%s passed, %s failed, %s warnings, %s skipped. Logs: %s\n' \
        "$pass" "$fail" "$warn" "$skip" "$QSHL_LOG_DIR"
}
