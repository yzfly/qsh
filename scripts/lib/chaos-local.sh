# shellcheck shell=bash
# Step 3 of scripts/local-test.sh: the chaos tests of crates/qsh-cli/tests/chaos.rs on this
# machine, in netns.sh's local mode. Sourced, not run; needs common.sh.
#
# Safety, on a shared machine:
# - Everything happens in three network namespaces named QSHL_CHAOS_PREFIX-c/-r/-s (default
#   qshl-<pid>), joined by veth pairs created inside them. No host interface, route, firewall
#   rule or sysctl is touched (the sysctls netns.sh sets are those of its own namespaces).
# - The pre-flight refuses to start when namespaces with the prefix exist already.
# - No user is created: the server side runs as the current user through an unprivileged sshd in
#   the server namespace, with HOME and XDG directories in the test directory.
# - Processes are killed by namespace (`ip netns pids`) or by pid, never by name or user.
# - The cleanup (also on Ctrl-C and errors) stops the test, deletes the namespaces, and compares
#   the host's links, addresses, routes, rules, qdiscs, nftables ruleset and forwarding sysctls
#   with a snapshot taken before; a difference is a loud failure.
# - Nothing is installed: missing tools skip the step (or the scenarios that need them).

QSHL_CHAOS_PREFIX=${QSHL_CHAOS_PREFIX:-qshl-$$}
QSHL_CHAOS_ACTIVE=0
QSHL_CHAOS_DIR=
QSHL_CHAOS_PID=
QSHL_CHAOS_BASELINE=
QSHL_SYS_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# The host's network state, for the before/after comparison (counters and timers left out)
qshl_host_snapshot() {
    local PATH=$QSHL_SYS_PATH
    echo "## links"
    ip -o link show | sed -E 's/\\ +/ /g'
    echo "## addresses"
    ip -o addr show | sed -E 's/(valid_lft|preferred_lft) [^ ]+//g'
    echo "## routes"
    ip route show table all
    ip -6 route show table all | sed -E 's/expires [0-9]+sec//g'
    echo "## rules"
    ip rule show
    ip -6 rule show
    echo "## qdiscs"
    tc qdisc show
    echo "## nftables"
    if command -v nft >/dev/null; then sudo -n nft -s list ruleset; fi
    echo "## sysctls"
    sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.promote_secondaries
    echo "## namespaces"
    ip netns list
}

# Why the chaos step cannot run here (printed), or nothing
qshl_chaos_missing() {
    local PATH=$QSHL_SYS_PATH tool
    if ! sudo -n true 2>/dev/null; then
        echo "passwordless sudo is not available"
        return
    fi
    for tool in ip tc nft runuser setpriv ssh ssh-keygen sha256sum python3; do
        command -v "$tool" >/dev/null || { echo "$tool is not installed"; return; }
    done
    [ -x /usr/sbin/sshd ] || { echo "/usr/sbin/sshd is not installed"; return; }
    if [ ! -d /sys/module/sch_netem ] && ! modinfo sch_netem >/dev/null 2>&1; then
        echo "the kernel has no netem module (sch_netem)"
    fi
}

# The environment of netns.sh and the chaos test, as root
qshl_chaos_env() {
    QSHL_CHAOS_ENV=(env -i "PATH=$QSHL_SYS_PATH" LANG=C.UTF-8 QSH_CHAOS=1 QSH_CHAOS_LOCAL=1
        "QSH_CHAOS_NS_PREFIX=$QSHL_CHAOS_PREFIX" "QSH_CHAOS_USER=$(id -un)"
        "QSH_CHAOS_DIR=$QSHL_CHAOS_DIR" "QSH_CHAOS_NETNS=$QSHL_REPO/tests/chaos/netns.sh")
}

# Our namespaces that exist
qshl_chaos_namespaces() {
    ip netns list 2>/dev/null | awk '{print $1}' | grep -E "^${QSHL_CHAOS_PREFIX}-[crs]\$" || true
}

# Stop the test, delete the namespaces, compare the host. Safe to call twice.
qshl_chaos_cleanup() {
    [ "$QSHL_CHAOS_ACTIVE" = 1 ] || return 0
    QSHL_CHAOS_ACTIVE=0
    local start=$SECONDS ns pid child
    if [ -n "$QSHL_CHAOS_PID" ] && kill -0 "$QSHL_CHAOS_PID" 2>/dev/null; then
        # sudo's child is the test binary: by pid
        for child in $(pgrep -P "$QSHL_CHAOS_PID" 2>/dev/null); do
            sudo -n kill -TERM "$child" 2>/dev/null || true
        done
        sleep 1
        for child in $(pgrep -P "$QSHL_CHAOS_PID" 2>/dev/null); do
            sudo -n kill -KILL "$child" 2>/dev/null || true
        done
        wait "$QSHL_CHAOS_PID" 2>/dev/null || true
    fi
    QSHL_CHAOS_PID=
    qshl_chaos_env
    sudo -n "${QSHL_CHAOS_ENV[@]}" "$QSHL_REPO/tests/chaos/netns.sh" down >/dev/null 2>&1 || true
    # Whatever netns.sh could not remove: ours only, by name and then by pid
    for ns in $(qshl_chaos_namespaces); do
        for pid in $(sudo -n ip netns pids "$ns" 2>/dev/null); do
            sudo -n kill -KILL "$pid" 2>/dev/null || true
        done
        sudo -n ip netns del "$ns" 2>/dev/null || true
    done
    local left
    left=$(qshl_chaos_namespaces | tr '\n' ' ')
    # The test ran as root: give its files back, so that they can be removed or read
    if [ -n "$QSHL_CHAOS_DIR" ] && [ -d "$QSHL_CHAOS_DIR" ]; then
        sudo -n chown -R "$(id -u):$(id -g)" "$QSHL_CHAOS_DIR" 2>/dev/null || true
    fi
    if [ -n "$left" ]; then
        qshl_result FAIL chaos "namespaces deleted" $((SECONDS - start)) "LEFT BEHIND: $left"
    else
        qshl_result PASS chaos "namespaces deleted" $((SECONDS - start)) "$QSHL_CHAOS_PREFIX-c/-r/-s gone"
    fi
    if [ -n "$QSHL_CHAOS_BASELINE" ]; then
        local after="$QSHL_LOG_DIR/host-after.txt" diff="$QSHL_LOG_DIR/host-diff.txt"
        qshl_host_snapshot >"$after" 2>&1
        if diff -u "$QSHL_CHAOS_BASELINE" "$after" >"$diff"; then
            qshl_result PASS chaos "host network unchanged" 0 \
                "links, addresses, routes, rules, qdiscs, nft ruleset, sysctls, namespaces: same as before"
        else
            {
                echo
                echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                echo "!! THE HOST'S NETWORK STATE DIFFERS FROM BEFORE THE CHAOS STEP: $diff"
                echo "!! (another service may have changed it meanwhile; check it now)"
                echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                sed 's/^/!! /' "$diff"
                echo
            } >&2
            qshl_result FAIL chaos "host network unchanged" 0 "DIFFERS: see $diff"
        fi
    fi
}

# One line about a scenario's records: checks passed, report-only and hard failures, measures
qshl_chaos_digest() {
    python3 -I - "$1" <<'EOF'
import json, sys
checks = {"pass": 0, "report": [], "hard": []}
measures = []
try:
    lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
except OSError:
    lines = []
for line in lines:
    try:
        r = json.loads(line)
    except ValueError:
        continue
    where = f"{r.get('profile', '')}"
    if r.get("kind") == "check":
        if r.get("ok"):
            checks["pass"] += 1
        elif r.get("hard"):
            checks["hard"].append(f"{where}:{r['metric']}={json.dumps(r['value'])}")
        else:
            checks["report"].append(f"{where}:{r['metric']}={json.dumps(r['value'])}")
    elif r.get("kind") == "measure" and r["metric"].endswith(("seconds", "_ms", "_s")):
        measures.append(f"{where}:{r['metric']}={json.dumps(r['value'])}")
parts = [f"{checks['pass']} checks passed"]
if checks["hard"]:
    parts.append("HARD FAIL " + ", ".join(checks["hard"]))
if checks["report"]:
    parts.append("report-only fail " + ", ".join(checks["report"]))
parts.append(", ".join(measures))
print("; ".join(p for p in parts if p))
EOF
}

# qshl_chaos ROOT CHAOS_TEST_BINARY QSH QSH_SERVER: run the selected chaos tests
# (QSHL_CHAOS_TESTS, comma-separated) with QSHL_CHAOS_PROFILES (forced, comma-separated, or
# "default": each test's own), QSHL_CHAOS_STRICT.
qshl_chaos() {
    local root=$1 bin=$2 qsh=$3 server=$4 why
    why=$(qshl_chaos_missing)
    if [ -n "$why" ]; then
        qshl_result SKIP chaos "chaos tests" 0 "$why"
        return 0
    fi
    if [ -n "$(qshl_chaos_namespaces)" ]; then
        qshl_result FAIL chaos "pre-flight" 0 \
            "namespaces $QSHL_CHAOS_PREFIX-* exist already; not touching them (another run?)"
        return 1
    fi
    local others
    others=$(ip netns list 2>/dev/null | awk '{print $1}' | grep -c '^qshl-' || true)
    QSHL_CHAOS_DIR="$root/chaos"
    mkdir -p "$QSHL_CHAOS_DIR"
    QSHL_CHAOS_BASELINE="$QSHL_LOG_DIR/host-before.txt"
    qshl_host_snapshot >"$QSHL_CHAOS_BASELINE" 2>&1
    sleep 2
    if ! qshl_host_snapshot 2>&1 | diff -q "$QSHL_CHAOS_BASELINE" - >/dev/null; then
        qshl_result WARN chaos "pre-flight" 0 \
            "the host's network state changed by itself within 2 s: the after-check may report noise"
        qshl_host_snapshot >"$QSHL_CHAOS_BASELINE" 2>&1
    fi
    local notes="prefix $QSHL_CHAOS_PREFIX, dir $QSHL_CHAOS_DIR"
    [ "$others" -gt 0 ] && notes="$notes; $others namespace(s) of other runs left alone"
    PATH=$QSHL_SYS_PATH command -v conntrack >/dev/null || notes="$notes; no conntrack (NAT flush skipped)"
    PATH=$QSHL_SYS_PATH command -v ethtool >/dev/null || notes="$notes; no ethtool (offloads stay on)"
    qshl_result PASS chaos "pre-flight" 0 "$notes"
    QSHL_CHAOS_ACTIVE=1

    qshl_chaos_env
    local profiles=()
    case ${QSHL_CHAOS_PROFILES:-clean,crossborder} in
        default) ;;
        *) profiles=("QSH_CHAOS_FORCE_PROFILES=${QSHL_CHAOS_PROFILES:-clean,crossborder}") ;;
    esac
    [ "${QSHL_CHAOS_STRICT:-0}" = 1 ] && profiles+=(QSH_CHAOS_STRICT=1)
    local test rc start log out digest status=0 tests
    IFS=, read -r -a tests <<<"${QSHL_CHAOS_TESTS:-bytes_exact,address_change,udp_block}"
    for test in "${tests[@]}"; do
        test=${test// /}
        [ -n "$test" ] || continue
        log="$QSHL_LOG_DIR/chaos-$test.log"
        out="$QSHL_CHAOS_DIR/results-$test.jsonl"
        start=$SECONDS
        qshl_say "[chaos] $test (profiles ${QSHL_CHAOS_PROFILES:-clean,crossborder}); log $log"
        # shellcheck disable=SC2024 # the log is the user's own file, written by this shell
        sudo -n "${QSHL_CHAOS_ENV[@]}" "${profiles[@]}" "QSH_CHAOS_QSH=$qsh" "QSH_CHAOS_SERVER=$server" \
            "QSH_CHAOS_OUT=$out" "$bin" --exact "$test" --test-threads=1 --nocapture >"$log" 2>&1 &
        QSHL_CHAOS_PID=$!
        rc=0
        wait "$QSHL_CHAOS_PID" || rc=$?
        QSHL_CHAOS_PID=
        sudo -n chown "$(id -u):$(id -g)" "$out" 2>/dev/null || true
        digest=$(qshl_chaos_digest "$out")
        if [ "$rc" = 0 ] && grep -q "1 passed" "$log"; then
            qshl_result PASS chaos "$test" $((SECONDS - start)) "$digest"
        else
            grep -E '^chaos: |panicked|FAIL' "$log" | tail -n 15 | sed 's/^/    | /' >&2
            qshl_result FAIL chaos "$test" $((SECONDS - start)) "exit $rc; $digest; log $log"
            status=1
        fi
    done
    cat "$QSHL_CHAOS_DIR"/results-*.jsonl >"$QSHL_LOG_DIR/chaos-results.jsonl" 2>/dev/null || true
    python3 -I "$QSHL_REPO/tests/chaos/report.py" "$QSHL_LOG_DIR/chaos-results.jsonl" \
        >"$QSHL_LOG_DIR/chaos-report.md" 2>/dev/null || true
    qshl_chaos_cleanup
    return "$status"
}
