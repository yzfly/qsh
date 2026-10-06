#!/usr/bin/env bash
# The local test rig of qsh: what must pass on a developer's machine before a milestone or a
# release (the repository's Actions run Linux CI only; see AGENTS.md and CONTRIBUTING.md).
#
#   1. static + unit + end-to-end: rustfmt, clippy -D warnings (default and all features),
#      rustdoc -D warnings, cargo test --workspace --all-features, cargo xtask gen --check,
#      cargo deny check, shellcheck
#   2. real sshd end to end, without root: a private unprivileged sshd on 127.0.0.1 and a free
#      high port, temporary HOME and XDG directories on both sides (scripts/lib/sshd_e2e.py)
#   3. --chaos: the chaos tests in network namespaces with netem and nftables, as the current
#      user behind sudo (scripts/lib/chaos-local.sh, tests/chaos/netns.sh local mode)
#   4. --fuzz N: every fuzz target for N seconds, when nightly and cargo-fuzz are installed
#
# Builds are queued on /tmp/heavy.lock at low priority with -j 2 and CARGO_INCREMENTAL=0, after a
# check for 3 GiB of free disk space. Nothing outside the repository's target/ (and the --tmp
# directory, if given) is written; no process this script did not start is killed.
#
# Usage: scripts/local-test.sh [OPTIONS]
#   --chaos                 run step 3 (needs passwordless sudo; off by default)
#   --chaos-tests LIST      chaos tests, comma-separated (default bytes_exact,address_change,udp_block;
#                           others: flood_interrupt nat_rebinding port_fallback compression upgrade
#                           throughput)
#   --chaos-profiles LIST   netem profiles every chaos test runs (default clean,crossborder; of clean,
#                           crossborder, lossy, terrible, slow), or "default" for each test's own
#   --chaos-strict          every chaos check hard, report-only ones too (QSH_CHAOS_STRICT=1)
#   --fuzz SECONDS          run step 4, SECONDS per fuzz target
#   --skip-static           skip step 1
#   --skip-e2e              skip step 2 (the binaries are still built when step 3 runs)
#   --pipe-mib N            size of the pipe check of step 2 (default 50)
#   --pipe-runs N           its runs over the default transport (default 20)
#   --pipe-runs-other N     its runs over tls and over ssh each (default 2; 0 to skip)
#   --e2e-only LIST         step 2 scenarios whose names contain one of LIST (comma-separated)
#   --tmp DIR               parent of the run's directory (default target/qshl, mode 0700, or /tmp
#                           when that path is longer than 60 bytes: the daemon's unix socket
#                           below it must fit in 107). Below a directory others can write, such
#                           as /tmp, the daemon upgrade refuses the test HOMEs' qsh-server
#                           (security.md 4.8) and the run passes the test hook
#                           QSH_TEST_TRUSTED_DIR to the daemons
#   --keep                  keep the temporary directory
#   -v, --verbose           stream every command's output, not only failures
#   -h, --help
#
# The chaos test's own knobs pass through from the environment: QSH_CHAOS_RUNS (runs per profile
# of flood_interrupt), QSH_CHAOS_ATTACHES (attaches of udp_block's S1 check), QSH_CHAOS_NAT_IDLE,
# QSH_CHAOS_WINDOW, QSH_CHAOS_VERBOSE (0: no client debug logs).
#
# The summary table at the end has one row per check (PASS, FAIL, WARN, SKIP); the exit status is
# 1 when any check failed. Logs go to target/local-test/<date>/; the chaos clients' logs and
# transcripts, sshd's and the daemon's logs to its chaos/logs/.
set -uo pipefail

QSHL_REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$QSHL_REPO" || exit 2

usage() {
    sed -n '2,/^set -uo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

CHAOS=0
FUZZ=0
SKIP_STATIC=0
SKIP_E2E=0
KEEP=0
TMPBASE=
PIPE_MIB=50
PIPE_RUNS=20
PIPE_RUNS_OTHER=2
E2E_ONLY=
QSHL_CHAOS_TESTS=bytes_exact,address_change,udp_block
QSHL_CHAOS_PROFILES=clean,crossborder
QSHL_CHAOS_STRICT=0
QSHL_VERBOSE=0

while [ $# -gt 0 ]; do
    case $1 in
        --chaos) CHAOS=1 ;;
        --chaos-tests) QSHL_CHAOS_TESTS=${2:?}; shift ;;
        --chaos-profiles) QSHL_CHAOS_PROFILES=${2:?}; shift ;;
        --chaos-strict) QSHL_CHAOS_STRICT=1 ;;
        --fuzz) FUZZ=${2:?}; shift ;;
        --skip-static) SKIP_STATIC=1 ;;
        --skip-e2e) SKIP_E2E=1 ;;
        --pipe-mib) PIPE_MIB=${2:?}; shift ;;
        --pipe-runs) PIPE_RUNS=${2:?}; shift ;;
        --pipe-runs-other) PIPE_RUNS_OTHER=${2:?}; shift ;;
        --e2e-only) E2E_ONLY=${2:?}; shift ;;
        --tmp) TMPBASE=${2:?}; shift ;;
        --keep) KEEP=1 ;;
        -v | --verbose) QSHL_VERBOSE=1 ;;
        -h | --help) usage; exit 0 ;;
        *) echo "local-test: unknown option $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
done
case $FUZZ in '' | *[!0-9]*) echo "local-test: --fuzz takes seconds" >&2; exit 2 ;; esac

export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 CARGO_TERM_COLOR=never RUST_BACKTRACE=1
QSHL_LOG_DIR="$QSHL_REPO/target/local-test/$(date +%Y%m%d-%H%M%S)"
QSHL_RESULTS="$QSHL_LOG_DIR/results.tsv"
mkdir -p "$QSHL_LOG_DIR"
: >"$QSHL_RESULTS"
export QSHL_REPO QSHL_LOG_DIR QSHL_RESULTS QSHL_VERBOSE
export QSHL_CHAOS_TESTS QSHL_CHAOS_PROFILES QSHL_CHAOS_STRICT

# shellcheck source=scripts/lib/common.sh
. "$QSHL_REPO/scripts/lib/common.sh"
# shellcheck source=scripts/lib/chaos-local.sh
. "$QSHL_REPO/scripts/lib/chaos-local.sh"

# The run's directory: by default in target/, where every directory above the test HOMEs
# belongs to the user (or root) and nobody else can write, like a real home directory
if [ -z "$TMPBASE" ]; then
    TMPBASE="$QSHL_REPO/target/qshl"
    if [ ${#TMPBASE} -gt 60 ]; then
        qshl_say "$TMPBASE is too long for the daemon's unix socket below it: using /tmp"
        TMPBASE=/tmp
    else
        mkdir -p "$TMPBASE" && chmod 700 "$TMPBASE" || exit 2
    fi
fi
ROOT=$(mktemp -d "$TMPBASE/qshl-rig-XXXXXX") || exit 2
chmod 700 "$ROOT"
FINISHED=0
# Under a directory the daemon upgrade does not accept above its program (m2.md 10.3 step 1):
# the test hook that makes it look no higher than the run's directory
QSHL_TRUSTED_DIR=
if qshl_untrusted_above "$ROOT"; then
    QSHL_TRUSTED_DIR=$ROOT
    qshl_say "$TMPBASE can be written by others: the daemons get QSH_TEST_TRUSTED_DIR=$ROOT"
fi
export QSHL_TRUSTED_DIR

finish() {
    local rc=$?
    trap - EXIT INT TERM HUP
    qshl_chaos_cleanup
    if [ "$FINISHED" != 1 ]; then
        qshl_result FAIL rig "interrupted" 0 "the rig stopped early (exit $rc)"
    fi
    if [ "$KEEP" = 1 ]; then
        qshl_say "kept $ROOT"
    else
        rm -rf "$ROOT"
    fi
    qshl_summary >&2
    if grep -q '^FAIL' "$QSHL_RESULTS"; then
        exit 1
    fi
    exit 0
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

qshl_say "qsh $(git describe --always --dirty 2>/dev/null || echo '?'), $(rustc --version 2>/dev/null)," \
    "$(qshl_free_gb /) GiB free on /; logs in $QSHL_LOG_DIR"

# ---------------------------------------------------------------------------------------------
# Step 1: static checks, unit and end-to-end tests

find_cargo_deny() {
    local scratch=/tmp/claude-1000/-home-ubuntu-yzfly-tokenssh/788480e9-1016-4049-8922-78a059390e00/scratchpad
    local candidate
    for candidate in "${QSHL_CARGO_DENY:-}" "$(command -v cargo-deny 2>/dev/null)" \
        "$scratch/deny/cargo-deny-0.20.2-x86_64-unknown-linux-musl/cargo-deny"; do
        if [ -n "$candidate" ] && [ -x "$candidate" ]; then
            echo "$candidate"
            return
        fi
    done
}

# The shellcheck program: from PATH, or from uv's cache (shellcheck-py; never downloaded here)
find_shellcheck() {
    if command -v shellcheck >/dev/null; then
        SHELLCHECK=(shellcheck)
    elif command -v uvx >/dev/null && uvx --offline -q --from shellcheck-py shellcheck --version >/dev/null 2>&1; then
        SHELLCHECK=(uvx --offline -q --from shellcheck-py shellcheck)
    else
        SHELLCHECK=()
    fi
}

run_shellcheck() {
    "${SHELLCHECK[@]}" -s sh scripts/install.sh &&
        "${SHELLCHECK[@]}" -s sh packaging/test/setup.sh packaging/test/entrypoint.sh &&
        "${SHELLCHECK[@]}" -s bash packaging/test/e2e.sh &&
        "${SHELLCHECK[@]}" -s sh -e SC2034 packaging/openrc/qsh-server &&
        "${SHELLCHECK[@]}" -s sh tests/chaos/*.sh &&
        "${SHELLCHECK[@]}" -s bash -x scripts/local-test.sh scripts/lib/*.sh
}

step_static() {
    qshl_check static "rustfmt" -- cargo fmt --all --check
    qshl_check static "clippy" --heavy -- \
        cargo clippy --workspace --all-targets --locked -j 2 -- -D warnings
    qshl_check static "clippy --all-features" --heavy -- \
        cargo clippy --workspace --all-targets --all-features --locked -j 2 -- -D warnings
    qshl_check static "rustdoc" --heavy -- \
        env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked -j 2
    qshl_check static "cargo test --all-features" --heavy -- \
        cargo test --workspace --all-features --locked -j 2
    qshl_check static "xtask gen --check" --heavy -- cargo xtask gen --check
    local deny
    deny=$(find_cargo_deny)
    if [ -n "$deny" ]; then
        qshl_check static "cargo deny check" -- "$deny" check
    else
        qshl_result WARN static "cargo deny check" 0 \
            "cargo-deny not found (set QSHL_CARGO_DENY or install it: cargo install --locked cargo-deny)"
    fi
    find_shellcheck
    if [ ${#SHELLCHECK[@]} -gt 0 ]; then
        qshl_check static "shellcheck" -- run_shellcheck
    else
        qshl_result WARN static "shellcheck" 0 \
            "shellcheck not found (apt install shellcheck, or uvx --from shellcheck-py shellcheck once)"
    fi
    qshl_check static "python syntax" -- \
        python3 -I -m py_compile scripts/lib/sshd_e2e.py tests/chaos/report.py
}

# ---------------------------------------------------------------------------------------------
# The binaries of steps 2 and 3: the test build of step 1 (all features: self-install for
# `qsh install`, test-hooks for the upgrade checks), copied out under the build lock so that a
# concurrent build cannot replace them mid-run

copy_artifacts() {
    python3 -I - "$1" "$2" <<'EOF'
import json, os, shutil, sys
found = {}
for line in open(sys.argv[1], encoding="utf-8"):
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") != "compiler-artifact" or not m.get("executable"):
        continue
    t = m["target"]
    # The programs themselves, not the unit-test harnesses of their bin targets
    if "bin" in t["kind"] and t["name"] in ("qsh", "qsh-server") and not m["profile"]["test"]:
        found[t["name"]] = m["executable"]
    elif t["name"] == "chaos" and m["profile"]["test"]:
        found["chaos"] = m["executable"]
missing = {"qsh", "qsh-server", "chaos"} - found.keys()
if missing:
    sys.exit(f"build: no {', '.join(sorted(missing))} in the cargo output")
for name, path in found.items():
    dest = os.path.join(sys.argv[2], name)
    shutil.copyfile(path, dest)
    os.chmod(dest, 0o755)
    print(f"{name}: {path} -> {dest}")
EOF
}

build_bins() {
    local jsonl="$QSHL_LOG_DIR/build.jsonl"
    qshl_disk_ok "${CARGO_TARGET_DIR:-$QSHL_REPO/target}" || return 1
    mkdir -p "$ROOT/bin"
    (
        flock 9
        nice -n 10 cargo test --workspace --all-features --locked -j 2 --no-run \
            --message-format=json-render-diagnostics >"$jsonl" &&
            copy_artifacts "$jsonl" "$ROOT/bin"
    ) 9>>/tmp/heavy.lock
}

# ---------------------------------------------------------------------------------------------
# Step 2: real sshd end to end

step_e2e() {
    local log="$QSHL_LOG_DIR/sshd-e2e.log" start=$SECONDS rc=0
    local args=(--qsh "$ROOT/bin/qsh" --server "$ROOT/bin/qsh-server" --no-copy
        --results "$QSHL_RESULTS" --tmp "$TMPBASE" --self-install --test-hooks
        --pipe-mib "$PIPE_MIB" --pipe-runs "$PIPE_RUNS" --pipe-runs-other "$PIPE_RUNS_OTHER")
    [ -n "$E2E_ONLY" ] && args+=(--only "$E2E_ONLY")
    [ -n "$QSHL_TRUSTED_DIR" ] && args+=(--trust-root)
    [ "$KEEP" = 1 ] && args+=(--keep)
    local before
    before=$(wc -l <"$QSHL_RESULTS")
    python3 -I "$QSHL_REPO/scripts/lib/sshd_e2e.py" "${args[@]}" 2>&1 | tee "$log"
    rc=${PIPESTATUS[0]}
    # The driver records its own rows; a crash before any row is a failure of its own
    if [ "$(wc -l <"$QSHL_RESULTS")" = "$before" ]; then
        qshl_result FAIL sshd "end-to-end driver" $((SECONDS - start)) "exit $rc; log $log"
    fi
}

# ---------------------------------------------------------------------------------------------
# Step 4: fuzzing

step_fuzz() {
    if ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
        qshl_result SKIP fuzz "cargo fuzz" 0 \
            "no nightly toolchain: rustup toolchain install nightly --profile minimal; cargo install cargo-fuzz"
        return
    fi
    if ! cargo +nightly fuzz --version >/dev/null 2>&1; then
        qshl_result SKIP fuzz "cargo fuzz" 0 "cargo-fuzz is not installed: cargo install cargo-fuzz"
        return
    fi
    local target
    for target in $(python3 -I -c 'import sys, tomllib; print(" ".join(b["name"] for b in tomllib.load(open(sys.argv[1], "rb")).get("bin", [])))' fuzz/Cargo.toml); do
        qshl_check fuzz "$target" --heavy -- \
            cargo +nightly fuzz run --target x86_64-unknown-linux-gnu "$target" -- \
            -max_total_time="$FUZZ" -rss_limit_mb=1024
    done
}

# ---------------------------------------------------------------------------------------------

if [ "$SKIP_STATIC" = 1 ]; then
    qshl_result SKIP static "static, unit and e2e tests" 0 "--skip-static"
else
    step_static
fi

if [ "$SKIP_E2E" = 0 ] || [ "$CHAOS" = 1 ]; then
    if qshl_check build "binaries (all features)" -- build_bins; then
        if [ "$SKIP_E2E" = 1 ]; then
            qshl_result SKIP sshd "real sshd end to end" 0 "--skip-e2e"
        else
            step_e2e
        fi
        if [ "$CHAOS" = 1 ]; then
            qshl_chaos "$ROOT" "$ROOT/bin/chaos" "$ROOT/bin/qsh" "$ROOT/bin/qsh-server"
        else
            qshl_result SKIP chaos "chaos tests" 0 "off by default: --chaos (needs sudo)"
        fi
    fi
else
    qshl_result SKIP sshd "real sshd end to end" 0 "--skip-e2e"
    qshl_result SKIP chaos "chaos tests" 0 "off by default: --chaos (needs sudo)"
fi

if [ "$FUZZ" -gt 0 ]; then
    step_fuzz
else
    qshl_result SKIP fuzz "cargo fuzz" 0 "off by default: --fuzz SECONDS"
fi

FINISHED=1
