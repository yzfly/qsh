#!/bin/sh
# The benchmark of docs/m2.md section 12.4: qsh, OpenSSH and mosh in the chaos topology under the
# same netem profile. Needs root, in a disposable machine (the bench workflow); mosh installed
# (ci-setup.sh --mosh).
#
# Usage: bench.sh CHAOS_TEST_BINARY [OUT_DIR]
#   CHAOS_TEST_BINARY  the `chaos` test of qsh-cli, built with --release
#                      (cargo test --release -p qsh-cli --features test-hooks --test chaos --no-run)
#   OUT_DIR            where results.jsonl and bench.md go (default ./bench-out)
#
# Settings (environment): QSH_BENCH_PROFILE (crossborder), QSH_BENCH_TOOLS (ssh,mosh,qsh),
# QSH_BENCH_RUNS (5), QSH_BENCH_KEYS (20), QSH_BENCH_SEQ (10000000), QSH_BENCH_CAP (300 s),
# QSH_BENCH_OUTAGE (60 s), QSH_BENCH_WINDOW (30 s); QSH_CHAOS_QSH and QSH_CHAOS_SERVER for
# binaries other than the ones the test was built with.
#
# The table is a draft for review: it goes into the README only after the maintainer approved
# its wording and method (m2.md section 14, Q4).
set -eu
if [ $# -lt 1 ]; then
    sed -n '2,/^set -eu/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
    exit 2
fi
bin=$1
out=${2:-bench-out}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"
rm -f "$out/results.jsonl"
status=0
QSH_CHAOS=1 QSH_BENCH=1 QSH_CHAOS_OUT="$out/results.jsonl" QSH_CHAOS_NETNS="$here/netns.sh" \
    "$bin" --exact bench_ssh_mosh_qsh --test-threads=1 --nocapture || status=$?
python3 "$here/report.py" "$out/results.jsonl" >"$out/bench.md"
cat "$out/bench.md"
"$here/netns.sh" down || true
exit $status
