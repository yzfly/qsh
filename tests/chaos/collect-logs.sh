#!/bin/sh
# Copy what explains a chaos run into OUT_DIR/logs for the workflow artifact: the clients' logs
# and transcripts, sshd's log, and the test user's daemon state (logs). Needs root.
# Usage: collect-logs.sh OUT_DIR
set -u
mkdir -p "${1:?usage: collect-logs.sh OUT_DIR}"
out=$(cd "$1" && pwd)/logs
DIR=${QSH_CHAOS_DIR:-/tmp/qsh-chaos}
TUSER=${QSH_CHAOS_USER:-qshtest}
mkdir -p "$out"
if [ -d "$DIR/clients" ]; then
    (cd "$DIR/clients" && find . -type f \( -name '*.log' -o -name '*.jsonl' \) -size -20M \
        -exec cp --parents {} "$out/" \;)
fi
cp "$DIR/sshd/sshd.log" "$out/" 2>/dev/null || true
if [ "${QSH_CHAOS_LOCAL:-}" = 1 ]; then
    home=$DIR/home
else
    home=$(getent passwd "$TUSER" | cut -d: -f6)
fi
# The daemon's logs only: its identity (key.der) stays on the runner
[ -n "$home" ] && [ -d "$home/.local/state/qsh" ] &&
    (cd "$home/.local/state/qsh" && find . -type f -name '*.log' -exec cp --parents {} "$out/" \;)
[ -n "${SUDO_UID:-}" ] && chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "${1}"
chmod -R a+rX "${1}"
exit 0
