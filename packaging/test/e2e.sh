#!/usr/bin/env bash
# End-to-end test of qsh against one Linux distribution, run on a CI runner (Ubuntu with docker
# and passwordless sudo for iptables).
#
#   QSH_BIN_DIR=target/x86_64-unknown-linux-musl/release packaging/test/e2e.sh fedora:latest
#
# Builds packaging/test/Dockerfile on the image, starts it with sshd on port 2222 and the static
# qsh-server in ~test/.local/bin, then runs the local qsh against it, non-interactively:
#
#   plain        qsh -p 2222 test@IP -- echo qsh-ok         QUIC should win
#   stdin        printf hello | qsh ... -- cat              stdin reaches the remote command
#   exit-code    qsh ... -- sh -c 'exit 7'                  qsh exits with the remote code
#   udp-blocked  the same, UDP to the container dropped    TLS over TCP must win
#   ssh-pipe     UDP dropped and TCP rejected except 2222  the ssh pipe must win
#
# The blocks are iptables rules in the runner's OUTPUT chain (the client's side of the path), so
# they behave the same whatever firewall tools each distribution image has.
set -euo pipefail

image="${1:?usage: e2e.sh IMAGE (e.g. debian:12)}"
bin_dir="${QSH_BIN_DIR:?set QSH_BIN_DIR to the directory with qsh and qsh-server}"
here="$(cd "$(dirname "$0")" && pwd)"
tag="$(printf '%s' "$image" | tr -c 'a-zA-Z0-9.-' '-')"
work="$here/.work/$tag"
name="qsh-e2e-$tag-$$"
timeout_s="${QSH_E2E_TIMEOUT:-60}"

qsh="$bin_dir/qsh"
[[ -x "$qsh" && -x "$bin_dir/qsh-server" ]] || {
    echo "e2e: $bin_dir must contain executable qsh and qsh-server" >&2
    exit 2
}

rules=()
cleanup() {
    local rule
    for rule in "${rules[@]}"; do
        # shellcheck disable=SC2086 # a rule is a list of iptables arguments
        sudo iptables -D OUTPUT $rule 2>/dev/null || true
    done
    rules=()
    docker rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

block() {
    # shellcheck disable=SC2086
    sudo iptables -I OUTPUT $1
    rules+=("$1")
}

unblock_all() {
    local rule
    for rule in "${rules[@]}"; do
        # shellcheck disable=SC2086
        sudo iptables -D OUTPUT $rule
    done
    rules=()
}

rm -rf "$work"
mkdir -p "$work/in" "$work/xdg/config" "$work/xdg/state" "$work/xdg/run" "$work/home"
chmod 0700 "$work/xdg/run"
ssh-keygen -q -t ed25519 -N '' -C qsh-e2e -f "$work/id_ed25519"
cp "$work/id_ed25519.pub" "$work/in/authorized_keys"
cp "$bin_dir/qsh-server" "$work/in/qsh-server"

echo "::group::image $image"
docker build --quiet --build-arg "BASE=$image" -t "qsh-e2e:$tag" "$here"
echo "::endgroup::"

docker run -d --name "$name" -v "$work/in:/qsh-in:ro" "qsh-e2e:$tag" >/dev/null
ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name")"
[[ -n "$ip" ]] || {
    echo "e2e: container has no IP address" >&2
    exit 1
}

ssh_opts=(-i "$work/id_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
    -o BatchMode=yes -o LogLevel=ERROR -o ConnectTimeout=5)

# Plain ssh first: proves the container works before qsh is blamed for anything.
for _ in $(seq 1 60); do
    if ssh "${ssh_opts[@]}" -p 2222 "test@$ip" true 2>/dev/null; then
        break
    fi
    sleep 1
done
ssh "${ssh_opts[@]}" -p 2222 "test@$ip" 'uname -a; cat /etc/os-release | head -n 2'

# The client gets its own XDG directories and HOME, never the runner user's.
run_qsh() {
    env HOME="$work/home" XDG_CONFIG_HOME="$work/xdg/config" XDG_STATE_HOME="$work/xdg/state" \
        XDG_RUNTIME_DIR="$work/xdg/run" \
        timeout "$timeout_s" "$qsh" "${ssh_opts[@]}" -p 2222 "test@$ip" "$@"
}

failures=0
# check NAME EXPECTED_RC EXPECTED_STDOUT STDIN -- QSH_ARGS...
check() {
    local case_name="$1" want_rc="$2" want_out="$3" input="$4"
    shift 5
    local out rc start end
    start=$(date +%s%N)
    set +e
    out="$(printf '%s' "$input" | run_qsh "$@" 2>"$work/$case_name.stderr")"
    rc=$?
    set -e
    end=$(date +%s%N)
    if [[ "$rc" == "$want_rc" && "$out" == "$want_out" ]]; then
        printf 'ok    %-12s %s (%d ms)\n' "$case_name" "$image" "$(((end - start) / 1000000))"
    else
        printf 'FAIL  %-12s %s: exit %s (want %s), stdout %q (want %q)\n' \
            "$case_name" "$image" "$rc" "$want_rc" "$out" "$want_out"
        echo "--- stderr"
        cat "$work/$case_name.stderr"
        failures=$((failures + 1))
    fi
}

check plain 0 qsh-ok '' -- -- echo qsh-ok
check stdin 0 hello hello -- -- cat
check exit-code 7 '' '' -- -- sh -c 'exit 7'

block "-d $ip -p udp -j DROP"
check udp-blocked 0 qsh-ok '' -- -- echo qsh-ok

block "-d $ip -p tcp ! --dport 2222 -j REJECT --reject-with tcp-reset"
check ssh-pipe 0 qsh-ok '' -- -- echo qsh-ok
unblock_all

if ((failures > 0)); then
    echo "::group::server side ($image)"
    docker logs "$name" 2>&1 | tail -n 50 || true
    docker exec "$name" sh -c 'find /home/test /tmp /run/user -path "*qsh*" 2>/dev/null | head -n 50' || true
    echo "::endgroup::"
    echo "e2e: $failures case(s) failed on $image" >&2
    exit 1
fi
echo "e2e: all cases passed on $image"
