#!/bin/sh
# Smoke test of an installed qsh package (any distribution, and Homebrew on macOS):
#
#   packaging/ci/smoke.sh VERSION
#
# Checks that qsh and qsh-server on PATH are VERSION, that their man pages are installed, and
# runs a real session on this machine: qsh bootstraps over a fake ssh (which runs the remote
# command locally), the installed qsh-server starts its daemon, and the client connects to it
# over QUIC on the loopback. Uses a temporary HOME and XDG directories; stops the daemon it
# started, and nothing else.
set -eu

version=$1

qsh --version | grep -F "$version"
qsh-server --version | grep -F "$version"
qsh --help > /dev/null
qsh-server --help > /dev/null
for page in qsh qsh-server qsh_config; do
	man -w "$page"
done

# A session over the loopback, with a fake ssh in front of PATH.
world=$(mktemp -d /tmp/qsh-smoke.XXXXXX)
mkdir -p "$world/bin" "$world/home" "$world/run" "$world/state" "$world/config"
chmod 0700 "$world/run"
cat > "$world/bin/ssh" << 'EOF'
#!/bin/sh
if [ "$1" = -G ]; then echo "hostname 127.0.0.1"; exit 0; fi
while [ $# -gt 0 ]; do
	case "$1" in
		-o|-p|-l|-i|-J|-F|-E|-b|-c|-m) shift 2 ;;
		--) shift; break ;;
		-*) shift ;;
		*) break ;;
	esac
done
shift
exec sh -c "$*"
EOF
chmod 0755 "$world/bin/ssh"
server_dir=$(dirname "$(command -v qsh-server)")
qsh_bin=$(command -v qsh)
export HOME="$world/home" XDG_RUNTIME_DIR="$world/run" XDG_STATE_HOME="$world/state" \
	XDG_CONFIG_HOME="$world/config" PATH="$world/bin:$server_dir:/usr/bin:/bin"
export QSH_SERVER_PORTS=${QSH_SERVER_PORTS:-61443-61463}

cleanup() {
	qsh-server stop > /dev/null 2>&1 || true
	rm -rf "$world"
}
trap cleanup EXIT

status=0
out=$("$qsh_bin" smokehost -- 'echo hello from qsh; exit 3' < /dev/null) || status=$?
echo "qsh said: $out (exit $status)"
[ "$out" = "hello from qsh" ] || { echo "smoke: unexpected output" >&2; exit 1; }
[ "$status" = 3 ] || { echo "smoke: unexpected exit status $status" >&2; exit 1; }
qsh-server status
qsh-server stop
echo "smoke: qsh $version works"
