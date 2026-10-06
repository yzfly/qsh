#!/bin/sh
# qsh-server doctor and tune on a distribution's stock container (distros.yml, job "doctor";
# m2.md 12.3). Runs as root inside the throwaway container, with the static qsh-server in
# /qsh/bin:
#
# 1. doctor, read only: every check is reported, with the distribution recognized; no check
#    fails (a container has no firewall, and qsh-server is installed where ssh finds it).
# 2. doctor --probe starts the daemon and reports its ports and certificate.
# 3. tune's dry run changes nothing; inside a container it changes no sysctl (they are the
#    host's).
# 4. tune --apply / --revert on a fake root seeded with stock values, with a stub modprobe:
#    the plan of this distribution is applied, doctor agrees, applying twice changes
#    nothing, and the revert leaves the tree byte for byte as before (S6).
#
# Usage: docker run --rm -v "$PWD/bin:/qsh/bin:ro" -v "$PWD/packaging/test:/t:ro" IMAGE sh /t/doctor.sh
set -eu

say() { printf 'doctor.sh: %s\n' "$*"; }
fail() { printf 'doctor.sh: FAILED: %s\n' "$*" >&2; exit 1; }

# Where a login-less ssh finds it (protocol.md 10.2 looks in PATH and ~/.local/bin)
cp /qsh/bin/qsh-server /usr/bin/qsh-server
B=/usr/bin/qsh-server
IDS="daemon ports firewall udp-buffers gso-gro tcp-bbr ipv6 mtu linger runtime-dir selinux apparmor clock limits conntrack cloud container discovery"

# --- 1. read only
$B doctor || true
status=0
$B doctor --json > /tmp/doctor.json || status=$?
[ "$status" -le 1 ] || fail "doctor --json exited with $status"
for id in $IDS; do
	grep -q "\"id\":\"$id\"" /tmp/doctor.json || fail "no check $id"
done
grep -q '"container":"' /tmp/doctor.json || fail "the container was not recognized"
grep -q '"family":"unknown"' /tmp/doctor.json && fail "the distribution was not recognized"
# serde_json writes members in sorted order: "id" then "status"
failed=$(grep -o '"id":"[a-z-]*","status":"fail"' /tmp/doctor.json || true)
[ -z "$failed" ] || fail "checks failed: $failed"
[ "$status" -eq 0 ] || fail "doctor exited 1 without a failed check"
[ -e /var/lib/qsh/tune.json ] && fail "doctor wrote a tune record"

# --- 2. --probe
$B doctor --json --probe > /tmp/probe.json || true
grep -q '"cert_sha256":"[0-9a-f]\{64\}"' /tmp/probe.json || fail "--probe reported no certificate"
grep -q '"running":true' /tmp/probe.json || fail "--probe did not start the daemon"
$B stop || true

# --- 3. the dry run, and --apply in the container itself (the host's sysctls are not touched)
before=$(cat /proc/sys/net/core/rmem_max)
$B tune
$B tune --apply --yes
[ "$(cat /proc/sys/net/core/rmem_max)" = "$before" ] || fail "tune changed a sysctl inside a container"
[ -e /etc/sysctl.d/90-qsh.conf ] && fail "tune wrote 90-qsh.conf inside a container"

# --- 4. apply and revert on a fake root
R=/tmp/fakeroot
S=/tmp/stubs
mkdir -p "$S" "$R/etc" "$R/run/systemd/system" "$R/proc/sys/kernel" "$R/proc/sys/net/core" "$R/proc/sys/net/ipv4"
cp /etc/os-release "$R/etc/os-release" 2>/dev/null || cp /usr/lib/os-release "$R/etc/os-release"
kernel=$(uname -r)
echo fakehost > "$R/proc/sys/kernel/hostname"
echo "$kernel" > "$R/proc/sys/kernel/osrelease"
echo 212992 > "$R/proc/sys/net/core/rmem_max"
echo 212992 > "$R/proc/sys/net/core/wmem_max"
echo fq_codel > "$R/proc/sys/net/core/default_qdisc"
echo "reno cubic" > "$R/proc/sys/net/ipv4/tcp_available_congestion_control"
echo "reno cubic" > "$R/proc/sys/net/ipv4/tcp_allowed_congestion_control"
echo cubic > "$R/proc/sys/net/ipv4/tcp_congestion_control"
echo 1024 > "$R/proc/sys/net/ipv4/ip_unprivileged_port_start"
mkdir -p "$R/lib/modules/$kernel"
echo "kernel/net/ipv4/tcp_bbr.ko:" > "$R/lib/modules/$kernel/modules.dep"
cat > "$S/modprobe" <<'EOF'
#!/bin/sh
f="$FAKE_ROOT/proc/sys/net/ipv4/tcp_available_congestion_control"
case "$*" in
	tcp_bbr) echo "reno cubic bbr" > "$f" ;;
	"-r tcp_bbr") echo "reno cubic" > "$f" ;;
	*) exit 1 ;;
esac
EOF
# The fake root is no container and has no services, whatever the image's own tools say
printf '#!/bin/sh\necho none\nexit 1\n' > "$S/systemd-detect-virt"
printf '#!/bin/sh\ncase "$*" in\n\t--version) echo "systemd 255 (255)" ;;\n\tis-active*) echo inactive; exit 3 ;;\n\t*) echo disabled; exit 1 ;;\nesac\n' > "$S/systemctl"
chmod 755 "$S/modprobe" "$S/systemd-detect-virt" "$S/systemctl"

# Every file with its checksum and every directory, without find (not in every image)
walk() {
	for f in "$1"/* "$1"/.[!.]*; do
		[ -e "$f" ] || [ -L "$f" ] || continue
		if [ -d "$f" ] && [ ! -L "$f" ]; then
			echo "dir $f"
			walk "$f"
		else
			echo "file $f $(cksum < "$f")"
		fi
	done
}
walk "$R" > /tmp/before

export FAKE_ROOT="$R"
T() { PATH="$S:$PATH" $B tune --root "$R" "$@"; }
T > /tmp/plan.txt
cat /tmp/plan.txt
grep -q '+net.core.rmem_max = 4194304' /tmp/plan.txt || fail "the plan does not raise rmem_max"
grep -q 'modprobe tcp_bbr' /tmp/plan.txt || fail "the plan does not load tcp_bbr"
[ "$(walk "$R")" = "$(cat /tmp/before)" ] || fail "the dry run changed the fake root"
T --apply --yes
[ "$(cat "$R/proc/sys/net/core/rmem_max")" = 4194304 ] || fail "rmem_max not raised"
[ -s "$R/var/lib/qsh/tune.json" ] || fail "no record"
PATH="$S:$PATH" $B doctor --root "$R" --json > /tmp/tuned.json || true
for id in udp-buffers tcp-bbr; do
	grep -q "\"id\":\"$id\",\"status\":\"ok\"" /tmp/tuned.json || fail "$id is not ok after tune"
done
T --apply --yes | grep -q 'nothing to change' || fail "applying twice changed something"
T --revert --yes
if [ "$(walk "$R")" != "$(cat /tmp/before)" ]; then
	echo "before:"; cat /tmp/before; echo "after:"; walk "$R"
	fail "the revert did not restore the fake root byte for byte"
fi
say "ok"
