#!/bin/sh
# The chaos topology of docs/m2.md section 12.2: three network namespaces joined by veth pairs,
#
#   qsh-c (client)  c0 ──veth── rc  qsh-r (router: netem, nft, NAT)  rs ──veth── s0  qsh-s (server)
#   10.77.1.2/24, fd77:1::2/64       10.77.1.1 | 10.77.2.1                       10.77.2.2/24, fd77:2::2/64
#
# with sshd in qsh-s (a test user and key), netem on both router interfaces (each direction its
# own delay and loss), nftables in the router for UDP blocking, outages and NAT.
#
# Needs root. It only touches its own namespaces, its own directory ($QSH_CHAOS_DIR, default
# /tmp/qsh-chaos) and its own user ($QSH_CHAOS_USER, default qshtest): never the host's
# firewall, routes or sysctls. Run it in a CI runner or a VM, not on a shared machine.
#
# Local mode (QSH_CHAOS_LOCAL=1, for `scripts/local-test.sh --chaos` on a developer's machine):
# the namespaces are $QSH_CHAOS_NS_PREFIX-c, -r and -s (default prefix qsh), no user is created:
# QSH_CHAOS_USER is an existing unprivileged user (the developer). sshd runs as that user
# (port $QSH_CHAOS_SSH_PORT, default 2222) with its keys in $QSH_CHAOS_DIR, and sets HOME and
# the XDG directories of every login to $QSH_CHAOS_DIR/home and $QSH_CHAOS_DIR/run, so nothing
# of the user's real home is read or written. Processes are found and killed by namespace,
# never by user.
#
# Usage: netns.sh COMMAND [ARGS]
#   up                    build the topology, the test user and sshd (tears down any old one)
#   down                  stop everything in the namespaces and delete them
#   install-server BIN    install BIN as the test user's ~/.local/bin/qsh-server
#   profile NAME          netem on both router interfaces: clean, crossborder, lossy, terrible,
#                         slow (135 ms, 2 Mbit/s, no loss), none
#   block-udp [PORTS]     drop forwarded UDP (all, or to and from PORTS, like 60443-60542)
#   offline | online      drop every forwarded packet | stop doing that (keeps block-udp rules)
#   unblock               remove every drop rule
#   nat on [SECONDS]      masquerade the client network with random ports and a short UDP
#                         conntrack timeout (default 15 s): NAT rebinding | nat off
#   move-client           the client's address changes from 10.77.1.2 to 10.77.1.3, as when a
#                         laptop moves from Wi-Fi to cellular | restore-client
#   reset                 profile clean, unblock, nat off, restore-client
#   as-user CMD...        run CMD as the test user with a clean environment (in the root netns;
#                         the daemon's control socket is a file, so this reaches it)
#   kill-user             stop the test user's daemon, then kill every process of the test user
#   status                show the topology
set -eu

PREFIX=${QSH_CHAOS_NS_PREFIX:-qsh}
C=$PREFIX-c
R=$PREFIX-r
S=$PREFIX-s
DIR=${QSH_CHAOS_DIR:-/tmp/qsh-chaos}
TUSER=${QSH_CHAOS_USER:-qshtest}
SERVER_IP=10.77.2.2
LOCAL=
[ "${QSH_CHAOS_LOCAL:-}" = 1 ] && LOCAL=1
SSH_PORT=22
[ -n "$LOCAL" ] && SSH_PORT=${QSH_CHAOS_SSH_PORT:-2222}

if [ "$(id -u)" != 0 ]; then
    echo "netns.sh: needs root" >&2
    exit 1
fi
if [ -n "$LOCAL" ] && { [ "$TUSER" = root ] || ! id "$TUSER" >/dev/null 2>&1; }; then
    echo "netns.sh: local mode needs QSH_CHAOS_USER, an existing user other than root" >&2
    exit 1
fi

inc() { ip netns exec "$C" "$@"; }
inr() { ip netns exec "$R" "$@"; }
ins() { ip netns exec "$S" "$@"; }
home() {
    if [ -n "$LOCAL" ]; then echo "$DIR/home"; else getent passwd "$TUSER" | cut -d: -f6; fi
}
ns_exists() { ip netns list | awk '{print $1}' | grep -qxF "$1"; }
# Local mode: the environment of the test user's logins and helpers, the test home and runtime
# directory instead of the user's real ones (sshd's SetEnv says the same)
local_env() {
    h=$(home)
    echo "HOME=$h XDG_RUNTIME_DIR=$DIR/run XDG_STATE_HOME=$h/.local/state XDG_CONFIG_HOME=$h/.config"
}

# Packet offloads off: netem would otherwise delay, drop and rate-limit 64 KiB GSO
# super-packets, which no real path does
no_offloads() {
    command -v ethtool >/dev/null || return 0
    for feature in tso gso gro lro tx-udp-segmentation rx-gro-list rx-udp-gro-forwarding; do
        ip netns exec "$1" ethtool -K "$2" "$feature" off >/dev/null 2>&1 || true
    done
}

# netem arguments per profile (docs/m2.md 12.2). `limit` counts the packets netem holds, in
# its delay line and its queue: about the path's BDP plus 200 ms of queue, so that a flood
# fills a queue of realistic depth rather than netem's default of 1000 packets
profile_args() {
    case $1 in
        clean) echo "delay 1ms rate 1gbit limit 10000" ;;
        crossborder) echo "delay 135ms 20ms loss 6% rate 10mbit limit 400" ;;
        lossy) echo "delay 150ms 30ms loss 10% reorder 5% 25% rate 8mbit limit 400" ;;
        terrible) echo "delay 300ms 50ms loss 20% reorder 10% rate 2mbit limit 200" ;;
        slow) echo "delay 135ms rate 2mbit limit 200" ;;
        none) echo "" ;;
        *)
            echo "netns.sh: unknown profile $1" >&2
            exit 2
            ;;
    esac
}

down() {
    # Local mode: the user is the developer, whose other processes are none of our business;
    # everything the tests started runs in the namespaces
    [ -n "$LOCAL" ] || pkill -KILL -u "$TUSER" 2>/dev/null || true
    for ns in "$C" "$S" "$R"; do
        if ns_exists "$ns"; then
            for pid in $(ip netns pids "$ns"); do kill -KILL "$pid" 2>/dev/null || true; done
            ip netns del "$ns"
        fi
    done
}

user_setup() {
    if [ -z "$LOCAL" ]; then
        if ! id "$TUSER" >/dev/null 2>&1; then
            useradd -m -s /bin/bash "$TUSER"
        fi
        # "*": no password, but not locked (sshd without PAM refuses locked accounts)
        usermod -p '*' "$TUSER"
    fi
    h=$(home)
    group=$(id -gn "$TUSER")
    install -d -m 755 "$DIR" "$DIR/data"
    install -d -m 700 "$DIR/ssh" "$DIR/sshd"
    [ -f "$DIR/ssh/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C qsh-chaos -f "$DIR/ssh/id_ed25519"
    [ -f "$DIR/sshd/host_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C qsh-chaos-host -f "$DIR/sshd/host_ed25519"
    # Local mode: sshd and every client run as the user, the keys are its own; the authorized
    # keys stay in the test directory, never in the user's ~/.ssh
    client_extra=
    sshd_extra=
    if [ -n "$LOCAL" ]; then
        install -d -o "$TUSER" -g "$group" -m 700 "$h" "$DIR/run" "$h/.local" "$h/.local/bin" "$h/.config"
        install -o "$TUSER" -g "$group" -m 600 "$DIR/ssh/id_ed25519.pub" "$DIR/ssh/authorized_keys"
        authorized="$DIR/ssh/authorized_keys"
        client_extra="  Port $SSH_PORT
  IdentityAgent none
  ControlMaster no
  ControlPath none"
        sshd_extra="Port $SSH_PORT
StrictModes no
PermitUserRC no
PermitUserEnvironment no
SetEnv $(local_env)"
    else
        install -d -o "$TUSER" -g "$group" -m 700 "$h/.ssh" "$h/.local" "$h/.local/bin"
        install -o "$TUSER" -g "$group" -m 600 "$DIR/ssh/id_ed25519.pub" "$h/.ssh/authorized_keys"
        authorized=.ssh/authorized_keys
    fi
    # The client side: every tool gets `-F $DIR/ssh/config` and dials 10.77.2.2
    cat >"$DIR/ssh/config" <<EOF
Host *
  User $TUSER
  IdentityFile $DIR/ssh/id_ed25519
  IdentitiesOnly yes
  BatchMode yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  GlobalKnownHostsFile /dev/null
  LogLevel ERROR
  ConnectTimeout 60
${client_extra}
EOF
    chmod 600 "$DIR/ssh/config"
    cat >"$DIR/sshd/sshd_config" <<EOF
${sshd_extra}
ListenAddress $SERVER_IP
ListenAddress fd77:2::2
HostKey $DIR/sshd/host_ed25519
PidFile $DIR/sshd/sshd.pid
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile $authorized
PermitRootLogin no
AllowUsers $TUSER
AcceptEnv LANG LC_* QSH_TEST_*
PrintMotd no
PrintLastLog no
MaxStartups 200
MaxSessions 200
Subsystem sftp internal-sftp
EOF
    if [ -n "$LOCAL" ]; then
        chown -R "$TUSER:$group" "$DIR/ssh" "$DIR/sshd"
    fi
}

# Does sshd in the server namespace let the client in?
ssh_check() {
    if [ -n "$LOCAL" ]; then
        user_in "$C" ssh -F "$DIR/ssh/config" $SERVER_IP true 2>/dev/null
    else
        inc ssh -F "$DIR/ssh/config" $SERVER_IP true 2>/dev/null
    fi
}

# Local mode: CMD as the test user in namespace NS, with the test environment only
user_in() {
    ns=$1
    shift
    # shellcheck disable=SC2046 # local_env is words without spaces
    ip netns exec "$ns" runuser -u "$TUSER" -- env -i USER="$TUSER" LOGNAME="$TUSER" \
        PATH=/usr/local/bin:/usr/bin:/bin LANG=C.UTF-8 $(local_env) "$@"
}

up() {
    down
    for ns in "$C" "$R" "$S"; do
        ip netns add "$ns"
        ip netns exec "$ns" ip link set lo up
    done
    ip link add c0 netns "$C" type veth peer name rc netns "$R"
    ip link add s0 netns "$S" type veth peer name rs netns "$R"

    inc sysctl -qw net.ipv4.conf.all.promote_secondaries=1 net.ipv4.conf.default.promote_secondaries=1
    inc ip addr add 10.77.1.2/24 dev c0
    inc ip -6 addr add fd77:1::2/64 dev c0 nodad
    inc sysctl -qw net.ipv4.conf.c0.promote_secondaries=1

    inr ip addr add 10.77.1.1/24 dev rc
    inr ip -6 addr add fd77:1::1/64 dev rc nodad
    inr ip addr add 10.77.2.1/24 dev rs
    inr ip -6 addr add fd77:2::1/64 dev rs nodad
    inr sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1

    ins ip addr add $SERVER_IP/24 dev s0
    ins ip -6 addr add fd77:2::2/64 dev s0 nodad

    for pair in "$C c0" "$R rc" "$R rs" "$S s0"; do
        # shellcheck disable=SC2086
        set -- $pair
        ip netns exec "$1" ip link set "$2" up
        no_offloads "$1" "$2"
    done
    inc ip route add default via 10.77.1.1 src 10.77.1.2
    inc ip -6 route add default via fd77:1::1
    ins ip route add default via 10.77.2.1
    ins ip -6 route add default via fd77:2::1

    inr nft -f - <<'EOF'
table inet qshchaos {
  chain forward {
    type filter hook forward priority 0; policy accept;
  }
  chain input {
    type filter hook input priority 0; policy accept;
  }
}
EOF
    profile clean

    user_setup
    if [ -n "$LOCAL" ]; then
        # Unprivileged: it can only log in its own user, which is all it is for
        user_in "$S" /usr/sbin/sshd -f "$DIR/sshd/sshd_config" -E "$DIR/sshd/sshd.log"
    else
        mkdir -p /run/sshd
        ins /usr/sbin/sshd -f "$DIR/sshd/sshd_config" -E "$DIR/sshd/sshd.log"
    fi
    i=0
    until ssh_check; do
        i=$((i + 1))
        if [ $i -ge 50 ]; then
            echo "netns.sh: sshd in $S does not answer" >&2
            cat "$DIR/sshd/sshd.log" >&2 || true
            exit 1
        fi
        sleep 0.2
    done
    echo "netns.sh: up (client $C 10.77.1.2, server $S $SERVER_IP, user $TUSER)"
}

profile() {
    args=$(profile_args "$1")
    for dev in rc rs; do
        inr tc qdisc del dev $dev root 2>/dev/null || true
        if [ -n "$args" ]; then
            # shellcheck disable=SC2086
            inr tc qdisc add dev $dev root netem $args
        fi
    done
}

block_udp() {
    if [ $# -eq 0 ]; then
        inr nft add rule inet qshchaos forward meta l4proto udp drop
    else
        inr nft add rule inet qshchaos forward udp dport "$1" drop
        inr nft add rule inet qshchaos forward udp sport "$1" drop
    fi
}

nat_on() {
    timeout=${1:-15}
    inr nft -f - <<'EOF'
table ip qshnat {
  chain post {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "rs" ip saddr 10.77.1.0/24 masquerade random
  }
}
EOF
    # Per network namespace once the NAT table exists. Liberal TCP tracking: netem's loss and
    # reordering must not make conntrack drop ssh's packets as out of window (they would leave
    # untranslated)
    inr sysctl -qw net.netfilter.nf_conntrack_udp_timeout="$timeout" \
        net.netfilter.nf_conntrack_udp_timeout_stream="$timeout" \
        net.netfilter.nf_conntrack_tcp_be_liberal=1
    # Like a real NAT: the server cannot reach the client except through a mapping, and
    # packets to a forgotten mapping vanish (no ICMP port unreachable from the router)
    inr nft add rule inet qshchaos forward iifname rs ip daddr 10.77.1.0/24 ct state new drop
    inr nft add rule inet qshchaos input iifname rs meta l4proto udp drop
}

nat_off() {
    inr nft delete table ip qshnat 2>/dev/null || true
    if command -v conntrack >/dev/null; then inr conntrack -F >/dev/null 2>&1 || true; fi
}

move_client() {
    inc ip addr add 10.77.1.3/24 dev c0
    inc ip route replace default via 10.77.1.1 dev c0 src 10.77.1.3
    inc ip addr del 10.77.1.2/24 dev c0
}

restore_client() {
    inc ip addr add 10.77.1.2/24 dev c0 2>/dev/null || true
    inc ip route replace default via 10.77.1.1 dev c0 src 10.77.1.2
    inc ip addr del 10.77.1.3/24 dev c0 2>/dev/null || true
}

as_user() {
    h=$(home)
    cd /
    if [ -n "$LOCAL" ]; then
        # shellcheck disable=SC2046 # local_env is words without spaces
        runuser -u "$TUSER" -- env -i USER="$TUSER" LOGNAME="$TUSER" PATH=/usr/local/bin:/usr/bin:/bin \
            LANG=C.UTF-8 $(local_env) "$@"
        return
    fi
    runuser -u "$TUSER" -- env -i HOME="$h" USER="$TUSER" LOGNAME="$TUSER" PATH=/usr/local/bin:/usr/bin:/bin \
        LANG=C.UTF-8 "$@"
}

# Local mode: the processes of the server namespace but sshd's listener (the daemon, sessions
# and ssh logins the tests started)
server_pids() {
    listener=$(cat "$DIR/sshd/sshd.pid" 2>/dev/null || true)
    for pid in $(ip netns pids "$S"); do
        [ "$pid" = "$listener" ] || echo "$pid"
    done
}

kill_user() {
    h=$(home)
    if [ -x "$h/.local/bin/qsh-server" ]; then
        as_user timeout 10 "$h/.local/bin/qsh-server" stop >/dev/null 2>&1 || true
    fi
    if [ -n "$LOCAL" ]; then
        for pid in $(server_pids); do kill -KILL "$pid" 2>/dev/null || true; done
        i=0
        while [ -n "$(server_pids)" ] && [ $i -lt 50 ]; do
            i=$((i + 1))
            sleep 0.1
        done
        return
    fi
    pkill -KILL -u "$TUSER" 2>/dev/null || true
    i=0
    while pgrep -u "$TUSER" >/dev/null 2>&1 && [ $i -lt 50 ]; do
        i=$((i + 1))
        sleep 0.1
    done
}

cmd=${1:-}
[ $# -gt 0 ] && shift
case $cmd in
    up) up ;;
    down) down ;;
    install-server)
        h=$(home)
        install -o "$TUSER" -g "$(id -gn "$TUSER")" -m 755 "$1" "$h/.local/bin/qsh-server.new"
        mv -f "$h/.local/bin/qsh-server.new" "$h/.local/bin/qsh-server"
        ;;
    profile) profile "$1" ;;
    block-udp) block_udp "$@" ;;
    offline) inr nft add rule inet qshchaos forward drop comment '"offline"' ;;
    online)
        handle=$(inr nft -a list chain inet qshchaos forward | sed -n 's/.*comment "offline".*# handle \([0-9]*\).*/\1/p')
        for h in $handle; do inr nft delete rule inet qshchaos forward handle "$h"; done
        ;;
    unblock) inr nft flush chain inet qshchaos forward ;;
    nat)
        case ${1:-} in
            on) shift; nat_on "$@" ;;
            off) nat_off ;;
            *) echo "netns.sh: nat on|off" >&2; exit 2 ;;
        esac
        ;;
    move-client) move_client ;;
    restore-client) restore_client ;;
    reset)
        profile clean
        inr nft flush chain inet qshchaos forward
        inr nft flush chain inet qshchaos input
        nat_off
        restore_client
        ;;
    as-user) as_user "$@" ;;
    kill-user) kill_user ;;
    status)
        for ns in "$C" "$R" "$S"; do
            echo "== $ns"
            ip netns exec "$ns" ip -br addr
            ip netns exec "$ns" ip route
            ip netns exec "$ns" tc qdisc show
        done
        inr nft list ruleset
        ;;
    *)
        sed -n '2,/^set -eu/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
        exit 2
        ;;
esac
