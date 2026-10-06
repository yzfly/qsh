//! The checks of `qsh-server doctor` (m2.md 8.2), each a function of what the [`System`]
//! shows and of the [`Context`] (the configuration, the daemon's status, the user the
//! per-user checks are about). Nothing here changes anything or calls the network.

use std::net::IpAddr;
use std::ops::RangeInclusive;

use serde_json::{json, Value};

use super::distro::{self, Family, OsRelease};
use super::firewall::{self, Ports, Verdict};
use super::system::{Bind, System};
use super::{Check, Fix, Status};

/// The UDP buffer limit the daemon asks for (`SO_RCVBUF` / `SO_SNDBUF`, m2.md 8.2).
pub const WANTED_BUFFER: u64 = 4_194_304;
/// The smallest useful descriptor limit (protocol.md 6.6).
pub const WANTED_NOFILE: u64 = 4096;
/// QUIC needs UDP payloads of 1200 bytes: 1200 + 8 (UDP) + 20 (IPv4).
pub const MIN_MTU_V4: u64 = 1228;
/// The same over IPv6 (40-byte header).
pub const MIN_MTU_V6: u64 = 1248;

/// The user the per-user checks are about: the invoking user, or `SUDO_USER` under sudo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// Login name.
    pub name: String,
    /// User id.
    pub uid: u32,
    /// Home directory.
    pub home: String,
    /// True when this is `SUDO_USER`, not the process's own user.
    pub sudo: bool,
}

/// What the daemon's control socket said.
#[derive(Debug, Clone, PartialEq)]
pub enum DaemonState {
    /// `qsh-server status` output.
    Running(Value),
    /// No daemon runs (and none was started).
    NotRunning,
    /// It could not be asked (root looking at another user, an error).
    Unreachable(String),
    /// `--probe` could not start it (the error, and where its log is).
    Failed(String, String),
}

/// What the checks need beyond the system itself.
#[derive(Debug, Clone)]
pub struct Context {
    /// This program's version.
    pub version: String,
    /// This program, for the discovery fix.
    pub exe: Option<String>,
    /// The configured port range (`[server] ports`, `QSH_SERVER_PORTS`).
    pub range: RangeInclusive<u16>,
    /// The configured extra ports.
    pub extra_ports: Vec<u16>,
    /// The daemon.
    pub daemon: DaemonState,
    /// `--probe`: the daemon was started if needed, and its ports and certificate are
    /// reported.
    pub probe: bool,
    /// The user of the per-user checks.
    pub user: User,
}

/// The host, for the report's first line and the JSON `host` object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInfo {
    /// Host name.
    pub name: String,
    /// os-release.
    pub os: OsRelease,
    /// Its family.
    pub family: Family,
    /// `systemd`, `openrc` or `unknown`.
    pub init: &'static str,
    /// systemd's version, when systemd runs.
    pub systemd: Option<String>,
    /// Kernel release.
    pub kernel: String,
    /// Virtualization (`kvm`, `xen`, …), None on bare metal or when unknown.
    pub virt: Option<String>,
    /// Container (`docker`, `podman`, `lxc`, `systemd-nspawn`, `wsl`), None outside one.
    pub container: Option<String>,
    /// Cloud provider id (`aws`, `gcp`, …), from DMI.
    pub cloud: Option<&'static str>,
}

impl HostInfo {
    /// Read it from the system.
    pub fn read(sys: &dyn System) -> HostInfo {
        let os = OsRelease::read(sys).unwrap_or_else(|| OsRelease::parse(""));
        let family = Family::of(&os);
        let init = distro::init_system(sys);
        HostInfo {
            name: read_trim(sys, "/proc/sys/kernel/hostname").unwrap_or_else(|| "localhost".into()),
            family,
            init,
            systemd: (init == "systemd").then(|| distro::systemd_version(sys)).flatten(),
            kernel: read_trim(sys, "/proc/sys/kernel/osrelease").unwrap_or_default(),
            virt: virtualization(sys),
            container: container(sys),
            cloud: cloud(sys).map(|c| c.id),
            os,
        }
    }

    /// The JSON `host` object (m2.md 8.1).
    pub fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "os_id": self.os.id,
            "os_version": self.os.version_id,
            "os_name": self.os.pretty_name,
            "family": self.family.as_str(),
            "init": self.init,
            "systemd": self.systemd,
            "kernel": self.kernel,
            "virt": self.virt,
            "container": self.container,
            "cloud": self.cloud,
        })
    }

    /// "Ubuntu 24.04 LTS, systemd 255, kernel 6.8.0, KVM (Amazon EC2)".
    pub fn describe(&self) -> String {
        let mut parts = vec![self.os.pretty_name.clone()];
        match (&self.systemd, self.init) {
            (Some(v), _) => parts.push(format!("systemd {v}")),
            (None, "openrc") => parts.push("OpenRC".into()),
            _ => {}
        }
        if !self.kernel.is_empty() {
            // "6.8.0-45-generic" → "6.8.0"
            let short = self.kernel.split(['-', '+']).next().unwrap_or(&self.kernel);
            parts.push(format!("kernel {short}"));
        }
        if let Some(c) = &self.container {
            parts.push(format!("in a {c} container"));
        }
        let cloud = self.cloud.and_then(cloud_by_id).map(|c| c.name);
        match (&self.virt, cloud) {
            (Some(v), Some(c)) => parts.push(format!("{} ({c})", virt_name(v))),
            (Some(v), None) => parts.push(virt_name(v)),
            (None, Some(c)) => parts.push(c.to_string()),
            (None, None) => {}
        }
        if self.family == Family::Unknown {
            parts.push("unknown distribution: generic fixes".into());
        }
        parts.join(", ")
    }
}

fn virt_name(v: &str) -> String {
    match v {
        "kvm" => "KVM".into(),
        "qemu" => "QEMU".into(),
        "xen" => "Xen".into(),
        "vmware" => "VMware".into(),
        "microsoft" => "Hyper-V".into(),
        "oracle" => "VirtualBox".into(),
        "amazon" => "Amazon Nitro".into(),
        "google" => "Google".into(),
        other => other.to_string(),
    }
}

fn read_trim(sys: &dyn System, path: &str) -> Option<String> {
    sys.read(path).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn read_u64(sys: &dyn System, path: &str) -> Option<u64> {
    read_trim(sys, path)?.parse().ok()
}

/// The path of a sysctl under /proc/sys.
pub fn sysctl_path(key: &str) -> String {
    format!("/proc/sys/{}", key.replace('.', "/"))
}

/// The value of a sysctl, None when it does not exist here.
pub fn sysctl(sys: &dyn System, key: &str) -> Option<String> {
    sys.read(&sysctl_path(key))
        .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
}

// ---------------------------------------------------------------------------------------
// Environment: virtualization, containers, clouds

/// Virtualization, from `systemd-detect-virt --vm`, else DMI.
pub fn virtualization(sys: &dyn System) -> Option<String> {
    if let Some(out) = sys.run("systemd-detect-virt", &["--vm"]) {
        let v = out.stdout.trim();
        return (out.ok() && !v.is_empty() && v != "none").then(|| v.to_string());
    }
    let dmi = |f: &str| read_trim(sys, &format!("/sys/class/dmi/id/{f}")).unwrap_or_default();
    let (vendor, product, bios) = (dmi("sys_vendor"), dmi("product_name"), dmi("bios_vendor"));
    let all = format!("{vendor} {product} {bios}");
    Some(
        if all.contains("Amazon EC2") {
            "amazon"
        } else if product.contains("KVM") || vendor == "QEMU" || all.contains("SeaBIOS") {
            "kvm"
        } else if all.contains("VMware") {
            "vmware"
        } else if all.contains("VirtualBox") || vendor.contains("innotek") {
            "oracle"
        } else if vendor.contains("Microsoft") && product.contains("Virtual Machine") {
            "microsoft"
        } else if all.contains("Xen") || sys.exists("/proc/xen") {
            "xen"
        } else if product == "Google Compute Engine" {
            "google"
        } else {
            return None;
        }
        .to_string(),
    )
}

/// The container this runs in, if any (m2.md 8.2, `container`).
pub fn container(sys: &dyn System) -> Option<String> {
    if sys.exists("/.dockerenv") {
        return Some("docker".into());
    }
    if sys.exists("/run/.containerenv") {
        return Some("podman".into());
    }
    if let Some(c) = read_trim(sys, "/run/systemd/container") {
        return Some(c);
    }
    if let Some(env) = sys.read("/proc/1/environ") {
        if let Some(c) = env.split('\0').find_map(|v| v.strip_prefix("container=")) {
            if !c.is_empty() {
                return Some(c.to_string());
            }
        }
    }
    if let Some(out) = sys.run("systemd-detect-virt", &["--container"]) {
        let v = out.stdout.trim();
        if out.ok() && !v.is_empty() && v != "none" {
            return Some(v.to_string());
        }
    }
    let release = sys.read("/proc/sys/kernel/osrelease").unwrap_or_default();
    if release.contains("microsoft") || release.contains("WSL") {
        return Some("wsl".into());
    }
    None
}

/// A cloud provider, as DMI shows it (m2.md 8.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cloud {
    /// `aws`, `gcp`, `azure`, `alibaba`, `tencent`, `oracle`, `hetzner`, `digitalocean`,
    /// `vultr`.
    pub id: &'static str,
    /// For people.
    pub name: &'static str,
    /// What must allow the ports there.
    pub firewall: &'static str,
}

const CLOUDS: &[Cloud] = &[
    Cloud {
        id: "aws",
        name: "Amazon EC2",
        firewall: "the instance's security group must allow inbound",
    },
    Cloud {
        id: "gcp",
        name: "Google Compute Engine",
        firewall: "a VPC firewall rule must allow ingress",
    },
    Cloud {
        id: "azure",
        name: "Microsoft Azure",
        firewall: "the network security group must allow inbound",
    },
    Cloud {
        id: "alibaba",
        name: "Alibaba Cloud",
        firewall: "the security group (安全组) must allow inbound",
    },
    Cloud {
        id: "tencent",
        name: "Tencent Cloud",
        firewall: "the security group (安全组) must allow inbound",
    },
    Cloud {
        id: "oracle",
        name: "Oracle Cloud",
        firewall: "the subnet's security list or the instance's NSG must allow inbound",
    },
    Cloud {
        id: "hetzner",
        name: "Hetzner Cloud",
        firewall: "a cloud firewall, if one is attached, must allow inbound",
    },
    Cloud {
        id: "digitalocean",
        name: "DigitalOcean",
        firewall: "a cloud firewall, if one is attached, must allow inbound",
    },
    Cloud {
        id: "vultr",
        name: "Vultr",
        firewall: "a Vultr firewall group, if one is attached, must allow inbound",
    },
];

fn cloud_by_id(id: &str) -> Option<Cloud> {
    CLOUDS.iter().copied().find(|c| c.id == id)
}

/// The cloud provider, from `/sys/class/dmi/id` only: no metadata service is contacted.
pub fn cloud(sys: &dyn System) -> Option<Cloud> {
    let dmi = |f: &str| read_trim(sys, &format!("/sys/class/dmi/id/{f}")).unwrap_or_default();
    let (vendor, product, bios, tag) = (
        dmi("sys_vendor"),
        dmi("product_name"),
        dmi("bios_vendor"),
        dmi("chassis_asset_tag"),
    );
    let id = if vendor.contains("Amazon EC2") || bios.contains("Amazon EC2") {
        "aws"
    } else if product.contains("Google Compute Engine") {
        "gcp"
    } else if tag == "7783-7084-3265-9085-8269-3286-77" {
        "azure"
    } else if vendor.contains("Alibaba Cloud") {
        "alibaba"
    } else if vendor.contains("Tencent Cloud") {
        "tencent"
    } else if tag == "OracleCloud.com" {
        "oracle"
    } else if vendor.contains("Hetzner") {
        "hetzner"
    } else if vendor.contains("DigitalOcean") {
        "digitalocean"
    } else if vendor.contains("Vultr") {
        "vultr"
    } else {
        return None;
    };
    cloud_by_id(id)
}

// ---------------------------------------------------------------------------------------
// Network facts

/// The IPv4 default route: (interface, gateway), the one with the lowest metric.
pub fn default_route_v4(sys: &dyn System) -> Option<(String, Option<IpAddr>)> {
    let text = sys.read("/proc/net/route")?;
    let mut best: Option<(u64, String, Option<IpAddr>)> = None;
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 || f[1] != "00000000" || f[7] != "00000000" {
            continue;
        }
        let metric: u64 = f[6].parse().unwrap_or(0);
        let gateway = u32::from_str_radix(f[2], 16)
            .ok()
            .filter(|g| *g != 0)
            .map(|g| IpAddr::from(g.to_le_bytes()));
        if best.as_ref().is_none_or(|b| metric < b.0) {
            best = Some((metric, f[0].to_string(), gateway));
        }
    }
    best.map(|(_, i, g)| (i, g))
}

/// The interface of the IPv6 default route.
pub fn default_route_v6(sys: &dyn System) -> Option<String> {
    let text = sys.read("/proc/net/ipv6_route")?;
    text.lines().find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        let default = f.len() >= 10 && f[0].chars().all(|c| c == '0') && f[1] == "00" && f[9] != "lo";
        // RTF_REJECT: an unreachable route is no way out
        let reject = f.get(8).and_then(|x| u32::from_str_radix(x, 16).ok()).unwrap_or(0) & 0x0200 != 0;
        (default && !reject).then(|| f[9].to_string())
    })
}

/// True for addresses that are not reachable from the internet without a NAT in front:
/// RFC 1918, carrier-grade NAT (RFC 6598), link-local.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private() || v4.is_link_local() || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Who holds `port` (UDP or TCP) according to /proc/net: the owner's user id.
fn port_holder(sys: &dyn System, port: u16, udp: bool) -> Option<u32> {
    let files: &[&str] = if udp {
        &["/proc/net/udp", "/proc/net/udp6"]
    } else {
        &["/proc/net/tcp", "/proc/net/tcp6"]
    };
    for file in files {
        let Some(text) = sys.read(file) else { continue };
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 8 {
                continue;
            }
            let Some(p) = f[1].rsplit(':').next().and_then(|p| u16::from_str_radix(p, 16).ok()) else {
                continue;
            };
            // TCP: listening sockets only
            if p == port && (udp || f[3] == "0A") {
                return f[7].parse().ok();
            }
        }
    }
    None
}

/// The login name of `uid`, from /etc/passwd.
pub fn user_name(sys: &dyn System, uid: u32) -> Option<String> {
    passwd_lines(sys).find_map(|f| (f.get(2)?.parse::<u32>().ok()? == uid).then(|| f[0].to_string()))
}

fn passwd_lines(sys: &dyn System) -> impl Iterator<Item = Vec<String>> {
    let text = sys
        .run("getent", &["passwd"])
        .filter(|o| o.ok())
        .map(|o| o.stdout)
        .or_else(|| sys.read("/etc/passwd"))
        .unwrap_or_default();
    text.lines()
        .map(|l| l.split(':').map(String::from).collect::<Vec<_>>())
        .filter(|f| f.len() >= 7)
        .collect::<Vec<_>>()
        .into_iter()
}

/// The user the per-user checks are about: `SUDO_USER` when running as root through sudo,
/// else this process's user.
pub fn target_user(sys: &dyn System, own: Option<(String, String)>) -> User {
    let euid = sys.euid();
    if euid == 0 {
        if let Some(name) = sys.env("SUDO_USER").filter(|n| !n.is_empty() && n != "root") {
            let entry = passwd_lines(sys).find(|f| f[0] == name);
            let uid = sys
                .env("SUDO_UID")
                .and_then(|u| u.parse().ok())
                .or_else(|| entry.as_ref().and_then(|f| f[2].parse().ok()))
                .unwrap_or(0);
            let home = entry.map(|f| f[5].clone()).unwrap_or_else(|| format!("/home/{name}"));
            return User {
                name,
                uid,
                home,
                sudo: true,
            };
        }
    }
    let (name, home) = own.unwrap_or_else(|| {
        (
            sys.env("USER").unwrap_or_else(|| euid.to_string()),
            sys.env("HOME").unwrap_or_else(|| "/".into()),
        )
    });
    User {
        name,
        uid: euid,
        home,
        sudo: false,
    }
}

// ---------------------------------------------------------------------------------------
// The checks

/// Every check of m2.md 8.2, in its order.
pub fn run_all(sys: &dyn System, host: &HostInfo, ctx: &Context) -> Vec<Check> {
    let route = default_route_v4(sys);
    let iface = route.as_ref().map(|r| r.0.clone());
    let ports = ports_of(ctx);
    let mut checks = vec![
        daemon(ctx),
        ports_check(sys, ctx),
        firewall_check(sys, host, &ports, iface.as_deref()),
        udp_buffers(sys, host),
        gso_gro(sys, host),
        tcp_bbr(sys, host),
        ipv6(sys),
        mtu(sys, iface.as_deref()),
        linger(sys, host, ctx),
        runtime_dir(sys, host, ctx),
        selinux(sys, ctx),
        apparmor(sys, ctx),
        clock(sys),
        limits(sys, host, ctx),
        conntrack(sys, host, &ports),
        cloud_check(sys, &ports),
        container_check(host, &ports),
        discovery(sys, host, ctx),
    ];
    if host.container.is_some() {
        for c in &mut checks {
            in_container(c);
        }
    }
    checks
}

/// Inside a container, host-wide settings are the host's: their fixes are for the host, and
/// tune does not apply them.
fn in_container(check: &mut Check) {
    if !["udp-buffers", "tcp-bbr", "conntrack"].contains(&check.id) {
        return;
    }
    if let Some(fix) = &mut check.fix {
        fix.tune = None;
        fix.note = Some("these settings belong to the container's host: run the commands there".into());
    }
    if check.status == Status::Warn {
        check.status = Status::Info;
    }
}

/// The ports the firewall and cloud checks are about.
pub fn ports_of(ctx: &Context) -> Ports {
    let (mut udp, mut tcp) = (*ctx.range.start(), *ctx.range.start());
    if let DaemonState::Running(s) = &ctx.daemon {
        let port = |k: &str| s[k].as_u64().and_then(|p| u16::try_from(p).ok()).filter(|p| *p != 0);
        udp = port("udp").unwrap_or(udp);
        tcp = port("tcp").unwrap_or(tcp);
    }
    // A daemon started with other ports (QSH_SERVER_PORTS) is what matters
    let mut range = ctx.range.clone();
    if !range.contains(&udp) || !range.contains(&tcp) {
        range = udp.min(tcp)..=udp.max(tcp);
    }
    Ports {
        range,
        extra: ctx.extra_ports.clone(),
        udp,
        tcp,
    }
}

fn daemon_ports(s: &Value) -> String {
    let (udp, tcp) = (s["udp"].as_u64().unwrap_or(0), s["tcp"].as_u64().unwrap_or(0));
    let mut text = match (udp, tcp) {
        (0, 0) => "no ports".to_string(),
        (u, t) if u == t => format!("UDP+TCP {u}"),
        (u, 0) => format!("UDP {u}"),
        (0, t) => format!("TCP {t}"),
        (u, t) => format!("UDP {u}, TCP {t}"),
    };
    if let Some(extra) = s["extra_ports"].as_array().filter(|e| !e.is_empty()) {
        let list: Vec<String> = extra
            .iter()
            .filter_map(|e| {
                let p = e["port"].as_u64()?;
                Some(match (e["udp"] == true, e["tcp"] == true) {
                    (true, true) => format!("{p}"),
                    (true, false) => format!("{p}/udp"),
                    _ => format!("{p}/tcp"),
                })
            })
            .collect();
        text.push_str(&format!(" (and {})", list.join(", ")));
    }
    text
}

/// Compare dotted versions: true when `a` is older than `b`.
fn older(a: &str, b: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> {
        v.split(['-', '+'])
            .next()
            .unwrap_or(v)
            .split('.')
            .map(|x| x.parse().unwrap_or(0))
            .collect()
    };
    parse(a) < parse(b)
}

fn daemon(ctx: &Context) -> Check {
    match &ctx.daemon {
        DaemonState::Running(s) => {
            let version = s["version"].as_str().unwrap_or("?").to_string();
            let sessions = s["session_count"].as_u64().unwrap_or(0);
            let plural = if sessions == 1 { "" } else { "s" };
            let summary = format!("{version} running, {}, {sessions} session{plural}", daemon_ports(s));
            let mut c = Check::new("daemon", Status::Ok, summary)
                .fact("version", version.clone())
                .fact("pid", s["pid"].clone())
                .fact("sessions", sessions);
            if older(&version, &ctx.version) {
                c.status = Status::Info;
                if s["can_upgrade"] == true {
                    c.summary = format!(
                        "{version} running (this is {}), {sessions} session{plural}: replaced in place at the next qsh login",
                        ctx.version
                    );
                    c = c.fix(
                        Fix::commands(false, ["qsh-server upgrade".to_string()])
                            .with_note("or now: it keeps every session"),
                    );
                } else {
                    c.summary = format!(
                        "{version} running (this is {}), {sessions} session{plural}: it cannot upgrade in place; replaced when its sessions end",
                        ctx.version
                    );
                    c = c.fix(
                        Fix::commands(false, ["qsh-server stop".to_string()])
                            .with_note("replaces it now, ending its sessions"),
                    );
                }
            } else if older(&ctx.version, &version) {
                c.status = Status::Info;
                c.summary = format!(
                    "{version} running, newer than this qsh-server ({}), {sessions} session{plural}",
                    ctx.version
                );
            }
            c
        }
        DaemonState::NotRunning => Check::new(
            "daemon",
            Status::Info,
            "not running; the next qsh login starts it (qsh-server doctor --probe starts it now)",
        ),
        DaemonState::Failed(why, log) => Check::new("daemon", Status::Fail, format!("the daemon cannot start: {why}"))
            .fix(Fix::default().with_note(format!("its log: {log}"))),
        DaemonState::Unreachable(why) => {
            let mut c = Check::new("daemon", Status::Skip, why.clone());
            if ctx.user.sudo {
                c = c.fix(
                    Fix::commands(false, ["qsh-server doctor".to_string()]).with_note(format!("as {}", ctx.user.name)),
                );
            }
            c
        }
    }
}

fn holder_text(sys: &dyn System, port: u16, udp: bool) -> String {
    match port_holder(sys, port, udp) {
        Some(uid) => match user_name(sys, uid) {
            Some(name) => format!("held by a program of {name}"),
            None => format!("held by a program of uid {uid}"),
        },
        None => "held by another program".into(),
    }
}

fn low_ports_fix(sys: &dyn System, port: u16) -> Fix {
    let start = sysctl(sys, "net.ipv4.ip_unprivileged_port_start").unwrap_or_else(|| "1024".into());
    Fix {
        root: true,
        tune: Some("low-ports"),
        tune_flags: vec![format!("--allow-low-ports={port}")],
        commands: vec![format!("sudo sysctl -w net.ipv4.ip_unprivileged_port_start={port}")],
        note: Some(format!(
            "now {start}; every local user could then bind ports {port}-1023: appropriate on a single-user host only"
        )),
    }
}

fn ports_check(sys: &dyn System, ctx: &Context) -> Check {
    let range = &ctx.range;
    let range_text = format!("{}-{}", range.start(), range.end());
    let (mut status, mut fix) = (Status::Ok, None);
    let mut summary;
    let mut daemon_extra: Vec<u16> = Vec::new();
    let mut facts = serde_json::Map::new();
    facts.insert("range".into(), json!([range.start(), range.end()]));
    facts.insert("extra_ports".into(), json!(ctx.extra_ports));
    if let DaemonState::Running(s) = &ctx.daemon {
        daemon_extra = s["extra_ports"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|e| e["port"].as_u64().and_then(|p| u16::try_from(p).ok()))
                    .collect()
            })
            .unwrap_or_default();
        summary = format!("the daemon holds {}", daemon_ports(s));
    } else {
        let mut free = None;
        let mut denied = false;
        for port in range.clone() {
            match (sys.bind(port, true), sys.bind(port, false)) {
                (Bind::Free, Bind::Free) => {
                    free = Some(port);
                    break;
                }
                (Bind::Denied, _) | (_, Bind::Denied) => denied = true,
                _ => {}
            }
        }
        facts.insert("free".into(), json!(free));
        match free {
            Some(p) => summary = format!("{p} is free on UDP and TCP (range {range_text})"),
            None if denied => {
                status = Status::Fail;
                summary = format!("no port of {range_text} can be bound: they are below ip_unprivileged_port_start");
                fix = Some(low_ports_fix(sys, *range.start()));
            }
            None => {
                status = Status::Fail;
                summary = format!("no port of {range_text} is free on both UDP and TCP");
                fix = Some(
                    Fix::commands(
                        false,
                        ["ports = \"61443-61542\" under [server] in ~/.config/qsh/config".to_string()],
                    )
                    .with_note("or for every user in /etc/qsh/qsh_config; see qsh_config(5)"),
                );
            }
        }
    }
    // Extra ports the daemon did not get (or would not get), and why
    let mut problems = Vec::new();
    for &port in &ctx.extra_ports {
        if daemon_extra.contains(&port) {
            continue;
        }
        let (u, t) = (sys.bind(port, true), sys.bind(port, false));
        let why = match (&u, &t) {
            (Bind::Free, Bind::Free) if matches!(ctx.daemon, DaemonState::Running(_)) => {
                format!(
                    "extra port {port} is free but the daemon did not bind it (it binds extra ports when it starts)"
                )
            }
            (Bind::Free, Bind::Free) => continue,
            (Bind::Denied, _) | (_, Bind::Denied) => {
                if fix.is_none() {
                    fix = Some(low_ports_fix(sys, port));
                }
                format!("extra port {port} is below ip_unprivileged_port_start")
            }
            (Bind::InUse, _) => format!("extra port {port}/udp is {}", holder_text(sys, port, true)),
            (_, Bind::InUse) => format!("extra port {port}/tcp is {}", holder_text(sys, port, false)),
            (Bind::Error(e), _) | (_, Bind::Error(e)) => format!("extra port {port}: {e}"),
        };
        problems.push(why);
    }
    if !problems.is_empty() {
        if status == Status::Ok {
            status = Status::Warn;
        }
        summary = format!("{summary}; {}", problems.join("; "));
    }
    Check {
        id: "ports",
        status,
        summary,
        facts,
        fix,
    }
}

fn firewall_check(sys: &dyn System, host: &HostInfo, ports: &Ports, iface: Option<&str>) -> Check {
    let found = firewall::detect(sys, host.family, ports, iface);
    let tools: Vec<&str> = found.iter().map(|f| f.tool).collect();
    let mut check = Check::new("firewall", Status::Ok, "no host firewall found").fact("tools", tools);
    if found.is_empty() {
        if sys.euid() != 0 {
            check.summary = "no ufw, firewalld or nftables service found (only root can read raw rules)".into();
        }
        return check;
    }
    let mut lines = Vec::new();
    let mut fixes: Vec<Fix> = Vec::new();
    for f in &found {
        let name = if f.detail.is_empty() {
            f.tool.to_string()
        } else {
            format!("{} ({})", f.tool, f.detail)
        };
        match &f.verdict {
            Verdict::Unknown(why) => {
                check.status = check.status.max(Status::Skip);
                lines.push(format!("{name} is active; {why}"));
                let mut fix = f.fix.clone();
                fix.tune = None;
                fix.note = Some("if they are not open yet (sudo qsh-server doctor tells)".into());
                fixes.push(fix);
            }
            Verdict::Checked {
                udp,
                tcp,
                extra_blocked,
            } => {
                let what = match (udp, tcp) {
                    (true, true) => format!("{name} allows UDP and TCP {}", ports.udp),
                    (false, false) => format!("{name} is active and allows neither UDP nor TCP {}", ports.udp),
                    (false, true) => format!("{name} blocks UDP {} (QUIC)", ports.udp),
                    (true, false) => format!("{name} blocks TCP {} (TLS)", ports.tcp),
                };
                let mut text = what;
                if !extra_blocked.is_empty() {
                    let list: Vec<String> = extra_blocked.iter().map(u16::to_string).collect();
                    text.push_str(&format!("; not the extra ports {}", list.join(", ")));
                }
                lines.push(text);
                if !(*udp && *tcp) {
                    check.status = Status::Fail;
                    fixes.push(f.fix.clone());
                } else if !extra_blocked.is_empty() {
                    check.status = check.status.max(Status::Warn);
                    fixes.push(f.fix.clone());
                }
            }
        }
    }
    check.summary = lines.join("; ");
    // The worst finding's fix: one line under the check
    check.fix = fixes.into_iter().max_by_key(|f| f.root);
    if let Some(zone) = found.iter().find_map(|f| f.zone.clone()) {
        check.facts.insert("zone".into(), zone.into());
    }
    check
        .facts
        .insert("allows".into(), found.iter().all(|f| f.allows_all()).into());
    check
}

fn udp_buffers(sys: &dyn System, host: &HostInfo) -> Check {
    let (r, w) = (
        read_u64(sys, "/proc/sys/net/core/rmem_max"),
        read_u64(sys, "/proc/sys/net/core/wmem_max"),
    );
    let (Some(r), Some(w)) = (r, w) else {
        return Check::new("udp-buffers", Status::Skip, "net.core.rmem_max cannot be read here");
    };
    let c = Check::new("udp-buffers", Status::Ok, "")
        .fact("rmem_max", r)
        .fact("wmem_max", w)
        .fact("wanted", WANTED_BUFFER);
    if r >= WANTED_BUFFER && w >= WANTED_BUFFER {
        let mut c = c;
        c.summary = format!("socket buffers up to {} MiB", r.min(w) / (1 << 20));
        return c;
    }
    let low: Vec<String> = [("net.core.rmem_max", r), ("net.core.wmem_max", w)]
        .iter()
        .filter(|(_, v)| *v < WANTED_BUFFER)
        .map(|(k, v)| format!("{k} is {v}"))
        .collect();
    let mut commands: Vec<String> = [("net.core.rmem_max", r), ("net.core.wmem_max", w)]
        .iter()
        .filter(|(_, v)| *v < WANTED_BUFFER)
        .map(|(k, _)| format!("sudo sysctl -w {k}={WANTED_BUFFER}"))
        .collect();
    commands.push(format!(
        "printf 'net.core.rmem_max = {WANTED_BUFFER}\\nnet.core.wmem_max = {WANTED_BUFFER}\\n' | sudo tee /etc/sysctl.d/90-qsh.conf"
    ));
    let _ = host;
    let mut c = c;
    c.status = Status::Warn;
    c.summary = format!("{}; QUIC on long fast paths needs {WANTED_BUFFER}", low.join(", "));
    c.fix(Fix::commands(true, commands).by_tune("udp-buffers"))
}

fn gso_gro(sys: &dyn System, host: &HostInfo) -> Check {
    let Some((gso, gro)) = sys.udp_offload() else {
        return Check::new("gso-gro", Status::Skip, "no UDP socket could be opened to test");
    };
    let kernel = host.kernel.split(['-', '+']).next().unwrap_or("").to_string();
    let c = Check::new("gso-gro", Status::Ok, "")
        .fact("gso_segments", gso as u64)
        .fact("gro_segments", gro as u64)
        .fact("kernel", kernel.clone());
    let mut c = c;
    match (gso > 1, gro > 1) {
        (true, true) => c.summary = format!("UDP GSO ({gso} segments) and GRO in use"),
        (true, false) => {
            c.status = Status::Info;
            c.summary = format!("UDP GSO in use, GRO not (kernel {kernel}; needs 5.0)");
        }
        (false, _) => {
            c.status = Status::Info;
            c.summary =
                format!("no UDP GSO or GRO (kernel {kernel}; GSO needs 4.18, GRO 5.0): a newer kernel sends faster");
        }
    }
    c
}

fn has_bbr_module(sys: &dyn System, kernel: &str) -> bool {
    ["/lib/modules", "/usr/lib/modules"].iter().any(|base| {
        let dir = format!("{base}/{kernel}");
        sys.read(&format!("{dir}/modules.builtin"))
            .is_some_and(|t| t.contains("tcp_bbr.ko"))
            || sys
                .read(&format!("{dir}/modules.dep"))
                .is_some_and(|t| t.contains("tcp_bbr.ko"))
    })
}

/// The BBR facts tune and the check share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bbr {
    /// `tcp_available_congestion_control`.
    pub available: Vec<String>,
    /// `tcp_allowed_congestion_control`.
    pub allowed: Vec<String>,
    /// `tcp_congestion_control`.
    pub current: String,
    /// `net.core.default_qdisc`.
    pub qdisc: String,
    /// BBR is built in or loaded, or its module exists for this kernel.
    pub possible: bool,
}

/// Read the BBR facts; None when the sysctls are not there.
pub fn bbr_facts(sys: &dyn System) -> Option<Bbr> {
    let list =
        |k: &str| -> Option<Vec<String>> { Some(sysctl(sys, k)?.split_whitespace().map(String::from).collect()) };
    let available = list("net.ipv4.tcp_available_congestion_control")?;
    let kernel = read_trim(sys, "/proc/sys/kernel/osrelease").unwrap_or_default();
    let possible = available.iter().any(|a| a == "bbr") || has_bbr_module(sys, &kernel);
    Some(Bbr {
        allowed: list("net.ipv4.tcp_allowed_congestion_control").unwrap_or_default(),
        current: sysctl(sys, "net.ipv4.tcp_congestion_control").unwrap_or_default(),
        qdisc: sysctl(sys, "net.core.default_qdisc").unwrap_or_default(),
        available,
        possible,
    })
}

fn tcp_bbr(sys: &dyn System, host: &HostInfo) -> Check {
    let Some(b) = bbr_facts(sys) else {
        return Check::new(
            "tcp-bbr",
            Status::Skip,
            "the TCP congestion control settings cannot be read here",
        );
    };
    let c = Check::new("tcp-bbr", Status::Ok, "")
        .fact("available", b.available.clone())
        .fact("allowed", b.allowed.clone())
        .fact("default", b.current.clone())
        .fact("qdisc", b.qdisc.clone())
        .fact("module", b.possible);
    let mut c = c;
    if b.current == "bbr" {
        c.summary = format!("BBR is the default congestion control (qdisc {})", b.qdisc);
    } else if b.allowed.iter().any(|a| a == "bbr") {
        c.summary = format!(
            "TLS connections use BBR; the ssh pipe uses {} (sudo qsh-server tune --bbr-default)",
            b.current
        );
    } else if b.possible {
        c.status = Status::Warn;
        c.summary = format!(
            "BBR is not allowed for unprivileged programs: TLS and the ssh pipe use {}, slow on lossy paths",
            b.current
        );
        let mut commands = Vec::new();
        if !b.available.iter().any(|a| a == "bbr") {
            commands.push("sudo modprobe tcp_bbr".to_string());
            commands.push("echo tcp_bbr | sudo tee /etc/modules-load.d/qsh.conf".to_string());
        }
        let mut allowed = b.allowed.clone();
        allowed.push("bbr".into());
        commands.push(format!(
            "sudo sysctl -w net.ipv4.tcp_allowed_congestion_control='{}'",
            allowed.join(" ")
        ));
        c = c.fix(Fix::commands(true, commands).by_tune("tcp-bbr"));
    } else {
        c.status = Status::Info;
        c.summary = format!(
            "this kernel has no tcp_bbr module: TLS and the ssh pipe use {}",
            b.current
        );
        if host.family.ships_bbr() {
            c.summary.push_str(" (the distribution's standard kernel has it)");
        }
    }
    c
}

fn ipv6(sys: &dyn System) -> Check {
    if !sys.exists("/proc/net/if_inet6") {
        return Check::new(
            "ipv6",
            Status::Info,
            "IPv6 is disabled: clients reach this host over IPv4 only",
        )
        .fact("enabled", false);
    }
    let v6only = sysctl(sys, "net.ipv6.bindv6only").unwrap_or_default() == "1";
    match default_route_v6(sys) {
        Some(iface) => Check::new(
            "ipv6",
            Status::Info,
            format!("IPv6 default route on {iface}; the daemon listens on IPv4 and IPv6"),
        )
        .fact("route", iface)
        .fact("bindv6only", v6only),
        None => Check::new(
            "ipv6",
            Status::Info,
            "no IPv6 default route: clients reach this host over IPv4",
        )
        .fact("route", Value::Null)
        .fact("bindv6only", v6only),
    }
}

fn mtu(sys: &dyn System, iface: Option<&str>) -> Check {
    let v6 = default_route_v6(sys);
    let Some(iface) = iface.map(String::from).or_else(|| v6.clone()) else {
        return Check::new("mtu", Status::Skip, "no default route");
    };
    let Some(mtu) = read_u64(sys, &format!("/sys/class/net/{iface}/mtu")) else {
        return Check::new("mtu", Status::Skip, format!("the MTU of {iface} cannot be read"));
    };
    let need = if v6.as_deref() == Some(iface.as_str())
        && read_u64(sys, "/proc/sys/net/ipv6/conf/all/disable_ipv6") != Some(1)
    {
        MIN_MTU_V6.max(if default_route_v4(sys).is_some() { MIN_MTU_V4 } else { 0 })
    } else {
        MIN_MTU_V4
    };
    let c = Check::new("mtu", Status::Info, format!("MTU {mtu} on {iface}"))
        .fact("interface", iface.clone())
        .fact("mtu", mtu)
        .fact("minimum", need);
    if mtu < need {
        let mut c = c;
        c.status = Status::Fail;
        c.summary = format!("MTU {mtu} on {iface} is below {need}: QUIC cannot work on this path; qsh uses TLS");
        return c.fix(
            Fix::commands(true, [format!("sudo ip link set dev {iface} mtu {need}")])
                .with_note("only if the network below allows it (a tunnel inside a tunnel usually does not)"),
        );
    }
    c
}

/// The effective `KillUserProcesses` of systemd-logind: the main file, then the drop-ins in
/// file name order, the last value winning; `no` by default.
pub fn kill_user_processes(sys: &dyn System) -> bool {
    let mut files = Vec::new();
    for main in ["/usr/lib/systemd/logind.conf", "/etc/systemd/logind.conf"] {
        if sys.exists(main) {
            files.push(main.to_string());
        }
    }
    let mut dropins: Vec<(String, String)> = Vec::new();
    for dir in [
        "/usr/lib/systemd/logind.conf.d",
        "/usr/local/lib/systemd/logind.conf.d",
        "/run/systemd/logind.conf.d",
        "/etc/systemd/logind.conf.d",
    ] {
        for name in sys.list(dir) {
            if name.ends_with(".conf") {
                // A later directory's file of the same name replaces an earlier one's
                dropins.retain(|(n, _)| *n != name);
                dropins.push((name.clone(), format!("{dir}/{name}")));
            }
        }
    }
    dropins.sort();
    files.extend(dropins.into_iter().map(|(_, p)| p));
    let mut value = false;
    for f in files {
        let Some(text) = sys.read(&f) else { continue };
        for line in text.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("KillUserProcesses=") {
                value = matches!(v.trim().to_lowercase().as_str(), "yes" | "true" | "1" | "on");
            }
        }
    }
    value
}

fn daemon_from_unit(sys: &dyn System, ctx: &Context) -> Option<bool> {
    let DaemonState::Running(s) = &ctx.daemon else {
        return None;
    };
    let pid = s["pid"].as_u64()?;
    let cgroup = sys.read(&format!("/proc/{pid}/cgroup"))?;
    Some(cgroup.contains("/qsh-server.service"))
}

fn linger(sys: &dyn System, host: &HostInfo, ctx: &Context) -> Check {
    let user = &ctx.user.name;
    if host.init == "openrc" {
        return Check::new(
            "linger",
            Status::Info,
            "OpenRC: the daemon outlives logins; to start it at boot, use the OpenRC script",
        )
        .fix(Fix::commands(
            true,
            [format!(
                "sudo ln -s qsh-server /etc/init.d/qsh-server.{user} && sudo rc-update add qsh-server.{user} default"
            )],
        ));
    }
    if host.init != "systemd" || host.container.is_some() && !sys.exists("/run/systemd/system") {
        return Check::new("linger", Status::Skip, "no systemd-logind: the daemon outlives logins");
    }
    let kup = kill_user_processes(sys);
    let lingering = sys.exists(&format!("/var/lib/systemd/linger/{user}"));
    let from_unit = daemon_from_unit(sys, ctx);
    let c = Check::new("linger", Status::Ok, "")
        .fact("kill_user_processes", kup)
        .fact("linger", lingering)
        .fact("user_unit", from_unit);
    let mut c = c;
    if !kup {
        c.summary = "sessions survive logout (KillUserProcesses=no)".into();
    } else if lingering && from_unit != Some(false) {
        c.summary = "sessions survive logout: lingering, the daemon runs from the user unit".into();
    } else {
        c.status = Status::Warn;
        c.summary = if lingering {
            "sessions end when you log out: KillUserProcesses=yes and the daemon does not run from the user unit".into()
        } else {
            "sessions end when you log out (KillUserProcesses=yes)".into()
        };
        let mut commands = Vec::new();
        if !lingering {
            commands.push(format!("sudo loginctl enable-linger {user}"));
        }
        commands.push("systemctl --user enable --now qsh-server".into());
        let mut fix = Fix::commands(true, commands);
        if !lingering {
            fix = fix.by_tune("linger");
        }
        c = c.fix(fix);
    }
    c
}

fn runtime_dir(sys: &dyn System, host: &HostInfo, ctx: &Context) -> Check {
    let user = &ctx.user;
    let dir = if user.sudo {
        Some(format!("/run/user/{}", user.uid)).filter(|d| sys.exists(d))
    } else {
        sys.env("XDG_RUNTIME_DIR").filter(|d| !d.is_empty())
    };
    let Some(dir) = dir else {
        return Check::new(
            "runtime-dir",
            Status::Info,
            format!("XDG_RUNTIME_DIR is unset: qsh uses /tmp/qsh-{}", user.uid),
        )
        .fix(Fix::default().with_note(host.family.runtime_dir_hint()));
    };
    let c = Check::new("runtime-dir", Status::Ok, format!("{dir} is private")).fact("path", dir.clone());
    match sys.meta(&dir) {
        Some(m) if m.dir && !m.symlink && m.uid == user.uid && m.mode & 0o077 == 0 => c,
        Some(m) => {
            let mut c = c;
            c.status = Status::Warn;
            c.summary = format!(
                "XDG_RUNTIME_DIR={dir} is not a private directory of {} (owner {}, mode {:o}): qsh refuses unsafe socket directories",
                user.name, m.uid, m.mode
            );
            c.fix(Fix::default().with_note(host.family.runtime_dir_hint()))
        }
        None => {
            let mut c = c;
            c.status = Status::Warn;
            c.summary = format!("XDG_RUNTIME_DIR={dir} does not exist");
            c.fix(Fix::default().with_note(host.family.runtime_dir_hint()))
        }
    }
}

fn daemon_context(sys: &dyn System, ctx: &Context) -> Option<String> {
    let pid = match &ctx.daemon {
        DaemonState::Running(s) => s["pid"].as_u64().map(|p| p.to_string()),
        _ => None,
    }
    .unwrap_or_else(|| "self".into());
    // Another process's label may not be readable; this program runs as the daemon would
    read_trim(sys, &format!("/proc/{pid}/attr/current")).or_else(|| read_trim(sys, "/proc/self/attr/current"))
}

fn selinux(sys: &dyn System, ctx: &Context) -> Check {
    let Some(enforce) = read_trim(sys, "/sys/fs/selinux/enforce") else {
        return Check::new("selinux", Status::Skip, "SELinux is not in use");
    };
    let mode = if enforce == "1" { "enforcing" } else { "permissive" };
    let domain = daemon_context(sys, ctx)
        .and_then(|c| c.split(':').nth(2).map(String::from))
        .unwrap_or_else(|| "unknown".into());
    let c = Check::new(
        "selinux",
        Status::Info,
        format!("SELinux {mode}; qsh-server runs as {domain}"),
    )
    .fact("mode", mode)
    .fact("domain", domain);
    if sys.euid() != 0 {
        return c;
    }
    let denials = sys
        .run("ausearch", &["-m", "avc", "-c", "qsh-server", "-ts", "recent"])
        .map(|o| o.stdout.matches("type=AVC").count())
        .unwrap_or(0);
    if denials == 0 {
        return c.fact("denials", 0);
    }
    let mut c = c.fact("denials", denials as u64);
    c.status = Status::Warn;
    c.summary = format!("SELinux {mode} denied qsh-server {denials} times recently");
    c.fix(Fix::commands(
        true,
        ["sudo ausearch -m avc -c qsh-server -ts recent | audit2why".to_string()],
    ))
}

fn apparmor(sys: &dyn System, ctx: &Context) -> Check {
    let enabled = read_trim(sys, "/sys/module/apparmor/parameters/enabled").is_some_and(|v| v == "Y");
    if !enabled {
        return Check::new("apparmor", Status::Skip, "AppArmor is not in use");
    }
    let label = daemon_context(sys, ctx).unwrap_or_else(|| "unconfined".into());
    let c = Check::new(
        "apparmor",
        Status::Info,
        if label == "unconfined" {
            "AppArmor enabled; qsh-server is unconfined".to_string()
        } else {
            format!("AppArmor confines qsh-server: {label}")
        },
    )
    .fact("label", label.clone());
    if label.contains("(enforce)") {
        let mut c = c;
        c.status = Status::Warn;
        let profile = label.split(" (").next().unwrap_or(&label).to_string();
        return c.fix(Fix::commands(
            true,
            [format!(
                "sudo journalctl -k -g 'apparmor=\"DENIED\".*profile=\"{profile}\"'"
            )],
        ));
    }
    c
}

fn clock(sys: &dyn System) -> Check {
    match sys.clock_synchronized() {
        Some(true) => Check::new("clock", Status::Ok, "synchronized").fact("synchronized", true),
        Some(false) => Check::new(
            "clock",
            Status::Info,
            "not synchronized; qsh does not depend on the clock for security",
        )
        .fact("synchronized", false),
        None => Check::new(
            "clock",
            Status::Skip,
            "this system cannot tell whether the clock is synchronized",
        ),
    }
}

fn limits(sys: &dyn System, host: &HostInfo, ctx: &Context) -> Check {
    let hard = sys.read("/proc/self/limits").and_then(|t| {
        t.lines().find_map(|l| {
            let rest = l.strip_prefix("Max open files")?;
            let f: Vec<&str> = rest.split_whitespace().collect();
            Some(match *f.get(1)? {
                "unlimited" => u64::MAX,
                v => v.parse().ok()?,
            })
        })
    });
    let Some(hard) = hard else {
        return Check::new("limits", Status::Skip, "the descriptor limit cannot be read");
    };
    let shown = if hard == u64::MAX {
        "unlimited".to_string()
    } else {
        hard.to_string()
    };
    if hard >= WANTED_NOFILE {
        return Check::new("limits", Status::Ok, format!("up to {shown} open descriptors")).fact("nofile_hard", shown);
    }
    Check::new(
        "limits",
        Status::Warn,
        format!("at most {shown} open descriptors: few connections and sessions fit"),
    )
    .fact("nofile_hard", shown)
    .fix(Fix::commands(true, [host.family.limits_fix(&ctx.user.name)]))
}

fn conntrack(sys: &dyn System, host: &HostInfo, ports: &Ports) -> Check {
    let Some(source) = sys.source_v4() else {
        return Check::new("conntrack", Status::Skip, "no IPv4 default route");
    };
    let c =
        Check::new("conntrack", Status::Ok, format!("{source} is a public address")).fact("source", source.to_string());
    if !is_private(source) {
        return c;
    }
    let mut c = c.fact("private", true);
    c.status = Status::Info;
    let timeout = sysctl(sys, "net.netfilter.nf_conntrack_udp_timeout_stream");
    if let Some(t) = &timeout {
        c.facts.insert("udp_timeout_stream".into(), t.clone().into());
    }
    c.summary = if host.cloud.is_some() {
        format!("{source} is private: the provider's NAT gives this host its public address (see cloud)")
    } else {
        format!(
            "{source} is private: clients outside reach this host only if the router forwards UDP and TCP {}",
            ports.range_text()
        )
    };
    c
}

fn cloud_check(sys: &dyn System, ports: &Ports) -> Check {
    let Some(cloud) = cloud(sys) else {
        return Check::new("cloud", Status::Skip, "no cloud provider recognized (DMI)");
    };
    let mut spans: Vec<String> = ports
        .spans()
        .into_iter()
        .map(|(a, b)| if a == b { a.to_string() } else { format!("{a}-{b}") })
        .collect();
    let last = spans.pop().unwrap_or_default();
    let list = if spans.is_empty() {
        last
    } else {
        format!("{} and {last}", spans.join(", "))
    };
    Check::new(
        "cloud",
        Status::Info,
        format!(
            "{}: {} UDP and TCP {list}; this host cannot see it (try qsh doctor HOST from your client)",
            cloud.name, cloud.firewall
        ),
    )
    .fact("provider", cloud.id)
}

fn container_check(host: &HostInfo, ports: &Ports) -> Check {
    match &host.container {
        None => Check::new("container", Status::Skip, "not in a container"),
        Some(c) => {
            let (u, t) = (ports.udp, ports.tcp);
            let mut check = Check::new(
                "container",
                Status::Info,
                format!("in a {c} container: its ports must be published, and sysctls belong to the host"),
            )
            .fact("kind", c.clone());
            if c == "docker" || c == "podman" {
                check = check.fix(Fix::commands(
                    false,
                    [format!("{c} run -p {u}:{u}/udp -p {t}:{t}/tcp …")],
                ));
            }
            check
        }
    }
}

fn discovery(sys: &dyn System, host: &HostInfo, ctx: &Context) -> Check {
    let user = &ctx.user;
    let local = format!("{}/.local/bin/qsh-server", user.home.trim_end_matches('/'));
    // What the discovery command (protocol.md 10.2) finds in a login-less shell
    let in_path = sys
        .run("env", &["-i", "sh", "-c", "command -v qsh-server"])
        .filter(|o| o.ok())
        .map(|o| o.stdout.trim().to_string())
        .filter(|p| p.starts_with('/'));
    let local_ok =
        sys.meta(&local).is_some_and(|m| !m.dir && m.mode & 0o111 != 0) || sys.meta(&local).is_some_and(|m| m.symlink);
    match (in_path, local_ok) {
        (Some(p), _) => Check::new("discovery", Status::Ok, format!("qsh HOST finds {p}")).fact("path", p),
        (None, true) => Check::new("discovery", Status::Ok, format!("qsh HOST finds {local}")).fact("path", local),
        (None, false) => {
            let exe = ctx.exe.clone().unwrap_or_else(|| "/path/to/qsh-server".into());
            let mut fix = Fix::commands(
                false,
                [format!("mkdir -p ~/.local/bin && ln -sf {exe} ~/.local/bin/qsh-server")],
            );
            fix.note = Some(match host.family.install_server() {
                Some(cmd) => {
                    format!("or install the distribution's package: {cmd}; or from the client: qsh install HOST")
                }
                None => "or from the client: qsh install HOST".into(),
            });
            Check::new(
                "discovery",
                Status::Fail,
                "qsh HOST cannot find qsh-server: it is neither in the PATH of non-interactive ssh logins nor in ~/.local/bin",
            )
            .fact("path", Value::Null)
            .fix(fix)
        }
    }
}
