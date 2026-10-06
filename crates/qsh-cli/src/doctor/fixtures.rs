//! Fixtures for the doctor tests: an in-memory [`System`] and the file trees and command
//! outputs of each supported distribution as their stock images show them.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::IpAddr;

use super::system::{Bind, Meta, Output, System};

/// An in-memory system: files, command outputs (by the whole command line), side effects of
/// commands on files, and a log of what ran.
#[derive(Debug, Default, Clone)]
pub struct Fake {
    pub files: RefCell<BTreeMap<String, String>>,
    pub dirs: RefCell<std::collections::BTreeSet<String>>,
    pub metas: HashMap<String, Meta>,
    pub commands: HashMap<String, Output>,
    /// Command line → files it writes (None: removes).
    pub effects: HashMap<String, Vec<(String, Option<String>)>>,
    pub ran: RefCell<Vec<String>>,
    pub env: HashMap<String, String>,
    pub euid: u32,
    pub binds: HashMap<(u16, bool), Bind>,
    pub offload: Option<(usize, usize)>,
    pub clock: Option<bool>,
    pub source: Option<IpAddr>,
}

fn parent(path: &str) -> Option<String> {
    let i = path.rfind('/')?;
    Some(if i == 0 { "/".into() } else { path[..i].into() })
}

impl Fake {
    pub fn new() -> Fake {
        Fake {
            euid: 1000,
            offload: Some((64, 64)),
            clock: Some(true),
            source: Some("203.0.113.10".parse().unwrap()),
            ..Fake::default()
        }
    }

    pub fn file(self, path: &str, content: &str) -> Fake {
        self.files.borrow_mut().insert(path.into(), content.into());
        self
    }

    pub fn dir(self, path: &str) -> Fake {
        self.dirs.borrow_mut().insert(path.into());
        self
    }

    pub fn no_file(self, path: &str) -> Fake {
        self.files.borrow_mut().remove(path);
        self
    }

    pub fn cmd(mut self, line: &str, status: i32, stdout: &str) -> Fake {
        self.commands.insert(
            line.into(),
            Output {
                status,
                stdout: stdout.into(),
                stderr: String::new(),
            },
        );
        self
    }

    pub fn effect(mut self, line: &str, path: &str, content: Option<&str>) -> Fake {
        self.effects
            .entry(line.into())
            .or_default()
            .push((path.into(), content.map(String::from)));
        self
    }

    pub fn meta(mut self, path: &str, uid: u32, mode: u32, dir: bool) -> Fake {
        self.metas.insert(
            path.into(),
            Meta {
                uid,
                mode,
                dir,
                symlink: false,
            },
        );
        self
    }

    pub fn env(mut self, k: &str, v: &str) -> Fake {
        self.env.insert(k.into(), v.into());
        self
    }

    pub fn root(mut self) -> Fake {
        self.euid = 0;
        self
    }

    pub fn snapshot(&self) -> BTreeMap<String, String> {
        self.files.borrow().clone()
    }

    fn has_dir(&self, path: &str) -> bool {
        if path == "/" || self.dirs.borrow().contains(path) {
            return true;
        }
        let prefix = format!("{}/", path.trim_end_matches('/'));
        self.files.borrow().keys().any(|k| k.starts_with(&prefix))
    }
}

impl System for Fake {
    fn read(&self, path: &str) -> Option<String> {
        self.files.borrow().get(path).cloned()
    }

    fn exists(&self, path: &str) -> bool {
        self.files.borrow().contains_key(path) || self.has_dir(path) || self.metas.contains_key(path)
    }

    fn list(&self, dir: &str) -> Vec<String> {
        let prefix = format!("{}/", dir.trim_end_matches('/'));
        let mut names: Vec<String> = self
            .files
            .borrow()
            .keys()
            .chain(self.dirs.borrow().iter())
            .filter_map(|k| k.strip_prefix(&prefix))
            .map(|rest| rest.split('/').next().unwrap_or(rest).to_string())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    fn meta(&self, path: &str) -> Option<Meta> {
        if let Some(m) = self.metas.get(path) {
            return Some(*m);
        }
        if self.files.borrow().contains_key(path) {
            return Some(Meta {
                uid: 0,
                mode: 0o644,
                dir: false,
                symlink: false,
            });
        }
        self.has_dir(path).then_some(Meta {
            uid: 0,
            mode: 0o755,
            dir: true,
            symlink: false,
        })
    }

    fn run(&self, program: &str, args: &[&str]) -> Option<Output> {
        let line = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        self.ran.borrow_mut().push(line.clone());
        if let Some(effects) = self.effects.get(&line) {
            for (path, content) in effects {
                match content {
                    Some(c) => {
                        self.files.borrow_mut().insert(path.clone(), c.clone());
                    }
                    None => {
                        self.files.borrow_mut().remove(path);
                    }
                }
            }
        }
        self.commands.get(&line).cloned()
    }

    fn env(&self, name: &str) -> Option<String> {
        self.env.get(name).cloned()
    }

    fn euid(&self) -> u32 {
        self.euid
    }

    fn bind(&self, port: u16, udp: bool) -> Bind {
        self.binds.get(&(port, udp)).cloned().unwrap_or(Bind::Free)
    }

    fn udp_offload(&self) -> Option<(usize, usize)> {
        self.offload
    }

    fn clock_synchronized(&self) -> Option<bool> {
        self.clock
    }

    fn source_v4(&self) -> Option<IpAddr> {
        self.source
    }

    fn write(&self, path: &str, content: &[u8], _mode: u32) -> io::Result<()> {
        let dir = parent(path).unwrap_or_default();
        if !self.has_dir(&dir) {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("no directory {dir}")));
        }
        self.files
            .borrow_mut()
            .insert(path.into(), String::from_utf8_lossy(content).into_owned());
        Ok(())
    }

    fn set(&self, path: &str, content: &str) -> io::Result<()> {
        let mut files = self.files.borrow_mut();
        match files.get_mut(path) {
            Some(f) => {
                *f = content.into();
                Ok(())
            }
            None => Err(io::Error::new(io::ErrorKind::NotFound, path.to_string())),
        }
    }

    fn remove(&self, path: &str) -> io::Result<()> {
        self.files
            .borrow_mut()
            .remove(path)
            .map(drop)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, path.to_string()))
    }

    fn mkdir(&self, path: &str) -> io::Result<()> {
        self.dirs.borrow_mut().insert(path.into());
        Ok(())
    }

    fn rmdir(&self, path: &str) -> io::Result<()> {
        let prefix = format!("{path}/");
        if self.files.borrow().keys().any(|k| k.starts_with(&prefix))
            || self.dirs.borrow().iter().any(|d| d.starts_with(&prefix))
        {
            return Err(io::Error::other("not empty"));
        }
        self.dirs.borrow_mut().remove(path);
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Distributions as their stock images show them

pub const UBUNTU_2404: &str = r#"PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
UBUNTU_CODENAME=noble
"#;

pub const UBUNTU_2004: &str = r#"NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.6 LTS"
VERSION_ID="20.04"
"#;

pub const DEBIAN_12: &str = r#"PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
"#;

pub const FEDORA_WS: &str = r#"NAME="Fedora Linux"
VERSION="41 (Workstation Edition)"
ID=fedora
VERSION_ID=41
PRETTY_NAME="Fedora Linux 41 (Workstation Edition)"
VARIANT="Workstation Edition"
VARIANT_ID=workstation
"#;

pub const ROCKY_9: &str = r#"NAME="Rocky Linux"
VERSION="9.4 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.4"
PRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"
"#;

pub const ALMA_9: &str = r#"NAME="AlmaLinux"
VERSION="9.4 (Seafoam Ocelot)"
ID="almalinux"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.4"
PRETTY_NAME="AlmaLinux 9.4 (Seafoam Ocelot)"
"#;

pub const TUMBLEWEED: &str = r#"NAME="openSUSE Tumbleweed"
# VERSION="20241001"
ID="opensuse-tumbleweed"
ID_LIKE="opensuse suse"
VERSION_ID="20241001"
PRETTY_NAME="openSUSE Tumbleweed"
"#;

pub const LEAP: &str = r#"NAME="openSUSE Leap"
VERSION="15.6"
ID="opensuse-leap"
ID_LIKE="suse opensuse"
VERSION_ID="15.6"
PRETTY_NAME="openSUSE Leap 15.6"
"#;

pub const ARCH: &str = r#"NAME="Arch Linux"
PRETTY_NAME="Arch Linux"
ID=arch
BUILD_ID=rolling
"#;

pub const ALPINE: &str = r#"NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.20.3
PRETTY_NAME="Alpine Linux v3.20"
"#;

pub const AMAZON_2023: &str = r#"NAME="Amazon Linux"
VERSION="2023"
ID="amzn"
ID_LIKE="fedora"
VERSION_ID="2023"
PLATFORM_ID="platform:al2023"
PRETTY_NAME="Amazon Linux 2023.6.20241010"
"#;

pub const VOID: &str = r#"NAME="Void"
ID="void"
PRETTY_NAME="Void Linux"
"#;

pub const ROUTE: &str = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\neth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";

pub const IPV6_ROUTE: &str = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n";

pub const LIMITS: &str = "Limit                     Soft Limit           Hard Limit           Units     \nMax cpu time              unlimited            unlimited            seconds   \nMax open files            1024                 524288               files     \n";

/// The common Linux files: kernel, network, limits, sysctls at their defaults.
pub fn linux(os_release: &str, kernel: &str) -> Fake {
    Fake::new()
        .file("/etc/os-release", os_release)
        .file("/proc/sys/kernel/hostname", "web1\n")
        .file("/proc/sys/kernel/osrelease", &format!("{kernel}\n"))
        .file("/proc/sys/net/core/rmem_max", "212992\n")
        .file("/proc/sys/net/core/wmem_max", "212992\n")
        .file("/proc/sys/net/core/default_qdisc", "fq_codel\n")
        .file("/proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic\n")
        .file("/proc/sys/net/ipv4/tcp_allowed_congestion_control", "reno cubic\n")
        .file("/proc/sys/net/ipv4/tcp_congestion_control", "cubic\n")
        .file("/proc/sys/net/ipv4/ip_unprivileged_port_start", "1024\n")
        .file("/proc/sys/net/ipv6/bindv6only", "0\n")
        .file(
            &format!("/lib/modules/{kernel}/modules.dep"),
            "kernel/net/ipv4/tcp_bbr.ko.zst:\nkernel/net/ipv4/tcp_cubic.ko:\n",
        )
        .file("/proc/net/route", ROUTE)
        .file("/proc/net/ipv6_route", IPV6_ROUTE)
        .file(
            "/proc/net/if_inet6",
            "fe800000000000000000000000000002 02 40 20 80 eth0\n",
        )
        .file("/sys/class/net/eth0/mtu", "1500\n")
        .file("/proc/self/limits", LIMITS)
        .file(
            "/etc/passwd",
            "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
        )
        .env("USER", "alice")
        .env("HOME", "/home/alice")
        .env("XDG_RUNTIME_DIR", "/run/user/1000")
        .meta("/run/user/1000", 1000, 0o700, true)
        .cmd("env -i sh -c command -v qsh-server", 0, "/usr/bin/qsh-server\n")
}

/// systemd with logind's defaults.
pub fn systemd(f: Fake, version: &str) -> Fake {
    f.dir("/run/systemd/system")
        .cmd(
            "systemctl --version",
            0,
            &format!("systemd {version} ({version}-1)\n+PAM +AUDIT\n"),
        )
        .cmd("systemd-detect-virt --vm", 0, "kvm\n")
        .cmd("systemd-detect-virt --container", 1, "none\n")
        .file("/etc/systemd/logind.conf", "[Login]\n#KillUserProcesses=no\n")
}

pub const FIREWALLD_PUBLIC: &str = "public (active)\n  target: default\n  icmp-block-inversion: no\n  interfaces: eth0\n  sources: \n  services: cockpit dhcpv6-client ssh\n  ports: \n  protocols: \n  forward: yes\n  masquerade: no\n  forward-ports: \n  source-ports: \n  icmp-blocks: \n  rich rules: \n";

pub const FIREWALLD_WORKSTATION: &str = "FedoraWorkstation (active)\n  target: default\n  icmp-block-inversion: no\n  interfaces: eth0\n  sources: \n  services: dhcpv6-client samba-client ssh\n  ports: 1025-65535/udp 1025-65535/tcp\n  protocols: \n";

pub const FIREWALLD_SERVICE_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>qsh</short>
  <description>qsh, a remote shell over QUIC.</description>
  <port protocol="udp" port="60443-60542"/>
  <port protocol="tcp" port="60443-60542"/>
</service>
"#;

/// firewalld running in `zone` with `list_all` as its settings.
pub fn firewalld(f: Fake, zone: &str, list_all: &str) -> Fake {
    f.cmd("firewall-cmd --state", 0, "running\n")
        .cmd("firewall-cmd --get-zone-of-interface=eth0", 0, &format!("{zone}\n"))
        .cmd(&format!("firewall-cmd --zone={zone} --list-all"), 0, list_all)
}

/// Each distribution of the CI matrix (and two more) as its stock image or a fresh cloud
/// instance shows it.
pub fn distro(name: &str) -> Fake {
    match name {
        "ubuntu-24.04" => systemd(linux(UBUNTU_2404, "6.8.0-45-generic"), "255")
            .file("/etc/ufw/ufw.conf", "# /etc/ufw/ufw.conf\nENABLED=no\nLOGLEVEL=low\n")
            .file("/sys/module/apparmor/parameters/enabled", "Y\n")
            .file("/proc/self/attr/current", "unconfined\n"),
        "ubuntu-20.04" => systemd(linux(UBUNTU_2004, "5.4.0-200-generic"), "245")
            .file("/etc/ufw/ufw.conf", "ENABLED=no\n")
            .file("/sys/module/apparmor/parameters/enabled", "Y\n"),
        "debian-12" => {
            systemd(linux(DEBIAN_12, "6.1.0-26-amd64"), "252").file("/sys/module/apparmor/parameters/enabled", "Y\n")
        }
        "fedora-workstation" => firewalld(
            systemd(linux(FEDORA_WS, "6.11.4-301.fc41.x86_64"), "256"),
            "FedoraWorkstation",
            FIREWALLD_WORKSTATION,
        )
        .file("/sys/fs/selinux/enforce", "1\n")
        .file(
            "/proc/self/attr/current",
            "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023\n",
        ),
        "rocky-9" => firewalld(
            systemd(linux(ROCKY_9, "5.14.0-427.13.1.el9_4.x86_64"), "252"),
            "public",
            FIREWALLD_PUBLIC,
        )
        .file("/sys/fs/selinux/enforce", "1\n")
        .file("/usr/lib/firewalld/services/qsh.xml", FIREWALLD_SERVICE_XML),
        "alma-9" => firewalld(
            systemd(linux(ALMA_9, "5.14.0-427.13.1.el9_4.x86_64"), "252"),
            "public",
            FIREWALLD_PUBLIC,
        )
        .file("/sys/fs/selinux/enforce", "1\n"),
        "tumbleweed" => firewalld(
            systemd(linux(TUMBLEWEED, "6.11.2-1-default"), "256"),
            "public",
            FIREWALLD_PUBLIC,
        )
        .file("/sys/fs/selinux/enforce", "1\n"),
        "leap" => firewalld(
            systemd(linux(LEAP, "6.4.0-150600.23.25-default"), "254"),
            "public",
            FIREWALLD_PUBLIC,
        )
        .file("/sys/module/apparmor/parameters/enabled", "Y\n"),
        "arch" => systemd(linux(ARCH, "6.11.3-arch1-1"), "256"),
        "alpine" => linux(ALPINE, "6.6.54-0-virt")
            .dir("/run/openrc")
            .no_file("/proc/net/if_inet6")
            .env("XDG_RUNTIME_DIR", ""),
        "amazon-2023" => systemd(linux(AMAZON_2023, "6.1.112-122.189.amzn2023.x86_64"), "252")
            .file("/sys/fs/selinux/enforce", "0\n")
            .file("/sys/class/dmi/id/sys_vendor", "Amazon EC2\n")
            .file("/sys/class/dmi/id/product_name", "t3.micro\n")
            .file("/sys/class/dmi/id/bios_vendor", "Amazon EC2\n"),
        "void" => linux(VOID, "6.6.1_1"),
        other => panic!("no fixture {other}"),
    }
}

/// Every fixture name.
pub const DISTROS: &[&str] = &[
    "ubuntu-24.04",
    "ubuntu-20.04",
    "debian-12",
    "fedora-workstation",
    "rocky-9",
    "alma-9",
    "tumbleweed",
    "leap",
    "arch",
    "alpine",
    "amazon-2023",
    "void",
];
