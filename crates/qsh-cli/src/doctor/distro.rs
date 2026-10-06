//! Which distribution this is (`/etc/os-release`, m2.md 8.6), and its idioms: how to install
//! qsh-server, how to make raw firewall rules permanent, where descriptor limits are set, how
//! a user gets `XDG_RUNTIME_DIR`. An unknown distribution gets the generic fixes, and the
//! report says so.

use super::System;

/// The fields of os-release(5) doctor uses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsRelease {
    /// `ID` (`ubuntu`, `fedora`, `alpine`, …).
    pub id: String,
    /// `ID_LIKE`, split.
    pub id_like: Vec<String>,
    /// `VERSION_ID`.
    pub version_id: String,
    /// `PRETTY_NAME`, or `NAME VERSION_ID`.
    pub pretty_name: String,
    /// `VARIANT_ID` (Fedora: `workstation`, `server`, …).
    pub variant_id: String,
}

impl OsRelease {
    /// Parse os-release(5): `KEY=value` lines, values optionally quoted with shell quoting.
    pub fn parse(text: &str) -> OsRelease {
        let mut os = OsRelease::default();
        let mut name = String::new();
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = unquote(value.trim());
            match key.trim() {
                "ID" => os.id = value.to_lowercase(),
                "ID_LIKE" => os.id_like = value.split_whitespace().map(str::to_lowercase).collect(),
                "VERSION_ID" => os.version_id = value,
                "PRETTY_NAME" => os.pretty_name = value,
                "VARIANT_ID" => os.variant_id = value.to_lowercase(),
                "NAME" => name = value,
                _ => {}
            }
        }
        if os.pretty_name.is_empty() {
            os.pretty_name = format!("{name} {}", os.version_id).trim().to_string();
        }
        if os.pretty_name.is_empty() {
            os.pretty_name = "Linux".into();
        }
        if os.id.is_empty() {
            os.id = "linux".into();
        }
        os
    }

    /// `/etc/os-release`, else `/usr/lib/os-release` (os-release(5)).
    pub fn read(sys: &dyn System) -> Option<OsRelease> {
        sys.read("/etc/os-release")
            .or_else(|| sys.read("/usr/lib/os-release"))
            .map(|t| OsRelease::parse(&t))
    }
}

fn unquote(value: &str) -> String {
    let inner = if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"')) || (value.starts_with('\'') && value.ends_with('\'')))
    {
        &value[1..value.len() - 1]
    } else {
        value
    };
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A column of m2.md 8.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// Debian, Ubuntu and their derivatives.
    Debian,
    /// Fedora, RHEL, CentOS Stream, Rocky, AlmaLinux, Oracle Linux.
    Fedora,
    /// openSUSE Leap and Tumbleweed, SLES.
    Suse,
    /// Arch Linux and derivatives.
    Arch,
    /// Alpine Linux (OpenRC).
    Alpine,
    /// Amazon Linux.
    Amazon,
    /// Anything else: generic fixes.
    Unknown,
}

impl Family {
    /// The family of `os`: by `ID`, then by `ID_LIKE` in order.
    pub fn of(os: &OsRelease) -> Family {
        std::iter::once(&os.id)
            .chain(&os.id_like)
            .find_map(|id| Family::by_id(id))
            .unwrap_or(Family::Unknown)
    }

    fn by_id(id: &str) -> Option<Family> {
        Some(match id {
            "debian" | "ubuntu" | "raspbian" | "linuxmint" | "pop" | "kali" => Family::Debian,
            "fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "ol" => Family::Fedora,
            "amzn" => Family::Amazon,
            "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" | "sles" | "suse" => Family::Suse,
            "arch" | "archarm" | "manjaro" | "endeavouros" => Family::Arch,
            "alpine" => Family::Alpine,
            _ => return None,
        })
    }

    /// The name in reports and JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            Family::Debian => "debian",
            Family::Fedora => "fedora",
            Family::Suse => "suse",
            Family::Arch => "arch",
            Family::Alpine => "alpine",
            Family::Amazon => "amazon",
            Family::Unknown => "unknown",
        }
    }

    /// The command that installs qsh-server from the distribution's packages.
    pub fn install_server(self) -> Option<&'static str> {
        Some(match self {
            Family::Debian => "sudo apt install qsh-server",
            Family::Fedora | Family::Amazon => "sudo dnf install qsh-server",
            Family::Suse => "sudo zypper install qsh-server",
            Family::Arch => "sudo pacman -S qsh",
            Family::Alpine => "sudo apk add qsh-server",
            Family::Unknown => return None,
        })
    }

    /// How raw nftables rules survive a reboot here (m2.md 8.6).
    pub fn nft_persistence(self) -> &'static str {
        match self {
            Family::Debian => "to keep it after a reboot, add the rule to /etc/nftables.conf (sudo systemctl enable nftables)",
            Family::Fedora | Family::Amazon => {
                "to keep it after a reboot, add the rule to /etc/sysconfig/nftables.conf (sudo systemctl enable nftables)"
            }
            Family::Suse | Family::Arch => {
                "to keep it after a reboot, add the rule to /etc/nftables.conf (sudo systemctl enable nftables)"
            }
            Family::Alpine => "to keep it after a reboot: sudo rc-service nftables save",
            Family::Unknown => "to keep it after a reboot, add the rule to the ruleset loaded at boot",
        }
    }

    /// How raw iptables rules survive a reboot here (m2.md 8.6).
    pub fn iptables_persistence(self) -> &'static str {
        match self {
            Family::Debian => "to keep it after a reboot: sudo netfilter-persistent save (package iptables-persistent)",
            Family::Fedora | Family::Amazon => {
                "to keep it after a reboot: sudo service iptables save (package iptables-services)"
            }
            Family::Suse => "to keep it after a reboot, use firewalld (sudo zypper install firewalld)",
            Family::Arch => "to keep it after a reboot: sudo iptables-save -f /etc/iptables/iptables.rules",
            Family::Alpine => "to keep it after a reboot: sudo /etc/init.d/iptables save",
            Family::Unknown => "to keep it after a reboot, save the rules where this system loads them at boot",
        }
    }

    /// Where the descriptor limit of a user's processes is raised.
    pub fn limits_fix(self, user: &str) -> String {
        match self {
            Family::Alpine => format!(
                "echo '{user} hard nofile 65536' | sudo tee /etc/security/limits.d/90-qsh.conf (pam_limits), or rc_ulimit=\"-n 65536\" in /etc/rc.conf for OpenRC services"
            ),
            _ => format!(
                "echo '{user} hard nofile 65536' | sudo tee /etc/security/limits.d/90-qsh.conf, then log in again (the user unit: DefaultLimitNOFILE= in /etc/systemd/user.conf)"
            ),
        }
    }

    /// How a user gets `XDG_RUNTIME_DIR` over ssh here (m2.md 8.6).
    pub fn runtime_dir_hint(self) -> &'static str {
        match self {
            Family::Alpine => {
                "set by elogind or pam_rundir (sudo apk add elogind), or use the OpenRC script qsh-server.USER, which creates /run/user/UID"
            }
            _ => "systemd-logind sets it for ssh logins through pam_systemd (UsePAM yes in sshd_config)",
        }
    }

    /// True for the distributions whose kernels ship `tcp_bbr` (m2.md 8.6).
    pub fn ships_bbr(self) -> bool {
        self != Family::Unknown
    }

    /// The mandatory access control system the distribution enables by default.
    pub fn default_mac(self) -> Option<&'static str> {
        match self {
            Family::Debian | Family::Suse => Some("apparmor"),
            Family::Fedora | Family::Amazon => Some("selinux"),
            _ => None,
        }
    }
}

/// The init system: `systemd`, `openrc`, or `unknown`.
pub fn init_system(sys: &dyn System) -> &'static str {
    if sys.exists("/run/systemd/system") {
        "systemd"
    } else if sys.exists("/run/openrc") || sys.exists("/sbin/openrc-run") {
        "openrc"
    } else {
        "unknown"
    }
}

/// systemd's version, from `systemctl --version` ("systemd 255 (255.4-1ubuntu8)").
pub fn systemd_version(sys: &dyn System) -> Option<String> {
    let out = sys.run("systemctl", &["--version"])?;
    let first = out.stdout.lines().next()?;
    let version = first.strip_prefix("systemd ")?.split_whitespace().next()?;
    Some(version.to_string())
}
