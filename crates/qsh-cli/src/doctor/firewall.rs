//! Host firewalls (m2.md 8.3): which one is active, whether it lets the daemon's UDP and TCP
//! ports in, and the exact command that opens them with that tool, in that zone.
//!
//! ufw and firewalld are read through their own status commands (ufw only as root). Raw
//! rulesets (nftables, iptables) are read as root only, and evaluated by a small model of the
//! input hook: a new UDP or TCP packet to the port, from an unknown address, on the default
//! route's interface, must be accepted by every base chain. Matches the model does not
//! understand never accept the packet and never drop it, so the verdict errs towards
//! "blocked" only where an explicit drop or a drop policy is reached.

use std::collections::HashMap;
use std::ops::RangeInclusive;

use serde_json::Value;

use super::distro::Family;
use super::{Fix, System};

/// Where the firewalld service file and the ufw application profile of the packages live
/// (m2.md 8.3, packaging/firewalld, packaging/ufw).
pub const FIREWALLD_SERVICE: [&str; 2] = ["/etc/firewalld/services/qsh.xml", "/usr/lib/firewalld/services/qsh.xml"];
/// The ufw application profile of the packages.
pub const UFW_PROFILE: &str = "/etc/ufw/applications.d/qsh";
/// The port range the packaged service file and profile open.
pub const PACKAGED_RANGE: RangeInclusive<u16> = 60443..=60542;

/// The ports to let in: the configured range and the extra ports, and the port the daemon
/// uses (or would use) first, which is what the verdict is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ports {
    /// The daemon's range (`[server] ports`).
    pub range: RangeInclusive<u16>,
    /// `[server] extra_ports`.
    pub extra: Vec<u16>,
    /// The UDP port the verdict is about.
    pub udp: u16,
    /// The TCP port the verdict is about.
    pub tcp: u16,
}

impl Ports {
    /// The range and the extra ports, as (first, last) pairs without duplicates.
    pub fn spans(&self) -> Vec<(u16, u16)> {
        let mut spans = vec![(*self.range.start(), *self.range.end())];
        for &p in &self.extra {
            if !self.range.contains(&p) && !spans.contains(&(p, p)) {
                spans.push((p, p));
            }
        }
        spans
    }

    /// True when the range is the one the packaged service file and profile open, and there
    /// are no extra ports.
    fn packaged(&self) -> bool {
        self.range == PACKAGED_RANGE
    }

    fn extra_spans(&self) -> Vec<(u16, u16)> {
        self.spans().into_iter().skip(1).collect()
    }

    /// `60443-60542` or `443`, with `sep` between first and last.
    fn span_text(span: (u16, u16), sep: &str) -> String {
        if span.0 == span.1 {
            span.0.to_string()
        } else {
            format!("{}{sep}{}", span.0, span.1)
        }
    }

    /// The range for people: `60443-60542`.
    pub fn range_text(&self) -> String {
        Ports::span_text((*self.range.start(), *self.range.end()), "-")
    }
}

/// What a firewall does to the daemon's ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Only root can tell (the reason).
    Unknown(String),
    /// Evaluated: whether UDP and TCP of the primary port get in, and the extra ports that do
    /// not.
    Checked {
        /// UDP of the primary port is let in.
        udp: bool,
        /// TCP of the primary port is let in.
        tcp: bool,
        /// Extra ports (UDP or TCP) that are not.
        extra_blocked: Vec<u16>,
    },
}

/// One active firewall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// `ufw`, `firewalld`, `nftables`, `iptables`.
    pub tool: &'static str,
    /// More about it, for people (`zone public`, `legacy`).
    pub detail: String,
    /// The firewalld zone of the default route's interface.
    pub zone: Option<String>,
    /// What it does to the ports.
    pub verdict: Verdict,
    /// The commands that open the ports with this tool.
    pub fix: Fix,
}

impl Finding {
    /// True when the primary port gets in on UDP and TCP and so do the extra ports.
    pub fn allows_all(&self) -> bool {
        matches!(&self.verdict, Verdict::Checked { udp: true, tcp: true, extra_blocked } if extra_blocked.is_empty())
    }
}

/// Every active firewall, in the order of m2.md 8.3. `iface` is the default route's
/// interface.
pub fn detect(sys: &dyn System, family: Family, ports: &Ports, iface: Option<&str>) -> Vec<Finding> {
    let root = sys.euid() == 0;
    let mut found = Vec::new();
    let mut managed = false;
    if let Some(f) = ufw(sys, ports, root) {
        managed = true;
        found.push(f);
    }
    if let Some(f) = firewalld(sys, ports, iface) {
        managed = true;
        found.push(f);
    }
    // A managing tool owns the raw ruleset; its rules are not judged a second time
    if managed {
        return found;
    }
    if root {
        found.extend(raw_as_root(sys, family, ports, iface));
    } else if let Some(f) = raw_service(sys, family, ports) {
        found.push(f);
    }
    found
}

// ---------------------------------------------------------------------------------------
// ufw

/// ufw is active: `ENABLED=yes` in ufw.conf and, under systemd, the service active.
fn ufw_active(sys: &dyn System) -> bool {
    let enabled = sys.read("/etc/ufw/ufw.conf").is_some_and(|c| {
        c.lines()
            .any(|l| l.trim().replace(' ', "").eq_ignore_ascii_case("ENABLED=yes"))
    });
    if !enabled {
        return false;
    }
    if sys.exists("/run/systemd/system") {
        return sys
            .run("systemctl", &["is-active", "ufw"])
            .is_some_and(|o| o.stdout.trim() == "active");
    }
    true
}

/// The `ufw allow` commands for `ports`.
pub fn ufw_allow_commands(sys: &dyn System, ports: &Ports) -> Vec<String> {
    let mut out = Vec::new();
    if ports.packaged() && sys.exists(UFW_PROFILE) {
        out.push("sudo ufw allow qsh".to_string());
        for span in ports.extra_spans() {
            out.push(format!("sudo ufw allow {}", Ports::span_text(span, ":")));
        }
        return out;
    }
    for span in ports.spans() {
        let text = Ports::span_text(span, ":");
        if span.0 == span.1 {
            out.push(format!("sudo ufw allow {text}"));
        } else {
            // ufw needs a protocol with a range
            out.push(format!("sudo ufw allow {text}/udp"));
            out.push(format!("sudo ufw allow {text}/tcp"));
        }
    }
    out
}

fn ufw(sys: &dyn System, ports: &Ports, root: bool) -> Option<Finding> {
    if !ufw_active(sys) {
        return None;
    }
    let fix = Fix::commands(true, ufw_allow_commands(sys, ports)).by_tune("firewall");
    let verdict = if root {
        match sys.run("ufw", &["status", "verbose"]) {
            Some(out) if out.ok() => {
                let profiles = ufw_profiles(sys);
                let chain = parse_ufw_status(&out.stdout, &profiles);
                evaluate(ports, |udp, port| eval_simple(&chain, udp, port))
            }
            _ => Verdict::Unknown("ufw status failed".into()),
        }
    } else {
        Verdict::Unknown("only root can read ufw's rules".into())
    };
    Some(Finding {
        tool: "ufw",
        detail: String::new(),
        zone: None,
        verdict,
        fix,
    })
}

/// Ports of one protocol: (protocol, (first, last)).
type Specs = Vec<(Proto, (u16, u16))>;
/// ufw's application profiles by name.
type Profiles = HashMap<String, Specs>;

/// The application profiles of ufw (`/etc/ufw/applications.d/*`): name → port specs.
fn ufw_profiles(sys: &dyn System) -> Profiles {
    let mut out = HashMap::new();
    for file in sys.list("/etc/ufw/applications.d") {
        let Some(text) = sys.read(&format!("/etc/ufw/applications.d/{file}")) else {
            continue;
        };
        let mut name: Option<String> = None;
        for line in text.lines() {
            let line = line.trim();
            if let Some(n) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                name = Some(n.trim().to_string());
            } else if let (Some(n), Some(spec)) = (&name, line.strip_prefix("ports=")) {
                let specs = spec
                    .split('|')
                    .flat_map(|part| {
                        let (ports, proto) = part.split_once('/').unwrap_or((part, ""));
                        let protos = match proto {
                            "udp" => vec![Proto::Udp],
                            "tcp" => vec![Proto::Tcp],
                            _ => vec![Proto::Udp, Proto::Tcp],
                        };
                        let spans: Vec<(u16, u16)> = ports.split(',').filter_map(|p| parse_span(p, ':')).collect();
                        protos
                            .into_iter()
                            .flat_map(move |pr| spans.clone().into_iter().map(move |s| (pr, s)))
                    })
                    .collect();
                out.insert(n.clone(), specs);
            }
        }
    }
    out
}

/// `ufw status verbose` as a chain: its rules in order, then the default incoming policy.
fn parse_ufw_status(text: &str, profiles: &Profiles) -> Chain {
    let mut chain = Chain {
        policy: Some(Action::Accept),
        rules: Vec::new(),
    };
    let mut in_rules = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Default:") {
            // "Default: deny (incoming), allow (outgoing), disabled (routed)"
            for part in rest.split(',') {
                let part = part.trim();
                if part.ends_with("(incoming)") {
                    chain.policy = Some(if part.starts_with("allow") {
                        Action::Accept
                    } else {
                        Action::Drop
                    });
                }
            }
            continue;
        }
        if line.starts_with("--") {
            in_rules = true;
            continue;
        }
        if !in_rules || line.is_empty() {
            continue;
        }
        let line = line.split(" # ").next().unwrap_or(line);
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some(at) = words
            .iter()
            .position(|w| ["ALLOW", "DENY", "REJECT", "LIMIT"].contains(w))
        else {
            continue;
        };
        let direction = words.get(at + 1).copied().unwrap_or("IN");
        if direction == "OUT" || direction == "FWD" {
            continue;
        }
        let action = match words[at] {
            "ALLOW" | "LIMIT" => Action::Accept,
            _ => Action::Drop,
        };
        let from: Vec<&str> = words[at + 1..]
            .iter()
            .copied()
            .filter(|w| *w != "IN" && *w != "(v6)")
            .collect();
        let to: Vec<&str> = words[..at].iter().copied().filter(|w| *w != "(v6)").collect();
        let mut conds = Vec::new();
        if from.first() != Some(&"Anywhere") {
            // Only some sources: not "everyone gets in"
            conds.push(Cond::Unknown);
        }
        let target = to.first().copied().unwrap_or("");
        if let Some(on) = to.iter().position(|w| *w == "on") {
            if let Some(iface) = to.get(on + 1) {
                conds.push(Cond::Iface(iface.to_string(), false));
            }
        }
        if target == "Anywhere" {
            // every port
        } else if let Some(specs) = profiles.get(target) {
            conds.push(Cond::Any(
                specs
                    .iter()
                    .map(|(proto, span)| vec![Cond::Proto(vec![*proto]), Cond::Port(vec![*span], false)])
                    .collect(),
            ));
        } else {
            let (port, proto) = target.split_once('/').unwrap_or((target, ""));
            match proto {
                "udp" => conds.push(Cond::Proto(vec![Proto::Udp])),
                "tcp" => conds.push(Cond::Proto(vec![Proto::Tcp])),
                "" => {}
                _ => conds.push(Cond::Unknown),
            }
            let spans: Vec<(u16, u16)> = port.split(',').filter_map(|p| parse_span(p, ':')).collect();
            if spans.is_empty() {
                // An address or something this model does not know
                conds.push(Cond::Unknown);
            } else {
                conds.push(Cond::Port(spans, false));
            }
        }
        chain.rules.push(Rule { conds, action });
    }
    chain
}

// ---------------------------------------------------------------------------------------
// firewalld

/// True when firewalld runs (`firewall-cmd --state`).
pub fn firewalld_running(sys: &dyn System) -> bool {
    sys.run("firewall-cmd", &["--state"])
        .is_some_and(|o| o.ok() && o.stdout.trim() == "running")
}

/// The zone of `iface`, else the default zone.
pub fn firewalld_zone(sys: &dyn System, iface: Option<&str>) -> Option<String> {
    let of_iface = iface.and_then(|i| {
        let arg = format!("--get-zone-of-interface={i}");
        sys.run("firewall-cmd", &[&arg])
            .filter(|o| o.ok())
            .map(|o| o.stdout.trim().to_string())
            .filter(|z| !z.is_empty() && !z.contains(' '))
    });
    of_iface.or_else(|| {
        sys.run("firewall-cmd", &["--get-default-zone"])
            .filter(|o| o.ok())
            .map(|o| o.stdout.trim().to_string())
            .filter(|z| !z.is_empty())
    })
}

/// True when firewalld knows the `qsh` service (the packages ship it).
pub fn firewalld_has_service(sys: &dyn System) -> bool {
    FIREWALLD_SERVICE.iter().any(|p| sys.exists(p))
}

/// The `--add-…` arguments for `ports` (the service when it fits, else ports).
pub fn firewalld_add_args(sys: &dyn System, ports: &Ports) -> Vec<String> {
    let mut args = Vec::new();
    let spans = if ports.packaged() && firewalld_has_service(sys) {
        args.push("--add-service=qsh".to_string());
        ports.extra_spans()
    } else {
        ports.spans()
    };
    for span in spans {
        let text = Ports::span_text(span, "-");
        args.push(format!("--add-port={text}/udp"));
        args.push(format!("--add-port={text}/tcp"));
    }
    args
}

fn firewalld(sys: &dyn System, ports: &Ports, iface: Option<&str>) -> Option<Finding> {
    if !firewalld_running(sys) {
        return None;
    }
    let zone = firewalld_zone(sys, iface).unwrap_or_else(|| "public".into());
    let args = firewalld_add_args(sys, ports);
    let fix = Fix::commands(
        true,
        [
            format!("sudo firewall-cmd --permanent --zone={zone} {}", args.join(" ")),
            "sudo firewall-cmd --reload".to_string(),
        ],
    )
    .by_tune("firewall");
    let zone_arg = format!("--zone={zone}");
    let verdict = match sys.run("firewall-cmd", &[&zone_arg, "--list-all"]) {
        Some(out) if out.ok() => {
            let service = FIREWALLD_SERVICE.iter().find_map(|p| sys.read(p));
            let chain = parse_firewalld_zone(&out.stdout, service.as_deref());
            evaluate(ports, |udp, port| eval_simple(&chain, udp, port))
        }
        _ => Verdict::Unknown("only root can read the zone's settings".into()),
    };
    Some(Finding {
        tool: "firewalld",
        detail: format!("zone {zone}"),
        zone: Some(zone),
        verdict,
        fix,
    })
}

/// `firewall-cmd --zone=Z --list-all` as a chain: the zone's services and ports, then its
/// target (`default` and `REJECT`/`DROP` reject, `ACCEPT` accepts).
fn parse_firewalld_zone(text: &str, qsh_service: Option<&str>) -> Chain {
    let mut chain = Chain {
        policy: Some(Action::Drop),
        rules: Vec::new(),
    };
    for line in text.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "target" => {
                if value.trim() == "ACCEPT" {
                    chain.policy = Some(Action::Accept);
                }
            }
            "services" => {
                if value.split_whitespace().any(|s| s == "qsh") {
                    let specs = qsh_service.map(parse_firewalld_service).unwrap_or_else(|| {
                        vec![
                            (Proto::Udp, (*PACKAGED_RANGE.start(), *PACKAGED_RANGE.end())),
                            (Proto::Tcp, (*PACKAGED_RANGE.start(), *PACKAGED_RANGE.end())),
                        ]
                    });
                    for (proto, span) in specs {
                        chain.rules.push(Rule {
                            conds: vec![Cond::Proto(vec![proto]), Cond::Port(vec![span], false)],
                            action: Action::Accept,
                        });
                    }
                }
            }
            "ports" => {
                for spec in value.split_whitespace() {
                    let (port, proto) = spec.split_once('/').unwrap_or((spec, ""));
                    let proto = match proto {
                        "udp" => Proto::Udp,
                        "tcp" => Proto::Tcp,
                        _ => continue,
                    };
                    if let Some(span) = parse_span(port, '-') {
                        chain.rules.push(Rule {
                            conds: vec![Cond::Proto(vec![proto]), Cond::Port(vec![span], false)],
                            action: Action::Accept,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    chain
}

/// The `<port protocol="udp" port="60443-60542"/>` elements of a firewalld service file.
fn parse_firewalld_service(xml: &str) -> Specs {
    let attr = |element: &str, name: &str| -> Option<String> {
        let at = element.find(&format!("{name}=\""))? + name.len() + 2;
        let end = element[at..].find('"')?;
        Some(element[at..at + end].to_string())
    };
    xml.split("<port")
        .skip(1)
        .filter_map(|element| {
            let element = element.split('>').next()?;
            let proto = match attr(element, "protocol")?.as_str() {
                "udp" => Proto::Udp,
                "tcp" => Proto::Tcp,
                _ => return None,
            };
            Some((proto, parse_span(&attr(element, "port")?, '-')?))
        })
        .collect()
}

// ---------------------------------------------------------------------------------------
// Raw rulesets: nftables and iptables

/// Without root: an nftables or iptables service that loads rules at boot.
fn raw_service(sys: &dyn System, family: Family, ports: &Ports) -> Option<Finding> {
    let enabled = |unit: &str| {
        if sys.exists("/run/systemd/system") {
            sys.run("systemctl", &["is-enabled", unit])
                .is_some_and(|o| o.stdout.trim() == "enabled")
                || sys
                    .run("systemctl", &["is-active", unit])
                    .is_some_and(|o| o.stdout.trim() == "active")
        } else {
            ["boot", "default"]
                .iter()
                .any(|level| sys.exists(&format!("/etc/runlevels/{level}/{unit}")))
        }
    };
    let (tool, fix) = if enabled("nftables") {
        (
            "nftables",
            nft_fix(family, ports, &[("inet".into(), "filter".into(), "input".into())]),
        )
    } else if ["iptables", "netfilter-persistent", "ip6tables"]
        .iter()
        .any(|u| enabled(u))
    {
        ("iptables", iptables_fix(family, ports))
    } else {
        return None;
    };
    Some(Finding {
        tool,
        detail: "service enabled".into(),
        zone: None,
        verdict: Verdict::Unknown(format!("only root can read the {tool} rules")),
        fix,
    })
}

fn raw_as_root(sys: &dyn System, family: Family, ports: &Ports, iface: Option<&str>) -> Vec<Finding> {
    let mut found = Vec::new();
    let backend = sys.run("iptables", &["-V"]).map(|o| {
        if o.stdout.contains("legacy") {
            "legacy"
        } else {
            "nf_tables"
        }
    });
    if let Some(out) = sys.run("nft", &["-j", "list", "ruleset"]).filter(|o| o.ok()) {
        if let Ok(json) = serde_json::from_str::<Value>(&out.stdout) {
            let ruleset = parse_nft(&json);
            if !ruleset.base.is_empty() {
                let verdict = evaluate(ports, |udp, port| ruleset.accepts(udp, port, iface));
                let blocking = ruleset.blocking_chains(ports, iface);
                let fix = nft_fix(family, ports, &blocking);
                found.push(Finding {
                    tool: "nftables",
                    detail: String::new(),
                    zone: None,
                    verdict,
                    fix,
                });
            }
        }
    }
    // iptables-legacy has its own tables, which packets pass as well as nftables'; the
    // nf_tables backend's rules are already in the nft ruleset
    let legacy = backend == Some("legacy") || (backend.is_some() && found.is_empty() && !sys_has_nft(sys));
    if legacy {
        let v4 = sys.run("iptables", &["-S"]).filter(|o| o.ok());
        let v6 = sys.run("ip6tables", &["-S"]).filter(|o| o.ok());
        let tables: Vec<Ruleset> = [v4, v6]
            .into_iter()
            .flatten()
            .map(|o| parse_iptables(&o.stdout))
            .collect();
        if tables.iter().any(|t| !t.base.is_empty()) {
            let verdict = evaluate(ports, |udp, port| tables.iter().all(|t| t.accepts(udp, port, iface)));
            found.push(Finding {
                tool: "iptables",
                detail: backend.unwrap_or("legacy").into(),
                zone: None,
                verdict,
                fix: iptables_fix(family, ports),
            });
        }
    }
    found
}

fn sys_has_nft(sys: &dyn System) -> bool {
    sys.run("nft", &["--version"]).is_some()
}

/// `udp dport { 60443-60542, 443 }` or `udp dport 60443-60542`.
fn nft_ports(ports: &Ports) -> String {
    let spans: Vec<String> = ports.spans().into_iter().map(|s| Ports::span_text(s, "-")).collect();
    if spans.len() == 1 {
        spans[0].clone()
    } else {
        format!("{{ {} }}", spans.join(", "))
    }
}

fn nft_fix(family: Family, ports: &Ports, chains: &[(String, String, String)]) -> Fix {
    let set = nft_ports(ports);
    let mut commands = Vec::new();
    for (fam, table, chain) in chains {
        for proto in ["udp", "tcp"] {
            commands.push(format!(
                "sudo nft insert rule {fam} {table} {chain} {proto} dport {set} accept"
            ));
        }
    }
    Fix::commands(true, commands).with_note(family.nft_persistence())
}

fn iptables_fix(family: Family, ports: &Ports) -> Fix {
    let spans: Vec<String> = ports.spans().into_iter().map(|s| Ports::span_text(s, ":")).collect();
    let mut commands = Vec::new();
    for program in ["iptables", "ip6tables"] {
        for proto in ["udp", "tcp"] {
            commands.push(if spans.len() == 1 {
                format!("sudo {program} -I INPUT -p {proto} --dport {} -j ACCEPT", spans[0])
            } else {
                format!(
                    "sudo {program} -I INPUT -p {proto} -m multiport --dports {} -j ACCEPT",
                    spans.join(",")
                )
            });
        }
    }
    Fix::commands(true, commands).with_note(family.iptables_persistence())
}

// ---------------------------------------------------------------------------------------
// The model

/// A transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    /// UDP.
    Udp,
    /// TCP.
    Tcp,
}

/// A condition of a rule, for a new packet from an unknown address.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Cond {
    /// The protocol is one of these.
    Proto(Vec<Proto>),
    /// The destination port is in one of these spans (or not, when negated).
    Port(Vec<(u16, u16)>, bool),
    /// Connection tracking state: true when "new" is among the states (or not, when negated).
    CtNew(bool),
    /// The input interface is this one (or not, when negated).
    Iface(String, bool),
    /// One of these lists of conditions holds.
    Any(Vec<Vec<Cond>>),
    /// Something the model does not know: assumed not to hold.
    Unknown,
}

/// What a rule does when its conditions hold.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    Accept,
    Drop,
    Jump(String),
    Goto(String),
    Return,
    /// Nothing (a counter, a log): the next rule.
    Continue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    conds: Vec<Cond>,
    action: Action,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Chain {
    /// The policy of a base chain (None: a regular chain, which returns).
    policy: Option<Action>,
    rules: Vec<Rule>,
}

/// A ruleset: its chains by name and the base chains of the input hook, in priority order.
#[derive(Debug, Clone, Default)]
struct Ruleset {
    chains: HashMap<String, Chain>,
    /// (family, table, chain name, key into `chains`, priority).
    base: Vec<(String, String, String, String, i64)>,
}

/// A new packet.
struct Packet<'a> {
    proto: Proto,
    port: u16,
    iface: Option<&'a str>,
}

fn holds(cond: &Cond, p: &Packet<'_>) -> bool {
    match cond {
        Cond::Proto(list) => list.contains(&p.proto),
        Cond::Port(spans, negated) => spans.iter().any(|(a, b)| (*a..=*b).contains(&p.port)) != *negated,
        Cond::CtNew(new) => *new,
        Cond::Iface(name, negated) => match p.iface {
            Some(i) => (i == name) != *negated,
            // Unknown interface: only "not lo" holds
            None => *negated && name == "lo",
        },
        Cond::Any(alternatives) => alternatives.iter().any(|all| all.iter().all(|c| holds(c, p))),
        Cond::Unknown => false,
    }
}

/// Run `name` for the packet: Some(true) accepted, Some(false) dropped, None returned (or
/// fell off a regular chain).
fn run_chain(chains: &HashMap<String, Chain>, name: &str, p: &Packet<'_>, depth: u32) -> Option<bool> {
    let chain = chains.get(name)?;
    if depth > 32 {
        return None;
    }
    for rule in &chain.rules {
        if !rule.conds.iter().all(|c| holds(c, p)) {
            continue;
        }
        match &rule.action {
            Action::Accept => return Some(true),
            Action::Drop => return Some(false),
            Action::Return => return None,
            Action::Continue => {}
            Action::Jump(target) => {
                if let Some(v) = run_chain(chains, target, p, depth + 1) {
                    return Some(v);
                }
            }
            Action::Goto(target) => return run_chain(chains, target, p, depth + 1),
        }
    }
    match chain.policy {
        Some(Action::Drop) => Some(false),
        Some(_) => Some(true),
        None => None,
    }
}

impl Ruleset {
    /// True when every base chain of the input hook accepts the packet.
    fn accepts(&self, udp: bool, port: u16, iface: Option<&str>) -> bool {
        let p = Packet {
            proto: if udp { Proto::Udp } else { Proto::Tcp },
            port,
            iface,
        };
        self.base
            .iter()
            .all(|(_, _, _, key, _)| run_chain(&self.chains, key, &p, 0) != Some(false))
    }

    /// The base chains that drop the daemon's primary ports: where a rule must be inserted.
    fn blocking_chains(&self, ports: &Ports, iface: Option<&str>) -> Vec<(String, String, String)> {
        self.base
            .iter()
            .filter(|(_, _, _, key, _)| {
                [(Proto::Udp, ports.udp), (Proto::Tcp, ports.tcp)]
                    .iter()
                    .any(|(proto, port)| {
                        let p = Packet {
                            proto: *proto,
                            port: *port,
                            iface,
                        };
                        run_chain(&self.chains, key, &p, 0) == Some(false)
                    })
            })
            .map(|(f, t, c, _, _)| (f.clone(), t.clone(), c.clone()))
            .collect()
    }
}

/// A chain with only these rules and a policy: ufw's and firewalld's view.
fn eval_simple(chain: &Chain, udp: bool, port: u16) -> bool {
    let mut chains = HashMap::new();
    chains.insert(String::new(), chain.clone());
    let p = Packet {
        proto: if udp { Proto::Udp } else { Proto::Tcp },
        port,
        iface: None,
    };
    run_chain(&chains, "", &p, 0) != Some(false)
}

/// The verdict for `ports`, given whether (udp, port) gets in.
fn evaluate(ports: &Ports, accepts: impl Fn(bool, u16) -> bool) -> Verdict {
    let mut extra_blocked = Vec::new();
    for &p in &ports.extra {
        if !(accepts(true, p) && accepts(false, p)) {
            extra_blocked.push(p);
        }
    }
    Verdict::Checked {
        udp: accepts(true, ports.udp),
        tcp: accepts(false, ports.tcp),
        extra_blocked,
    }
}

/// `60443:60542`, `60443-60542` or `443`.
fn parse_span(text: &str, sep: char) -> Option<(u16, u16)> {
    let text = text.trim();
    match text.split_once(sep) {
        Some((a, b)) => {
            let (a, b) = (a.trim().parse().ok()?, b.trim().parse().ok()?);
            (a <= b).then_some((a, b))
        }
        None => text.parse().ok().map(|p| (p, p)),
    }
}

// ---- nftables (nft -j list ruleset)

fn parse_nft(json: &Value) -> Ruleset {
    let mut set = Ruleset::default();
    let Some(items) = json["nftables"].as_array() else {
        return set;
    };
    let key = |family: &str, table: &str, chain: &str| format!("{family} {table} {chain}");
    for item in items {
        if let Some(chain) = item.get("chain") {
            let (family, table, name) = (
                chain["family"].as_str().unwrap_or(""),
                chain["table"].as_str().unwrap_or(""),
                chain["name"].as_str().unwrap_or(""),
            );
            let k = key(family, table, name);
            let base = chain.get("hook").is_some();
            let policy = base.then(|| match chain["policy"].as_str() {
                Some("drop") => Action::Drop,
                _ => Action::Accept,
            });
            set.chains.insert(
                k.clone(),
                Chain {
                    policy,
                    rules: Vec::new(),
                },
            );
            let filter = chain["type"].as_str().is_none_or(|t| t == "filter");
            if chain["hook"].as_str() == Some("input") && filter && ["inet", "ip", "ip6"].contains(&family) {
                let prio = chain["prio"].as_i64().unwrap_or(0);
                set.base.push((family.into(), table.into(), name.into(), k, prio));
            }
        } else if let Some(rule) = item.get("rule") {
            let (family, table, chain) = (
                rule["family"].as_str().unwrap_or(""),
                rule["table"].as_str().unwrap_or(""),
                rule["chain"].as_str().unwrap_or(""),
            );
            let k = key(family, table, chain);
            let parsed = parse_nft_rule(rule["expr"].as_array().map(Vec::as_slice).unwrap_or(&[]), family, table);
            if let Some(c) = set.chains.get_mut(&k) {
                c.rules.push(parsed);
            }
        }
    }
    set.base.sort_by_key(|b| b.4);
    set
}

fn nft_proto(v: &Value) -> Vec<Proto> {
    let one = |s: &str| match s {
        "udp" => Some(Proto::Udp),
        "tcp" => Some(Proto::Tcp),
        _ => None,
    };
    match v {
        Value::String(s) => one(s).into_iter().collect(),
        Value::Object(o) if o.contains_key("set") => o["set"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().and_then(one)).collect())
            .unwrap_or_default(),
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().and_then(one)).collect(),
        _ => Vec::new(),
    }
}

fn nft_spans(v: &Value) -> Option<Vec<(u16, u16)>> {
    let one = |x: &Value| -> Option<(u16, u16)> {
        if let Some(p) = x.as_u64() {
            let p = u16::try_from(p).ok()?;
            return Some((p, p));
        }
        let r = x.get("range")?.as_array()?;
        let a = u16::try_from(r.first()?.as_u64()?).ok()?;
        let b = u16::try_from(r.get(1)?.as_u64()?).ok()?;
        Some((a, b))
    };
    if let Some(s) = v.get("set").and_then(Value::as_array) {
        return s.iter().map(one).collect();
    }
    if let Some(a) = v.as_array() {
        return a.iter().map(one).collect();
    }
    one(v).map(|s| vec![s])
}

fn nft_strings(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        Value::Object(o) => o
            .get("set")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn nft_verdict(v: &Value, family: &str, table: &str) -> Option<Action> {
    let o = v.as_object()?;
    let target = |x: &Value| format!("{family} {table} {}", x["target"].as_str().unwrap_or(""));
    if o.contains_key("accept") {
        Some(Action::Accept)
    } else if o.contains_key("drop") || o.contains_key("reject") {
        Some(Action::Drop)
    } else if o.contains_key("return") {
        Some(Action::Return)
    } else if let Some(j) = o.get("jump") {
        Some(Action::Jump(target(j)))
    } else {
        o.get("goto").map(|g| Action::Goto(target(g)))
    }
}

fn parse_nft_rule(exprs: &[Value], family: &str, table: &str) -> Rule {
    let mut conds = Vec::new();
    let mut action = Action::Continue;
    for e in exprs {
        if let Some(m) = e.get("match") {
            let negated = m["op"].as_str() == Some("!=");
            let left = &m["left"];
            let right = &m["right"];
            let cond = if let Some(payload) = left.get("payload") {
                let field = payload["field"].as_str().unwrap_or("");
                let proto = payload["protocol"].as_str().unwrap_or("");
                match (proto, field) {
                    ("udp" | "tcp" | "th", "dport") => match nft_spans(right) {
                        Some(spans) => {
                            let mut c = Vec::new();
                            if proto != "th" {
                                c.push(Cond::Proto(nft_proto(&Value::String(proto.into()))));
                            }
                            c.push(Cond::Port(spans, negated));
                            Cond::Any(vec![c])
                        }
                        None => Cond::Unknown,
                    },
                    ("ip", "protocol") | ("ip6", "nexthdr") if !negated => Cond::Proto(nft_proto(right)),
                    _ => Cond::Unknown,
                }
            } else if let Some(meta) = left.get("meta") {
                match meta["key"].as_str() {
                    Some("l4proto") if !negated => Cond::Proto(nft_proto(right)),
                    Some("iifname" | "iif") => match right.as_str() {
                        Some(name) => Cond::Iface(name.into(), negated),
                        None => Cond::Unknown,
                    },
                    // The packet's family: both are possible
                    Some("nfproto") => continue,
                    _ => Cond::Unknown,
                }
            } else if left.get("ct").is_some_and(|ct| ct["key"].as_str() == Some("state")) {
                let states = nft_strings(right);
                Cond::CtNew(states.iter().any(|s| s == "new") != negated)
            } else {
                Cond::Unknown
            };
            conds.push(cond);
        } else if let Some(vmap) = e.get("vmap") {
            // `ct state vmap { established : accept, invalid : drop }`: what "new" maps to
            if vmap["key"]
                .get("ct")
                .is_some_and(|ct| ct["key"].as_str() == Some("state"))
            {
                let entries = vmap["data"]["set"].as_array().cloned().unwrap_or_default();
                let new = entries.iter().find_map(|pair| {
                    let pair = pair.as_array()?;
                    let states = nft_strings(pair.first()?);
                    states
                        .iter()
                        .any(|s| s == "new")
                        .then(|| nft_verdict(pair.get(1)?, family, table))
                        .flatten()
                });
                if let Some(v) = new {
                    action = v;
                    break;
                }
            }
            // Other maps: no verdict this model can tell
        } else if let Some(v) = nft_verdict(e, family, table) {
            action = v;
            break;
        } else if e.get("xt").is_some() {
            conds.push(Cond::Unknown);
        }
        // counter, log, limit, comment: no effect on the verdict
    }
    Rule { conds, action }
}

// ---- iptables -S

fn parse_iptables(text: &str) -> Ruleset {
    let mut set = Ruleset::default();
    for line in text.lines() {
        let words = shell_words(line);
        let Some(first) = words.first() else { continue };
        match first.as_str() {
            "-P" if words.len() >= 3 => {
                let policy = if words[2] == "ACCEPT" {
                    Action::Accept
                } else {
                    Action::Drop
                };
                let chain = set.chains.entry(words[1].clone()).or_default();
                chain.policy = Some(policy);
                if words[1] == "INPUT" {
                    set.base
                        .push(("ip".into(), "filter".into(), "INPUT".into(), "INPUT".into(), 0));
                }
            }
            "-N" if words.len() >= 2 => {
                set.chains.entry(words[1].clone()).or_default();
            }
            "-A" if words.len() >= 2 => {
                let rule = parse_iptables_rule(&words[2..]);
                set.chains.entry(words[1].clone()).or_default().rules.push(rule);
            }
            _ => {}
        }
    }
    set
}

fn parse_iptables_rule(words: &[String]) -> Rule {
    let mut conds = Vec::new();
    let mut action = Action::Continue;
    let mut negate = false;
    let mut i = 0;
    let arg = |i: usize| words.get(i + 1).map(String::as_str).unwrap_or("");
    while i < words.len() {
        let w = words[i].as_str();
        let mut skip = 2;
        match w {
            "!" => {
                negate = true;
                i += 1;
                continue;
            }
            "-p" | "--protocol" => conds.push(match (arg(i), negate) {
                ("udp", false) => Cond::Proto(vec![Proto::Udp]),
                ("tcp", false) => Cond::Proto(vec![Proto::Tcp]),
                ("udp", true) => Cond::Proto(vec![Proto::Tcp]),
                ("tcp", true) => Cond::Proto(vec![Proto::Udp]),
                ("all", false) => Cond::Proto(vec![Proto::Udp, Proto::Tcp]),
                _ => Cond::Unknown,
            }),
            "--dport" | "--destination-port" | "--dports" | "--destination-ports" => {
                let spans: Option<Vec<(u16, u16)>> = arg(i).split(',').map(|p| parse_span(p, ':')).collect();
                conds.push(match spans {
                    Some(s) => Cond::Port(s, negate),
                    None => Cond::Unknown,
                });
            }
            "-i" | "--in-interface" => {
                let name = arg(i).trim_end_matches('+');
                conds.push(if arg(i).ends_with('+') {
                    Cond::Unknown
                } else {
                    Cond::Iface(name.into(), negate)
                });
            }
            "--state" | "--ctstate" => {
                let new = arg(i).split(',').any(|s| s == "NEW");
                conds.push(Cond::CtNew(new != negate));
            }
            // Modules whose options are read above or that do not restrict a new packet
            "-m" | "--match" => {
                let module = arg(i);
                if !["udp", "tcp", "multiport", "state", "conntrack", "comment", "limit"].contains(&module) {
                    conds.push(Cond::Unknown);
                }
            }
            "--comment" | "--limit" | "--limit-burst" | "--reject-with" | "--log-prefix" | "--log-level" => {}
            "-j" | "--jump" => {
                action = match arg(i) {
                    "ACCEPT" => Action::Accept,
                    "DROP" | "REJECT" => Action::Drop,
                    "RETURN" => Action::Return,
                    "LOG" | "NFLOG" | "ULOG" => Action::Continue,
                    other => Action::Jump(other.into()),
                };
            }
            "-g" | "--goto" => action = Action::Goto(arg(i).into()),
            "-c" => skip = 3,
            _ => {
                // -s, -d, --sport and anything else: unknown for an arbitrary packet
                conds.push(Cond::Unknown);
                skip = if words.get(i + 1).is_some_and(|n| !n.starts_with('-')) {
                    2
                } else {
                    1
                };
            }
        }
        negate = false;
        i += skip;
    }
    Rule { conds, action }
}

/// Split a line of `iptables -S` into words, keeping "quoted comments" as one.
fn shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut any = false;
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    words.push(std::mem::take(&mut current));
                    any = false;
                }
            }
            c => {
                current.push(c);
                any = true;
            }
        }
    }
    if any {
        words.push(current);
    }
    words
}

#[cfg(test)]
pub(super) mod model_tests {
    use super::*;

    pub(crate) fn ports() -> Ports {
        Ports {
            range: 60443..=60542,
            extra: vec![],
            udp: 60443,
            tcp: 60443,
        }
    }

    #[test]
    fn ufw_status_rules_in_order_then_the_default() {
        let text = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n60443:60542/udp            ALLOW IN    Anywhere                   # qsh\n22/tcp (v6)                ALLOW IN    Anywhere (v6)\n";
        let chain = parse_ufw_status(text, &HashMap::new());
        assert!(eval_simple(&chain, true, 60443));
        assert!(!eval_simple(&chain, false, 60443));
        assert!(eval_simple(&chain, false, 22));
        let allow = text.replace("deny (incoming)", "allow (incoming)");
        assert!(eval_simple(&parse_ufw_status(&allow, &HashMap::new()), false, 60443));
        // Only from one network: not "everyone"
        let some = "Default: deny (incoming)\n--\n60443:60542/udp ALLOW IN 10.0.0.0/8\n";
        assert!(!eval_simple(&parse_ufw_status(some, &HashMap::new()), true, 60443));
    }

    #[test]
    fn spans() {
        assert_eq!(parse_span("60443:60542", ':'), Some((60443, 60542)));
        assert_eq!(parse_span("443", ':'), Some((443, 443)));
        assert_eq!(parse_span("9-1", '-'), None);
        let mut p = ports();
        p.extra = vec![443, 60500];
        assert_eq!(p.spans(), vec![(60443, 60542), (443, 443)]);
        assert_eq!(nft_ports(&p), "{ 60443-60542, 443 }");
    }

    #[test]
    fn iptables_words() {
        assert_eq!(
            shell_words(r#"-A INPUT -m comment --comment "a b" -j ACCEPT"#),
            ["-A", "INPUT", "-m", "comment", "--comment", "a b", "-j", "ACCEPT"]
        );
    }
}
