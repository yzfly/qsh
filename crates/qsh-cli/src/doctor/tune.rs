//! `qsh-server tune [--apply] [--revert]` (m2.md 8.4, security.md 4.9): the only part of
//! qsh that changes anything as root, and only when an administrator asks.
//!
//! It may change exactly this, and nothing else: `/etc/sysctl.d/90-qsh.conf` (socket buffer
//! limits, the allowed congestion controls; with explicit flags the default congestion control
//! and `ip_unprivileged_port_start`), `/etc/modules-load.d/qsh.conf` (`tcp_bbr`), the runtime
//! values of those sysctls, the `tcp_bbr` module, rules in ufw or firewalld that let the
//! daemon's ports in, linger for the invoking user; and its own record,
//! `/var/lib/qsh/tune.json`, which lists every change with what undoes it.
//!
//! Every step first looks at the current state and is left out when the host already
//! satisfies it, so applying twice changes nothing the second time. `--revert` undoes what the
//! record lists, and only where the host still is as tune left it.

use std::fmt::Write as _;

use serde_json::{json, Value};

use super::checks::{self, HostInfo, User, WANTED_BUFFER};
use super::diff;
use super::firewall::{self, Ports, Verdict};
use super::System;

/// The sysctl drop-in tune writes.
pub const SYSCTL_FILE: &str = "/etc/sysctl.d/90-qsh.conf";
/// The modules-load.d file tune writes.
pub const MODULES_FILE: &str = "/etc/modules-load.d/qsh.conf";
/// The record of what tune did.
pub const RECORD: &str = "/var/lib/qsh/tune.json";

const SYSCTL_HEADER: &str = "# Written by qsh-server tune (qsh-server(1)); qsh-server tune --revert removes it.\n";
const MODULES_HEADER: &str =
    "# Written by qsh-server tune (qsh-server(1)): BBR for qsh's TLS connections and the ssh pipe.\n";

/// What to change beyond the default plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// `--bbr-default`: BBR and fq for every TCP connection of the host.
    pub bbr_default: bool,
    /// `--allow-low-ports=N`: `net.ipv4.ip_unprivileged_port_start = N`.
    pub low_ports: Option<u16>,
    /// `--linger`: enable linger even where `KillUserProcesses=no`.
    pub linger: bool,
    /// The ports to let in.
    pub ports: Ports,
}

/// One change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Write a file.
    File {
        /// The fixes it serves (`udp-buffers`, `tcp-bbr`, …).
        fixes: Vec<&'static str>,
        /// Where.
        path: String,
        /// What is there now (None: no file).
        before: Option<String>,
        /// What tune writes.
        after: String,
    },
    /// Set a sysctl now (`sysctl -w`).
    Sysctl {
        /// The fix it serves.
        fix: &'static str,
        /// `net.core.rmem_max`.
        key: String,
        /// The value now.
        before: String,
        /// The value tune sets.
        after: String,
    },
    /// Load a kernel module now (`modprobe`).
    Module {
        /// The fix it serves.
        fix: &'static str,
        /// `tcp_bbr`.
        name: String,
    },
    /// Run commands of a managing tool (ufw, firewalld, loginctl).
    Commands {
        /// The fix it serves.
        fix: &'static str,
        /// The commands, as argument vectors.
        run: Vec<Vec<String>>,
        /// The commands that undo them.
        undo: Vec<Vec<String>>,
        /// Files the commands change, recorded so that a revert restores them exactly.
        files: Vec<String>,
        /// The command that makes the tool reread those files after a restore.
        reload: Option<Vec<String>>,
    },
}

/// What `--apply` would do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// The changes, in order.
    pub steps: Vec<Step>,
    /// What tune leaves to the administrator, and why.
    pub notes: Vec<String>,
}

/// One line of a sysctl drop-in: `key = value`.
fn sysctl_line(key: &str, value: &str) -> String {
    format!("{key} = {value}")
}

/// `content` with `key` set to `value`: the key's line replaced, or appended.
fn set_sysctl_line(content: &str, key: &str, value: &str) -> String {
    let mut out = String::new();
    let mut found = false;
    for line in content.lines() {
        let k = line.split('=').next().unwrap_or("").trim();
        if !line.trim_start().starts_with('#') && k == key {
            if !found {
                out.push_str(&sysctl_line(key, value));
                out.push('\n');
            }
            found = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !found {
        out.push_str(&sysctl_line(key, value));
        out.push('\n');
    }
    out
}

/// Build the plan: every fix that applies, left out where the host already satisfies it.
pub fn plan(sys: &dyn System, host: &HostInfo, user: &User, opts: &Options) -> Plan {
    let mut plan = Plan::default();
    let mut sysctls: Vec<(&'static str, String, String)> = Vec::new();
    let mut module = false;
    if let Some(c) = &host.container {
        plan.notes.push(format!(
            "inside a {c} container: sysctls and kernel modules belong to the host; run qsh-server tune there"
        ));
    } else {
        // udp-buffers: raise, never lower
        for key in ["net.core.rmem_max", "net.core.wmem_max"] {
            if let Some(v) = checks::sysctl(sys, key).and_then(|v| v.parse::<u64>().ok()) {
                if v < WANTED_BUFFER {
                    sysctls.push(("udp-buffers", key.into(), WANTED_BUFFER.to_string()));
                }
            }
        }
        // tcp-bbr: the module, and bbr among the allowed controls
        if let Some(b) = checks::bbr_facts(sys) {
            let wants_bbr = !b.allowed.iter().any(|a| a == "bbr") || (opts.bbr_default && b.current != "bbr");
            if wants_bbr && !b.possible {
                plan.notes
                    .push("this kernel has no tcp_bbr module: BBR cannot be enabled".into());
            } else if wants_bbr || opts.bbr_default {
                if !b.available.iter().any(|a| a == "bbr") {
                    module = true;
                }
                if !b.allowed.iter().any(|a| a == "bbr") {
                    let mut allowed = b.allowed.clone();
                    allowed.push("bbr".into());
                    sysctls.push((
                        "tcp-bbr",
                        "net.ipv4.tcp_allowed_congestion_control".into(),
                        allowed.join(" "),
                    ));
                }
                if opts.bbr_default {
                    if b.qdisc != "fq" {
                        sysctls.push(("bbr-default", "net.core.default_qdisc".into(), "fq".into()));
                    }
                    if b.current != "bbr" {
                        sysctls.push(("bbr-default", "net.ipv4.tcp_congestion_control".into(), "bbr".into()));
                    }
                }
            }
        }
        if let Some(n) = opts.low_ports {
            let now = checks::sysctl(sys, "net.ipv4.ip_unprivileged_port_start").and_then(|v| v.parse::<u16>().ok());
            match now {
                Some(v) if v > n => {
                    sysctls.push(("low-ports", "net.ipv4.ip_unprivileged_port_start".into(), n.to_string()))
                }
                Some(_) => {}
                None => plan
                    .notes
                    .push("net.ipv4.ip_unprivileged_port_start does not exist here (Linux 4.11+)".into()),
            }
        }
    }
    if module {
        let before = sys.read(MODULES_FILE);
        let after = format!("{MODULES_HEADER}tcp_bbr\n");
        if before.as_deref() != Some(after.as_str()) {
            plan.steps.push(Step::File {
                fixes: vec!["tcp-bbr"],
                path: MODULES_FILE.into(),
                before,
                after,
            });
        }
        plan.steps.push(Step::Module {
            fix: "tcp-bbr",
            name: "tcp_bbr".into(),
        });
    }
    if !sysctls.is_empty() {
        let before = sys.read(SYSCTL_FILE);
        let mut after = before.clone().unwrap_or_else(|| SYSCTL_HEADER.to_string());
        let mut fixes = Vec::new();
        for (fix, key, value) in &sysctls {
            after = set_sysctl_line(&after, key, value);
            if !fixes.contains(fix) {
                fixes.push(*fix);
            }
        }
        if before.as_deref() != Some(after.as_str()) {
            plan.steps.push(Step::File {
                fixes,
                path: SYSCTL_FILE.into(),
                before,
                after,
            });
        }
        for (fix, key, value) in sysctls {
            let now = checks::sysctl(sys, &key).unwrap_or_default();
            if now != value {
                plan.steps.push(Step::Sysctl {
                    fix,
                    key,
                    before: now,
                    after: value,
                });
            }
        }
    }
    firewall_steps(sys, host, opts, &mut plan);
    linger_step(sys, host, user, opts, &mut plan);
    plan
}

fn argv(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| w.to_string()).collect()
}

fn firewall_steps(sys: &dyn System, host: &HostInfo, opts: &Options, plan: &mut Plan) {
    let iface = checks::default_route_v4(sys).map(|r| r.0);
    for finding in firewall::detect(sys, host.family, &opts.ports, iface.as_deref()) {
        let open = match &finding.verdict {
            Verdict::Checked { .. } => !finding.allows_all(),
            Verdict::Unknown(_) => {
                if sys.euid() != 0 {
                    plan.notes.push(format!(
                        "{}: only root can read its rules; as root, tune leaves out what is already open",
                        finding.tool
                    ));
                }
                true
            }
        };
        if !open {
            continue;
        }
        match finding.tool {
            "ufw" => {
                let mut run = Vec::new();
                let mut undo = Vec::new();
                for command in firewall::ufw_allow_commands(sys, &opts.ports) {
                    // "sudo ufw allow X" → ufw allow X comment qsh
                    let rule: Vec<String> = command.split_whitespace().skip(3).map(String::from).collect();
                    let mut r = argv(&["ufw", "allow"]);
                    r.extend(rule.clone());
                    r.extend(argv(&["comment", "qsh"]));
                    run.push(r);
                    let mut u = argv(&["ufw", "delete", "allow"]);
                    u.extend(rule);
                    undo.push(u);
                }
                plan.steps.push(Step::Commands {
                    fix: "firewall",
                    run,
                    undo,
                    files: vec!["/etc/ufw/user.rules".into(), "/etc/ufw/user6.rules".into()],
                    reload: Some(argv(&["ufw", "reload"])),
                });
            }
            "firewalld" => {
                let zone = finding.zone.clone().unwrap_or_else(|| "public".into());
                if !valid_zone(&zone) {
                    plan.notes.push(format!(
                        "firewalld: the zone {zone:?} is not a plain name; tune leaves it alone"
                    ));
                    continue;
                }
                let add = firewall::firewalld_add_args(sys, &opts.ports);
                let remove: Vec<String> = add.iter().map(|a| a.replacen("--add-", "--remove-", 1)).collect();
                let base = argv(&["firewall-cmd", "--permanent"]);
                let zone_arg = format!("--zone={zone}");
                let mut run = base.clone();
                run.push(zone_arg.clone());
                run.extend(add);
                let mut undo = base;
                undo.push(zone_arg);
                undo.extend(remove);
                let reload = argv(&["firewall-cmd", "--reload"]);
                plan.steps.push(Step::Commands {
                    fix: "firewall",
                    run: vec![run, reload.clone()],
                    undo: vec![undo, reload.clone()],
                    files: vec![
                        format!("/etc/firewalld/zones/{zone}.xml"),
                        format!("/etc/firewalld/zones/{zone}.xml.old"),
                    ],
                    reload: Some(reload),
                });
            }
            tool => {
                let mut note = format!(
                    "{tool}: tune does not change raw rulesets; to let the ports in: {}",
                    finding.fix.commands.join(" && ")
                );
                if let Some(n) = &finding.fix.note {
                    note.push_str(&format!(" ({n})"));
                }
                plan.notes.push(note);
            }
        }
    }
}

fn linger_step(sys: &dyn System, host: &HostInfo, user: &User, opts: &Options, plan: &mut Plan) {
    if host.init != "systemd" {
        if opts.linger {
            plan.notes.push("--linger: there is no systemd-logind here".into());
        }
        return;
    }
    let lingering = sys.exists(&format!("/var/lib/systemd/linger/{}", user.name));
    let wanted = opts.linger || checks::kill_user_processes(sys);
    if !wanted || lingering {
        return;
    }
    if !user.sudo {
        if opts.linger {
            plan.notes.push(
                "--linger: run tune through sudo from the account whose sessions should survive (SUDO_USER)".into(),
            );
        }
        return;
    }
    plan.steps.push(Step::Commands {
        fix: "linger",
        run: vec![argv(&["loginctl", "enable-linger", &user.name])],
        undo: vec![argv(&["loginctl", "disable-linger", &user.name])],
        files: Vec::new(),
        reload: None,
    });
}

/// The plan for people: diffs for files, exact commands for everything else.
pub fn render(plan: &Plan) -> String {
    let mut out = String::new();
    let mut header = String::new();
    let mut section = |out: &mut String, title: String| {
        if title != header {
            if !out.is_empty() {
                out.push('\n');
            }
            let _ = writeln!(out, "# {title}");
            header = title;
        }
    };
    for step in &plan.steps {
        match step {
            Step::File {
                fixes,
                path,
                before,
                after,
            } => {
                section(&mut out, format!("{}: {path}", fixes.join(", ")));
                out.push_str(&diff::unified(path, before.as_deref(), Some(after)));
            }
            Step::Sysctl {
                fix,
                key,
                before,
                after,
            } => {
                section(&mut out, format!("{fix}: at once"));
                let _ = writeln!(
                    out,
                    "sysctl -w {}    # was {before}",
                    shell_join(&[format!("{key}={after}")])
                );
            }
            Step::Module { fix, name } => {
                section(&mut out, format!("{fix}: at once"));
                let _ = writeln!(out, "modprobe {name}");
            }
            Step::Commands { fix, run, .. } => {
                section(&mut out, fix.to_string());
                for r in run {
                    let _ = writeln!(out, "{}", shell_join(r));
                }
            }
        }
    }
    if !plan.notes.is_empty() && !out.is_empty() {
        out.push('\n');
    }
    for note in &plan.notes {
        let _ = writeln!(out, "# {note}");
    }
    out
}

/// Words joined for display, quoting the ones with spaces.
fn shell_join(words: &[String]) -> String {
    words
        .iter()
        .map(|w| {
            if w.is_empty() || w.contains(|c: char| c.is_whitespace() || c == '\'') {
                format!("'{}'", w.replace('\'', "'\\''"))
            } else {
                w.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------------------
// The record

/// A file and what tune left in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecord {
    /// The path.
    pub path: String,
    /// Its content before (None: it did not exist).
    pub before: Option<String>,
    /// Its permission bits before, put back with the content (None: it did not exist).
    pub mode: Option<u32>,
    /// Its owner and group before (None: it did not exist).
    pub owner: Option<(u32, u32)>,
    /// SHA-256 of what it contained afterwards (None: it did not exist afterwards).
    pub sha256: Option<String>,
}

/// One change as recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// A file tune wrote.
    File {
        /// The fixes.
        fixes: Vec<String>,
        /// The file.
        file: FileRecord,
        /// Directories tune created for it, outermost first.
        created_dirs: Vec<String>,
    },
    /// A runtime sysctl.
    Sysctl {
        /// The fix.
        fix: String,
        /// The key.
        key: String,
        /// The value before.
        before: String,
        /// The value tune set.
        after: String,
    },
    /// A module tune loaded.
    Module {
        /// The fix.
        fix: String,
        /// The module.
        name: String,
    },
    /// Commands of a managing tool.
    Commands {
        /// The fix.
        fix: String,
        /// What was run.
        run: Vec<Vec<String>>,
        /// What undoes it.
        undo: Vec<Vec<String>>,
        /// The files the commands changed: restored exactly on revert when nobody changed
        /// them since.
        files: Vec<FileRecord>,
        /// What makes the tool reread restored files.
        reload: Option<Vec<String>>,
    },
}

/// `/var/lib/qsh/tune.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Record {
    /// Format version (1).
    pub qsh_tune: u64,
    /// The qsh-server that wrote it.
    pub version: String,
    /// Directories created for the record itself, outermost first.
    pub created_dirs: Vec<String>,
    /// The changes, in the order they were made.
    pub changes: Vec<Change>,
}

impl Record {
    /// Read the record; None when there is none, an error when it is unusable. The record says
    /// what `--revert` runs and writes as root, so it is used only when it and its directory
    /// can only have been written by root (or by this user, under a stand-in root), and when
    /// every change in it is one tune itself makes ([`Record::validate`], review H3).
    pub fn load(sys: &dyn System) -> Result<Option<Record>, String> {
        let Some(meta) = sys.meta(RECORD) else {
            return Ok(None);
        };
        let euid = sys.euid();
        for (path, m) in [(parent(RECORD), sys.meta(parent(RECORD))), (RECORD, Some(meta))] {
            let Some(m) = m else {
                return Err(format!("{path}: cannot be examined"));
            };
            let why = if m.symlink {
                Some("is a symbolic link")
            } else if m.uid != 0 && m.uid != euid {
                Some("belongs to another user")
            } else if m.mode & 0o022 != 0 {
                Some("is writable by group or others")
            } else {
                None
            };
            if let Some(why) = why {
                return Err(format!("{path} {why}: refusing to use the record"));
            }
        }
        let Some(text) = sys.read(RECORD) else {
            return Err(format!("{RECORD}: cannot be read"));
        };
        let value: Value = serde_json::from_str(&text).map_err(|e| format!("{RECORD}: {e}"))?;
        if value["qsh_tune"].as_u64() != Some(super::SCHEMA) {
            return Err(format!("{RECORD}: unknown format {}", value["qsh_tune"]));
        }
        let record =
            Record::from_json(&value).ok_or_else(|| format!("{RECORD}: not a record qsh-server tune can read"))?;
        record
            .validate()
            .map_err(|e| format!("{RECORD}: {e}; qsh-server tune did not write this, refusing to use it"))?;
        Ok(Some(record))
    }

    /// Check that every change is one tune makes: only its own files (the sysctl and
    /// modules-load.d files, the ufw and firewalld files its firewall commands change) and the
    /// directories above them, only the sysctls it sets with values of their kind, only
    /// `tcp_bbr`, and only the commands of ufw, firewall-cmd and loginctl in exactly the forms
    /// it runs them, with arguments of the kinds it uses (review H3: the record decides what a
    /// revert runs as root).
    pub fn validate(&self) -> Result<(), String> {
        for d in &self.created_dirs {
            if !is_ancestor(d, RECORD) {
                return Err(format!("a directory {d:?} that tune does not create"));
            }
        }
        for change in &self.changes {
            match change {
                Change::File {
                    fixes,
                    file,
                    created_dirs,
                } => {
                    if file.path != SYSCTL_FILE && file.path != MODULES_FILE {
                        return Err(format!("a file {:?} that tune does not write", file.path));
                    }
                    check_file_record(file)?;
                    if let Some(d) = created_dirs.iter().find(|d| !is_ancestor(d, &file.path)) {
                        return Err(format!("a directory {d:?} that tune does not create"));
                    }
                    if let Some(f) = fixes.iter().find(|f| !FIXES.contains(&f.as_str())) {
                        return Err(format!("an unknown fix {f:?}"));
                    }
                }
                Change::Sysctl {
                    fix,
                    key,
                    before,
                    after,
                    ..
                } => {
                    if !FIXES.contains(&fix.as_str()) {
                        return Err(format!("an unknown fix {fix:?}"));
                    }
                    if !SYSCTLS.contains(&key.as_str()) {
                        return Err(format!("a sysctl {key:?} that tune does not set"));
                    }
                    if !sysctl_value(before) || !sysctl_value(after) {
                        return Err(format!("a value of {key} that is not a sysctl value"));
                    }
                }
                Change::Module { name, .. } => {
                    if name != "tcp_bbr" {
                        return Err(format!("a module {name:?} that tune does not load"));
                    }
                }
                Change::Commands {
                    fix,
                    run,
                    undo,
                    files,
                    reload,
                } => {
                    let all = run.iter().chain(undo).chain(reload);
                    let tool = run.first().and_then(|r| r.first()).map(String::as_str);
                    let ok = match (fix.as_str(), tool) {
                        ("firewall", Some("ufw")) => {
                            all.clone().all(|c| ufw_command(c))
                                && files.iter().map(|f| f.path.as_str()).eq(UFW_FILES)
                                && reload.as_deref() == Some(&argv(&["ufw", "reload"])[..])
                        }
                        ("firewall", Some("firewall-cmd")) => {
                            let zone = run[0].get(2).and_then(|z| z.strip_prefix("--zone=")).unwrap_or("");
                            valid_zone(zone)
                                && all.clone().all(|c| firewalld_command(c, zone))
                                && files.iter().map(|f| f.path.clone()).eq(firewalld_files(zone))
                                && reload.as_deref() == Some(&argv(&["firewall-cmd", "--reload"])[..])
                        }
                        ("linger", Some("loginctl")) => {
                            let user = run[0].get(2).map(String::as_str).unwrap_or("");
                            valid_user(user)
                                && run.as_slice() == [argv(&["loginctl", "enable-linger", user])]
                                && undo.as_slice() == [argv(&["loginctl", "disable-linger", user])]
                                && files.is_empty()
                                && reload.is_none()
                        }
                        _ => false,
                    };
                    if !ok {
                        return Err(format!("{fix} commands that tune does not run"));
                    }
                    for f in files {
                        check_file_record(f)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn save(&mut self, sys: &dyn System) -> Result<(), String> {
        // Private: the record holds copies of firewall configuration files (/etc/ufw/user.rules
        // is 0640), so the directory is 0700 and the record 0600 (review M2)
        if self.created_dirs.is_empty() {
            self.created_dirs = make_dirs(sys, parent(RECORD), 0o700).map_err(|e| format!("{RECORD}: {e}"))?;
        } else {
            make_dirs(sys, parent(RECORD), 0o700).map_err(|e| format!("{RECORD}: {e}"))?;
        }
        let mut text = serde_json::to_string_pretty(&self.to_json()).map_err(|e| e.to_string())?;
        text.push('\n');
        sys.write(RECORD, text.as_bytes(), 0o600, None)
            .map_err(|e| format!("{RECORD}: {e}"))
    }

    /// Add a change, merging with an earlier one of the same file or sysctl: the earliest
    /// "before" is what a revert must restore.
    fn add(&mut self, change: Change) {
        match &change {
            Change::File {
                file,
                created_dirs,
                fixes,
            } => {
                for c in &mut self.changes {
                    if let Change::File {
                        file: old,
                        created_dirs: old_dirs,
                        fixes: old_fixes,
                    } = c
                    {
                        if old.path == file.path {
                            old.sha256 = file.sha256.clone();
                            old_dirs.extend(created_dirs.iter().cloned());
                            for f in fixes {
                                if !old_fixes.contains(f) {
                                    old_fixes.push(f.clone());
                                }
                            }
                            return;
                        }
                    }
                }
            }
            Change::Sysctl { key, after, .. } => {
                for c in &mut self.changes {
                    if let Change::Sysctl {
                        key: old_key,
                        after: old_after,
                        ..
                    } = c
                    {
                        if old_key == key {
                            *old_after = after.clone();
                            return;
                        }
                    }
                }
            }
            Change::Module { name, .. } => {
                if self
                    .changes
                    .iter()
                    .any(|c| matches!(c, Change::Module { name: n, .. } if n == name))
                {
                    return;
                }
            }
            Change::Commands { .. } => {}
        }
        self.changes.push(change);
    }
}

/// The fixes tune makes.
const FIXES: [&str; 6] = [
    "udp-buffers",
    "tcp-bbr",
    "bbr-default",
    "firewall",
    "low-ports",
    "linger",
];

/// The sysctls tune sets.
const SYSCTLS: [&str; 6] = [
    "net.core.rmem_max",
    "net.core.wmem_max",
    "net.ipv4.tcp_allowed_congestion_control",
    "net.core.default_qdisc",
    "net.ipv4.tcp_congestion_control",
    "net.ipv4.ip_unprivileged_port_start",
];

/// The files ufw's commands change.
const UFW_FILES: [&str; 2] = ["/etc/ufw/user.rules", "/etc/ufw/user6.rules"];

/// The files firewalld's commands change for `zone`.
fn firewalld_files(zone: &str) -> [String; 2] {
    [
        format!("/etc/firewalld/zones/{zone}.xml"),
        format!("/etc/firewalld/zones/{zone}.xml.old"),
    ]
}

/// True when `dir` is a directory above `path` (not `/`).
fn is_ancestor(dir: &str, path: &str) -> bool {
    dir != "/"
        && path.len() > dir.len()
        && path.starts_with(dir)
        && path.as_bytes()[dir.len()] == b'/'
        && !dir.ends_with('/')
}

/// A value tune reads from or writes to a sysctl: numbers or names, separated by spaces.
fn sysctl_value(v: &str) -> bool {
    v.len() <= 256
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b' ' || b == b'-')
}

/// A firewalld zone name as tune uses it.
fn valid_zone(z: &str) -> bool {
    !z.is_empty()
        && z.len() <= 64
        && !z.starts_with(['-', '.'])
        && z.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A login name as loginctl gets it from tune (SUDO_USER).
fn valid_user(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 64
        && !u.starts_with('-')
        && u.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-$".contains(&b))
}

/// A port or port range of ufw, with or without a protocol (`60443`, `60443:60542/udp`), or
/// the application profile `qsh`.
fn ufw_rule(r: &str) -> bool {
    if r == "qsh" {
        return true;
    }
    let (ports, proto) = match r.split_once('/') {
        Some((p, proto)) => (p, Some(proto)),
        None => (r, None),
    };
    let number = |p: &str| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit());
    let ports_ok = match ports.split_once(':') {
        Some((a, b)) => number(a) && number(b),
        None => number(ports),
    };
    ports_ok && matches!(proto, None | Some("udp") | Some("tcp"))
}

/// `ufw allow RULE comment qsh`, `ufw delete allow RULE` or `ufw reload`.
fn ufw_command(c: &[String]) -> bool {
    let c: Vec<&str> = c.iter().map(String::as_str).collect();
    match c.as_slice() {
        ["ufw", "allow", rule, "comment", "qsh"] => ufw_rule(rule),
        ["ufw", "delete", "allow", rule] => ufw_rule(rule),
        ["ufw", "reload"] => true,
        _ => false,
    }
}

/// `firewall-cmd --permanent --zone=ZONE (--add-…|--remove-…)…` or `firewall-cmd --reload`.
fn firewalld_command(c: &[String], zone: &str) -> bool {
    let c: Vec<&str> = c.iter().map(String::as_str).collect();
    match c.as_slice() {
        ["firewall-cmd", "--reload"] => true,
        ["firewall-cmd", "--permanent", z, args @ ..] if *z == format!("--zone={zone}") && !args.is_empty() => {
            args.iter().all(|a| {
                let Some(rest) = a.strip_prefix("--add-").or_else(|| a.strip_prefix("--remove-")) else {
                    return false;
                };
                rest == "service=qsh"
                    || rest.strip_prefix("port=").is_some_and(|p| {
                        let (ports, proto) = p.split_once('/').unwrap_or((p, ""));
                        let number = |p: &str| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit());
                        let ports_ok = match ports.split_once('-') {
                            Some((a, b)) => number(a) && number(b),
                            None => number(ports),
                        };
                        ports_ok && (proto == "udp" || proto == "tcp")
                    })
            })
        }
        _ => false,
    }
}

/// A recorded file's mode and owner are plain.
fn check_file_record(f: &FileRecord) -> Result<(), String> {
    if f.mode.is_some_and(|m| m & !0o777 != 0) {
        return Err(format!("a mode of {} that tune does not restore", f.path));
    }
    Ok(())
}

fn strings(v: &Value) -> Option<Vec<String>> {
    v.as_array()?.iter().map(|x| x.as_str().map(String::from)).collect()
}

fn argvs(v: &Value) -> Option<Vec<Vec<String>>> {
    v.as_array()?.iter().map(strings).collect()
}

fn opt_string(v: &Value) -> Option<Option<String>> {
    match v {
        Value::Null => Some(None),
        Value::String(s) => Some(Some(s.clone())),
        _ => None,
    }
}

impl FileRecord {
    fn to_json(&self) -> Value {
        json!({
            "path": self.path,
            "before": self.before,
            "mode": self.mode,
            "uid": self.owner.map(|o| o.0),
            "gid": self.owner.map(|o| o.1),
            "sha256": self.sha256,
        })
    }

    fn from_json(v: &Value) -> Option<FileRecord> {
        let number = |k: &str| -> Option<Option<u32>> {
            match &v[k] {
                Value::Null => Some(None),
                n => Some(Some(u32::try_from(n.as_u64()?).ok()?)),
            }
        };
        let owner = match (number("uid")?, number("gid")?) {
            (Some(u), Some(g)) => Some((u, g)),
            (None, None) => None,
            _ => return None,
        };
        Some(FileRecord {
            path: v["path"].as_str()?.to_string(),
            before: opt_string(&v["before"])?,
            mode: number("mode")?,
            owner,
            sha256: opt_string(&v["sha256"])?,
        })
    }
}

impl Change {
    fn to_json(&self) -> Value {
        match self {
            Change::File {
                fixes,
                file,
                created_dirs,
            } => {
                let mut v = file.to_json();
                v["kind"] = json!("file");
                v["fixes"] = json!(fixes);
                v["created_dirs"] = json!(created_dirs);
                v
            }
            Change::Sysctl {
                fix,
                key,
                before,
                after,
            } => {
                json!({ "kind": "sysctl", "fix": fix, "key": key, "before": before, "after": after })
            }
            Change::Module { fix, name } => json!({ "kind": "module", "fix": fix, "name": name }),
            Change::Commands {
                fix,
                run,
                undo,
                files,
                reload,
            } => json!({
                "kind": "commands",
                "fix": fix,
                "run": run,
                "undo": undo,
                "files": files.iter().map(FileRecord::to_json).collect::<Vec<_>>(),
                "reload": reload,
            }),
        }
    }

    fn from_json(v: &Value) -> Option<Change> {
        let s = |k: &str| v[k].as_str().map(String::from);
        Some(match v["kind"].as_str()? {
            "file" => Change::File {
                fixes: strings(&v["fixes"])?,
                file: FileRecord::from_json(v)?,
                created_dirs: strings(&v["created_dirs"]).unwrap_or_default(),
            },
            "sysctl" => Change::Sysctl {
                fix: s("fix")?,
                key: s("key")?,
                before: s("before")?,
                after: s("after")?,
            },
            "module" => Change::Module {
                fix: s("fix")?,
                name: s("name")?,
            },
            "commands" => Change::Commands {
                fix: s("fix")?,
                run: argvs(&v["run"])?,
                undo: argvs(&v["undo"])?,
                files: v["files"]
                    .as_array()?
                    .iter()
                    .map(FileRecord::from_json)
                    .collect::<Option<_>>()?,
                reload: match &v["reload"] {
                    Value::Null => None,
                    r => Some(strings(r)?),
                },
            },
            _ => return None,
        })
    }
}

impl Record {
    /// The JSON form of `/var/lib/qsh/tune.json`.
    pub fn to_json(&self) -> Value {
        json!({
            "qsh_tune": self.qsh_tune,
            "version": self.version,
            "created_dirs": self.created_dirs,
            "changes": self.changes.iter().map(Change::to_json).collect::<Vec<_>>(),
        })
    }

    /// Read the JSON form; None when it is not a record.
    pub fn from_json(v: &Value) -> Option<Record> {
        Some(Record {
            qsh_tune: v["qsh_tune"].as_u64()?,
            version: v["version"].as_str().unwrap_or("").to_string(),
            created_dirs: strings(&v["created_dirs"]).unwrap_or_default(),
            changes: v["changes"]
                .as_array()?
                .iter()
                .map(Change::from_json)
                .collect::<Option<_>>()?,
        })
    }
}

fn parent(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(i) => &path[..i],
    }
}

/// Create `dir` and its missing parents (`mode` for `dir`, 0755 above it); the ones
/// created, outermost first.
fn make_dirs(sys: &dyn System, dir: &str, mode: u32) -> std::io::Result<Vec<String>> {
    let mut missing = Vec::new();
    let mut d = dir;
    while d != "/" && !sys.exists(d) {
        missing.push(d.to_string());
        d = parent(d);
    }
    missing.reverse();
    for m in &missing {
        sys.mkdir(m, if m == dir { mode } else { 0o755 })?;
    }
    Ok(missing)
}

fn sha256_hex(text: &str) -> String {
    qsh_core::crypto::hex(&qsh_core::crypto::sha256(text.as_bytes()))
}

fn snapshot(sys: &dyn System, path: &str) -> FileRecord {
    let before = sys.read(path);
    let meta = before.as_ref().and_then(|_| sys.meta(path));
    FileRecord {
        path: path.into(),
        sha256: before.as_deref().map(sha256_hex),
        mode: meta.map(|m| m.mode & 0o777),
        owner: meta.map(|m| (m.uid, m.gid)),
        before,
    }
}

fn run_argv(sys: &dyn System, words: &[String]) -> Result<(), String> {
    let (program, args) = words.split_first().ok_or("an empty command")?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match sys.run(program, &args) {
        Some(o) if o.ok() => Ok(()),
        Some(o) => Err(format!(
            "{} failed (status {}): {}",
            shell_join(words),
            o.status,
            o.stderr.trim()
        )),
        None => Err(format!("{program} cannot be run")),
    }
}

/// Carry out `plan`, recording each change as it is made. On the first failure it stops,
/// saves what it did (so that `--revert` can undo it) and returns the error.
pub fn apply(sys: &dyn System, plan: &Plan, log: &mut dyn FnMut(String)) -> Result<(), String> {
    let mut record = match Record::load(sys)? {
        Some(r) => r,
        None => Record {
            qsh_tune: super::SCHEMA,
            version: qsh_core::server::version().into(),
            ..Record::default()
        },
    };
    let result = apply_steps(sys, plan, &mut record, log);
    if !record.changes.is_empty() {
        record.version = qsh_core::server::version().into();
        record.save(sys)?;
    }
    result
}

fn apply_steps(sys: &dyn System, plan: &Plan, record: &mut Record, log: &mut dyn FnMut(String)) -> Result<(), String> {
    for step in &plan.steps {
        match step {
            Step::File {
                fixes,
                path,
                before,
                after,
            } => {
                let was = snapshot(sys, path);
                if was.before != *before {
                    return Err(format!("{path} changed while tune was running; nothing written"));
                }
                let created = make_dirs(sys, parent(path), 0o755).map_err(|e| format!("{path}: {e}"))?;
                // An existing file keeps its mode and owner
                sys.write(path, after.as_bytes(), was.mode.unwrap_or(0o644), was.owner)
                    .map_err(|e| format!("{path}: {e}"))?;
                record.add(Change::File {
                    fixes: fixes.iter().map(|f| f.to_string()).collect(),
                    file: FileRecord {
                        sha256: Some(sha256_hex(after)),
                        ..was
                    },
                    created_dirs: created,
                });
                log(format!("wrote {path}"));
            }
            Step::Sysctl {
                fix,
                key,
                before,
                after,
            } => {
                sys.set(&checks::sysctl_path(key), &format!("{after}\n"))
                    .map_err(|e| format!("sysctl {key}: {e}"))?;
                record.add(Change::Sysctl {
                    fix: fix.to_string(),
                    key: key.clone(),
                    before: before.clone(),
                    after: after.clone(),
                });
                log(format!("set {key} = {after} (was {before})"));
            }
            Step::Module { fix, name } => {
                run_argv(sys, &argv(&["modprobe", name]))?;
                record.add(Change::Module {
                    fix: fix.to_string(),
                    name: name.clone(),
                });
                log(format!("loaded {name}"));
            }
            Step::Commands {
                fix,
                run,
                undo,
                files,
                reload,
            } => {
                let before: Vec<FileRecord> = files.iter().map(|f| snapshot(sys, f)).collect();
                let mut done = 0;
                let mut error = None;
                for r in run {
                    match run_argv(sys, r) {
                        Ok(()) => done += 1,
                        Err(e) => {
                            error = Some(e);
                            break;
                        }
                    }
                }
                if done > 0 {
                    let files = before
                        .into_iter()
                        .map(|f| FileRecord {
                            sha256: sys.read(&f.path).as_deref().map(sha256_hex),
                            ..f
                        })
                        .collect();
                    record.add(Change::Commands {
                        fix: fix.to_string(),
                        run: run[..done].to_vec(),
                        undo: undo.clone(),
                        files,
                        reload: reload.clone(),
                    });
                    for r in &run[..done] {
                        log(format!("ran {}", shell_join(r)));
                    }
                }
                if let Some(e) = error {
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

/// What `--revert` would undo, for people.
pub fn render_record(record: &Record) -> String {
    let mut out = String::new();
    for change in record.changes.iter().rev() {
        let _ = match change {
            Change::File { file, .. } => match &file.before {
                Some(_) => writeln!(out, "restore {}", file.path),
                None => writeln!(out, "remove {}", file.path),
            },
            Change::Sysctl { key, before, .. } => writeln!(out, "sysctl -w {key}='{before}'"),
            Change::Module { name, .. } => writeln!(out, "modprobe -r {name} (if unused)"),
            Change::Commands { undo, files, .. } => {
                if files.is_empty() {
                    undo.iter().try_for_each(|u| writeln!(out, "{}", shell_join(u)))
                } else {
                    let names: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
                    writeln!(
                        out,
                        "restore {} (or: {})",
                        names.join(", "),
                        undo.iter().map(|u| shell_join(u)).collect::<Vec<_>>().join(" && ")
                    )
                }
            }
        };
    }
    out
}

/// Put `file` back as it was before; false when it changed since tune left it.
fn restore(sys: &dyn System, file: &FileRecord) -> Result<bool, String> {
    let now = sys.read(&file.path);
    if now.as_deref().map(sha256_hex) != file.sha256 {
        return Ok(false);
    }
    // With its mode and owner: the record is only read when root or this user wrote it, and
    // only with plain modes (Record::validate)
    match &file.before {
        Some(content) => sys.write(&file.path, content.as_bytes(), file.mode.unwrap_or(0o644), file.owner),
        None if now.is_some() => sys.remove(&file.path),
        None => Ok(()),
    }
    .map_err(|e| format!("{}: {e}", file.path))?;
    Ok(true)
}

fn remove_dirs(sys: &dyn System, dirs: &[String]) {
    // Innermost first; a directory someone put files into stays
    for d in dirs.iter().rev() {
        let _ = sys.rmdir(d);
    }
}

/// Undo what the record lists, newest first, only where the host is still as tune left it;
/// then delete the record. Returns warnings about what was left alone.
pub fn revert(sys: &dyn System, record: &Record, log: &mut dyn FnMut(String)) -> Result<Vec<String>, String> {
    let mut warnings = Vec::new();
    for change in record.changes.iter().rev() {
        match change {
            Change::File { file, created_dirs, .. } => {
                if restore(sys, file)? {
                    remove_dirs(sys, created_dirs);
                    log(match file.before {
                        Some(_) => format!("restored {}", file.path),
                        None => format!("removed {}", file.path),
                    });
                } else {
                    warnings.push(format!("{} changed since tune wrote it: left alone", file.path));
                }
            }
            Change::Sysctl { key, before, after, .. } => {
                let now = checks::sysctl(sys, key).unwrap_or_default();
                if now == *after {
                    sys.set(&checks::sysctl_path(key), &format!("{before}\n"))
                        .map_err(|e| format!("sysctl {key}: {e}"))?;
                    log(format!("set {key} = {before}"));
                } else {
                    warnings.push(format!("{key} is {now} now, not what tune set ({after}): left alone"));
                }
            }
            Change::Module { name, .. } => {
                let in_use = checks::sysctl(sys, "net.ipv4.tcp_congestion_control").is_some_and(|c| c == "bbr");
                if in_use || run_argv(sys, &argv(&["modprobe", "-r", name])).is_err() {
                    log(format!("{name} stays loaded until the next boot (in use)"));
                } else {
                    log(format!("unloaded {name}"));
                }
            }
            Change::Commands {
                undo, files, reload, ..
            } => {
                let unchanged = !files.is_empty()
                    && files
                        .iter()
                        .all(|f| sys.read(&f.path).as_deref().map(sha256_hex) == f.sha256);
                if unchanged {
                    for f in files {
                        restore(sys, f)?;
                        log(format!("restored {}", f.path));
                    }
                    if let Some(r) = reload {
                        run_argv(sys, r)?;
                        log(format!("ran {}", shell_join(r)));
                    }
                } else {
                    if !files.is_empty() {
                        warnings.push(format!(
                            "{} changed since tune ran; undoing its rules with commands instead",
                            files.iter().map(|f| f.path.as_str()).collect::<Vec<_>>().join(", ")
                        ));
                    }
                    for u in undo {
                        match run_argv(sys, u) {
                            Ok(()) => log(format!("ran {}", shell_join(u))),
                            Err(e) => warnings.push(e),
                        }
                    }
                }
            }
        }
    }
    sys.remove(RECORD).map_err(|e| format!("{RECORD}: {e}"))?;
    remove_dirs(sys, &record.created_dirs);
    Ok(warnings)
}

// ---------------------------------------------------------------------------------------
// The command

/// What `qsh-server tune` was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// `--apply`.
    pub apply: bool,
    /// `--revert`.
    pub revert: bool,
    /// `--yes`: no confirmation (scripts).
    pub yes: bool,
    /// The plan's options.
    pub options: Options,
}

/// The trade-offs of the explicit flags (security.md 4.9), shown before the plan.
fn warnings(options: &Options) -> Vec<String> {
    let mut out = Vec::new();
    if options.bbr_default {
        out.push(
            "--bbr-default changes the congestion control of every TCP connection of this host (sshd's included)"
                .to_string(),
        );
    }
    if let Some(n) = options.low_ports {
        out.push(format!(
            "--allow-low-ports={n}: every local user can then bind ports {n}-1023, and take a service's port before it starts; appropriate on a single-user host only"
        ));
    }
    out
}

/// Run `qsh-server tune`. `ask` puts a yes/no question on the terminal (None: there is no
/// terminal); `needs_root` is true when changes would touch the real system without root.
/// Returns the exit status.
pub fn command(
    sys: &dyn System,
    host: &HostInfo,
    user: &User,
    request: &Request,
    needs_root: bool,
    ask: &mut dyn FnMut(&str) -> Option<bool>,
    out: &mut dyn std::io::Write,
) -> u8 {
    let mut say = |text: &str| {
        let _ = writeln!(out, "{text}");
    };
    if request.revert {
        let record = match Record::load(sys) {
            Ok(Some(r)) => r,
            Ok(None) => {
                say("qsh-server tune: nothing to revert (no record of earlier changes)");
                return 0;
            }
            Err(e) => {
                say(&format!("qsh-server tune: {e}"));
                return 1;
            }
        };
        say(&format!(
            "qsh-server tune --revert undoes what tune changed ({RECORD}):\n\n{}",
            render_record(&record)
        ));
        if needs_root {
            say("qsh-server tune: --revert needs root: sudo qsh-server tune --revert");
            return 1;
        }
        if !confirm(request, ask, "Revert these changes?", &mut say) {
            return 1;
        }
        let mut lines = Vec::new();
        let result = revert(sys, &record, &mut |l| lines.push(l));
        for l in lines {
            say(&format!("  {l}"));
        }
        return match result {
            Ok(warnings) => {
                for w in &warnings {
                    say(&format!("qsh-server tune: {w}"));
                }
                say(if warnings.is_empty() {
                    "Reverted."
                } else {
                    "Reverted, except what was changed by someone else since."
                });
                0
            }
            Err(e) => {
                say(&format!("qsh-server tune: {e}"));
                1
            }
        };
    }
    for w in warnings(&request.options) {
        say(&format!("qsh-server tune: warning: {w}"));
    }
    let plan = plan(sys, host, user, &request.options);
    if plan.steps.is_empty() {
        let text = render(&plan);
        if !text.is_empty() {
            say(text.trim_end());
        }
        say("qsh-server tune: nothing to change.");
        return 0;
    }
    say(&format!(
        "qsh-server tune: what --apply changes\n\n{}",
        render(&plan).trim_end()
    ));
    say("");
    if !request.apply {
        let sudo = if needs_root { "sudo " } else { "" };
        say(&format!(
            "Nothing changed. {sudo}qsh-server tune --apply makes these changes; tune --revert undoes them."
        ));
        return 0;
    }
    if needs_root {
        say("qsh-server tune: --apply needs root: sudo qsh-server tune --apply");
        return 1;
    }
    if !confirm(request, ask, "Apply these changes?", &mut say) {
        return 1;
    }
    let mut lines = Vec::new();
    let result = apply(sys, &plan, &mut |l| lines.push(l));
    for l in lines {
        say(&format!("  {l}"));
    }
    match result {
        Ok(()) => {
            say(&format!(
                "Done; recorded in {RECORD}. qsh-server tune --revert undoes it."
            ));
            0
        }
        Err(e) => {
            say(&format!(
                "qsh-server tune: {e}\nWhat was done before that is recorded in {RECORD}; qsh-server tune --revert undoes it."
            ));
            1
        }
    }
}

fn confirm(
    request: &Request,
    ask: &mut dyn FnMut(&str) -> Option<bool>,
    question: &str,
    say: &mut dyn FnMut(&str),
) -> bool {
    if request.yes {
        return true;
    }
    match ask(&format!("{question} [y/N] ")) {
        Some(true) => true,
        Some(false) => {
            say("Nothing changed.");
            false
        }
        None => {
            say("qsh-server tune: no terminal to confirm on; nothing changed (--yes confirms in scripts)");
            false
        }
    }
}
