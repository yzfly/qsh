//! `qsh-server doctor`, `qsh-server tune` and `qsh doctor` (m2.md section 8): find every
//! host-side problem that makes qsh slower or stops a transport, say exactly how to fix it on
//! *this* distribution, and, as root and only when asked, fix it after showing a diff.
//!
//! The parts are kept apart so that each can be tested on its own:
//!
//! - [`system`]: everything doctor and tune read or change goes through the [`System`] trait
//!   (files under a root, commands, the environment, a few system calls). The real one reads
//!   the host, or a directory standing in for `/` (`--root`); tests use fixture trees.
//! - [`distro`]: `/etc/os-release`, the distribution family and its idioms (packages,
//!   firewall persistence, limits).
//! - [`firewall`]: ufw, firewalld, nftables and iptables: which is active, whether it lets
//!   the daemon's ports in, the exact command that opens them.
//! - [`checks`]: the checks of m2.md 8.2, each a pure function of what the system shows.
//! - [`report`]: the human output (one line per check, the fix under each problem) and the
//!   JSON (`"doctor":1`, stable check ids).
//! - [`tune`]: the plan, the diff, applying it, the record and the revert.
//! - [`client`]: `qsh doctor [HOST]`: the client's own checks, the server's report over ssh,
//!   probes of every transport and port, and a diagnosis combining both sides.
//!
//! Doctor makes no network calls (except the probes of `qsh doctor HOST`, which speak qsh's
//! own protocol to the host the user asked about) and changes nothing.

use serde_json::{Map, Value};

pub mod checks;
pub mod client;
mod diff;
pub mod distro;
pub mod firewall;
pub mod report;
pub mod system;
pub mod tune;

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests;

pub use system::System;

/// The version of the JSON reports (`"doctor":1`) and of the tune record.
pub const SCHEMA: u64 = 1;

/// How a check came out (m2.md 8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Status {
    /// Fine.
    Ok,
    /// Nothing to do, worth knowing.
    Info,
    /// Not applicable, or not determinable without root (the summary says which).
    Skip,
    /// Works, but slower or fragile.
    Warn,
    /// A transport or a feature cannot work; qsh still works through the others.
    Fail,
}

impl Status {
    /// The name in reports: `ok`, `info`, `skip`, `warn`, `fail`.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Info => "info",
            Status::Skip => "skip",
            Status::Warn => "warn",
            Status::Fail => "fail",
        }
    }
}

/// What to do about a check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fix {
    /// The commands need root.
    pub root: bool,
    /// The fix `qsh-server tune` applies (`udp-buffers`, `tcp-bbr`, `firewall`, `linger`,
    /// `low-ports`, `bbr-default`), if it can.
    pub tune: Option<&'static str>,
    /// The flags `tune --apply` needs for it (`--allow-low-ports=443`).
    pub tune_flags: Vec<String>,
    /// The exact commands, for this distribution.
    pub commands: Vec<String>,
    /// One more sentence, when commands are not all (persistence, a trade-off).
    pub note: Option<String>,
}

impl Fix {
    /// A fix made of `commands`.
    pub fn commands(root: bool, commands: impl IntoIterator<Item = String>) -> Fix {
        Fix {
            root,
            commands: commands.into_iter().collect(),
            ..Fix::default()
        }
    }

    /// The same fix, which `qsh-server tune` can apply as `id`.
    pub fn by_tune(mut self, id: &'static str) -> Fix {
        self.tune = Some(id);
        self
    }

    /// The same fix with `note`.
    pub fn with_note(mut self, note: impl Into<String>) -> Fix {
        self.note = Some(note.into());
        self
    }

    /// The JSON form (m2.md 8.1).
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("root".into(), Value::Bool(self.root));
        if let Some(t) = self.tune {
            out.insert("tune".into(), Value::String(t.into()));
            if !self.tune_flags.is_empty() {
                out.insert("tune_flags".into(), self.tune_flags.clone().into());
            }
        }
        out.insert("commands".into(), self.commands.clone().into());
        if let Some(note) = &self.note {
            out.insert("note".into(), Value::String(note.clone()));
        }
        Value::Object(out)
    }
}

/// The result of one check.
#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    /// The stable id (m2.md 8.2): `daemon`, `ports`, `firewall`, …
    pub id: &'static str,
    /// How it came out.
    pub status: Status,
    /// One line for people.
    pub summary: String,
    /// What was found, for scripts (stable member names per check).
    pub facts: Map<String, Value>,
    /// What to do, when there is something to do.
    pub fix: Option<Fix>,
}

impl Check {
    /// A check result without facts or fix.
    pub fn new(id: &'static str, status: Status, summary: impl Into<String>) -> Check {
        Check {
            id,
            status,
            summary: summary.into(),
            facts: Map::new(),
            fix: None,
        }
    }

    /// Add a fact.
    pub fn fact(mut self, name: &str, value: impl Into<Value>) -> Check {
        self.facts.insert(name.into(), value.into());
        self
    }

    /// Set the fix.
    pub fn fix(mut self, fix: Fix) -> Check {
        self.fix = Some(fix);
        self
    }

    /// The JSON form (m2.md 8.1).
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("id".into(), Value::String(self.id.into()));
        out.insert("status".into(), Value::String(self.status.as_str().into()));
        out.insert("summary".into(), Value::String(self.summary.clone()));
        out.insert("facts".into(), Value::Object(self.facts.clone()));
        if let Some(fix) = &self.fix {
            out.insert("fix".into(), fix.to_json());
        }
        Value::Object(out)
    }
}

/// Exit status of doctor (m2.md 8.1): 0 when no check failed, 1 when one did.
pub fn exit_status(checks: &[Check]) -> u8 {
    u8::from(checks.iter().any(|c| c.status == Status::Fail))
}
