//! The configuration files, qsh_config(5) (docs/DESIGN.md section 6).
//!
//! qsh needs no configuration; these files only change defaults. Two files are read, the
//! user's first: `$XDG_CONFIG_HOME/qsh/config` (`~/.config/qsh/config`), then
//! `/etc/qsh/qsh_config`. Both are TOML:
//!
//! ```toml
//! [host."*.example.com,!build*"]
//! transports = ["quic", "ssh"]
//!
//! [defaults]
//! escape_char = "^]"
//!
//! [server]
//! ports = "61000-61099"
//! ```
//!
//! # Precedence
//!
//! For each setting the first value found wins, as in ssh_config(5): the user's file before
//! the system's, and in each file the matching `[host."pattern"]` tables in the order they
//! appear, then `[defaults]`. Over all of that, environment variables
//! ([`HostSettings::apply_env`], [`ServerSettings::apply_env`]), and over those the command
//! line:
//!
//! ```text
//! command line > environment > user file > system file > built-in default
//! ```
//!
//! # Compatibility and errors
//!
//! A key this version does not know is a [`Warning`] naming the key, file and line, so that a
//! configuration written for a newer qsh still works with an older one (as does an unknown
//! transport name in `transports`). A syntax error, a value of the wrong type or out of range,
//! a file that is not a regular file, larger than [`MAX_FILE_SIZE`], owned by another user
//! (other than root), or writable by group or others is a [`ConfigError`]: like ssh, qsh does
//! not run with settings it cannot trust or understand. A file that does not exist is simply
//! skipped; one that cannot be read for lack of permission is skipped with a warning.
//!
//! # Use
//!
//! ```no_run
//! use qsh_core::config::{Config, ConfigPaths};
//! use qsh_core::Paths;
//!
//! # fn main() -> Result<(), qsh_core::config::ConfigError> {
//! let (config, warnings) = Config::load(&ConfigPaths::standard(&Paths::from_env()))?;
//! for w in &warnings {
//!     eprintln!("qsh: {w}");
//! }
//! // The client: the destination as typed, and the HostName that `ssh -G` resolved
//! let mut host = config.for_host("me@web1", Some("web1.example.com"));
//! for w in host.apply_process_env() {
//!     eprintln!("qsh: {w}");
//! }
//! // … then the command line's own options override `host`
//! let race = host.race();
//! # let _ = race;
//!
//! // qsh-server
//! let mut server = config.server();
//! server.apply_process_env();
//! # Ok(())
//! # }
//! ```

use std::ffi::OsString;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::ops::{Range, RangeInclusive};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use toml::de::{DeString, DeTable, DeValue};
use toml::Spanned;

use crate::paths::Paths;
use crate::proto::bootstrap::MAX_EXTRA_PORTS;
use crate::server::ServerConfig;
use crate::transport::{RaceConfig, Transport};

mod pattern;
#[cfg(test)]
mod tests;

pub use pattern::{destination_host, PatternList};

/// The system-wide configuration file.
pub const SYSTEM_CONFIG: &str = "/etc/qsh/qsh_config";

/// The name of the user's configuration file in the configuration directory
/// ([`Paths::config`]).
pub const USER_CONFIG: &str = "config";

/// Configuration files larger than this are refused.
pub const MAX_FILE_SIZE: u64 = 1 << 20;

/// The delay between the starts of consecutive transports in the race (see
/// [`HostSettings::race`]).
const STAGGER: Duration = Duration::from_millis(400);

/// Which files to read. A None is not read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigPaths {
    /// The user's file, read first: its values win.
    pub user: Option<PathBuf>,
    /// The system's file.
    pub system: Option<PathBuf>,
}

impl ConfigPaths {
    /// The standard files: `config` in the user's configuration directory, and
    /// [`SYSTEM_CONFIG`].
    pub fn standard(paths: &Paths) -> ConfigPaths {
        ConfigPaths {
            user: Some(paths.config.join(USER_CONFIG)),
            system: Some(PathBuf::from(SYSTEM_CONFIG)),
        }
    }
}

/// Something in a configuration file that was ignored, with where it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    /// The file.
    pub file: PathBuf,
    /// The line, counting from 1, when the warning is about one.
    pub line: Option<usize>,
    /// What was ignored, and why.
    pub message: String,
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        location(f, &self.file, self.line)?;
        f.write_str(&self.message)
    }
}

/// Why the configuration cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// The file.
    pub file: PathBuf,
    /// The line, counting from 1, when the error is on one.
    pub line: Option<usize>,
    /// What is wrong, and how to fix it when that is not obvious.
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        location(f, &self.file, self.line)?;
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConfigError {}

fn location(f: &mut fmt::Formatter<'_>, file: &Path, line: Option<usize>) -> fmt::Result {
    match line {
        Some(line) => write!(f, "{}:{line}: ", file.display()),
        None => write!(f, "{}: ", file.display()),
    }
}

/// `predict`: predictive local echo (reserved for M3; this version never predicts).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Predict {
    /// When the path is slow and the program is not full-screen.
    #[default]
    Auto,
    /// Whenever possible.
    Always,
    /// Never.
    Never,
}

/// `keepalive`: how often to send something on an idle connection, so NATs keep its mapping.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Keepalive {
    /// qsh's own interval, learned per network (M2).
    #[default]
    Auto,
    /// This interval.
    Every(Duration),
}

/// `catchup`: smart catch-up, SNAPSHOT instead of a backlog the path cannot carry in about
/// two seconds (m2.md section 6).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Catchup {
    /// Accept snapshots on tty sessions whose output goes to a terminal.
    #[default]
    Auto,
    /// Never: every byte, however long it takes (0.2 behaviour).
    Off,
}

/// `compression` (client): offer the `zstd` capability (m2.md section 7).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Compression {
    /// Offer it; the server compresses when the path is slow and the output compressible.
    #[default]
    Auto,
    /// Do not offer it.
    Off,
}

/// `upgrade` (server): when the daemon replaces itself with a newer qsh-server in place,
/// keeping its sessions (m2.md section 10).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Upgrade {
    /// When a newer `qsh-server` asks, and by itself when idle.
    #[default]
    Auto,
    /// Only on `qsh-server upgrade`.
    Manual,
}

/// `install`: what to do when the host has no qsh-server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Install {
    /// On a terminal, ask once whether to install it.
    #[default]
    Ask,
    /// Never offer; fail with exit status 42.
    Never,
}

/// The client's settings for one host, every one resolved ([`Config::for_host`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSettings {
    /// The transports to race, in order of preference (`transports`).
    pub transports: Vec<Transport>,
    /// The path of qsh-server on the host; None: search `PATH` and `~/.local/bin`
    /// (`server_command`).
    pub server_command: Option<String>,
    /// The escape character; None: escapes are off (`escape_char`).
    pub escape_char: Option<u8>,
    /// Predictive echo (`predict`, reserved).
    pub predict: Predict,
    /// Show a status line while the connection is lost (`status_line`).
    pub status_line: bool,
    /// The ssh program (`ssh`).
    pub ssh: OsString,
    /// Options for ssh, given after the command line's own (`ssh_options`).
    pub ssh_options: Vec<String>,
    /// The keepalive interval (`keepalive`).
    pub keepalive: Keepalive,
    /// Offer to install qsh-server when the host has none (`install`).
    pub install: Install,
    /// On attaching to a session from a new client, replay the output it kept
    /// (`replay_on_attach`).
    pub replay_on_attach: bool,
    /// Remember per network which transport and port worked (`path_memory`, m2.md section 3).
    pub path_memory: bool,
    /// Smart catch-up (`catchup`, m2.md section 6; reserved, not used by this version).
    pub catchup: Catchup,
    /// Compression (`compression`, m2.md section 7; reserved, not used by this version).
    pub compression: Compression,
}

impl Default for HostSettings {
    fn default() -> Self {
        HostSettings {
            transports: vec![Transport::Quic, Transport::Tls, Transport::Ssh],
            server_command: None,
            escape_char: Some(b'~'),
            predict: Predict::Auto,
            status_line: true,
            ssh: OsString::from("ssh"),
            ssh_options: Vec::new(),
            keepalive: Keepalive::Auto,
            install: Install::Ask,
            replay_on_attach: true,
            path_memory: true,
            catchup: Catchup::Auto,
            compression: Compression::Auto,
        }
    }
}

impl HostSettings {
    /// When each transport starts in the race. The first listed starts at once; each next
    /// one 400 ms after the one before it, but never earlier than its own default (TLS
    /// 400 ms, ssh pipe 3 s: the pipe costs an ssh login, so it waits unless it is first).
    /// Transports not listed are not used.
    pub fn race(&self) -> RaceConfig {
        let default = RaceConfig::default();
        let mut race = RaceConfig {
            quic: None,
            tls: None,
            ssh: None,
        };
        let mut previous: Option<Duration> = None;
        for transport in &self.transports {
            let (slot, own) = match transport {
                Transport::Quic => (&mut race.quic, default.quic),
                Transport::Tls => (&mut race.tls, default.tls),
                Transport::Ssh => (&mut race.ssh, default.ssh),
            };
            if slot.is_some() {
                continue;
            }
            let start = match previous {
                None => Duration::ZERO,
                Some(p) => own.unwrap_or_default().max(p + STAGGER),
            };
            *slot = Some(start);
            previous = Some(start);
        }
        race
    }

    /// Apply the environment variables over the files: `QSH_TRANSPORTS` (comma-separated
    /// transports) and `QSH_SSH` (the ssh program). `var` looks a variable up. Returns
    /// warnings about values that were ignored.
    pub fn apply_env(&mut self, var: impl Fn(&str) -> Option<OsString>) -> Vec<String> {
        let mut warnings = Vec::new();
        if let Some(value) = var("QSH_TRANSPORTS") {
            let value = value.to_string_lossy();
            let mut transports = Vec::new();
            for name in value.split(',').map(str::trim).filter(|n| !n.is_empty()) {
                match transport_named(name) {
                    Some(t) if !transports.contains(&t) => transports.push(t),
                    Some(_) => {}
                    None => warnings.push(format!(
                        "QSH_TRANSPORTS: unknown transport {name:?} (known: quic, tls, ssh)"
                    )),
                }
            }
            if transports.is_empty() {
                warnings.push(format!("QSH_TRANSPORTS: no usable transport in {value:?}; ignored"));
            } else {
                self.transports = transports;
            }
        }
        if let Some(program) = var("QSH_SSH").filter(|p| !p.is_empty()) {
            self.ssh = program;
        }
        warnings
    }

    /// [`HostSettings::apply_env`] with the process's environment.
    pub fn apply_process_env(&mut self) -> Vec<String> {
        self.apply_env(|name| std::env::var_os(name))
    }
}

/// `[server]` settings for qsh-server ([`Config::server`]); None: the built-in default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerSettings {
    /// The daemon's port range: the first port free on both UDP and TCP (`ports`).
    pub ports: Option<RangeInclusive<u16>>,
    /// More ports to listen on, for networks that block the first (`extra_ports`, at most
    /// [`MAX_EXTRA_PORTS`], without duplicates; m2.md section 5).
    pub extra_ports: Option<Vec<u16>>,
    /// The most sessions one daemon keeps (`max_sessions`).
    pub max_sessions: Option<usize>,
    /// How long a session without a client is kept (`detached_ttl`).
    pub detached_ttl: Option<Duration>,
    /// How long a session whose program exited is kept (`exited_ttl`).
    pub exited_ttl: Option<Duration>,
    /// Output kept per session for clients that come back (`replay_bytes`).
    pub replay_bytes: Option<usize>,
    /// Limits on unauthenticated connections (`[server.preauth]`).
    pub preauth: PreauthSettings,
    /// Screen models and the `snapshot` capability (`snapshot`, m2.md section 6; not used by
    /// this version).
    pub snapshot: Option<bool>,
    /// Accept the `zstd` capability (`compression`, m2.md section 7; not used by this version).
    pub compression: Option<bool>,
    /// When the daemon upgrades itself in place (`upgrade`, m2.md section 10).
    pub upgrade: Option<Upgrade>,
}

/// `[server.preauth]`: limits on connections before authentication (protocol.md 6.6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreauthSettings {
    /// Unauthenticated connections per daemon (`connections`).
    pub connections: Option<usize>,
    /// The same per source address, IPv6 per /64 (`per_source`).
    pub per_source: Option<usize>,
    /// Failed authentications a source may cause in a burst (`failure_burst`).
    pub failure_burst: Option<u32>,
    /// One more allowed failure per this much time (`failure_refill`).
    pub failure_refill: Option<Duration>,
}

impl ServerSettings {
    /// Apply `QSH_SERVER_PORTS` (`FIRST-LAST`) over the files. Returns warnings about
    /// values that were ignored.
    pub fn apply_env(&mut self, var: impl Fn(&str) -> Option<OsString>) -> Vec<String> {
        let mut warnings = Vec::new();
        if let Some(value) = var("QSH_SERVER_PORTS") {
            let value = value.to_string_lossy();
            match parse_ports(&value) {
                Some(ports) => self.ports = Some(ports),
                None => warnings.push(format!(
                    "QSH_SERVER_PORTS: {value:?} is not a port range FIRST-LAST; ignored"
                )),
            }
        }
        warnings
    }

    /// [`ServerSettings::apply_env`] with the process's environment.
    pub fn apply_process_env(&mut self) -> Vec<String> {
        self.apply_env(|name| std::env::var_os(name))
    }

    /// Set the fields of `config` that these settings give.
    pub fn apply(&self, config: &mut ServerConfig) {
        if let Some(ports) = &self.extra_ports {
            config.extra_ports.clone_from(ports);
        }
        if let Some(on) = self.snapshot {
            config.snapshot = on;
        }
        if let Some(on) = self.compression {
            config.compression = on;
        }
        if let Some(upgrade) = self.upgrade {
            config.upgrade = upgrade;
        }
        if let Some(n) = self.max_sessions {
            config.max_sessions = n;
        }
        if let Some(ports) = &self.ports {
            config.ports = ports.clone();
        }
        if let Some(ttl) = self.detached_ttl {
            config.detached_ttl = ttl;
        }
        if let Some(ttl) = self.exited_ttl {
            config.exited_ttl = ttl;
        }
        if let Some(bytes) = self.replay_bytes {
            config.output_replay = bytes;
        }
        let p = &self.preauth;
        if let Some(n) = p.connections {
            config.preauth.total = n;
        }
        if let Some(n) = p.per_source {
            config.preauth.per_source = n;
        }
        if let Some(n) = p.failure_burst {
            config.preauth.failure_burst = n;
        }
        if let Some(d) = p.failure_refill {
            config.preauth.failure_refill = d;
        }
    }

    /// Fill what is unset here from `other` (a file of lower precedence).
    fn fill_from(&mut self, other: &ServerSettings) {
        fill(&mut self.ports, &other.ports);
        fill(&mut self.extra_ports, &other.extra_ports);
        fill(&mut self.max_sessions, &other.max_sessions);
        fill(&mut self.detached_ttl, &other.detached_ttl);
        fill(&mut self.exited_ttl, &other.exited_ttl);
        fill(&mut self.replay_bytes, &other.replay_bytes);
        fill(&mut self.preauth.connections, &other.preauth.connections);
        fill(&mut self.preauth.per_source, &other.preauth.per_source);
        fill(&mut self.preauth.failure_burst, &other.preauth.failure_burst);
        fill(&mut self.preauth.failure_refill, &other.preauth.failure_refill);
        fill(&mut self.snapshot, &other.snapshot);
        fill(&mut self.compression, &other.compression);
        fill(&mut self.upgrade, &other.upgrade);
    }
}

fn fill<T: Clone>(slot: &mut Option<T>, other: &Option<T>) {
    if slot.is_none() {
        slot.clone_from(other);
    }
}

/// The client settings of one table; None: not set there.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ClientLayer {
    transports: Option<Vec<Transport>>,
    server_command: Option<String>,
    escape_char: Option<Option<u8>>,
    predict: Option<Predict>,
    status_line: Option<bool>,
    ssh: Option<String>,
    ssh_options: Option<Vec<String>>,
    keepalive: Option<Keepalive>,
    install: Option<Install>,
    replay_on_attach: Option<bool>,
    path_memory: Option<bool>,
    catchup: Option<Catchup>,
    compression: Option<Compression>,
}

impl ClientLayer {
    fn fill_from(&mut self, other: &ClientLayer) {
        fill(&mut self.transports, &other.transports);
        fill(&mut self.server_command, &other.server_command);
        fill(&mut self.escape_char, &other.escape_char);
        fill(&mut self.predict, &other.predict);
        fill(&mut self.status_line, &other.status_line);
        fill(&mut self.ssh, &other.ssh);
        fill(&mut self.ssh_options, &other.ssh_options);
        fill(&mut self.keepalive, &other.keepalive);
        fill(&mut self.install, &other.install);
        fill(&mut self.replay_on_attach, &other.replay_on_attach);
        fill(&mut self.path_memory, &other.path_memory);
        fill(&mut self.catchup, &other.catchup);
        fill(&mut self.compression, &other.compression);
    }

    fn resolve(self) -> HostSettings {
        let d = HostSettings::default();
        HostSettings {
            transports: self.transports.unwrap_or(d.transports),
            server_command: self.server_command.or(d.server_command),
            escape_char: self.escape_char.unwrap_or(d.escape_char),
            predict: self.predict.unwrap_or(d.predict),
            status_line: self.status_line.unwrap_or(d.status_line),
            ssh: self.ssh.map(OsString::from).unwrap_or(d.ssh),
            ssh_options: self.ssh_options.unwrap_or(d.ssh_options),
            keepalive: self.keepalive.unwrap_or(d.keepalive),
            install: self.install.unwrap_or(d.install),
            replay_on_attach: self.replay_on_attach.unwrap_or(d.replay_on_attach),
            path_memory: self.path_memory.unwrap_or(d.path_memory),
            catchup: self.catchup.unwrap_or(d.catchup),
            compression: self.compression.unwrap_or(d.compression),
        }
    }
}

const CLIENT_KEYS: &[&str] = &[
    "transports",
    "server_command",
    "escape_char",
    "predict",
    "status_line",
    "ssh",
    "ssh_options",
    "keepalive",
    "install",
    "replay_on_attach",
    "path_memory",
    "catchup",
    "compression",
];

#[derive(Debug, Clone)]
struct HostBlock {
    patterns: PatternList,
    layer: ClientLayer,
}

#[derive(Debug, Clone)]
struct FileConfig {
    path: PathBuf,
    hosts: Vec<HostBlock>,
    defaults: ClientLayer,
    server: ServerSettings,
}

/// The configuration from qsh_config files: the user's and the system's, in that order.
#[derive(Debug, Clone, Default)]
pub struct Config {
    files: Vec<FileConfig>,
}

impl Config {
    /// Read the files of `paths` (the user's, then the system's), skipping those that do not
    /// exist. Warnings are about keys and values that were ignored; an error means the
    /// configuration cannot be used (see the module documentation).
    pub fn load(paths: &ConfigPaths) -> Result<(Config, Vec<Warning>), ConfigError> {
        let mut warnings = Vec::new();
        let mut files = Vec::new();
        for path in [paths.user.as_deref(), paths.system.as_deref()].into_iter().flatten() {
            if let Some(text) = read_file(path, &mut warnings)? {
                files.push(parse_file(&text, path, &mut warnings)?);
            }
        }
        Ok((Config { files }, warnings))
    }

    /// Parse the text of one configuration file, named `file` in messages, without reading
    /// or checking any file.
    pub fn parse(text: &str, file: &Path) -> Result<(Config, Vec<Warning>), ConfigError> {
        let mut warnings = Vec::new();
        let parsed = parse_file(text, file, &mut warnings)?;
        Ok((Config { files: vec![parsed] }, warnings))
    }

    /// The files that were read, in order of precedence.
    pub fn files(&self) -> impl Iterator<Item = &Path> {
        self.files.iter().map(|f| f.path.as_path())
    }

    /// The client's settings for `destination` (as typed: `host`, `user@host`,
    /// `ssh://user@host:port`) whose ssh configuration resolves to `hostname` (`ssh -G`'s
    /// `hostname`, when known). A `[host."pattern"]` table applies when its patterns match
    /// either name, and none of its negated patterns matches either.
    pub fn for_host(&self, destination: &str, hostname: Option<&str>) -> HostSettings {
        let host = destination_host(destination);
        let mut names = vec![host];
        if let Some(h) = hostname.filter(|h| !h.is_empty() && !h.eq_ignore_ascii_case(host)) {
            names.push(h);
        }
        let mut layer = ClientLayer::default();
        for file in &self.files {
            for block in file.hosts.iter().filter(|b| b.patterns.matches(&names)) {
                layer.fill_from(&block.layer);
            }
            layer.fill_from(&file.defaults);
        }
        layer.resolve()
    }

    /// The `[server]` settings, the user's file over the system's.
    pub fn server(&self) -> ServerSettings {
        let mut settings = ServerSettings::default();
        for file in &self.files {
            settings.fill_from(&file.server);
        }
        settings
    }
}

/// Read a configuration file: None when it does not exist (or cannot be read for lack of
/// permission, with a warning).
fn read_file(path: &Path, warnings: &mut Vec<Warning>) -> Result<Option<String>, ConfigError> {
    let error = |message: String| ConfigError {
        file: path.to_path_buf(),
        line: None,
        message,
    };
    // O_NONBLOCK: opening a FIFO put in the file's place must not hang
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            warnings.push(Warning {
                file: path.to_path_buf(),
                line: None,
                message: format!("cannot read it ({e}); ignored"),
            });
            return Ok(None);
        }
        Err(e) => return Err(error(format!("cannot open it: {e}"))),
    };
    let meta = file.metadata().map_err(|e| error(e.to_string()))?;
    if !meta.is_file() {
        return Err(error("not a regular file".into()));
    }
    check_owner_and_mode(path, meta.uid(), meta.mode(), crate::sys::euid()).map_err(error)?;
    let mut bytes = Vec::new();
    (&file)
        .take(MAX_FILE_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| error(format!("cannot read it: {e}")))?;
    if bytes.len() as u64 > MAX_FILE_SIZE {
        return Err(error(format!("larger than {} KiB", MAX_FILE_SIZE / 1024)));
    }
    String::from_utf8(bytes).map(Some).map_err(|e| {
        let valid = e.utf8_error().valid_up_to();
        ConfigError {
            file: path.to_path_buf(),
            line: Some(line_of(e.as_bytes(), valid)),
            message: "not valid UTF-8".into(),
        }
    })
}

/// Like ssh with its own files: the owner must be the user or root, and nobody else may
/// write to it, since the file names programs qsh runs (`ssh`, `ssh_options`).
fn check_owner_and_mode(path: &Path, owner: u32, mode: u32, euid: u32) -> Result<(), String> {
    if owner != 0 && owner != euid {
        return Err(format!(
            "bad owner: the file belongs to user id {owner}; it must belong to you or root"
        ));
    }
    if mode & 0o022 != 0 {
        return Err(format!(
            "bad permissions: writable by group or others (mode {:04o}); fix with: chmod go-w {}",
            mode & 0o7777,
            path.display()
        ));
    }
    Ok(())
}

fn line_of(text: &[u8], offset: usize) -> usize {
    text[..offset.min(text.len())].iter().filter(|&&b| b == b'\n').count() + 1
}

type Entry<'t, 'i> = (&'t Spanned<DeString<'i>>, &'t Spanned<DeValue<'i>>);

/// The entries of a table in the order they appear in the file.
fn entries<'t, 'i>(table: &'t DeTable<'i>) -> Vec<Entry<'t, 'i>> {
    let mut entries: Vec<_> = table.iter().collect();
    entries.sort_by_key(|(k, _)| k.span().start);
    entries
}

/// Parsing one file: its text and name, for messages.
struct Reader<'a> {
    file: &'a Path,
    text: &'a str,
    warnings: &'a mut Vec<Warning>,
}

fn parse_file(text: &str, file: &Path, warnings: &mut Vec<Warning>) -> Result<FileConfig, ConfigError> {
    let mut r = Reader { file, text, warnings };
    let root = DeTable::parse(text).map_err(|e| ConfigError {
        file: file.to_path_buf(),
        line: e.span().map(|s| line_of(text.as_bytes(), s.start)),
        message: e.message().trim().to_string(),
    })?;
    let mut parsed = FileConfig {
        path: file.to_path_buf(),
        hosts: Vec::new(),
        defaults: ClientLayer::default(),
        server: ServerSettings::default(),
    };
    for (key, value) in entries(root.get_ref()) {
        match key.get_ref().as_ref() {
            "defaults" => parsed.defaults = r.client(r.table(key, value)?)?,
            "host" => {
                for (pattern, block) in entries(r.table(key, value)?) {
                    let patterns = PatternList::parse(pattern.get_ref()).map_err(|e| r.error(pattern.span(), e))?;
                    let layer = r.client(r.table(pattern, block)?)?;
                    parsed.hosts.push(HostBlock { patterns, layer });
                }
            }
            "server" => parsed.server = r.server(r.table(key, value)?)?,
            name if CLIENT_KEYS.contains(&name) => r.warn(
                key.span(),
                format!("`{name}` outside a table, ignored: put it in [defaults] or a [host.\"pattern\"] table"),
            ),
            name => r.warn(key.span(), format!("unknown key `{name}`, ignored")),
        }
    }
    Ok(parsed)
}

impl Reader<'_> {
    fn line(&self, span: Range<usize>) -> usize {
        line_of(self.text.as_bytes(), span.start)
    }

    fn error(&self, span: Range<usize>, message: impl Into<String>) -> ConfigError {
        ConfigError {
            file: self.file.to_path_buf(),
            line: Some(self.line(span)),
            message: message.into(),
        }
    }

    fn warn(&mut self, span: Range<usize>, message: String) {
        let line = Some(self.line(span));
        self.warnings.push(Warning {
            file: self.file.to_path_buf(),
            line,
            message,
        });
    }

    fn table<'t, 'i>(
        &self,
        key: &Spanned<DeString<'_>>,
        value: &'t Spanned<DeValue<'i>>,
    ) -> Result<&'t DeTable<'i>, ConfigError> {
        value
            .get_ref()
            .as_table()
            .ok_or_else(|| self.error(value.span(), format!("`{}` must be a table", key.get_ref())))
    }

    fn client(&mut self, table: &DeTable<'_>) -> Result<ClientLayer, ConfigError> {
        let mut layer = ClientLayer::default();
        for (key, value) in entries(table) {
            let name = key.get_ref().as_ref();
            let v = value.get_ref();
            let span = value.span();
            match name {
                "transports" => layer.transports = Some(self.transports(value)?),
                "server_command" => {
                    let s = self.string(name, value)?;
                    if s.is_empty() || s.chars().any(char::is_control) {
                        return Err(self.error(span, "`server_command` must be a path, without control characters"));
                    }
                    layer.server_command = Some(s.to_string());
                }
                "escape_char" => {
                    let s = self.string(name, value)?;
                    let c = parse_escape_char(s).ok_or_else(|| {
                        self.error(
                            span.clone(),
                            format!("`escape_char` must be one character, ^X or \"none\", not {s:?}"),
                        )
                    })?;
                    layer.escape_char = Some(c);
                }
                "predict" => {
                    layer.predict = Some(match self.string(name, value)? {
                        "auto" => Predict::Auto,
                        "always" => Predict::Always,
                        "never" => Predict::Never,
                        other => return Err(self.error(span, one_of(name, other, "\"auto\", \"always\" or \"never\""))),
                    })
                }
                "status_line" => layer.status_line = Some(self.boolean(name, value)?),
                "ssh" => {
                    let s = self.string(name, value)?;
                    if s.is_empty() || s.contains('\0') {
                        return Err(self.error(span, "`ssh` must name a program"));
                    }
                    layer.ssh = Some(s.to_string());
                }
                "ssh_options" => {
                    let options = self.strings(name, value)?;
                    if options.iter().any(|o| o.contains('\0')) {
                        return Err(self.error(span, "`ssh_options` must not contain NUL characters"));
                    }
                    layer.ssh_options = Some(options);
                }
                "keepalive" => {
                    layer.keepalive = Some(match v {
                        DeValue::String(s) if s == "auto" => Keepalive::Auto,
                        _ => Keepalive::Every(self.duration(name, value, 1, 3600)?),
                    })
                }
                "install" => {
                    layer.install = Some(match self.string(name, value)? {
                        "ask" => Install::Ask,
                        "never" => Install::Never,
                        other => return Err(self.error(span, one_of(name, other, "\"ask\" or \"never\""))),
                    })
                }
                "replay_on_attach" => layer.replay_on_attach = Some(self.boolean(name, value)?),
                "path_memory" => layer.path_memory = Some(self.boolean(name, value)?),
                "catchup" => {
                    layer.catchup = Some(match self.string(name, value)? {
                        "auto" => Catchup::Auto,
                        "off" => Catchup::Off,
                        other => return Err(self.error(span, one_of(name, other, "\"auto\" or \"off\""))),
                    })
                }
                "compression" => {
                    layer.compression = Some(match self.string(name, value)? {
                        "auto" => Compression::Auto,
                        "off" => Compression::Off,
                        other => return Err(self.error(span, one_of(name, other, "\"auto\" or \"off\""))),
                    })
                }
                other => self.warn(key.span(), format!("unknown key `{other}`, ignored")),
            }
        }
        Ok(layer)
    }

    fn transports(&mut self, value: &Spanned<DeValue<'_>>) -> Result<Vec<Transport>, ConfigError> {
        let Some(items) = value.get_ref().as_array() else {
            return Err(self.error(
                value.span(),
                "`transports` must be an array, like [\"quic\", \"tls\", \"ssh\"]",
            ));
        };
        let mut transports = Vec::new();
        for item in items {
            let Some(name) = item.get_ref().as_str() else {
                return Err(self.error(item.span(), "`transports` must be an array of strings"));
            };
            match transport_named(name) {
                Some(t) if transports.contains(&t) => {
                    self.warn(item.span(), format!("transport {name:?} listed twice"));
                }
                Some(t) => transports.push(t),
                // A transport of a newer version
                None => self.warn(
                    item.span(),
                    format!("unknown transport {name:?}, ignored (known: quic, tls, ssh)"),
                ),
            }
        }
        if transports.is_empty() {
            return Err(self.error(value.span(), "`transports` lists no usable transport"));
        }
        Ok(transports)
    }

    fn server(&mut self, table: &DeTable<'_>) -> Result<ServerSettings, ConfigError> {
        let mut s = ServerSettings::default();
        for (key, value) in entries(table) {
            let name = key.get_ref().as_ref();
            match name {
                "ports" => s.ports = Some(self.ports(name, value)?),
                "extra_ports" => {
                    let Some(items) = value.get_ref().as_array() else {
                        return Err(self.error(value.span(), "`extra_ports` must be an array of ports"));
                    };
                    let mut ports: Vec<u16> = Vec::new();
                    for item in items {
                        let p = self.integer("extra_ports", item, 1, 65535)? as u16;
                        if ports.contains(&p) {
                            self.warn(item.span(), format!("port {p} listed twice in `extra_ports`"));
                        } else if ports.len() == MAX_EXTRA_PORTS {
                            self.warn(
                                item.span(),
                                format!("`extra_ports` has more than {MAX_EXTRA_PORTS} ports; port {p} ignored"),
                            );
                        } else {
                            ports.push(p);
                        }
                    }
                    s.extra_ports = Some(ports);
                }
                "snapshot" => s.snapshot = Some(self.boolean(name, value)?),
                "compression" => s.compression = Some(self.boolean(name, value)?),
                "upgrade" => {
                    s.upgrade = Some(match self.string(name, value)? {
                        "auto" => Upgrade::Auto,
                        "manual" => Upgrade::Manual,
                        other => return Err(self.error(value.span(), one_of(name, other, "\"auto\" or \"manual\""))),
                    })
                }
                "max_sessions" => s.max_sessions = Some(self.integer(name, value, 1, 100_000)? as usize),
                "detached_ttl" => s.detached_ttl = Some(self.duration(name, value, 1, 365 * 86400)?),
                "exited_ttl" => s.exited_ttl = Some(self.duration(name, value, 1, 365 * 86400)?),
                "replay_bytes" => s.replay_bytes = Some(self.size(name, value, 1 << 20, 1 << 30)?),
                "preauth" => {
                    for (key, value) in entries(self.table(key, value)?) {
                        let name = key.get_ref().as_ref();
                        let p = &mut s.preauth;
                        match name {
                            "connections" => p.connections = Some(self.integer(name, value, 1, 65536)? as usize),
                            "per_source" => p.per_source = Some(self.integer(name, value, 1, 65536)? as usize),
                            "failure_burst" => p.failure_burst = Some(self.integer(name, value, 1, 10_000)? as u32),
                            "failure_refill" => p.failure_refill = Some(self.duration(name, value, 1, 86400)?),
                            other => self.warn(key.span(), format!("unknown key `preauth.{other}`, ignored")),
                        }
                    }
                }
                other => self.warn(key.span(), format!("unknown key `server.{other}`, ignored")),
            }
        }
        Ok(s)
    }

    fn string<'v>(&self, name: &str, value: &'v Spanned<DeValue<'_>>) -> Result<&'v str, ConfigError> {
        value
            .get_ref()
            .as_str()
            .ok_or_else(|| self.error(value.span(), format!("`{name}` must be a string")))
    }

    fn boolean(&self, name: &str, value: &Spanned<DeValue<'_>>) -> Result<bool, ConfigError> {
        value
            .get_ref()
            .as_bool()
            .ok_or_else(|| self.error(value.span(), format!("`{name}` must be true or false")))
    }

    fn strings(&self, name: &str, value: &Spanned<DeValue<'_>>) -> Result<Vec<String>, ConfigError> {
        let not = || self.error(value.span(), format!("`{name}` must be an array of strings"));
        let items = value.get_ref().as_array().ok_or_else(not)?;
        items
            .iter()
            .map(|i| i.get_ref().as_str().map(str::to_string).ok_or_else(not))
            .collect()
    }

    /// An integer in `min..=max`.
    fn integer(&self, name: &str, value: &Spanned<DeValue<'_>>, min: i64, max: i64) -> Result<i64, ConfigError> {
        let out_of_range = || self.error(value.span(), format!("`{name}` must be a number from {min} to {max}"));
        let DeValue::Integer(i) = value.get_ref() else {
            return Err(out_of_range());
        };
        let n = i64::from_str_radix(i.as_str(), i.radix()).map_err(|_| out_of_range())?;
        if !(min..=max).contains(&n) {
            return Err(out_of_range());
        }
        Ok(n)
    }

    /// A duration of `min..=max` seconds: a number of seconds, or a string like "90s", "10m",
    /// "1h30m", "6h", "2d", "1w".
    fn duration(&self, name: &str, value: &Spanned<DeValue<'_>>, min: u64, max: u64) -> Result<Duration, ConfigError> {
        let bad = || {
            self.error(
                value.span(),
                format!("`{name}` must be a time from {min} to {max} seconds, like 30, \"90s\", \"10m\" or \"6h\""),
            )
        };
        let seconds = match value.get_ref() {
            DeValue::Integer(i) => u64::from_str_radix(i.as_str(), i.radix()).ok(),
            DeValue::String(s) => parse_seconds(s),
            _ => None,
        }
        .ok_or_else(bad)?;
        if !(min..=max).contains(&seconds) {
            return Err(bad());
        }
        Ok(Duration::from_secs(seconds))
    }

    /// A size of `min..=max` bytes: a number of bytes, or a string with K, M or G (powers of
    /// 1024; "KiB", "MiB", "GiB" too).
    fn size(&self, name: &str, value: &Spanned<DeValue<'_>>, min: u64, max: u64) -> Result<usize, ConfigError> {
        let bad = || {
            self.error(
                value.span(),
                format!(
                    "`{name}` must be a size from {} KiB to {} MiB, like \"8M\"",
                    min >> 10,
                    max >> 20
                ),
            )
        };
        let bytes = match value.get_ref() {
            DeValue::Integer(i) => u64::from_str_radix(i.as_str(), i.radix()).ok(),
            DeValue::String(s) => parse_size(s),
            _ => None,
        }
        .ok_or_else(bad)?;
        if !(min..=max).contains(&bytes) {
            return Err(bad());
        }
        usize::try_from(bytes).map_err(|_| bad())
    }

    fn ports(&self, name: &str, value: &Spanned<DeValue<'_>>) -> Result<RangeInclusive<u16>, ConfigError> {
        let ports = match value.get_ref() {
            DeValue::Integer(_) => {
                let p = self.integer(name, value, 1, 65535)? as u16;
                Some(p..=p)
            }
            DeValue::String(s) => parse_ports(s).filter(|r| *r.start() > 0),
            _ => None,
        };
        ports.ok_or_else(|| {
            self.error(
                value.span(),
                format!("`{name}` must be a port range \"FIRST-LAST\" (1 to 65535) or a port"),
            )
        })
    }
}

fn one_of(name: &str, value: &str, allowed: &str) -> String {
    format!("`{name}` must be {allowed}, not {value:?}")
}

fn transport_named(name: &str) -> Option<Transport> {
    match name {
        "quic" => Some(Transport::Quic),
        "tls" => Some(Transport::Tls),
        "ssh" => Some(Transport::Ssh),
        _ => None,
    }
}

/// `"~"`, `"^]"` (a control character), `"none"`: Some(None) for none, None when invalid.
fn parse_escape_char(s: &str) -> Option<Option<u8>> {
    if s == "none" {
        return Some(None);
    }
    match s.as_bytes() {
        [c] if c.is_ascii() && !c.is_ascii_control() => Some(Some(*c)),
        [b'^', c] if (b'@'..=b'_').contains(&c.to_ascii_uppercase()) => Some(Some(c.to_ascii_uppercase() & 0x1f)),
        _ => None,
    }
}

/// `FIRST-LAST` or a single port.
fn parse_ports(text: &str) -> Option<RangeInclusive<u16>> {
    let (a, b) = text.split_once('-').unwrap_or((text, text));
    let (a, b): (u16, u16) = (a.trim().parse().ok()?, b.trim().parse().ok()?);
    (a <= b).then_some(a..=b)
}

/// Seconds in the time format of sshd_config(5): numbers each followed by a unit (s, m, h, d,
/// w; none means seconds), added up: "90", "10m", "1h30m".
fn parse_seconds(text: &str) -> Option<u64> {
    let mut total: u64 = 0;
    let mut number: Option<u64> = None;
    for c in text.trim().chars() {
        if let Some(d) = c.to_digit(10) {
            number = Some(number.unwrap_or(0).checked_mul(10)?.checked_add(u64::from(d))?);
            continue;
        }
        let unit = match c.to_ascii_lowercase() {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            'w' => 7 * 86400,
            _ => return None,
        };
        total = total.checked_add(number.take()?.checked_mul(unit)?)?;
    }
    if text.trim().is_empty() {
        return None;
    }
    total.checked_add(number.unwrap_or(0))
}

/// Bytes: a number, optionally followed by K, M or G (powers of 1024), optionally "iB" or "B".
fn parse_size(text: &str) -> Option<u64> {
    let text = text.trim();
    let digits = text.find(|c: char| !c.is_ascii_digit()).unwrap_or(text.len());
    let (number, unit) = text.split_at(digits);
    let number: u64 = number.parse().ok()?;
    let shift = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 0,
        "k" | "kb" | "kib" => 10,
        "m" | "mb" | "mib" => 20,
        "g" | "gb" | "gib" => 30,
        _ => return None,
    };
    number.checked_mul(1 << shift)
}
