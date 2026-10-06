//! `qsh install HOST` (cargo feature `self-install`, which distribution builds leave off): put
//! `qsh-server`, of this qsh's version, into `~/.local/bin` on the host, without root.
//!
//! 1. Find the host's system over ssh (`uname -s`, `uname -m`, and what install.sh also looks
//!    at: a 32-bit userland on a 64-bit ARM kernel, Rosetta), which names a release target.
//! 2. Get a `qsh-server` built for that target, in this order:
//!    - `--from FILE`: the binary given;
//!    - the `qsh-server` next to this `qsh`, when it is of the same version and this build's
//!      target is the host's (the static musl builds of a release run on every Linux of their
//!      architecture; macOS builds on macOS of theirs). Nothing is downloaded;
//!    - the release archive for the target, downloaded **here** (https only, redirects too)
//!      and checked against the release's `SHA256SUMS`, whose minisign signature
//!      (`SHA256SUMS.minisig`) is checked first against the release key compiled in
//!      ([`RELEASE_KEY`]); the host needs no network access;
//!    - as a last resort, when nothing could be downloaded here, the release's install script,
//!      downloaded over https **on the host** to a file and run there with
//!      `--require-signature` (it downloads and checks the same archive and signature there).
//! 3. Copy it over ssh (its stdin into a temporary file next to the destination), check that it
//!    runs (`qsh-server --version` on the host) and only then rename it into place, so a binary
//!    that does not run never replaces one that does.
//!
//! Downloads use `curl` (else `wget`) as a subprocess, and the archive is unpacked by `tar`:
//! an HTTP client with TLS and a trust store, and gzip and tar decoders, would add a large
//! dependency tree to a program whose runtime otherwise never touches the network, for a
//! convenience that every system with a release download already has the tools for. The
//! checksum is computed here (`ring`, through `qsh_core::crypto::sha256`), and the signature
//! checked here too ([`qsh_core::minisign`]).

use std::fs;
use std::io::{self, Read as _};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use qsh_core::crypto;
use qsh_core::transport::ssh::SshCommand;

/// Where releases are published; `QSH_DOWNLOAD_URL` overrides it (mirrors, tests), as for
/// install.sh.
pub const RELEASES: &str = "https://github.com/yzfly/qsh/releases";

/// The public key of the qsh release key, which signs every release's `SHA256SUMS` (minisign
/// format, key id 247743DF6C75BDD8; also in docs/security.md and scripts/install.sh). Anyone
/// can check a download with it: `minisign -Vm SHA256SUMS -P <this key>`.
pub const RELEASE_KEY: &str = "RWTYvXVs30N3JIE/A5TMPWUWD9ktnPZqQ6lSzYJahI7u5lpiPBCKWHlf";

/// The key releases are checked against: [`RELEASE_KEY`], or in builds with the cargo
/// feature `test-hooks` (never a release), `QSH_TEST_RELEASE_KEY` when set.
fn release_key() -> Result<qsh_core::minisign::PublicKey, String> {
    let text = std::env::var("QSH_TEST_RELEASE_KEY")
        .ok()
        .filter(|_| cfg!(feature = "test-hooks"))
        .unwrap_or_else(|| RELEASE_KEY.to_string());
    qsh_core::minisign::PublicKey::parse(&text).map_err(|e| format!("the release key: {e}"))
}

/// The trusted comment the release workflow signs with `SHA256SUMS` of `version`.
pub fn signed_comment(version: &str) -> String {
    format!("qsh {version} SHA256SUMS")
}

/// Check `minisig` as the release key's signature of `sums`, a `SHA256SUMS` of `version`.
pub fn check_signature(sums: &[u8], minisig: &str, version: &str) -> Result<(), String> {
    check_signature_with(&release_key()?, sums, minisig, version)
}

/// [`check_signature`] with `key`.
pub fn check_signature_with(
    key: &qsh_core::minisign::PublicKey,
    sums: &[u8],
    minisig: &str,
    version: &str,
) -> Result<(), String> {
    let comment = qsh_core::minisign::verify(key, sums, minisig)
        .map_err(|e| format!("SHA256SUMS of {version} is not signed by the qsh release key ({e}); not installing"))?;
    if comment != signed_comment(version) {
        return Err(format!(
            "SHA256SUMS was signed for {:?}, not for qsh {version}; not installing",
            qsh_core::text::sanitize(&comment, 80)
        ));
    }
    Ok(())
}

/// This qsh's version, the one installed.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The line `qsh-server --version` prints for [`VERSION`].
fn version_line() -> String {
    format!("qsh-server {VERSION}")
}

/// What to install, and from where.
#[derive(Debug, Clone)]
pub struct Options {
    /// Install this binary instead of finding or downloading one.
    pub from: Option<PathBuf>,
    /// The releases URL: `https://…/releases`, or `file://…` (mirrors, tests).
    pub releases: String,
    /// The version to install.
    pub version: String,
    /// ssh may ask for passwords on the terminal.
    pub interactive: bool,
}

impl Options {
    /// The defaults, with `QSH_DOWNLOAD_URL` from the environment.
    pub fn from_env(from: Option<PathBuf>, interactive: bool) -> Options {
        Options {
            from,
            releases: std::env::var("QSH_DOWNLOAD_URL")
                .ok()
                .filter(|u| !u.is_empty())
                .unwrap_or_else(|| RELEASES.to_string())
                .trim_end_matches('/')
                .to_string(),
            version: VERSION.to_string(),
            interactive,
        }
    }

    fn archive_name(&self, target: &str) -> String {
        format!("qsh-{}-{target}.tar.gz", self.version)
    }

    fn release_url(&self, file: &str) -> String {
        format!("{}/download/v{}/{file}", self.releases, self.version)
    }
}

/// What the probe found on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    /// `uname -s`.
    pub os: String,
    /// `uname -m`.
    pub arch: String,
    /// The release target for it, or why there is none.
    pub target: Result<String, String>,
    /// A qsh-server found as the client finds it (PATH, then ~/.local/bin): its path and what
    /// `--version` printed.
    pub existing: Option<(String, String)>,
}

/// Marks the start of the probe's output; anything before it is shell start-up noise.
const PROBE_MARK: &str = "QSH-PROBE";

/// Marks the installed server's version line in the copy's output.
const INSTALLED_MARK: &str = "QSH-INSTALLED";

/// The probe, a single-quoted `sh -c` program for any login shell (protocol.md 10.2: no `!`,
/// backslash, newline or inner single quote).
const PROBE: &str = "sh -c 'echo; echo QSH-PROBE; uname -s; uname -m; getconf LONG_BIT 2>/dev/null || echo 64; \
sysctl -n sysctl.proc_translated 2>/dev/null || echo 0; \
for p in \"$(command -v qsh-server)\" \"$HOME/.local/bin/qsh-server\"; do \
if [ -n \"$p\" ] && [ -x \"$p\" ]; then echo \"$p\"; \"$p\" --version 2>/dev/null || echo; exit 0; fi; done; exit 0'";

/// Copy stdin to `~/.local/bin/qsh-server` on the host: into a temporary file, which must run
/// (`--version`) before it replaces the old one; the version is printed after a mark.
const COPY: &str = "sh -c 'd=\"$HOME/.local/bin\"; t=\"$d/.qsh-server.$$\"; \
mkdir -p \"$d\" && cat > \"$t\" && chmod 755 \"$t\" && \"$t\" --version >/dev/null && mv -f \"$t\" \"$d/qsh-server\" && \
echo && echo QSH-INSTALLED && exec \"$d/qsh-server\" --version; s=$?; rm -f \"$t\"; exit $s'";

/// The release target for a host's `uname -s`, `uname -m`, `getconf LONG_BIT` and
/// `sysctl.proc_translated`, as install.sh decides it.
pub fn target_for(os: &str, arch: &str, long_bit: &str, translated: &str) -> Result<String, String> {
    match os {
        "Linux" => {
            let arch = match arch {
                "x86_64" | "amd64" => "x86_64",
                // A 64-bit kernel can run a 32-bit userland (Raspberry Pi OS): match the userland
                "aarch64" | "arm64" if long_bit == "32" => "armv7",
                "aarch64" | "arm64" => "aarch64",
                a if a.starts_with("armv7") || a == "armv8l" => "armv7",
                "riscv64" => "riscv64gc",
                other => {
                    return Err(format!(
                        "no qsh build for Linux on {other} (there are for x86_64, aarch64, armv7, riscv64); build it from source there: cargo install qsh-cli"
                    ))
                }
            };
            Ok(if arch == "armv7" {
                "armv7-unknown-linux-musleabihf".into()
            } else {
                format!("{arch}-unknown-linux-musl")
            })
        }
        "Darwin" => match arch {
            // A shell under Rosetta reports x86_64 on Apple silicon: the native build
            "x86_64" if translated == "1" => Ok("aarch64-apple-darwin".into()),
            "x86_64" => Ok("x86_64-apple-darwin".into()),
            "arm64" | "aarch64" => Ok("aarch64-apple-darwin".into()),
            other => Err(format!("no qsh build for macOS on {other}")),
        },
        other => Err(format!(
            "no qsh build for {other} (there are for Linux and macOS); build it from source there: cargo install qsh-cli"
        )),
    }
}

/// This build's release target, when its `qsh-server` can be copied to a host of the same
/// target: the static musl builds on Linux, and macOS builds. None for other builds (a glibc
/// build may not run on another distribution).
pub fn local_target() -> Option<&'static str> {
    if cfg!(all(target_os = "linux", target_env = "musl")) {
        match std::env::consts::ARCH {
            "x86_64" => Some("x86_64-unknown-linux-musl"),
            "aarch64" => Some("aarch64-unknown-linux-musl"),
            "arm" => Some("armv7-unknown-linux-musleabihf"),
            "riscv64" => Some("riscv64gc-unknown-linux-musl"),
            _ => None,
        }
    } else if cfg!(target_os = "macos") {
        match std::env::consts::ARCH {
            "x86_64" => Some("x86_64-apple-darwin"),
            "aarch64" => Some("aarch64-apple-darwin"),
            _ => None,
        }
    } else {
        None
    }
}

/// The `qsh-server` next to this `qsh`, if it is of the same version.
fn local_server() -> Option<PathBuf> {
    let path = std::env::current_exe().ok()?.with_file_name("qsh-server");
    let out = Command::new(&path)
        .arg("--version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    (out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == version_line()).then_some(path)
}

/// The lines after `mark` in `output`.
fn after_mark<'a>(output: &'a str, mark: &str) -> Option<Vec<&'a str>> {
    let mut lines = output.lines();
    lines.by_ref().find(|l| l.trim() == mark)?;
    Some(lines.map(str::trim).collect())
}

/// Parse the probe's output.
pub fn parse_probe(output: &str) -> Option<Remote> {
    let lines = after_mark(output, PROBE_MARK)?;
    let field = |i: usize| lines.get(i).copied().unwrap_or("");
    let (os, arch) = (field(0), field(1));
    if os.is_empty() || arch.is_empty() {
        return None;
    }
    let existing = (!field(4).is_empty()).then(|| (field(4).to_string(), field(5).to_string()));
    Some(Remote {
        os: os.into(),
        arch: arch.into(),
        target: target_for(os, arch, field(2), field(3)),
        existing,
    })
}

fn ssh_failed(ssh: &SshCommand, status: std::process::ExitStatus) -> String {
    match status.code() {
        Some(255) => format!("ssh to {} failed", ssh.destination),
        Some(code) => format!("the command on {} failed (exit status {code})", ssh.destination),
        None => format!("ssh to {} was killed", ssh.destination),
    }
}

/// Step 1: what the host is.
pub fn probe(ssh: &SshCommand, interactive: bool) -> Result<Remote, String> {
    let out = ssh
        .one_off(PROBE, !interactive)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("cannot run ssh: {e}"))?;
    if !out.status.success() {
        return Err(ssh_failed(ssh, out.status));
    }
    parse_probe(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| format!("cannot tell the system of {} (no answer from uname)", ssh.destination))
}

/// Step 3: copy `binary` to `~/.local/bin/qsh-server` on the host; what the installed server's
/// `--version` says.
pub fn copy(ssh: &SshCommand, binary: &Path, interactive: bool) -> Result<String, String> {
    let file = fs::File::open(binary).map_err(|e| format!("{}: {e}", binary.display()))?;
    let out = ssh
        .one_off(COPY, !interactive)
        .stdin(Stdio::from(file))
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("cannot run ssh: {e}"))?;
    if out.status.code() == Some(126) {
        return Err(format!(
            "the qsh-server binary does not run on {} (built for another system?); nothing was replaced",
            ssh.destination
        ));
    }
    if !out.status.success() {
        return Err(ssh_failed(ssh, out.status));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    after_mark(&text, INSTALLED_MARK)
        .and_then(|lines| lines.into_iter().find(|l| !l.is_empty()).map(str::to_string))
        .ok_or_else(|| format!("no answer from qsh-server on {} after copying it", ssh.destination))
}

/// A private temporary directory, removed when dropped.
#[derive(Debug)]
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> io::Result<TempDir> {
        let dir = std::env::temp_dir().join(format!("qsh-install-{}", crypto::hex(&crypto::random::<8>())));
        fs::DirBuilder::new().mode(0o700).create(&dir)?;
        Ok(TempDir(dir))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The scheme of a download URL qsh accepts: https, or file (mirrors on disk, tests).
fn allowed_scheme(url: &str) -> Option<&'static str> {
    if url.starts_with("https://") {
        Some("=https")
    } else if url.starts_with("file://") {
        Some("=file")
    } else {
        None
    }
}

/// Download `url` to `dest` with curl, else wget. Only https:// (and file://, for mirrors on
/// disk and tests) is accepted, for the URL and for every redirect: curl is told so
/// (`--proto`, `--proto-redir`); wget cannot be, so the redirects it followed are read from its
/// headers and a download that went through plain http is refused.
fn fetch(url: &str, dest: &Path) -> Result<(), String> {
    let Some(proto) = allowed_scheme(url) else {
        return Err(format!("{url}: only https:// and file:// downloads are allowed"));
    };
    let curl = Command::new("curl")
        .args([
            "--proto",
            proto,
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "-fsSL",
            "--retry",
            "3",
            "-o",
        ])
        .arg(dest)
        .arg(url)
        .stdin(Stdio::null())
        .status();
    match curl {
        Ok(s) if s.success() => return Ok(()),
        Ok(s) => {
            return Err(format!(
                "downloading {url} failed (curl exit status {})",
                s.code().unwrap_or(-1)
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("cannot run curl: {e}")),
    }
    if proto != "=https" {
        return Err("curl is needed to download from a file:// URL".into());
    }
    // -S: the server's headers on stderr, where every redirect's Location shows
    let wget = Command::new("wget")
        .args(["-nv", "-S", "--https-only", "--max-redirect=10", "-O"])
        .arg(dest)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    match wget {
        Ok(out) if out.status.success() => {
            if redirected_to_http(&String::from_utf8_lossy(&out.stderr)) {
                let _ = fs::remove_file(dest);
                return Err(format!("downloading {url} was redirected to plain http; not used"));
            }
            Ok(())
        }
        Ok(out) => Err(format!(
            "downloading {url} failed (wget exit status {})",
            out.status.code().unwrap_or(-1)
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err("neither curl nor wget is installed here".into()),
        Err(e) => Err(format!("cannot run wget: {e}")),
    }
}

/// True when wget's headers (`-S`) show a redirect to anything but https.
pub fn redirected_to_http(headers: &str) -> bool {
    headers.lines().any(|line| {
        let line = line.trim().to_ascii_lowercase();
        line.strip_prefix("location:")
            .map(str::trim)
            .is_some_and(|to| to.contains("://") && !to.starts_with("https://"))
    })
}

/// The SHA-256 that `sums` (a SHA256SUMS file) lists for `name`.
pub fn listed_sha256(sums: &str, name: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let hash = parts.next()?;
        let file = parts.next()?.trim_start_matches('*');
        (file == name && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| hash.to_ascii_lowercase())
    })
}

/// Why getting a binary failed: the download did not happen (another way may work), or it
/// happened and is not to be trusted, or must not be tried (stop: never fall back to the
/// host's own download then).
#[derive(Debug)]
pub enum DownloadError {
    /// Could not download; the host may manage on its own.
    Unavailable(String),
    /// The archive does not match its checksum, or is not what it should be.
    Rejected(String),
}

/// Step 2, downloading: the release archive for `target`, checked against SHA256SUMS, unpacked
/// in `dir`; the path of its `qsh-server`.
fn download(
    options: &Options,
    target: &str,
    dir: &Path,
    progress: &mut dyn FnMut(&str),
) -> Result<PathBuf, DownloadError> {
    let archive = options.archive_name(target);
    // A plain http URL is not "unavailable": the host must not fetch it either (review L1)
    if allowed_scheme(&options.releases).is_none() {
        return Err(DownloadError::Rejected(format!(
            "{}: only https:// and file:// downloads are allowed",
            options.releases
        )));
    }
    progress(&format!("downloading {archive}"));
    let sums_path = dir.join("SHA256SUMS");
    fetch(&options.release_url("SHA256SUMS"), &sums_path).map_err(DownloadError::Unavailable)?;
    // The checksums count only once their signature checks out
    let sig_path = dir.join("SHA256SUMS.minisig");
    fetch(&options.release_url("SHA256SUMS.minisig"), &sig_path)
        .map_err(|e| DownloadError::Rejected(format!("{e}: the release's signature is missing; not installing")))?;
    let sums_bytes = fs::read(&sums_path).map_err(|e| DownloadError::Rejected(format!("SHA256SUMS: {e}")))?;
    let minisig =
        fs::read_to_string(&sig_path).map_err(|e| DownloadError::Rejected(format!("SHA256SUMS.minisig: {e}")))?;
    check_signature(&sums_bytes, &minisig, &options.version).map_err(DownloadError::Rejected)?;
    progress("SHA256SUMS: signed by the qsh release key");
    let archive_path = dir.join(&archive);
    fetch(&options.release_url(&archive), &archive_path).map_err(DownloadError::Rejected)?;
    let sums = String::from_utf8(sums_bytes).map_err(|e| DownloadError::Rejected(format!("SHA256SUMS: {e}")))?;
    let expected = listed_sha256(&sums, &archive)
        .ok_or_else(|| DownloadError::Rejected(format!("SHA256SUMS of {} lists no {archive}", options.version)))?;
    let mut bytes = Vec::new();
    fs::File::open(&archive_path)
        .and_then(|mut f| f.read_to_end(&mut bytes))
        .map_err(|e| DownloadError::Rejected(format!("{archive}: {e}")))?;
    let actual = crypto::hex(&crypto::sha256(&bytes));
    if actual != expected {
        return Err(DownloadError::Rejected(format!(
            "{archive} does not match its checksum in SHA256SUMS (expected {expected}, got {actual}); not installing it"
        )));
    }
    progress(&format!(
        "{archive}: {}, checksum OK",
        crate::terminal::human_bytes(bytes.len() as u64)
    ));
    let member = format!("qsh-{}-{target}/qsh-server", options.version);
    let unpack = dir.join("unpacked");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&unpack)
        .map_err(|e| DownloadError::Rejected(e.to_string()))?;
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(&archive_path)
        .arg("-C")
        .arg(&unpack)
        .arg(&member)
        .stdin(Stdio::null())
        .status()
        .map_err(|e| DownloadError::Unavailable(format!("cannot run tar: {e}")))?;
    let binary = unpack.join(&member);
    // A regular file, not a link to somewhere else
    let regular = fs::symlink_metadata(&binary).is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0);
    if !status.success() || !regular {
        return Err(DownloadError::Rejected(format!("{archive} has no executable {member}")));
    }
    Ok(binary)
}

/// Step 2, last resort: the release's install script, run on the host. Downloaded over https
/// only (redirects included: curl is told, wget's redirects are checked) into a file, never
/// piped into a shell, and run with `--require-signature`, so that it installs nothing whose
/// signature it could not check.
fn remote_script(ssh: &SshCommand, options: &Options) -> Result<String, String> {
    let safe = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_./:@%+=~,".contains(&b))
    };
    if !safe(&options.releases) || !safe(&options.version) {
        return Err("the download URL or version has characters that cannot go into a remote command".into());
    }
    if !options.releases.starts_with("https://") {
        return Err(format!("{}: the host downloads only over https://", options.releases));
    }
    let url = options.release_url("install.sh");
    let command = remote_script_command(&url, &options.releases, &options.version);
    let out = ssh
        .one_off(&command, !options.interactive)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("cannot run ssh: {e}"))?;
    if !out.status.success() {
        return Err(ssh_failed(ssh, out.status));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    after_mark(&text, INSTALLED_MARK)
        .and_then(|lines| lines.into_iter().find(|l| !l.is_empty()).map(str::to_string))
        .ok_or_else(|| format!("the install script on {} did not install qsh-server", ssh.destination))
}

/// The remote command of the last-resort install on the host: a single-quoted `sh -c` program for any login
/// shell (no `!`, backslash, newline or inner single quote; protocol.md 10.2).
pub fn remote_script_command(url: &str, releases: &str, version: &str) -> String {
    format!(
        "sh -c 'u=\"{url}\"; t=$(mktemp) || exit 1; h=$(mktemp) || exit 1; \
if command -v curl >/dev/null 2>&1; then curl --proto =https --proto-redir =https --tlsv1.2 -fsSL -o \"$t\" \"$u\"; s=$?; \
else wget -nv -S --https-only --max-redirect=10 -O \"$t\" \"$u\" 2>\"$h\"; s=$?; \
if [ $s = 0 ] && grep -i \"location:\" \"$h\" | grep -iv \"location: *https://\" | grep -q \"://\"; then echo \"qsh: the download was redirected to plain http\" >&2; s=1; fi; fi; \
if [ $s = 0 ]; then QSH_DOWNLOAD_URL=\"{releases}\" sh \"$t\" --server-only --require-signature --version {version} --prefix \"$HOME/.local\"; s=$?; fi; \
rm -f \"$t\" \"$h\"; [ $s = 0 ] || exit $s; echo; echo QSH-INSTALLED; exec \"$HOME/.local/bin/qsh-server\" --version'"
    )
}

/// Install qsh-server on the host. `progress` gets one line per step. Returns what the
/// installed server's `--version` says.
pub fn install(ssh: &SshCommand, options: &Options, progress: &mut dyn FnMut(&str)) -> Result<String, String> {
    let destination = &ssh.destination;
    let interactive = options.interactive;
    let want = format!("qsh-server {}", options.version);
    let remote = probe(ssh, interactive)?;
    let what = match &remote.target {
        Ok(t) => format!("{} {} ({t})", remote.os, remote.arch),
        Err(_) => format!("{} {}", remote.os, remote.arch),
    };
    match &remote.existing {
        Some((path, version)) if version == &want && options.from.is_none() => {
            progress(&format!(
                "{destination}: {what}; {version} is already installed ({path})"
            ));
            return Ok(version.clone());
        }
        Some((path, version)) => {
            let version = if version.is_empty() {
                "a qsh-server that does not run"
            } else {
                version
            };
            progress(&format!("{destination}: {what}; replacing {version} ({path})"));
            if !path.ends_with("/.local/bin/qsh-server") {
                progress(&format!(
                    "note: {path} is in PATH on {destination}, and qsh uses it before ~/.local/bin"
                ));
            }
        }
        None => progress(&format!("{destination}: {what}; qsh-server is not installed")),
    }
    let check = |installed: String| {
        if installed == want {
            Ok(installed)
        } else {
            Err(format!(
                "qsh-server on {destination} reports {installed:?}, expected {want:?}"
            ))
        }
    };
    let installed = if let Some(binary) = &options.from {
        progress(&format!(
            "copying {} to {destination}:~/.local/bin/qsh-server",
            binary.display()
        ));
        // A binary given by hand may be of another version: it is reported, and accepted
        copy(ssh, binary, interactive)
    } else {
        let target = remote.target.clone()?;
        let local = (options.version == VERSION && local_target() == Some(target.as_str()))
            .then(local_server)
            .flatten();
        if let Some(local) = local {
            progress(&format!(
                "copying this machine's qsh-server {VERSION} to {destination}:~/.local/bin/qsh-server"
            ));
            copy(ssh, &local, interactive).and_then(check)
        } else {
            let dir = TempDir::new().map_err(|e| format!("cannot create a temporary directory: {e}"))?;
            match download(options, &target, &dir.0, progress) {
                Ok(binary) => {
                    progress(&format!("copying qsh-server to {destination}:~/.local/bin/qsh-server"));
                    copy(ssh, &binary, interactive).and_then(check)
                }
                Err(DownloadError::Rejected(e)) => Err(e),
                Err(DownloadError::Unavailable(e)) => {
                    progress(&format!("{e}; running the install script on {destination} instead"));
                    remote_script(ssh, options).and_then(check)
                }
            }
        }
    }?;
    progress(&format!(
        "installed: {destination}:~/.local/bin/qsh-server is {installed}"
    ));
    Ok(installed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review L1: the compiled-in release key parses, and SHA256SUMS counts only with a
    /// signature by it, for this very version.
    #[test]
    fn sha256sums_need_the_release_signature_of_their_version() {
        let key = qsh_core::minisign::PublicKey::parse(RELEASE_KEY).unwrap();
        assert_eq!(key.id_hex(), "247743DF6C75BDD8");
        let seed = [3u8; 32];
        let test_key = qsh_core::minisign::public_key(&seed, *b"testtest").unwrap();
        let sums = b"00  qsh-0.5.0-x86_64-unknown-linux-musl.tar.gz\n";
        let sig = qsh_core::minisign::sign(&seed, test_key.id, sums, &signed_comment("0.5.0")).unwrap();
        assert_eq!(check_signature_with(&test_key, sums, &sig, "0.5.0"), Ok(()));
        // Another version's signed list: refused (no rollback to an older release's files)
        assert!(check_signature_with(&test_key, sums, &sig, "0.5.1")
            .unwrap_err()
            .contains("not for qsh 0.5.1"));
        assert!(check_signature_with(&test_key, b"11  x\n", &sig, "0.5.0").is_err());
        // Not the release key
        assert!(check_signature_with(&key, sums, &sig, "0.5.0")
            .unwrap_err()
            .contains("not signed"));
    }

    /// Review L1: wget cannot be told to refuse a redirect to http; its headers are read.
    #[test]
    fn redirects_to_plain_http_are_seen() {
        let https = "  HTTP/1.1 302 Found\n  Location: https://objects.example/x\n  HTTP/1.1 200 OK\n";
        assert!(!redirected_to_http(https));
        assert!(redirected_to_http(
            "  HTTP/1.1 302 Found\n  Location: http://evil.example/x\n"
        ));
        assert!(redirected_to_http("  location:   HTTP://evil.example/x\n"));
        assert!(redirected_to_http("  Location: ftp://x/y\n"));
        // A relative redirect stays on the https origin
        assert!(!redirected_to_http("  Location: /releases/x\n"));
    }

    /// Review L1: the host's fallback downloads to a file over https only and runs the script
    /// with --require-signature; the command is one a login shell passes on intact.
    #[test]
    fn the_remote_fallback_command_is_safe_shell() {
        let c = remote_script_command(
            "https://github.com/yzfly/qsh/releases/download/v0.5.0/install.sh",
            "https://github.com/yzfly/qsh/releases",
            "0.5.0",
        );
        assert!(c.starts_with("sh -c '") && c.ends_with('\''), "{c}");
        let inner = &c[7..c.len() - 1];
        for bad in ['\'', '\\', '!', '\n'] {
            assert!(!inner.contains(bad), "{bad:?} in {inner}");
        }
        for part in [
            "--proto =https --proto-redir =https",
            "--require-signature",
            "--https-only",
            "mktemp",
        ] {
            assert!(inner.contains(part), "{part}: {inner}");
        }
        assert!(!inner.contains("| sh") && !inner.contains("|sh"), "{inner}");
        let syntax = Command::new("sh").args(["-n", "-c", inner]).status().unwrap();
        assert!(syntax.success(), "{inner}");
    }

    #[test]
    fn targets_as_install_sh_names_them() {
        let t = |os, arch, bits, tr| target_for(os, arch, bits, tr);
        assert_eq!(t("Linux", "x86_64", "64", "0").unwrap(), "x86_64-unknown-linux-musl");
        assert_eq!(t("Linux", "amd64", "64", "0").unwrap(), "x86_64-unknown-linux-musl");
        assert_eq!(t("Linux", "aarch64", "64", "0").unwrap(), "aarch64-unknown-linux-musl");
        assert_eq!(
            t("Linux", "aarch64", "32", "0").unwrap(),
            "armv7-unknown-linux-musleabihf"
        );
        assert_eq!(
            t("Linux", "armv7l", "32", "0").unwrap(),
            "armv7-unknown-linux-musleabihf"
        );
        assert_eq!(
            t("Linux", "riscv64", "64", "0").unwrap(),
            "riscv64gc-unknown-linux-musl"
        );
        assert!(t("Linux", "mips", "32", "0")
            .unwrap_err()
            .contains("no qsh build for Linux on mips"));
        assert_eq!(t("Darwin", "arm64", "64", "0").unwrap(), "aarch64-apple-darwin");
        assert_eq!(t("Darwin", "x86_64", "64", "1").unwrap(), "aarch64-apple-darwin");
        assert_eq!(t("Darwin", "x86_64", "64", "0").unwrap(), "x86_64-apple-darwin");
        assert!(t("FreeBSD", "amd64", "64", "0").unwrap_err().contains("FreeBSD"));
    }

    #[test]
    fn the_probe_is_read_after_start_up_noise() {
        let out = "Welcome!\n\nQSH-PROBE\nLinux\naarch64\n64\n0\n/home/a/.local/bin/qsh-server\nqsh-server 0.1.0\n";
        let r = parse_probe(out).unwrap();
        assert_eq!((r.os.as_str(), r.arch.as_str()), ("Linux", "aarch64"));
        assert_eq!(r.target.unwrap(), "aarch64-unknown-linux-musl");
        assert_eq!(
            r.existing,
            Some(("/home/a/.local/bin/qsh-server".into(), "qsh-server 0.1.0".into()))
        );
        let r = parse_probe("\nQSH-PROBE\nLinux\nx86_64\n64\n0\n").unwrap();
        assert_eq!(r.existing, None);
        assert!(parse_probe("no mark\nLinux\n").is_none());
        assert!(parse_probe("QSH-PROBE\n").is_none());
    }

    #[test]
    fn remote_commands_survive_any_login_shell() {
        for cmd in [PROBE, COPY] {
            assert!(cmd.starts_with("sh -c '") && cmd.ends_with('\''), "{cmd}");
            let inner = &cmd[7..cmd.len() - 1];
            assert!(!inner.contains(['\'', '!', '\\', '\n']), "{cmd}");
        }
    }

    #[test]
    fn checksums_are_looked_up_by_name() {
        let sums = format!(
            "{}  qsh-0.1.1-x86_64-unknown-linux-musl.tar.gz\n{} *qsh-0.1.1-aarch64-unknown-linux-musl.tar.gz\n",
            "ab".repeat(32),
            "CD".repeat(32)
        );
        assert_eq!(
            listed_sha256(&sums, "qsh-0.1.1-x86_64-unknown-linux-musl.tar.gz").unwrap(),
            "ab".repeat(32)
        );
        assert_eq!(
            listed_sha256(&sums, "qsh-0.1.1-aarch64-unknown-linux-musl.tar.gz").unwrap(),
            "cd".repeat(32)
        );
        assert!(listed_sha256(&sums, "qsh-0.1.1-x86_64-apple-darwin.tar.gz").is_none());
        assert!(listed_sha256("short  name\n", "name").is_none());
    }

    #[test]
    fn urls_follow_the_release_layout() {
        let o = Options {
            from: None,
            releases: RELEASES.into(),
            version: "0.1.1".into(),
            interactive: false,
        };
        assert_eq!(
            o.release_url(&o.archive_name("x86_64-unknown-linux-musl")),
            "https://github.com/yzfly/qsh/releases/download/v0.1.1/qsh-0.1.1-x86_64-unknown-linux-musl.tar.gz"
        );
        assert!(fetch("http://example.com/x", Path::new("/nonexistent")).is_err());
    }
}
