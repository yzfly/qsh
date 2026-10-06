//! `qsh install` and the offer to install, against the fake ssh (see `common`): the "remote"
//! is this machine with the test world's HOME, and the destination `bare` has no qsh-server
//! but in `~/.local/bin`. A stub `uname` decides what system the host is; releases come from
//! a directory through `file://` (QSH_DOWNLOAD_URL).

#![cfg(feature = "self-install")]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use common::*;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const TARGET: &str = "x86_64-unknown-linux-musl";

fn write_exec(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// A world whose host says it is Linux on x86_64.
fn world(name: &str) -> World {
    let w = World::new(name);
    write_exec(
        &w.dir.join("bin/uname"),
        "#!/bin/sh\ncase \"$1\" in -s) echo Linux ;; -m) echo x86_64 ;; *) exec /usr/bin/env -i PATH=/usr/bin:/bin uname \"$@\" ;; esac\n",
    );
    w
}

fn curl_available() -> bool {
    Command::new("curl")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// A release directory as GitHub serves it: download/vX/{archive, SHA256SUMS}, with `server`
/// as the archive's qsh-server. Returns the file:// URL.
fn release(w: &World, server: &Path) -> (String, PathBuf) {
    let root = w.dir.join("releases");
    let dir = root.join(format!("download/v{VERSION}"));
    let stage = w.dir.join("stage").join(format!("qsh-{VERSION}-{TARGET}"));
    fs::create_dir_all(&dir).unwrap();
    fs::create_dir_all(&stage).unwrap();
    fs::copy(server, stage.join("qsh-server")).unwrap();
    let archive = format!("qsh-{VERSION}-{TARGET}.tar.gz");
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "tar -cf - -C {} qsh-{VERSION}-{TARGET} | gzip -1 > {}",
            w.dir.join("stage").display(),
            dir.join(&archive).display()
        ))
        .status()
        .unwrap();
    assert!(status.success());
    let sum = qsh_core::crypto::hex(&qsh_core::crypto::sha256(&fs::read(dir.join(&archive)).unwrap()));
    fs::write(dir.join("SHA256SUMS"), format!("{sum}  {archive}\n")).unwrap();
    (format!("file://{}", root.display()), dir.join("SHA256SUMS"))
}

fn installed(w: &World) -> PathBuf {
    w.dir.join("home/.local/bin/qsh-server")
}

/// `--from`: the given binary is copied over ssh into ~/.local/bin, where the client finds it.
#[test]
fn install_from_a_file_then_connect() {
    let w = world("inst-from");
    let (code, _, err) = w.run(&["bare", "true"]);
    assert_eq!(code, 42, "{err}");
    assert!(err.contains("qsh install bare"), "{err}");
    let (code, _, err) = w.run(&["install", "bare", "--from", QSH_SERVER]);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("bare: Linux x86_64 (x86_64-unknown-linux-musl); qsh-server is not installed"),
        "{err}"
    );
    assert!(
        err.contains(&format!(
            "installed: bare:~/.local/bin/qsh-server is qsh-server {VERSION}"
        )),
        "{err}"
    );
    let mode = fs::metadata(installed(&w)).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o755);
    let (code, out, err) = w.run(&["bare", "echo", "via-local-bin"]);
    assert_eq!((code, out.as_str()), (0, "via-local-bin\n"), "{err}");
    // Once it is there, installing again does nothing
    let (code, _, err) = w.run(&["install", "bare"]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("is already installed"), "{err}");
}

/// A binary that does not run on the host never replaces anything.
#[test]
fn a_binary_that_does_not_run_is_refused() {
    let w = world("inst-bad");
    let junk = w.dir.join("junk");
    fs::write(&junk, b"\x7fELF not really").unwrap();
    let (code, _, err) = w.run(&["install", "bare", "--from", &junk.display().to_string()]);
    assert_eq!(code, 255, "{err}");
    assert!(err.contains("does not run on bare"), "{err}");
    assert!(!installed(&w).exists());
    let left: Vec<_> = fs::read_dir(w.dir.join("home/.local/bin")).unwrap().collect();
    assert!(left.is_empty(), "no temporary file left: {left:?}");
}

/// No local binary for the host: the release archive is downloaded here, checked against
/// SHA256SUMS, unpacked and copied over. A wrong checksum stops everything.
#[test]
fn install_downloads_and_checks_the_release() {
    if !curl_available() {
        eprintln!("no curl: skipped");
        return;
    }
    let w = world("inst-dl");
    let stub = w.dir.join("stub-server");
    write_exec(&stub, &format!("#!/bin/sh\necho 'qsh-server {VERSION}'\n"));
    let (url, sums) = release(&w, &stub);
    let mut cmd = w.qsh(&["install", "bare"]);
    cmd.env("QSH_DOWNLOAD_URL", &url);
    let out = cmd.stdin(Stdio::null()).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(
        err.contains(&format!("downloading qsh-{VERSION}-{TARGET}.tar.gz")),
        "{err}"
    );
    assert!(err.contains("checksum OK"), "{err}");
    assert_eq!(fs::read(installed(&w)).unwrap(), fs::read(&stub).unwrap());

    // Tampered: refused, and nothing installed
    fs::remove_file(installed(&w)).unwrap();
    fs::write(&sums, format!("{}  qsh-{VERSION}-{TARGET}.tar.gz\n", "0".repeat(64))).unwrap();
    let mut cmd = w.qsh(&["install", "bare"]);
    cmd.env("QSH_DOWNLOAD_URL", &url);
    let out = cmd.stdin(Stdio::null()).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(255), "{err}");
    assert!(err.contains("does not match its checksum"), "{err}");
    assert!(!installed(&w).exists());
}

/// On a terminal, a host without qsh-server gets one question; yes installs it (here from the
/// release directory, with the real qsh-server) and the session starts.
#[test]
fn the_install_prompt_installs_and_connects() {
    if !curl_available() {
        eprintln!("no curl: skipped");
        return;
    }
    let mut w = world("inst-ask");
    let (url, _) = release(&w, Path::new(QSH_SERVER));
    w.set("QSH_DOWNLOAD_URL", url);
    let mut tty = Tty::spawn(w.qsh(&["bare", "echo prompt-ok; exit 3"]));
    tty.wait_for(
        "qsh-server is not installed on bare. Install it to ~/.local/bin there? [Y/n]",
        Duration::from_secs(20),
    );
    tty.send(b"\r");
    tty.wait_for("prompt-ok", Duration::from_secs(60));
    assert_eq!(tty.exit_code(Duration::from_secs(20)), 3, "{:?}", tty.text());
    assert!(tty.text().contains("checksum OK"), "{:?}", tty.text());
    assert!(installed(&w).exists());

    // No: the hint, exit 42; and `install = "never"` asks nothing
    fs::remove_file(installed(&w)).unwrap();
    let _ = w.command(QSH_SERVER, &["stop"]).output();
    let mut tty = Tty::spawn(w.qsh(&["bare", "true"]));
    tty.wait_for("[Y/n]", Duration::from_secs(20));
    tty.send(b"n\r");
    assert_eq!(tty.exit_code(Duration::from_secs(20)), 42);
    assert!(tty.text().contains("qsh install bare"), "{:?}", tty.text());
    fs::create_dir_all(w.dir.join("config/qsh")).unwrap();
    fs::write(w.dir.join("config/qsh/config"), "[defaults]\ninstall = \"never\"\n").unwrap();
    fs::set_permissions(w.dir.join("config/qsh/config"), fs::Permissions::from_mode(0o600)).unwrap();
    let mut tty = Tty::spawn(w.qsh(&["bare", "true"]));
    assert_eq!(tty.exit_code(Duration::from_secs(20)), 42, "{:?}", tty.text());
    assert!(!tty.text().contains("[Y/n]"), "{:?}", tty.text());
}
