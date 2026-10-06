//! `qsh install` and the offer to install, against the fake ssh (see `common`): the "remote"
//! is this machine with the test world's HOME, and the destination `bare` has no qsh-server
//! but in `~/.local/bin`. A stub `uname` decides what system the host is; releases come from
//! a directory through `file://` (QSH_DOWNLOAD_URL), their SHA256SUMS signed with a test key
//! that the test hook QSH_TEST_RELEASE_KEY makes qsh trust.

#![cfg(all(feature = "self-install", feature = "test-hooks"))]

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

/// The test release key's seed and id.
const TEST_SEED: [u8; 32] = [42; 32];
const TEST_KEY_ID: [u8; 8] = *b"qsh-test";

fn test_key() -> qsh_core::minisign::PublicKey {
    qsh_core::minisign::public_key(&TEST_SEED, TEST_KEY_ID).unwrap()
}

/// SHA256SUMS.minisig next to `sums`, signed with the test key for `version`.
fn sign(sums: &Path, version: &str) {
    let sig = qsh_core::minisign::sign(
        &TEST_SEED,
        TEST_KEY_ID,
        &fs::read(sums).unwrap(),
        &format!("qsh {version} SHA256SUMS"),
    )
    .unwrap();
    fs::write(sums.with_file_name("SHA256SUMS.minisig"), sig).unwrap();
}

/// A world whose host says it is Linux on x86_64, and whose qsh trusts the test release key.
fn world(name: &str) -> World {
    let mut w = World::new(name);
    w.set("QSH_TEST_RELEASE_KEY", test_key().to_base64());
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
    sign(&dir.join("SHA256SUMS"), VERSION);
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
    // A truncated ELF header, with the NUL bytes every real one has: a shell that gets ENOEXEC
    // runs a file as a script unless it looks binary, and bash 3.2 (macOS's sh) looks only for a
    // NUL before the first newline
    fs::write(&junk, b"\x7fELF\x02\x01\x01\x00\x00\x00 not really").unwrap();
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

    assert!(err.contains("signed by the qsh release key"), "{err}");

    let refused = |what: &str, url: &str, expected: &str| {
        let _ = fs::remove_file(installed(&w));
        let mut cmd = w.qsh(&["install", "bare"]);
        cmd.env("QSH_DOWNLOAD_URL", url);
        let out = cmd.stdin(Stdio::null()).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(255), "{what}: {err}");
        assert!(err.contains(expected), "{what}: {err}");
        assert!(
            !err.contains("install script"),
            "{what}: no fallback to the host: {err}"
        );
        assert!(!installed(&w).exists(), "{what}");
    };
    // A tampered archive: its checksum
    let archive = sums.with_file_name(format!("qsh-{VERSION}-{TARGET}.tar.gz"));
    let good = fs::read(&archive).unwrap();
    let mut bad = good.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    fs::write(&archive, &bad).unwrap();
    refused("archive", &url, "does not match its checksum");
    fs::write(&archive, &good).unwrap();
    // Review L1: a tampered SHA256SUMS, consistent with the tampered archive: its signature
    let original = fs::read(&sums).unwrap();
    let sum = qsh_core::crypto::hex(&qsh_core::crypto::sha256(&bad));
    fs::write(&sums, format!("{sum}  qsh-{VERSION}-{TARGET}.tar.gz\n")).unwrap();
    fs::write(&archive, &bad).unwrap();
    refused("sums", &url, "not signed by the qsh release key");
    fs::write(&archive, &good).unwrap();
    fs::write(&sums, &original).unwrap();
    // No signature at all
    let minisig = sums.with_file_name("SHA256SUMS.minisig");
    let signature = fs::read(&minisig).unwrap();
    fs::remove_file(&minisig).unwrap();
    refused("unsigned", &url, "signature is missing");
    // Another version's signature
    sign(&sums, "0.0.1");
    refused("rollback", &url, "not for qsh");
    fs::write(&minisig, &signature).unwrap();
    // Review L1: plain http is not "unavailable" (which would make the host download it): refused
    refused("http", "http://127.0.0.1:9/qsh/releases", "only https:// and file://");
}

/// Review L1: install.sh checks the release signature too, with minisign or OpenSSL 3; with
/// --require-signature it refuses when it cannot. Downloads are served by a stub curl that
/// maps the https mirror to the release directory, and the script's key is the test key.
#[test]
fn install_sh_checks_the_release_signature() {
    let openssl3 = Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).starts_with("OpenSSL 3"));
    if !openssl3 {
        eprintln!("no OpenSSL 3: skipped");
        return;
    }
    let w = world("inst-sh");
    let stub = w.dir.join("stub-server");
    write_exec(&stub, &format!("#!/bin/sh\necho 'qsh-server {VERSION}'\n"));
    let (url, sums) = release(&w, &stub);
    let local = url.trim_start_matches("file://").to_string();
    let bin = w.dir.join("shbin");
    fs::create_dir_all(&bin).unwrap();
    // curl ... -o FILE URL, with https://mirror.invalid/qsh/releases standing for the directory
    write_exec(
        &bin.join("curl"),
        &format!(
            "#!/bin/sh\nout=; url=\nwhile [ $# -gt 0 ]; do case \"$1\" in -o) out=$2; shift 2 ;; -*) shift ;; *) url=$1; shift ;; esac; done\n\
f={local}${{url#https://mirror.invalid/qsh/releases}}\n[ -f \"$f\" ] || exit 22\ncp \"$f\" \"$out\"\n"
        ),
    );
    let script = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/install.sh")).unwrap();
    assert!(
        script.contains(qsh_cli::install::RELEASE_KEY),
        "install.sh has the release key"
    );
    let script = script.replace(qsh_cli::install::RELEASE_KEY, &test_key().to_base64());
    fs::write(w.dir.join("install.sh"), script).unwrap();
    let run = |extra: &[&str]| {
        let out = Command::new("sh")
            .arg(w.dir.join("install.sh"))
            .args(["--server-only", "--version", VERSION, "--prefix"])
            .arg(w.dir.join("prefix"))
            .args(extra)
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("HOME", w.dir.join("home"))
            .env("QSH_DOWNLOAD_URL", "https://mirror.invalid/qsh/releases")
            .output()
            .unwrap();
        (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned())
    };
    let target = w.dir.join("prefix/bin/qsh-server");
    // A uname that says x86_64 Linux, as the world's
    fs::copy(w.dir.join("bin/uname"), bin.join("uname")).unwrap();
    // install.sh verifies with minisign or OpenSSL 3; macOS ships LibreSSL, which cannot, and
    // then a required signature is refused rather than skipped
    let can_verify = Command::new("sh")
        .args(["-c", "command -v minisign || openssl version | grep -q '^OpenSSL 3'"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .is_ok_and(|o| o.status.success());
    let (code, err) = run(&["--require-signature"]);
    if can_verify {
        assert_eq!(code, Some(0), "{err}");
        assert!(err.contains("signature OK"), "{err}");
        assert_eq!(fs::read(&target).unwrap(), fs::read(&stub).unwrap());
        fs::remove_file(&target).unwrap();
    } else {
        assert_eq!(code, Some(1), "{err}");
        assert!(err.contains("cannot check the release signature"), "{err}");
        assert!(!target.exists(), "nothing is installed without a checked signature");
        // The checks below need a verifier
        return;
    }
    // Tampered checksums: refused
    let original = fs::read(&sums).unwrap();
    let mut changed = original.clone();
    changed[0] = if changed[0] == b'0' { b'1' } else { b'0' };
    fs::write(&sums, &changed).unwrap();
    let (code, err) = run(&[]);
    assert_ne!(code, Some(0), "{err}");
    assert!(err.contains("not signed by the qsh release key"), "{err}");
    assert!(!target.exists());
    fs::write(&sums, &original).unwrap();
    // Another version's signature: refused
    sign(&sums, "0.0.1");
    let (code, err) = run(&[]);
    assert_ne!(code, Some(0), "{err}");
    assert!(err.contains("signed for another version"), "{err}");
    assert!(!target.exists(), "{err}");
    // No way to check it here, and required: refused (an openssl that cannot, no minisign)
    sign(&sums, VERSION);
    write_exec(&bin.join("openssl"), "#!/bin/sh\necho 'OpenSSL 1.1.1w'\n");
    let (code, err) = run(&["--require-signature"]);
    assert_ne!(code, Some(0), "{err}");
    assert!(err.contains("cannot check the release signature"), "{err}");
    assert!(!target.exists(), "{err}");
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
        "qsh-server is not installed on bare. Install it to ~/.local/bin there? [y/N]",
        Duration::from_secs(20),
    );
    tty.send(b"y\r");
    tty.wait_for("prompt-ok", Duration::from_secs(60));
    assert_eq!(tty.exit_code(Duration::from_secs(20)), 3, "{:?}", tty.text());
    assert!(tty.text().contains("checksum OK"), "{:?}", tty.text());
    assert!(installed(&w).exists());

    // No: the hint, exit 42; and `install = "never"` asks nothing
    fs::remove_file(installed(&w)).unwrap();
    let _ = w.command(QSH_SERVER, &["stop"]).output();
    let mut tty = Tty::spawn(w.qsh(&["bare", "true"]));
    // Review L5: no by default; an empty answer is no
    tty.wait_for("[y/N]", Duration::from_secs(20));
    tty.send(b"\r");
    assert_eq!(tty.exit_code(Duration::from_secs(20)), 42);
    assert!(tty.text().contains("qsh install bare"), "{:?}", tty.text());
    fs::create_dir_all(w.dir.join("config/qsh")).unwrap();
    fs::write(w.dir.join("config/qsh/config"), "[defaults]\ninstall = \"never\"\n").unwrap();
    fs::set_permissions(w.dir.join("config/qsh/config"), fs::Permissions::from_mode(0o600)).unwrap();
    let mut tty = Tty::spawn(w.qsh(&["bare", "true"]));
    assert_eq!(tty.exit_code(Duration::from_secs(20)), 42, "{:?}", tty.text());
    assert!(!tty.text().contains("[y/N]"), "{:?}", tty.text());
}
