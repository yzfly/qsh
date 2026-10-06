//! `qsh-server doctor`, `qsh-server tune` and `qsh doctor` end to end, with the real
//! programs: doctor's JSON on this machine (read only), `--probe` starting the daemon,
//! `qsh doctor HOST` through the fake ssh probing every transport (and seeing a blocked UDP
//! port for what it is), and tune applying and reverting a fake root byte for byte, with stub
//! commands on PATH. Nothing here needs root or touches this machine's settings.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::{World, QSH_SERVER};
use serde_json::Value;

const IDS: &[&str] = &[
    "daemon",
    "ports",
    "firewall",
    "udp-buffers",
    "gso-gro",
    "tcp-bbr",
    "ipv6",
    "mtu",
    "linger",
    "runtime-dir",
    "selinux",
    "apparmor",
    "clock",
    "limits",
    "conntrack",
    "cloud",
    "container",
    "discovery",
];

fn json_of(out: &std::process::Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: {}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn check<'a>(report: &'a Value, id: &str) -> &'a Value {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("no {id} in {report:#}"))
}

/// A fake root with the files doctor reads, as a Debian host with stock settings shows them.
fn fake_root(dir: &Path) {
    let files: &[(&str, &str)] = &[
        (
            "etc/os-release",
            "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n",
        ),
        ("proc/sys/kernel/hostname", "fakehost\n"),
        ("proc/sys/kernel/osrelease", "6.1.0-26-amd64\n"),
        ("proc/sys/net/core/rmem_max", "212992\n"),
        ("proc/sys/net/core/wmem_max", "212992\n"),
        ("proc/sys/net/core/default_qdisc", "fq_codel\n"),
        ("proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic\n"),
        ("proc/sys/net/ipv4/tcp_allowed_congestion_control", "reno cubic\n"),
        ("proc/sys/net/ipv4/tcp_congestion_control", "cubic\n"),
        ("proc/sys/net/ipv4/ip_unprivileged_port_start", "1024\n"),
        (
            "lib/modules/6.1.0-26-amd64/modules.dep",
            "kernel/net/ipv4/tcp_bbr.ko:\n",
        ),
        ("etc/ssh/sshd_config", "UsePAM yes\n"),
    ];
    for (path, content) in files {
        let p = dir.join(path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }
    fs::create_dir_all(dir.join("run/systemd/system")).unwrap();
    fs::create_dir_all(dir.join("etc/firewalld/zones")).unwrap();
}

/// Every file and directory under `dir`, with the files' contents.
fn tree(dir: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            let rel = p.strip_prefix(dir).unwrap().to_path_buf();
            if p.is_dir() {
                out.insert(rel, None);
                stack.push(p);
            } else {
                out.insert(rel, Some(fs::read(&p).unwrap()));
            }
        }
    }
    out
}

fn script(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Stubs of the system commands tune runs, keeping their state in FAKE_ROOT and FW_STATE:
/// firewall-cmd (firewalld with zone public, writing its zone file like firewalld does),
/// modprobe (tcp_bbr makes bbr available), systemctl, systemd-detect-virt.
fn stubs(bin: &Path) {
    script(
        &bin.join("firewall-cmd"),
        r#"#!/bin/sh
# POSIX tools only: macOS's sed has no `-i` without a suffix and no `\n` in a replacement
set -e
zone="$FAKE_ROOT/etc/firewalld/zones/public.xml"
runtime="$FW_STATE/runtime"
# edit add|remove LINE: the zone file with LINE added before </zone>, or without LINE
edit() {
  awk -v op="$1" -v line="$2" 'op == "add" && $0 == "</zone>" { print line } op == "remove" && $0 == line { next } { print }' "$zone" > "$zone.new"
  cat "$zone.new" > "$zone"
  rm -f "$zone.new"
}
echo "firewall-cmd $*" >> "$FW_STATE/log"
case "$1" in
  --state) echo running; exit 0 ;;
  --get-zone-of-interface=*) echo public; exit 0 ;;
  --get-default-zone) echo public; exit 0 ;;
  --reload) if [ -f "$zone" ]; then cp "$zone" "$runtime"; else rm -f "$runtime"; fi; echo success; exit 0 ;;
  --zone=public)
    echo "public (active)"
    echo "  target: default"
    echo "  services: ssh $(sed -n 's|.*<service name="\(.*\)"/>.*|\1|p' "$runtime" 2>/dev/null | tr '\n' ' ')"
    echo "  ports: $(sed -n 's|.*<port protocol="\(.*\)" port="\(.*\)"/>.*|\2/\1|p' "$runtime" 2>/dev/null | tr '\n' ' ')"
    exit 0 ;;
  --permanent)
    shift 2
    [ -f "$zone" ] || printf '<?xml version="1.0" encoding="utf-8"?>\n<zone>\n  <service name="ssh"/>\n</zone>\n' > "$zone"
    for a; do
      case "$a" in
        --add-port=*) p=${a#--add-port=}; edit add "  <port protocol=\"${p#*/}\" port=\"${p%/*}\"/>" ;;
        --remove-port=*) p=${a#--remove-port=}; edit remove "  <port protocol=\"${p#*/}\" port=\"${p%/*}\"/>" ;;
        --add-service=*) edit add "  <service name=\"${a#--add-service=}\"/>" ;;
        --remove-service=*) edit remove "  <service name=\"${a#--remove-service=}\"/>" ;;
      esac
    done
    echo success; exit 0 ;;
esac
exit 2
"#,
    );
    script(
        &bin.join("modprobe"),
        r#"#!/bin/sh
f="$FAKE_ROOT/proc/sys/net/ipv4/tcp_available_congestion_control"
case "$*" in
  tcp_bbr) echo "reno cubic bbr" > "$f" ;;
  "-r tcp_bbr") echo "reno cubic" > "$f" ;;
  *) exit 1 ;;
esac
"#,
    );
    script(
        &bin.join("systemctl"),
        r#"#!/bin/sh
case "$*" in
  --version) echo "systemd 252 (252.30-1~deb12u2)" ;;
  is-active*) echo inactive; exit 3 ;;
  is-enabled*) echo disabled; exit 1 ;;
  *) exit 1 ;;
esac
"#,
    );
    script(&bin.join("systemd-detect-virt"), "#!/bin/sh\necho none\nexit 1\n");
}

/// `qsh-server tune ARGS --root ROOT --commands BIN`, BIN next to ROOT.
fn tune(root: &Path, env: &[(&str, String)], args: &[&str]) -> (i32, String) {
    let bin = root.parent().unwrap().join("bin");
    tune_with(root, Some(&bin), env, args)
}

fn tune_with(root: &Path, commands: Option<&Path>, env: &[(&str, String)], args: &[&str]) -> (i32, String) {
    let mut c = Command::new(QSH_SERVER);
    c.arg("tune").args(args).arg("--root").arg(root).stdin(Stdio::null());
    if let Some(bin) = commands {
        c.arg("--commands").arg(bin);
    }
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn server_doctor_reports_every_check_read_only() {
    let world = World::new("doc-json");
    let out = world.command(QSH_SERVER, &["doctor", "--json"]).output().unwrap();
    let code = out.status.code().unwrap();
    assert!(code == 0 || code == 1, "{code}");
    let report = json_of(&out);
    assert_eq!(report["doctor"], 1);
    let ids: Vec<&str> = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, IDS);
    assert_eq!(report["daemon"]["running"], false);
    assert!(world.status().is_none(), "doctor without --probe starts nothing");
    // The failing checks decide the exit status
    let failed = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["status"] == "fail");
    assert_eq!(code, i32::from(failed));
    // People get one line per check and the closing line
    let out = world.command(QSH_SERVER, &["doctor"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with("qsh-server doctor: "), "{text}");
    for id in IDS {
        assert!(text.contains(&format!(" {id} ")), "{id}: {text}");
    }
}

#[test]
fn probe_starts_the_daemon_and_reports_its_ports_and_pin() {
    let world = World::new("doc-probe");
    let out = world
        .command(QSH_SERVER, &["doctor", "--json", "--probe"])
        .output()
        .unwrap();
    let report = json_of(&out);
    let d = &report["daemon"];
    assert_eq!(d["running"], true, "{report:#}");
    assert_eq!(d["udp"].as_u64(), Some(u64::from(world.port)));
    assert_eq!(d["tcp"].as_u64(), Some(u64::from(world.port)));
    assert_eq!(d["cert_sha256"].as_str().map(str::len), Some(64));
    assert_eq!(check(&report, "daemon")["status"], "ok");
    assert!(check(&report, "ports")["summary"]
        .as_str()
        .unwrap()
        .starts_with("the daemon holds UDP+TCP"));
    assert!(world.status().is_some());
}

#[test]
fn qsh_doctor_host_probes_every_transport() {
    let world = World::new("doc-host");
    let out = world
        .qsh(&["doctor", "--json", "fakehost"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let code = out.status.code().unwrap();
    assert!(
        code == 0 || code == 1,
        "{code}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = json_of(&out);
    assert_eq!(report["doctor"], 1);
    assert_eq!(report["server"]["doctor"], 1, "{report:#}");
    let probes = report["probes"].as_array().unwrap();
    let outcome = |t: &str| {
        probes
            .iter()
            .find(|p| p["transport"] == t)
            .map(|p| p["outcome"].as_str().unwrap().to_string())
    };
    for t in ["quic", "tls", "ssh"] {
        assert_eq!(outcome(t).as_deref(), Some("ok"), "{t}: {report:#}");
    }
    let quic = probes
        .iter()
        .find(|p| p["port"] == world.port && p["rtt_ms"].is_u64())
        .unwrap();
    assert!(quic["mtu"].as_u64().unwrap() >= 1200, "{quic}");
    assert_eq!(
        report["diagnosis"][0],
        "QUIC works from here: qsh uses it, and keeps sessions across address changes"
    );
    // The outcome is remembered for this network
    assert!(world.dir.join("state/qsh/paths.json").exists());
    // And people get the three sections
    let out = world
        .qsh(&["doctor", "fakehost"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    for part in [
        "qsh doctor: fakehost",
        "This machine",
        "From here to fakehost",
        "On ",
        "Diagnosis",
    ] {
        assert!(text.contains(part), "{part}: {text}");
    }
}

#[test]
fn qsh_doctor_host_sees_that_this_network_blocks_udp() {
    let world = World::new("doc-udp");
    // A UDP port that swallows everything, announced in place of the daemon's
    let hole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let hole_port = hole.local_addr().unwrap().port();
    let root = world.dir.join("fakeroot");
    fake_root(&root);
    // No init system in it: nothing asks this machine's systemctl about firewall services
    fs::remove_dir_all(root.join("run")).unwrap();
    // ssh: the world's fake, with doctor run on the fake root (no host firewall) and its
    // announced UDP port replaced by the black hole
    let bin = world.dir.join("bin");
    fs::rename(bin.join("ssh"), bin.join("ssh-real")).unwrap();
    script(
        &bin.join("ssh"),
        &format!(
            r#"#!/bin/sh
real="$(dirname "$0")/ssh-real"
case "$*" in
  *"doctor --json --probe"*) ;;
  *) exec "$real" "$@" ;;
esac
for a; do
  shift
  case "$a" in
    *"doctor --json --probe"*) a=$(printf '%s' "$a" | sed "s|doctor --json --probe|doctor --json --probe --root {root} --commands {bin}|") ;;
  esac
  set -- "$@" "$a"
done
out=$("$real" "$@"); status=$?
printf '%s\n' "$out" | sed 's/"udp":[0-9]*/"udp":{hole_port}/g'
exit $status
"#,
            root = root.display(),
            bin = bin.display()
        ),
    );
    let out = world
        .qsh(&["doctor", "--json", "fakehost"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let report = json_of(&out);
    let probes = report["probes"].as_array().unwrap();
    let quic = probes.iter().find(|p| p["port"] == hole_port).unwrap();
    assert_eq!(quic["outcome"], "timeout", "{report:#}");
    assert_eq!(check(&report["server"], "firewall")["status"], "ok");
    assert_eq!(
        report["diagnosis"][0],
        "nothing on the server blocks UDP, and TLS works: your network blocks UDP; qsh will use TLS on this network (remembered)"
    );
    assert_eq!(
        out.status.code(),
        Some(i32::from(
            report["server"]["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["status"] == "fail")
        ))
    );
    // Remembered: QUIC is blocked here, for the next connection
    let memory = fs::read_to_string(world.dir.join("state/qsh/paths.json")).unwrap();
    assert!(memory.contains("\"fail\""), "{memory}");
    drop(hole);
}

#[test]
fn tune_applies_and_reverts_a_fake_root_byte_for_byte() {
    // Reached through a symbolic link, as every temporary directory is on macOS (/tmp ->
    // /private/tmp): only what is below the root is walked without following links
    let real = PathBuf::from(format!("/tmp/qsht-{}-tune.real", std::process::id()));
    let dir = PathBuf::from(format!("/tmp/qsht-{}-tune", std::process::id()));
    let _ = fs::remove_file(&dir);
    let _ = fs::remove_dir_all(&real);
    fs::create_dir_all(&real).unwrap();
    std::os::unix::fs::symlink(&real, &dir).unwrap();
    let (root, bin, state) = (dir.join("root"), dir.join("bin"), dir.join("fw"));
    for d in [&bin, &state] {
        fs::create_dir_all(d).unwrap();
    }
    fake_root(&root);
    stubs(&bin);
    let env = vec![
        ("PATH", format!("{}:/usr/bin:/bin", bin.display())),
        ("FAKE_ROOT", root.display().to_string()),
        ("FW_STATE", state.display().to_string()),
        ("QSH_SERVER_PORTS", "60443-60542".into()),
        ("HOME", dir.display().to_string()),
        ("XDG_CONFIG_HOME", dir.join("config").display().to_string()),
    ];
    let before = tree(&root);

    // The dry run shows the plan and changes nothing
    let (code, text) = tune(&root, &env, &[]);
    assert_eq!(code, 0, "{text}");
    for part in [
        "+++ b/etc/sysctl.d/90-qsh.conf",
        "+net.core.rmem_max = 4194304",
        "+tcp_bbr",
        "modprobe tcp_bbr",
        "firewall-cmd --permanent --zone=public --add-port=60443-60542/udp --add-port=60443-60542/tcp",
        "Nothing changed.",
    ] {
        assert!(text.contains(part), "{part}: {text}");
    }
    assert_eq!(tree(&root), before);
    // --apply without a terminal and without --yes: refused
    let (code, text) = tune(&root, &env, &["--apply"]);
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("no terminal to confirm on"), "{text}");
    assert_eq!(tree(&root), before);

    let (code, text) = tune(&root, &env, &["--apply", "--yes"]);
    assert_eq!(code, 0, "{text}");
    assert_eq!(
        fs::read_to_string(root.join("proc/sys/net/core/rmem_max")).unwrap(),
        "4194304\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("proc/sys/net/ipv4/tcp_allowed_congestion_control")).unwrap(),
        "reno cubic bbr\n"
    );
    assert!(root.join("var/lib/qsh/tune.json").exists());
    let zone = fs::read_to_string(root.join("etc/firewalld/zones/public.xml")).unwrap();
    let log = fs::read_to_string(state.join("log")).unwrap_or_default();
    assert!(zone.contains("60443-60542"), "{zone}\n{log}\n{text}");

    // doctor agrees
    let mut c = Command::new(QSH_SERVER);
    c.args(["doctor", "--json", "--root"])
        .arg(&root)
        .arg("--commands")
        .arg(&bin)
        .stdin(Stdio::null());
    for (k, v) in &env {
        c.env(k, v);
    }
    let report = json_of(&c.output().unwrap());
    for id in ["udp-buffers", "tcp-bbr", "firewall"] {
        assert_eq!(check(&report, id)["status"], "ok", "{id}: {report:#}");
    }

    // Twice: nothing to change
    let (code, text) = tune(&root, &env, &["--apply", "--yes"]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("nothing to change"), "{text}");

    // Revert: the root is byte for byte as before
    let (code, text) = tune(&root, &env, &["--revert", "--yes"]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("Reverted."), "{text}");
    assert_eq!(tree(&root), before, "{text}");
    let log = fs::read_to_string(state.join("log")).unwrap();
    assert!(log.ends_with("firewall-cmd --reload\n"), "{log}");
    let (code, text) = tune(&root, &env, &["--revert", "--yes"]);
    assert_eq!((code, text.contains("nothing to revert")), (0, true), "{text}");
    let _ = fs::remove_file(&dir);
    let _ = fs::remove_dir_all(&real);
}

#[test]
fn qsh_doctor_without_a_host_checks_this_machine() {
    let world = World::new("doc-local");
    let out = world.qsh(&["doctor", "--json"]).stdin(Stdio::null()).output().unwrap();
    let report = json_of(&out);
    let ids: Vec<&str> = report["client"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["network", "udp-buffers", "ssh", "path-memory"]);
    // `qsh -- doctor` is still a host named doctor: the fake ssh runs it
    let (_, _, err) = world.run(&["--", "doctor", "true"]);
    assert!(!err.contains("not available"), "{err}");
}

/// Review H3: `--root` stands in for `/` for the files only; it never runs a command of the
/// host. Before, a planted record under the root made `tune --revert --root R` run whatever
/// program it named, from PATH, as whoever ran it.
#[test]
fn a_stand_in_root_runs_no_command_of_the_host() {
    let dir = PathBuf::from(format!("/tmp/qsht-{}-tune-nocmd", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let (root, bin) = (dir.join("root"), dir.join("bin"));
    fs::create_dir_all(&bin).unwrap();
    fake_root(&root);
    let marker = dir.join("ran");
    // On PATH, but not given with --commands
    script(
        &bin.join("modprobe"),
        &format!("#!/bin/sh\ntouch {}\n", marker.display()),
    );
    let env = vec![
        ("PATH", format!("{}:/usr/bin:/bin", bin.display())),
        ("HOME", dir.display().to_string()),
        ("XDG_CONFIG_HOME", dir.join("config").display().to_string()),
    ];
    let (code, text) = tune_with(&root, None, &env, &["--apply", "--yes"]);
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("modprobe cannot be run"), "{text}");
    assert!(!marker.exists(), "a command of the host ran: {text}");
    let _ = fs::remove_dir_all(&dir);
}

/// Review H3: what a record under a stand-in root names cannot reach outside it: a path with
/// `..` is refused with the record, and a symbolic link (here a sysctl file that points at a
/// file outside) is never followed, neither to read nor to write.
#[test]
fn a_planted_record_cannot_reach_outside_the_stand_in_root() {
    let dir = PathBuf::from(format!("/tmp/qsht-{}-tune-planted", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let (root, bin) = (dir.join("root"), dir.join("bin"));
    fs::create_dir_all(&bin).unwrap();
    fake_root(&root);
    stubs(&bin);
    let victim = dir.join("victim.txt");
    fs::write(&victim, "precious\n").unwrap();
    let sha = |t: &str| qsh_core::crypto::hex(&qsh_core::crypto::sha256(t.as_bytes()));
    let record_dir = root.join("var/lib/qsh");
    fs::create_dir_all(&record_dir).unwrap();
    fs::set_permissions(&record_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let plant = |changes: serde_json::Value| {
        let record = serde_json::json!({"qsh_tune": 1, "version": "0.0.1", "created_dirs": [], "changes": changes});
        let path = record_dir.join("tune.json");
        fs::write(&path, record.to_string()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    };
    let env = vec![
        ("PATH", format!("{}:/usr/bin:/bin", bin.display())),
        ("FAKE_ROOT", root.display().to_string()),
        ("FW_STATE", dir.display().to_string()),
        ("HOME", dir.display().to_string()),
        ("XDG_CONFIG_HOME", dir.join("config").display().to_string()),
    ];
    // A path that escapes: refused with the whole record
    plant(
        serde_json::json!([{"kind": "file", "path": "/../victim.txt", "before": null,
        "sha256": sha("precious\n"), "fixes": ["udp-buffers"], "created_dirs": []}]),
    );
    let (code, text) = tune(&root, &env, &["--revert", "--yes"]);
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("did not write"), "{text}");
    assert_eq!(fs::read_to_string(&victim).unwrap(), "precious\n");
    // A sysctl file that is a link to the victim, recorded as tune left it
    let sysctl = root.join("proc/sys/net/core/rmem_max");
    fs::remove_file(&sysctl).unwrap();
    std::os::unix::fs::symlink(&victim, &sysctl).unwrap();
    plant(
        serde_json::json!([{"kind": "sysctl", "fix": "udp-buffers", "key": "net.core.rmem_max",
        "before": "212992", "after": "precious"}]),
    );
    let (code, text) = tune(&root, &env, &["--revert", "--yes"]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("left alone"), "{text}");
    assert_eq!(fs::read_to_string(&victim).unwrap(), "precious\n");
    // The record itself as a link: refused
    let elsewhere = dir.join("record.json");
    fs::write(&elsewhere, "{}").unwrap();
    let _ = fs::remove_file(record_dir.join("tune.json"));
    std::os::unix::fs::symlink(&elsewhere, record_dir.join("tune.json")).unwrap();
    let (code, text) = tune(&root, &env, &["--revert", "--yes"]);
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("symbolic link"), "{text}");
    let _ = fs::remove_dir_all(&dir);
}
