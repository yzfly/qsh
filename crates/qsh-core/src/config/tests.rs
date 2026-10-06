use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

fn parse(text: &str) -> (Config, Vec<Warning>) {
    Config::parse(text, Path::new("test.toml")).unwrap()
}

fn parse_err(text: &str) -> ConfigError {
    Config::parse(text, Path::new("test.toml")).unwrap_err()
}

/// A directory of its own under the system's temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "qsh-config-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    fn file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, text).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn no_files_give_the_defaults() {
    let (config, warnings) = Config::load(&ConfigPaths::default()).unwrap();
    assert!(warnings.is_empty());
    assert_eq!(config.for_host("host", None), HostSettings::default());
    assert_eq!(config.server(), ServerSettings::default());
    assert_eq!(config.files().count(), 0);
    let d = HostSettings::default();
    assert_eq!(d.transports, [Transport::Quic, Transport::Tls, Transport::Ssh]);
    assert_eq!(d.escape_char, Some(b'~'));
    assert_eq!(d.ssh, "ssh");
}

#[test]
fn every_client_key_is_read() {
    let (config, warnings) = parse(
        r#"
[defaults]
transports = ["tls", "ssh"]
server_command = "/opt/qsh/bin/qsh-server"
escape_char = "^]"
predict = "never"
status_line = false
ssh = "/usr/local/bin/ssh"
ssh_options = ["-o", "Compression=yes"]
keepalive = 25
install = "never"
replay_on_attach = false
"#,
    );
    assert!(warnings.is_empty(), "{warnings:?}");
    let h = config.for_host("any", None);
    assert_eq!(
        h,
        HostSettings {
            transports: vec![Transport::Tls, Transport::Ssh],
            server_command: Some("/opt/qsh/bin/qsh-server".into()),
            escape_char: Some(0x1d),
            predict: Predict::Never,
            status_line: false,
            ssh: "/usr/local/bin/ssh".into(),
            ssh_options: vec!["-o".into(), "Compression=yes".into()],
            keepalive: Keepalive::Every(Duration::from_secs(25)),
            install: Install::Never,
            replay_on_attach: false,
        }
    );
    let (config, _) = parse("[defaults]\nkeepalive = \"auto\"\nescape_char = \"none\"\n");
    let h = config.for_host("any", None);
    assert_eq!(h.keepalive, Keepalive::Auto);
    assert_eq!(h.escape_char, None);
    let (config, _) = parse("[defaults]\nkeepalive = \"1m\"\nescape_char = \"%\"\n");
    let h = config.for_host("any", None);
    assert_eq!(h.keepalive, Keepalive::Every(Duration::from_secs(60)));
    assert_eq!(h.escape_char, Some(b'%'));
}

#[test]
fn first_match_wins_per_key() {
    let (config, warnings) = parse(
        r#"
[host."web1"]
transports = ["ssh"]

[host."web*"]
transports = ["quic"]
escape_char = "%"

[defaults]
escape_char = "+"
status_line = false
"#,
    );
    assert!(warnings.is_empty());
    let web1 = config.for_host("web1", None);
    assert_eq!(web1.transports, [Transport::Ssh]);
    assert_eq!(web1.escape_char, Some(b'%'));
    assert!(!web1.status_line);
    let web2 = config.for_host("web2", None);
    assert_eq!(web2.transports, [Transport::Quic]);
    let db = config.for_host("db", None);
    assert_eq!(db.transports, HostSettings::default().transports);
    assert_eq!(db.escape_char, Some(b'+'));
}

#[test]
fn tables_apply_in_file_order_not_alphabetical() {
    // "z*" sorts after "a*"; the file lists it first, so it wins
    let (config, _) = parse("[host.\"z*,zebra\"]\nssh = \"first\"\n[host.\"*\"]\nssh = \"second\"\n");
    assert_eq!(config.for_host("zebra", None).ssh, "first");
    assert_eq!(config.for_host("other", None).ssh, "second");
}

#[test]
fn patterns_match_the_destination_or_the_resolved_name() {
    let (config, _) = parse(
        r#"
[host."*.corp.example.com,!*.lab.corp.example.com"]
transports = ["tls"]
[host."jump?"]
transports = ["ssh"]
"#,
    );
    // The alias as typed matches nothing; the HostName ssh resolved does
    assert_eq!(
        config.for_host("me@build", Some("build.corp.example.com")).transports,
        [Transport::Tls]
    );
    assert_eq!(config.for_host("x.corp.example.com", None).transports, [Transport::Tls]);
    // Negation vetoes, whichever name it matches
    assert_eq!(
        config.for_host("build", Some("a.lab.corp.example.com")).transports,
        HostSettings::default().transports
    );
    assert_eq!(config.for_host("ssh://u@JUMP1:2222", None).transports, [Transport::Ssh]);
    assert_eq!(
        config.for_host("jump12", None).transports,
        HostSettings::default().transports
    );
}

#[test]
fn glob_matching() {
    let m = |p: &str, names: &[&str]| PatternList::parse(p).unwrap().matches(names);
    assert!(m("*", &["anything"]));
    assert!(m("web*", &["web"]));
    assert!(m("web*", &["WEB-1"]));
    assert!(m("w?b", &["wib"]));
    assert!(!m("w?b", &["wb"]));
    assert!(m("*.example.com", &["a.b.example.com"]));
    assert!(!m("*.example.com", &["example.com"]));
    assert!(m("a*b*c", &["axxbyyc"]));
    assert!(!m("a*b*c", &["axxbyy"]));
    assert!(m("a, b", &["b"]));
    assert!(m("a b", &["b"]));
    assert!(!m("!a", &["a"]));
    assert!(!m("!a", &["b"]), "negations alone match nothing");
    assert!(m("*,!secret*", &["public"]));
    assert!(!m("*,!secret*", &["secret1"]));
    assert!(!m("*,!secret*", &["public", "secret1"]));
    // No exponential backtracking
    let long = "a".repeat(200);
    assert!(!m("*a*a*a*a*a*a*a*a*b", &[long.as_str()]));
    for bad in ["", ",", "a,,b", "a,", "!", "a, !"] {
        assert!(PatternList::parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn destination_hosts() {
    assert_eq!(destination_host("host"), "host");
    assert_eq!(destination_host("user@host"), "host");
    assert_eq!(destination_host("us@er@host"), "host");
    assert_eq!(destination_host("ssh://user@host:2222"), "host");
    assert_eq!(destination_host("ssh://host"), "host");
    assert_eq!(destination_host("ssh://u@[2001:db8::1]:22"), "2001:db8::1");
}

#[test]
fn unknown_keys_warn_with_their_line() {
    let (config, warnings) = parse(
        "[defaults]\nstatus_line = true\nfuture_key = 1\n\n[forward]\nx = 1\n[server]\nmystery = 2\n[server.preauth]\nodd = 3\n",
    );
    let shown: Vec<String> = warnings.iter().map(ToString::to_string).collect();
    assert_eq!(
        shown,
        [
            "test.toml:3: unknown key `future_key`, ignored",
            "test.toml:5: unknown key `forward`, ignored",
            "test.toml:8: unknown key `server.mystery`, ignored",
            "test.toml:10: unknown key `preauth.odd`, ignored",
        ]
    );
    assert!(config.for_host("h", None).status_line);
    let (_, warnings) = parse("transports = [\"quic\"]\n");
    assert!(warnings[0].message.contains("[defaults]"), "{warnings:?}");
}

#[test]
fn unknown_transports_are_skipped_with_a_warning() {
    let (config, warnings) = parse("[defaults]\ntransports = [\"webtransport\", \"quic\", \"quic\"]\n");
    assert_eq!(config.for_host("h", None).transports, [Transport::Quic]);
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert_eq!(warnings[0].line, Some(2));
    let e = parse_err("[defaults]\ntransports = [\"webtransport\"]\n");
    assert!(e.message.contains("no usable transport"), "{e}");
}

#[test]
fn bad_values_are_errors_with_their_line() {
    let cases = [
        ("[defaults]\n\ntransports = \"quic\"\n", 3, "must be an array"),
        ("[defaults]\ntransports = [1]\n", 2, "array of strings"),
        ("[defaults]\nescape_char = \"ab\"\n", 2, "escape_char"),
        ("[defaults]\nescape_char = \"\"\n", 2, "escape_char"),
        ("[defaults]\npredict = \"sometimes\"\n", 2, "\"auto\""),
        ("[defaults]\nstatus_line = \"yes\"\n", 2, "true or false"),
        ("[defaults]\nkeepalive = 0\n", 2, "keepalive"),
        ("[defaults]\nkeepalive = 99999\n", 2, "keepalive"),
        ("[defaults]\nkeepalive = \"soon\"\n", 2, "keepalive"),
        ("[defaults]\ninstall = \"always\"\n", 2, "\"ask\""),
        ("[defaults]\nssh = \"\"\n", 2, "program"),
        ("[defaults]\nssh_options = \"-v\"\n", 2, "array of strings"),
        ("[defaults]\nserver_command = \"a\\nb\"\n", 2, "control"),
        ("defaults = 1\n", 1, "must be a table"),
        ("[host]\nweb = 1\n", 2, "must be a table"),
        ("[host.\"a,,b\"]\nssh = \"x\"\n", 1, "empty pattern"),
        ("[server]\nports = \"60443\"\nmax_sessions = 0\n", 3, "max_sessions"),
        ("[server]\nports = \"9-1\"\n", 2, "port range"),
        ("[server]\nports = \"0-10\"\n", 2, "port range"),
        ("[server]\nports = 70000\n", 2, "ports"),
        ("[server]\ndetached_ttl = \"forever\"\n", 2, "detached_ttl"),
        ("[server]\nreplay_bytes = \"1K\"\n", 2, "replay_bytes"),
        ("[server]\nextra_ports = [443, 0]\n", 2, "extra_ports"),
        ("[server.preauth]\nfailure_refill = 0\n", 2, "failure_refill"),
    ];
    for (text, line, needle) in cases {
        let e = parse_err(text);
        assert_eq!(e.line, Some(line), "{text:?}: {e}");
        assert!(e.message.contains(needle), "{text:?}: {e}");
        assert!(e.to_string().starts_with(&format!("test.toml:{line}: ")), "{e}");
    }
}

#[test]
fn syntax_errors_name_the_line() {
    let e = parse_err("[defaults]\nstatus_line = true\nescape_char = \n");
    assert_eq!(e.line, Some(3), "{e}");
    let e = parse_err("[defaults]\n[defaults]\n");
    assert_eq!(e.line, Some(2), "{e}");
    let e = parse_err("[defaults]\nssh = \"a\"\nssh = \"b\"\n");
    assert_eq!(e.line, Some(3), "{e}");
}

#[test]
fn every_server_key_is_read() {
    let (config, warnings) = parse(
        r#"
[server]
ports = "61000-61099"
extra_ports = [443, 8443]
max_sessions = 50
detached_ttl = "1d"
exited_ttl = 600
replay_bytes = "16M"

[server.preauth]
connections = 128
per_source = 4
failure_burst = 5
failure_refill = "30s"
"#,
    );
    assert!(warnings.is_empty(), "{warnings:?}");
    let s = config.server();
    assert_eq!(
        s,
        ServerSettings {
            ports: Some(61000..=61099),
            extra_ports: Some(vec![443, 8443]),
            max_sessions: Some(50),
            detached_ttl: Some(Duration::from_secs(86400)),
            exited_ttl: Some(Duration::from_secs(600)),
            replay_bytes: Some(16 << 20),
            preauth: PreauthSettings {
                connections: Some(128),
                per_source: Some(4),
                failure_burst: Some(5),
                failure_refill: Some(Duration::from_secs(30)),
            },
        }
    );
    let mut server = ServerConfig::new(Paths::under(Path::new("/nonexistent")));
    s.apply(&mut server);
    assert_eq!(server.ports, 61000..=61099);
    assert_eq!(server.detached_ttl, Duration::from_secs(86400));
    assert_eq!(server.exited_ttl, Duration::from_secs(600));
    assert_eq!(server.output_replay, 16 << 20);
    assert_eq!(server.preauth.total, 128);
    assert_eq!(server.preauth.per_source, 4);
    assert_eq!(server.preauth.failure_burst, 5);
    assert_eq!(server.preauth.failure_refill, Duration::from_secs(30));
    // A single port
    let (config, _) = parse("[server]\nports = 60443\n");
    assert_eq!(config.server().ports, Some(60443..=60443));
}

#[test]
fn time_and_size_formats() {
    assert_eq!(parse_seconds("90"), Some(90));
    assert_eq!(parse_seconds("90s"), Some(90));
    assert_eq!(parse_seconds("10m"), Some(600));
    assert_eq!(parse_seconds("1h30m"), Some(5400));
    assert_eq!(parse_seconds("1H30"), Some(3630));
    assert_eq!(parse_seconds("2w"), Some(14 * 86400));
    for bad in ["", "h", "1x", "1.5h", "-1", "99999999999999999999"] {
        assert_eq!(parse_seconds(bad), None, "{bad:?}");
    }
    assert_eq!(parse_size("8M"), Some(8 << 20));
    assert_eq!(parse_size("8MiB"), Some(8 << 20));
    assert_eq!(parse_size("512 KiB"), Some(512 << 10));
    assert_eq!(parse_size("1G"), Some(1 << 30));
    assert_eq!(parse_size("1048576"), Some(1 << 20));
    for bad in ["", "M", "8T", "x8M", "99999999999999999999G"] {
        assert_eq!(parse_size(bad), None, "{bad:?}");
    }
    assert_eq!(parse_escape_char("^a"), Some(Some(1)));
    assert_eq!(parse_escape_char("^["), Some(Some(0x1b)));
    assert_eq!(parse_escape_char("^"), Some(Some(b'^')));
    assert_eq!(parse_escape_char("^1"), None);
    assert_eq!(parse_escape_char("é"), None);
    assert_eq!(parse_escape_char("\t"), None);
}

#[test]
fn the_race_follows_the_order() {
    let race = |t: &[Transport]| {
        HostSettings {
            transports: t.to_vec(),
            ..HostSettings::default()
        }
        .race()
    };
    let ms = Duration::from_millis;
    let r = race(&[Transport::Quic, Transport::Tls, Transport::Ssh]);
    assert_eq!((r.quic, r.tls, r.ssh), (Some(ms(0)), Some(ms(400)), Some(ms(3000))));
    let default = RaceConfig::default();
    assert_eq!((r.quic, r.tls, r.ssh), (default.quic, default.tls, default.ssh));
    let r = race(&[Transport::Tls, Transport::Quic]);
    assert_eq!((r.quic, r.tls, r.ssh), (Some(ms(400)), Some(ms(0)), None));
    let r = race(&[Transport::Quic, Transport::Ssh]);
    assert_eq!((r.quic, r.tls, r.ssh), (Some(ms(0)), None, Some(ms(3000))));
    let r = race(&[Transport::Ssh, Transport::Quic]);
    assert_eq!((r.quic, r.tls, r.ssh), (Some(ms(400)), None, Some(ms(0))));
}

#[test]
fn the_environment_overrides_the_files() {
    let (config, _) = parse("[defaults]\ntransports = [\"quic\"]\nssh = \"from-file\"\n[server]\nports = \"1-2\"\n");
    let env = |vars: &'static [(&'static str, &'static str)]| {
        move |name: &str| vars.iter().find(|(k, _)| *k == name).map(|(_, v)| OsString::from(v))
    };
    let mut h = config.for_host("h", None);
    let warnings = h.apply_env(env(&[("QSH_TRANSPORTS", "ssh, tls,bogus"), ("QSH_SSH", "/bin/myssh")]));
    assert_eq!(h.transports, [Transport::Ssh, Transport::Tls]);
    assert_eq!(h.ssh, "/bin/myssh");
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    // Nothing usable: the file's value stays
    let mut h = config.for_host("h", None);
    let warnings = h.apply_env(env(&[("QSH_TRANSPORTS", "bogus"), ("QSH_SSH", "")]));
    assert_eq!(h.transports, [Transport::Quic]);
    assert_eq!(h.ssh, "from-file");
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    let mut s = config.server();
    assert!(s.apply_env(env(&[("QSH_SERVER_PORTS", "7000-7009")])).is_empty());
    assert_eq!(s.ports, Some(7000..=7009));
    let mut s = config.server();
    assert_eq!(s.apply_env(env(&[("QSH_SERVER_PORTS", "x")])).len(), 1);
    assert_eq!(s.ports, Some(1..=2));
}

#[test]
fn the_user_file_overrides_the_system_file() {
    let dir = TempDir::new();
    let system = dir.file(
        "system",
        r#"
[host."web*"]
transports = ["tls"]
escape_char = "%"
[defaults]
status_line = false
ssh = "system-ssh"
[server]
ports = "61000-61009"
max_sessions = 10
"#,
    );
    let user = dir.file(
        "user",
        r#"
[defaults]
transports = ["ssh"]
ssh = "user-ssh"
[server]
max_sessions = 20
"#,
    );
    let paths = ConfigPaths {
        user: Some(user.clone()),
        system: Some(system.clone()),
    };
    let (config, warnings) = Config::load(&paths).unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(config.files().collect::<Vec<_>>(), [user.as_path(), system.as_path()]);
    // The user's [defaults] come before the system's [host] tables, as in ssh
    let web = config.for_host("web1", None);
    assert_eq!(web.transports, [Transport::Ssh]);
    assert_eq!(web.escape_char, Some(b'%'));
    assert_eq!(web.ssh, "user-ssh");
    assert!(!web.status_line);
    let server = config.server();
    assert_eq!(server.ports, Some(61000..=61009));
    assert_eq!(server.max_sessions, Some(20));
    // Missing files are skipped
    let paths = ConfigPaths {
        user: Some(dir.0.join("missing")),
        system: Some(system),
    };
    let (config, _) = Config::load(&paths).unwrap();
    assert_eq!(config.files().count(), 1);
    assert_eq!(config.for_host("db", None).ssh, "system-ssh");
}

#[test]
fn files_others_may_write_are_refused() {
    let dir = TempDir::new();
    let user = dir.file("user", "[defaults]\nssh = \"/tmp/evil\"\n");
    for mode in [0o666, 0o664, 0o646] {
        fs::set_permissions(&user, fs::Permissions::from_mode(mode)).unwrap();
        let e = Config::load(&ConfigPaths {
            user: Some(user.clone()),
            system: None,
        })
        .unwrap_err();
        assert!(e.message.contains("chmod go-w"), "{e}");
        assert_eq!(e.file, user);
    }
    fs::set_permissions(&user, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(Config::load(&ConfigPaths {
        user: Some(user.clone()),
        system: None,
    })
    .is_ok());
    // Another user's file (root is fine)
    assert!(check_owner_and_mode(&user, 1234, 0o644, 1000)
        .unwrap_err()
        .contains("bad owner"));
    assert!(check_owner_and_mode(&user, 0, 0o644, 1000).is_ok());
    assert!(check_owner_and_mode(&user, 1000, 0o100600, 1000).is_ok());
}

#[test]
fn odd_files_are_refused() {
    let dir = TempDir::new();
    let load = |p: PathBuf| {
        Config::load(&ConfigPaths {
            user: Some(p),
            system: None,
        })
    };
    // A directory
    let e = load(dir.0.clone()).unwrap_err();
    assert!(e.message.contains("regular file"), "{e}");
    // A FIFO: refused without hanging
    let fifo = dir.0.join("fifo");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .is_ok_and(|s| s.success());
    if made {
        let e = load(fifo).unwrap_err();
        assert!(e.message.contains("regular file"), "{e}");
    }
    // Too large
    let big = dir.file("big", &"# padding\n".repeat((MAX_FILE_SIZE as usize) / 10 + 1));
    let e = load(big).unwrap_err();
    assert!(e.message.contains("larger than"), "{e}");
    // Not UTF-8, on line 2
    let latin1 = dir.0.join("latin1");
    fs::write(&latin1, b"# ok\n# caf\xe9\n").unwrap();
    fs::set_permissions(&latin1, fs::Permissions::from_mode(0o644)).unwrap();
    let e = load(latin1).unwrap_err();
    assert_eq!(e.line, Some(2), "{e}");
    // Syntax errors carry the file's name
    let broken = dir.file("broken", "[defaults\n");
    let e = load(broken.clone()).unwrap_err();
    assert_eq!(e.file, broken);
    assert_eq!(e.line, Some(1));
}

#[test]
fn unreadable_files_are_skipped_with_a_warning() {
    if crate::sys::euid() == 0 {
        // root reads everything
        return;
    }
    let dir = TempDir::new();
    let user = dir.file("user", "[defaults]\nssh = \"x\"\n");
    fs::set_permissions(&user, fs::Permissions::from_mode(0o000)).unwrap();
    let (config, warnings) = Config::load(&ConfigPaths {
        user: Some(user),
        system: None,
    })
    .unwrap();
    assert_eq!(config.files().count(), 0);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].message.contains("ignored"));
}

#[test]
fn the_man_page_example_is_valid() {
    // Keep in step with the EXAMPLES of xtask/src/qsh_config.5
    let (config, warnings) = parse(include_str!("example.toml"));
    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(config.for_host("me@build3", None).transports, [Transport::Ssh]);
    assert_eq!(
        config.for_host("db", Some("db.corp.example.com")).transports,
        [Transport::Tls, Transport::Ssh]
    );
    assert_eq!(config.for_host("db", Some("db.corp.example.com")).escape_char, None);
    assert_eq!(config.for_host("laptop", None).escape_char, Some(0x1d));
    assert_eq!(config.server().ports, Some(61000..=61099));
}

#[test]
fn parsing_takes_any_text() {
    let mut rng = crate::testutil::Rng::new(11);
    let pieces = [
        "[defaults]\n",
        "[host.\"",
        "*",
        "!",
        ",",
        "\"]\n",
        "[server]\n",
        "[server.preauth]\n",
        "transports",
        "ssh",
        " = ",
        "[\"quic\"",
        ", \"x\"]",
        "\"",
        "1h",
        "-",
        "99999999999999999999",
        "true",
        "\n",
        "{",
        "}",
        "#",
        "=",
        ".",
        "keepalive",
        "ports",
        "escape_char",
        "\"^",
        "é",
        "\\u0000",
    ];
    for _ in 0..3000 {
        let n = rng.range(0, 40);
        let text: String = (0..n)
            .map(|_| pieces[rng.range(0, pieces.len() as u64) as usize])
            .collect();
        if let Ok((config, _)) = Config::parse(&text, Path::new("random")) {
            let host = config.for_host("user@web1", Some("web1.example.com"));
            let _ = host.race();
            let _ = config.server();
        }
    }
}
