//! Chaos tests and the benchmark (docs/m2.md sections 12.2 and 12.4).
//!
//! Every test here does nothing unless `QSH_CHAOS=1`, and then needs root: it builds the
//! topology of `tests/chaos/netns.sh` (client, router and server network namespaces, netem on
//! the router, sshd and a test user in the server namespace) and drives the real `qsh`, `ssh`
//! and `mosh` in the client namespace on pseudo terminals. Run it in a disposable machine (the
//! `chaos` and `bench` workflows), never on a shared one:
//!
//! ```sh
//! cargo test --release -p qsh-cli --features test-hooks --test chaos --no-run   # then, as root:
//! QSH_CHAOS=1 target/release/deps/chaos-* --test-threads=1 --nocapture [FILTER...]
//! ```
//!
//! Each scenario writes its measurements and checks as JSON lines to `QSH_CHAOS_OUT` (default
//! `$QSH_CHAOS_DIR/results.jsonl`); `tests/chaos/report.py` renders them as Markdown.
//!
//! A check is **hard** (the test fails) or **report-only**: a criterion of m2.md whose feature
//! has not landed yet carries the work package it waits for (`until`), is printed and recorded,
//! and fails nothing. `QSH_CHAOS_STRICT=1` makes every check hard: run that once the package is
//! merged, then drop its `until`.
//!
//! Environment: `QSH_CHAOS_DIR` (work directory, default /tmp/qsh-chaos), `QSH_CHAOS_PROFILES`
//! (comma-separated subset of each scenario's profiles), `QSH_CHAOS_RUNS` (Ctrl-C runs per
//! profile, default 5), `QSH_CHAOS_NAT_IDLE` (seconds, default 40), `QSH_CHAOS_WINDOW`
//! (throughput window, seconds, default 20), `QSH_CHAOS_QSH` / `QSH_CHAOS_SERVER` (binaries,
//! default the ones cargo built), `QSH_CHAOS_NETNS` (the helper script). The benchmark also
//! needs `QSH_BENCH=1`; see [`bench_ssh_mosh_qsh`]. `QSH_CHAOS_FORCE_PROFILES` (comma-separated)
//! runs exactly those profiles in every scenario, its own or not.
//!
//! Local mode (`QSH_CHAOS_LOCAL=1`, driven by `scripts/local-test.sh --chaos`): netns.sh's local
//! mode with namespaces named `$QSH_CHAOS_NS_PREFIX-c/-r/-s`, no test user (`QSH_CHAOS_USER` is
//! the developer, unprivileged), its home in `$QSH_CHAOS_DIR/home`; the clients run as that user
//! too, not as root.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

/// The server's address in the topology.
const HOST: &str = "10.77.2.2";

/// Prints `T<n>:<server clock in ns>` every 50 ms. The namespaces share one kernel clock, so a
/// tick tells exactly when the program printed it.
const TICKER: &str = r#"i=0; while :; do i=$((i+1)); echo "T$i:$(date +%s%N)"; sleep 0.05; done"#;

/// The prompt of the measuring shell.
const PROMPT: &str = "QPMARK";

/// A shell whose prompt is [`PROMPT`], as one remote command (ssh, qsh) ...
const SHELL: &str = "env 'PS1=QPMARK$ ' bash --norc --noprofile -i";

/// ... and as an argument vector (mosh runs it without a shell).
const SHELL_ARGV: [&str; 6] = ["env", "PS1=QPMARK$ ", "bash", "--norc", "--noprofile", "-i"];

/// The output flood typed into the shell.
const FLOOD: &str = "yes 0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz\r";

/// Work packages that are merged: a check waiting only for these is hard. Add a package here
/// when it lands; its criteria then fail the workflow instead of being reported.
const LANDED: &[&str] = &["WP-1", "WP-2", "WP-4"];

/// A network profile of m2.md 12.2 (the netem arguments are in netns.sh).
#[derive(Debug, Clone, Copy)]
struct Profile {
    name: &'static str,
    /// Round-trip time without jitter.
    rtt_ms: f64,
    rate_mbit: f64,
    /// Packet loss each way (netns.sh).
    loss: f64,
}

const CLEAN: Profile = Profile {
    name: "clean",
    rtt_ms: 2.0,
    rate_mbit: 1000.0,
    loss: 0.0,
};
const CROSSBORDER: Profile = Profile {
    name: "crossborder",
    rtt_ms: 270.0,
    rate_mbit: 10.0,
    loss: 0.06,
};
const LOSSY: Profile = Profile {
    name: "lossy",
    rtt_ms: 300.0,
    rate_mbit: 8.0,
    loss: 0.10,
};
const TERRIBLE: Profile = Profile {
    name: "terrible",
    rtt_ms: 600.0,
    rate_mbit: 2.0,
    loss: 0.20,
};
/// The compression path: 135 ms each way, 2 Mbit/s, no loss.
const SLOW: Profile = Profile {
    name: "slow",
    rtt_ms: 270.0,
    rate_mbit: 2.0,
    loss: 0.0,
};

const ALL_PROFILES: [Profile; 5] = [CLEAN, CROSSBORDER, LOSSY, TERRIBLE, SLOW];

/// `defaults`, narrowed to `QSH_CHAOS_PROFILES` when that is set; `QSH_CHAOS_FORCE_PROFILES`
/// replaces them.
fn profiles(defaults: &[Profile]) -> Vec<Profile> {
    if let Ok(list) = std::env::var("QSH_CHAOS_FORCE_PROFILES") {
        if !list.trim().is_empty() {
            return list
                .split(',')
                .filter_map(|n| ALL_PROFILES.iter().copied().find(|p| p.name == n.trim()))
                .collect();
        }
    }
    match std::env::var("QSH_CHAOS_PROFILES") {
        Ok(list) if !list.trim().is_empty() => defaults
            .iter()
            .copied()
            .filter(|p| list.split(',').any(|n| n.trim() == p.name))
            .collect(),
        _ => defaults.to_vec(),
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

/// The variable's value, `default` when it is unset or empty.
fn env_str(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| v == "1")
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn sleep(d: Duration) {
    std::thread::sleep(d);
}

fn ns(t: SystemTime) -> u128 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos()
}

/// Milliseconds from `from` to `to` (0 when `to` is earlier).
fn ms_between(from: SystemTime, to: SystemTime) -> f64 {
    to.duration_since(from).map_or(0.0, |d| d.as_secs_f64() * 1000.0)
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// The nearest-rank quantile `q` of `values`.
fn quantile(values: &[f64], q: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_by(f64::total_cmp);
    let rank = ((q * v.len() as f64).ceil() as usize).clamp(1, v.len());
    Some(v[rank - 1])
}

/// The false-failure rate a quantile check accepts: the probability that a system whose
/// true quantile sits exactly on the bound fails the check (it is lower the more the system
/// beats the bound).
const CHECK_ALPHA: f64 = 0.05;

/// `P(X ≥ k)` for `X ~ Binomial(n, p)`.
fn binomial_at_least(n: usize, k: usize, p: f64) -> f64 {
    let mut choose = 1.0;
    let mut sum = 0.0;
    for i in 0..=n {
        if i >= k {
            sum += choose * p.powi(i as i32) * (1.0 - p).powi((n - i) as i32);
        }
        choose = choose * (n - i) as f64 / (i + 1) as f64;
    }
    sum.min(1.0)
}

/// A bound that should hold at quantile `q` (0.5: p50, 0.95: p95), checked on few samples: the
/// sample quantile of 9 runs is a poor estimate (the p95 of 9 is their maximum, and at 6 %
/// loss, where 40 % of the runs pay a recovery, a median of 9 over a bound that holds fails a
/// quarter of the time). Instead a one-sided binomial test: with `over` of the `n` samples
/// above the bound, the check fails only if that many would happen with probability below
/// [`CHECK_ALPHA`] were exactly the fraction `1 − q` of runs above it. With 9 samples it
/// allows 2 over the p95 bound (3 have probability 0.008 at the bound, 2 have 0.071) and 7
/// over the p50 bound (8: 0.020, 7: 0.090). Returns (over, the test's p-value, pass).
fn quantile_check(values: &[f64], q: f64, bound: f64) -> (usize, f64, bool) {
    let over = values.iter().filter(|&&x| x > bound).count();
    let p = binomial_at_least(values.len(), over, 1.0 - q);
    (over, p, !values.is_empty() && p >= CHECK_ALPHA)
}

/// Loss recoveries an interrupt pays at quantile `q` beyond S3's 10 % loss: the smallest r
/// with `P(L ≤ r) ≥ q`, where the losses L before k = 4 exposed packets (the input, the
/// snapshot, a packet before each on its stream) get through at loss `p` each way are
/// negative binomial (m2.md 6.4).
fn recoveries(p: f64, q: f64) -> u32 {
    const K: i32 = 4;
    let mut cdf = 0.0;
    let mut coefficient = 1.0; // C(K + l − 1, l)
    for l in 0..32 {
        cdf += coefficient * p.powi(l) * (1.0 - p).powi(K);
        if cdf >= q {
            return l as u32;
        }
        coefficient = coefficient * f64::from(K + l) / f64::from(l + 1);
    }
    32
}

// ---------------------------------------------------------------------------------------------
// The lab: topology, test user, results

/// The shared test environment. One per process; tests take turns (a mutex), and the workflow
/// also runs them with `--test-threads=1`.
#[derive(Debug)]
struct Lab {
    dir: PathBuf,
    netns: PathBuf,
    qsh: PathBuf,
    server: PathBuf,
    ssh_config: PathBuf,
    user: String,
    user_home: PathBuf,
    /// The client namespace.
    client_ns: String,
    /// Local mode: the clients run as this user (`uid`, `gid`) instead of root.
    run_as: Option<(String, String)>,
    results: PathBuf,
    strict: bool,
    /// Current scenario and profile, for the records.
    scenario: String,
    profile: String,
    /// Hard checks that failed in the running test.
    failures: Vec<String>,
}

/// The lab, or None when the chaos tests are not enabled.
fn lab() -> Option<MutexGuard<'static, Lab>> {
    if !env_flag("QSH_CHAOS") {
        eprintln!("chaos: skipped (QSH_CHAOS=1, as root, in a disposable machine; see tests/chaos/)");
        return None;
    }
    assert_eq!(
        qsh_core::sys::euid(),
        0,
        "QSH_CHAOS=1 needs root (network namespaces, netem, nftables)"
    );
    static LAB: OnceLock<Mutex<Lab>> = OnceLock::new();
    let mut lab = LAB
        .get_or_init(|| Mutex::new(Lab::setup()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    lab.failures.clear();
    Some(lab)
}

impl Lab {
    fn setup() -> Lab {
        // What this process inherited (a lock of `flock … cargo test`) must not reach the clients
        qsh_core::sys::cloexec_from(3);
        let dir = PathBuf::from(env_str("QSH_CHAOS_DIR", "/tmp/qsh-chaos"));
        let netns = std::env::var_os("QSH_CHAOS_NETNS").map_or_else(
            || PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/chaos/netns.sh")),
            PathBuf::from,
        );
        let qsh = std::env::var_os("QSH_CHAOS_QSH").map_or_else(|| env!("CARGO_BIN_EXE_qsh").into(), PathBuf::from);
        let server =
            std::env::var_os("QSH_CHAOS_SERVER").map_or_else(|| env!("CARGO_BIN_EXE_qsh-server").into(), PathBuf::from);
        let results = std::env::var_os("QSH_CHAOS_OUT").map_or_else(|| dir.join("results.jsonl"), PathBuf::from);
        let user = env_str("QSH_CHAOS_USER", "qshtest");
        let local = env_flag("QSH_CHAOS_LOCAL");
        let id = |flag: &str| {
            let out = Command::new("id").args([flag, &user]).output().unwrap();
            assert!(out.status.success(), "id {flag} {user}");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let run_as = local.then(|| (id("-u"), id("-g")));
        let mut lab = Lab {
            ssh_config: dir.join("ssh/config"),
            dir,
            netns,
            qsh,
            server,
            user,
            user_home: PathBuf::new(),
            client_ns: format!("{}-c", env_str("QSH_CHAOS_NS_PREFIX", "qsh")),
            run_as,
            results,
            strict: env_flag("QSH_CHAOS_STRICT"),
            scenario: "setup".into(),
            profile: String::new(),
            failures: Vec::new(),
        };
        lab.net(&["up"]);
        let server = lab.server.display().to_string();
        lab.net(&["install-server", &server]);
        lab.user_home = if local {
            lab.dir.join("home")
        } else {
            let passwd = Command::new("getent").args(["passwd", &lab.user]).output().unwrap();
            let passwd = String::from_utf8_lossy(&passwd.stdout).into_owned();
            PathBuf::from(passwd.trim().split(':').nth(5).expect("the test user's home"))
        };
        if let Some(parent) = lab.results.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let version = |program: &str, arg: &str| {
            Command::new(program)
                .arg(arg)
                .output()
                .map(|o| {
                    let text = if o.stdout.is_empty() { o.stderr } else { o.stdout };
                    String::from_utf8_lossy(&text).lines().next().unwrap_or("").to_string()
                })
                .unwrap_or_else(|_| "absent".into())
        };
        lab.record(json!({
            "kind": "env",
            "qsh": version(&lab.qsh.display().to_string(), "--version"),
            "ssh": version("ssh", "-V"),
            "mosh": version("mosh", "--version"),
            "kernel": version("uname", "-r"),
            "commit": std::env::var("GITHUB_SHA").ok(),
        }));
        lab
    }

    /// Run the helper script; panics when it fails.
    fn net(&self, args: &[&str]) {
        let out = Command::new(&self.netns)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|e| panic!("{}: {e}", self.netns.display()));
        assert!(
            out.status.success(),
            "netns.sh {args:?}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Start a scenario on `profile`: the network back to normal, no daemon, no session.
    fn start(&mut self, scenario: &str, profile: Profile) {
        self.scenario = scenario.into();
        self.profile = profile.name.into();
        eprintln!("chaos: === {scenario} / {}", profile.name);
        self.net(&["reset"]);
        self.net(&["kill-user"]);
        self.net(&["profile", profile.name]);
    }

    /// A fresh client: its own HOME and XDG directories, `config` as its qsh config file.
    fn client(&self, name: &str, config: &str) -> Client {
        let dir = self.dir.join("clients").join(name);
        let _ = fs::remove_dir_all(&dir);
        for sub in ["home", "run", "state", "config/qsh", "logs"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.join("run"), fs::Permissions::from_mode(0o700)).unwrap();
        if !config.is_empty() {
            // qsh ignores a configuration file others can write (the runner's umask is 002)
            fs::write(dir.join("config/qsh/config"), config).unwrap();
            fs::set_permissions(dir.join("config/qsh/config"), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let env = vec![
            ("HOME".into(), dir.join("home").display().to_string()),
            ("XDG_RUNTIME_DIR".into(), dir.join("run").display().to_string()),
            ("XDG_STATE_HOME".into(), dir.join("state").display().to_string()),
            ("XDG_CONFIG_HOME".into(), dir.join("config").display().to_string()),
            (
                "PATH".into(),
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
            ),
            ("TERM".into(), "xterm-256color".into()),
            ("LANG".into(), "C.UTF-8".into()),
        ];
        if let Some((uid, gid)) = &self.run_as {
            let status = Command::new("chown")
                .args(["-R", &format!("{uid}:{gid}")])
                .arg(&dir)
                .status()
                .unwrap();
            assert!(status.success(), "chown {}", dir.display());
        }
        Client {
            dir,
            env,
            qsh: self.qsh.clone(),
            ssh_config: self.ssh_config.display().to_string(),
            ns: self.client_ns.clone(),
            run_as: self.run_as.clone(),
        }
    }

    /// A file of `mb` MiB of random bytes, readable by the test user.
    fn random_file(&self, mb: u64) -> PathBuf {
        let path = self.dir.join(format!("data/random-{mb}M"));
        if !path.exists() {
            let status = Command::new("sh")
                .args(["-c", &format!("head -c {mb}M /dev/urandom > '{}.tmp'", path.display())])
                .status()
                .unwrap();
            assert!(status.success());
            fs::rename(path.with_extension("tmp"), &path).unwrap();
        }
        path
    }

    /// A build log of about `mb` MiB: what compression is for.
    fn build_log(&self, mb: u64) -> PathBuf {
        let path = self.dir.join(format!("data/build-{mb}M.log"));
        if !path.exists() {
            let mut text = String::new();
            let mut i = 0u64;
            while (text.len() as u64) < mb << 20 {
                let line = match i % 5 {
                    0 => format!(
                        "   Compiling crate-{} v0.{}.{} (/home/build/src/crate-{})\n",
                        i % 311,
                        i % 7,
                        i % 13,
                        i % 311
                    ),
                    1 => format!(
                        "cc -O2 -g -Wall -Wextra -fPIC -I/usr/include/glib-2.0 -Iinclude -c src/module_{}.c -o build/module_{}.o\n",
                        i % 503,
                        i % 503
                    ),
                    2 => format!("[{:>3}%] Building C object CMakeFiles/app.dir/src/file_{}.c.o\n", i % 101, i % 997),
                    3 => format!(
                        "warning: unused variable `tmp_{}`\n  --> src/lib_{}.rs:{}:9\n   |\n",
                        i % 17,
                        i % 89,
                        i % 400
                    ),
                    _ => format!("test tests::case_{} ... ok\n", i % 1009),
                };
                text.push_str(&line);
                i += 1;
            }
            fs::write(&path, text).unwrap();
        }
        path
    }

    /// The test user's file `relative` (in its home) with `content`, or removed when None.
    fn user_file(&self, relative: &str, content: Option<&str>) {
        let path = self.user_home.join(relative);
        match content {
            Some(content) => {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(&path, content).unwrap();
                // qsh-server ignores a configuration file others can write
                let _ = Command::new("chmod")
                    .args(["-R", "go-w"])
                    .arg(self.user_home.join(".config"))
                    .status();
                let _ = Command::new("chown")
                    .args(["-R", &format!("{}:", self.user)])
                    .arg(self.user_home.join(".config"))
                    .status();
            }
            None => {
                let _ = fs::remove_file(path);
            }
        }
    }

    /// `qsh-server status` of the test user's daemon, None when none runs.
    /// `as_version`: the version `qsh-server status` claims (`QSH_TEST_VERSION`), so that asking
    /// does not upgrade an older daemon (every control request of a newer program does).
    fn server_status(&self, as_version: Option<&str>) -> Option<Value> {
        let program = self.user_home.join(".local/bin/qsh-server").display().to_string();
        let mut args = vec!["as-user".to_string()];
        args.extend(as_version.map(|v| format!("QSH_TEST_VERSION={v}")));
        args.extend([program, "status".into()]);
        let out = Command::new(&self.netns).args(&args).output().ok()?;
        out.status
            .success()
            .then(|| serde_json::from_slice(&out.stdout).ok())
            .flatten()
    }

    fn record(&self, mut value: Value) {
        if value.get("kind").is_some_and(|k| k != "env") {
            value["scenario"] = json!(self.scenario);
            value["profile"] = json!(self.profile);
        }
        let mut line = value.to_string();
        line.push('\n');
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.results)
            .unwrap();
        file.write_all(line.as_bytes()).unwrap();
    }

    /// A measurement without a criterion.
    fn measure(&self, metric: &str, value: Value, unit: &str) {
        eprintln!("chaos: {}/{} {metric} = {value} {unit}", self.scenario, self.profile);
        self.record(json!({"kind": "measure", "metric": metric, "value": value, "unit": unit}));
    }

    /// A criterion: hard unless `until` names the work package it waits for.
    fn check(&mut self, metric: &str, value: Value, limit: &str, ok: bool, until: Option<&str>) {
        let hard = self.strict || until.is_none_or(|u| u.split(", ").all(|wp| LANDED.contains(&wp)));
        let verdict = match (ok, hard) {
            (true, _) => "pass".to_string(),
            (false, true) => "FAIL".to_string(),
            (false, false) => format!("report-only fail (until {})", until.unwrap_or("")),
        };
        eprintln!(
            "chaos: {}/{} {metric} = {value} (limit {limit}): {verdict}",
            self.scenario, self.profile
        );
        self.record(json!({
            "kind": "check", "metric": metric, "value": value, "limit": limit,
            "ok": ok, "hard": hard, "until": until,
        }));
        if !ok && hard {
            self.failures.push(format!(
                "{}/{} {metric} = {value}, limit {limit}",
                self.scenario, self.profile
            ));
        }
    }

    /// One cell of the benchmark table.
    fn bench(&self, tool: &str, row: &str, value: Value, text: &str) {
        eprintln!("bench: {} {tool} {row}: {text}", self.profile);
        self.record(json!({"kind": "bench", "tool": tool, "row": row, "value": value, "text": text}));
    }

    /// End of a test: fail when a hard check failed.
    fn finish(&mut self) {
        let failures = std::mem::take(&mut self.failures);
        assert!(
            failures.is_empty(),
            "hard chaos checks failed:\n{}",
            failures.join("\n")
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Clients in the client namespace

#[derive(Debug)]
struct Client {
    dir: PathBuf,
    env: Vec<(String, String)>,
    qsh: PathBuf,
    ssh_config: String,
    /// The client namespace.
    ns: String,
    /// Local mode: (uid, gid) to run as.
    run_as: Option<(String, String)>,
}

impl Client {
    /// `program args` in the client namespace, with this client's environment only.
    fn command<S: AsRef<std::ffi::OsStr>>(&self, program: impl AsRef<std::ffi::OsStr>, args: &[S]) -> Command {
        let mut c = Command::new("ip");
        c.args(["netns", "exec", &self.ns]);
        if let Some((uid, gid)) = &self.run_as {
            // setpriv, not runuser: it leaves the environment (the client's HOME) alone
            c.args(["setpriv", "--reuid", uid, "--regid", gid, "--clear-groups", "--"]);
        }
        c.arg(program).args(args).env_clear();
        for (k, v) in &self.env {
            c.env(k, v);
        }
        c.current_dir(&self.dir);
        c
    }

    /// qsh, writing its transcript to `transcript` when given.
    fn qsh(&self, transcript: Option<&Path>, args: &[&str]) -> Command {
        let mut all = vec!["-F", self.ssh_config.as_str()];
        all.extend_from_slice(args);
        let mut c = self.command(&self.qsh, &all);
        if let Some(t) = transcript {
            c.env("QSH_TRANSCRIPT", t);
        }
        c
    }

    fn ssh(&self, args: &[&str]) -> Command {
        let mut all = vec!["-F", self.ssh_config.as_str()];
        all.extend_from_slice(args);
        self.command("ssh", &all)
    }

    /// mosh to the server running `argv`, with `predict` (never, adaptive, always).
    fn mosh(&self, predict: &str, argv: &[&str]) -> Command {
        let mut all = vec![
            format!("--ssh=ssh -F {}", self.ssh_config),
            format!("--predict={predict}"),
            HOST.to_string(),
            "--".to_string(),
        ];
        all.extend(argv.iter().map(|s| s.to_string()));
        self.command("mosh", &all)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn log(&self, name: &str) -> PathBuf {
        self.dir.join("logs").join(name)
    }
}

/// Run a non-interactive command to its end, at most `timeout`: (exit code, elapsed).
fn run_to_end(mut cmd: Command, stdin: Stdio, stdout: Stdio, log: &Path, timeout: Duration) -> (Option<i32>, Duration) {
    cmd.stdin(stdin).stdout(stdout).stderr(File::create(log).unwrap());
    let started = Instant::now();
    let mut child = cmd.spawn().unwrap();
    let code = wait_child(&mut child, timeout);
    (code, started.elapsed())
}

/// The exit code of `child` (-1 for a signal), waiting at most `timeout`; killed and None after.
fn wait_child(child: &mut Child, timeout: Duration) -> Option<i32> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status.code().unwrap_or(-1));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        sleep(Duration::from_millis(20));
    }
}

/// Bytes per second of `cmd`'s stdout over `window` from its first byte: (Mbit/s, bytes in the
/// window). None when no byte came within `first`.
fn window_rate(mut cmd: Command, log: &Path, window: Duration, first: Duration) -> Option<(f64, u64)> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(File::create(log).unwrap());
    let mut child = cmd.spawn().unwrap();
    let mut out = child.stdout.take().unwrap();
    let samples: Arc<Mutex<Vec<(Instant, u64)>>> = Arc::default();
    let sink = samples.clone();
    let reader = std::thread::spawn(move || {
        let mut buf = vec![0u8; 256 << 10];
        let mut total = 0u64;
        while let Ok(n) = out.read(&mut buf) {
            if n == 0 {
                break;
            }
            total += n as u64;
            sink.lock().unwrap().push((Instant::now(), total));
        }
    });
    let deadline = Instant::now() + first;
    let start = loop {
        if let Some(s) = samples.lock().unwrap().first().copied() {
            break Some(s);
        }
        if Instant::now() >= deadline || reader.is_finished() {
            break None;
        }
        sleep(Duration::from_millis(20));
    };
    if let Some((t0, _)) = start {
        while Instant::now() < t0 + window && !reader.is_finished() {
            sleep(Duration::from_millis(50));
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    let (t0, b0) = start?;
    let samples = samples.lock().unwrap();
    let (t1, b1) = samples
        .iter()
        .rev()
        .find(|(t, _)| *t <= t0 + window)
        .copied()
        .unwrap_or((t0, b0));
    let seconds = (t1 - t0).as_secs_f64().max(0.001);
    Some(((b1 - b0) as f64 * 8.0 / seconds / 1e6, b1 - b0))
}

fn sha256(path: &Path) -> String {
    let out = Command::new("sha256sum").arg(path).output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string()
}

// ---------------------------------------------------------------------------------------------
// A program on a pseudo terminal, with the arrival time of every byte

#[derive(Debug, Default)]
struct Received {
    data: Vec<u8>,
    /// (end offset, arrival) of every read.
    chunks: Vec<(usize, SystemTime)>,
    eof: bool,
}

/// A line `T<n>:<ns>` of [`TICKER`] on the terminal.
#[derive(Debug, Clone, Copy)]
struct Tick {
    seq: u64,
    printed: u128,
    arrived: SystemTime,
}

#[derive(Debug)]
struct Term {
    child: Child,
    master: File,
    rx: Arc<Mutex<Received>>,
}

impl Term {
    /// `cmd` on a new 100x30 pseudo terminal; stderr goes to `log`.
    fn spawn(mut cmd: Command, log: &Path) -> Term {
        let (master, slave) = qsh_core::sys::openpty(100, 30).unwrap();
        let slave = File::from(slave);
        cmd.stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(File::create(log).unwrap());
        let child = cmd.spawn().unwrap();
        drop(slave);
        let master = File::from(master);
        let mut reader = master.try_clone().unwrap();
        let rx: Arc<Mutex<Received>> = Arc::default();
        let sink = rx.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 64 << 10];
            loop {
                match reader.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        let now = SystemTime::now();
                        let mut rx = sink.lock().unwrap();
                        rx.data.extend_from_slice(&buf[..n]);
                        let end = rx.data.len();
                        rx.chunks.push((end, now));
                    }
                    _ => break,
                }
            }
            sink.lock().unwrap().eof = true;
        });
        Term { child, master, rx }
    }

    /// How many bytes arrived so far.
    fn pos(&self) -> usize {
        self.rx.lock().unwrap().data.len()
    }

    fn send(&mut self, bytes: &[u8]) {
        let _ = self.master.write_all(bytes);
        let _ = self.master.flush();
    }

    fn arrival(rx: &Received, pos: usize) -> SystemTime {
        let i = rx.chunks.partition_point(|c| c.0 <= pos);
        rx.chunks.get(i).map_or_else(SystemTime::now, |c| c.1)
    }

    /// Wait for `needle` at or after offset `from`: (its offset, when its last byte arrived).
    fn wait_for(&self, needle: &str, from: usize, timeout: Duration) -> Option<(usize, SystemTime)> {
        let needle = needle.as_bytes();
        let deadline = Instant::now() + timeout;
        let mut scanned = from;
        loop {
            {
                let rx = self.rx.lock().unwrap();
                if rx.data.len() >= scanned + needle.len() {
                    if let Some(i) = rx.data[scanned..].windows(needle.len()).position(|w| w == needle) {
                        let at = scanned + i;
                        return Some((at, Term::arrival(&rx, at + needle.len() - 1)));
                    }
                    scanned = rx.data.len() + 1 - needle.len();
                }
                if rx.eof {
                    return None;
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            sleep(Duration::from_millis(10));
        }
    }

    /// The 19-digit number after `label` (like `L1:`), at or after `from`, and when it arrived.
    fn wait_stamp(&self, label: &str, from: usize, timeout: Duration) -> Option<(u128, SystemTime)> {
        let deadline = Instant::now() + timeout;
        let (at, _) = self.wait_for(label, from, timeout)?;
        let start = at + label.len();
        loop {
            {
                let rx = self.rx.lock().unwrap();
                if rx.data.len() >= start + 19 {
                    let digits = &rx.data[start..start + 19];
                    let value = std::str::from_utf8(digits).ok()?.parse().ok()?;
                    return Some((value, Term::arrival(&rx, start + 18)));
                }
                if rx.eof {
                    return None;
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            sleep(Duration::from_millis(10));
        }
    }

    /// The complete ticks at or after `from`.
    fn ticks(&self, from: usize) -> Vec<Tick> {
        let rx = self.rx.lock().unwrap();
        parse_ticks(&rx.data, from)
            .into_iter()
            .map(|(seq, printed, end)| Tick {
                seq,
                printed,
                arrived: Term::arrival(&rx, end),
            })
            .collect()
    }

    /// Wait for the first tick at or after `from` printed after `after`.
    fn wait_tick_after(&self, from: usize, after: SystemTime, timeout: Duration) -> Option<Tick> {
        let deadline = Instant::now() + timeout;
        let after = ns(after);
        loop {
            if let Some(t) = self.ticks(from).into_iter().find(|t| t.printed > after) {
                return Some(t);
            }
            if self.rx.lock().unwrap().eof || Instant::now() >= deadline {
                return None;
            }
            sleep(Duration::from_millis(20));
        }
    }

    /// The text that arrived at or after `from`, lossily.
    fn text(&self, from: usize) -> String {
        let rx = self.rx.lock().unwrap();
        String::from_utf8_lossy(&rx.data[from.min(rx.data.len())..]).into_owned()
    }

    fn exit_code(&mut self, timeout: Duration) -> Option<i32> {
        wait_child(&mut self.child, timeout)
    }

    /// End the client: `exit` to the shell, then kill.
    fn close(mut self) {
        self.send(b"\x15exit\r");
        if wait_child(&mut self.child, secs(3)).is_none() {
            let _ = self.child.kill();
        }
    }
}

impl Drop for Term {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `T<seq>:<19 digits>` followed by a non-digit, from `from` on: (seq, printed, offset of the
/// last digit).
fn parse_ticks(data: &[u8], from: usize) -> Vec<(u64, u128, usize)> {
    let mut ticks = Vec::new();
    let mut i = from;
    while i < data.len() {
        if data[i] != b'T' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < data.len() && data[j].is_ascii_digit() {
            j += 1;
        }
        if j == i + 1 || j >= data.len() || data[j] != b':' {
            i += 1;
            continue;
        }
        let k = j + 1;
        let mut end = k;
        while end < data.len() && data[end].is_ascii_digit() {
            end += 1;
        }
        if end - k != 19 || end >= data.len() {
            i += 1;
            continue;
        }
        let seq = std::str::from_utf8(&data[i + 1..j]).ok().and_then(|s| s.parse().ok());
        let printed = std::str::from_utf8(&data[k..end]).ok().and_then(|s| s.parse().ok());
        if let (Some(seq), Some(printed)) = (seq, printed) {
            ticks.push((seq, printed, end - 1));
        }
        i = end;
    }
    ticks
}

/// Tick numbers missing between the first and the last tick received.
fn missing_ticks(ticks: &[Tick]) -> u64 {
    let mut seqs: Vec<u64> = ticks.iter().map(|t| t.seq).collect();
    seqs.sort_unstable();
    seqs.dedup();
    match (seqs.first(), seqs.last()) {
        (Some(first), Some(last)) => last - first + 1 - seqs.len() as u64,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------------------------
// The client's transcript (QSH_TRANSCRIPT, client/transcript.rs)

fn transcript(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Wait for a transcript record matching `pred`: (record, when it was seen, ±10 ms).
fn wait_record(path: &Path, pred: impl Fn(&Value) -> bool, timeout: Duration) -> Option<(Value, Instant)> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(r) = transcript(path).into_iter().find(&pred) {
            return Some((r, Instant::now()));
        }
        if Instant::now() >= deadline {
            return None;
        }
        sleep(Duration::from_millis(10));
    }
}

/// What a transcript says about one output stream.
#[derive(Debug, Default)]
struct Coverage {
    /// Offset of the first record.
    base: u64,
    /// Everything before this is delivered or announced.
    end: u64,
    /// Ranges neither delivered nor announced as a gap or covered by a snapshot.
    holes: Vec<(u64, u64)>,
    gaps: usize,
    gap_bytes: u64,
    snapshots: usize,
    /// Output bytes accepted (replays included).
    delivered: u64,
    /// OUTPUT_ZSTD messages.
    zstd: usize,
    /// `transport` of every `connected` record, in order.
    connected: Vec<String>,
    /// `remote` of every `connected` record, in order.
    remotes: Vec<String>,
    disconnects: usize,
    /// `transport:port:outcome` of every `attempt` record, in order.
    attempts: Vec<String>,
}

/// Walk the records in order: every byte of `stream` from the first offset on must be in an
/// OUTPUT, inside an OUTPUT_GAP, or before a SNAPSHOT's offset.
fn coverage(records: &[Value], stream: &str) -> Coverage {
    let mut c = Coverage::default();
    let mut started = false;
    let u = |r: &Value, k: &str| r[k].as_u64().unwrap_or(0);
    for r in records {
        match r["ev"].as_str().unwrap_or("") {
            "output" if r["stream"] == stream => {
                let (offset, len) = (u(r, "offset"), u(r, "len"));
                if !started {
                    started = true;
                    c.base = offset;
                    c.end = offset;
                }
                if offset > c.end {
                    c.holes.push((c.end, offset));
                }
                c.end = c.end.max(offset + len);
                c.delivered += len;
                if r.get("zstd").is_some() {
                    c.zstd += 1;
                }
            }
            "gap" => {
                let (from, to) = (u(r, "from"), u(r, "to"));
                if !started {
                    started = true;
                    c.base = from;
                    c.end = from;
                }
                if from > c.end {
                    c.holes.push((c.end, from));
                }
                c.end = c.end.max(to);
                c.gaps += 1;
                c.gap_bytes += to.saturating_sub(from);
            }
            "snapshot" => {
                c.snapshots += 1;
                started = true;
                c.end = c.end.max(u(r, "offset"));
            }
            "connected" => {
                c.connected.push(r["transport"].as_str().unwrap_or("?").to_lowercase());
                c.remotes.push(r["remote"].as_str().unwrap_or("").to_string());
            }
            "disconnected" => c.disconnects += 1,
            "attempt" => c.attempts.push(format!(
                "{}:{}:{}",
                r["transport"].as_str().unwrap_or("?").to_lowercase(),
                u(r, "port"),
                r["outcome"].as_str().unwrap_or("?")
            )),
            _ => {}
        }
    }
    c
}

// ---------------------------------------------------------------------------------------------
// Scenarios (m2.md 12.2)

/// `bytes-exact`: a pipe session's `cat` returns exactly what it got; a tty session's `seq`
/// arrives whole or with announced gaps only.
#[test]
fn bytes_exact() {
    let Some(mut lab) = lab() else { return };
    for p in profiles(&[CLEAN, CROSSBORDER, LOSSY, TERRIBLE]) {
        lab.start("bytes-exact", p);
        // Sizes that end in a few minutes on each path (m2.md says 50 MB and 2 000 000 lines)
        let (mb, lines) = match p.name {
            "clean" => (50, 2_000_000),
            "crossborder" => (8, 1_000_000),
            "lossy" => (3, 300_000),
            _ => (1, 50_000),
        };
        let input = lab.random_file(mb);
        let client = lab.client(&format!("bytes-{}", p.name), "[defaults]\ncatchup = \"off\"\n");
        let output = client.path("pipe.out");
        let (code, took) = run_to_end(
            client.qsh(Some(&client.path("pipe.jsonl")), &[HOST, "--", "cat"]),
            File::open(&input).unwrap().into(),
            File::create(&output).unwrap().into(),
            &client.log("pipe.log"),
            secs(900),
        );
        lab.check("pipe_exit_code", json!(code), "0", code == Some(0), None);
        let same = sha256(&input) == sha256(&output);
        lab.check(
            "pipe_sha256_equal",
            json!(same),
            &format!("{mb} MiB each way, equal"),
            same,
            None,
        );
        lab.measure("pipe_seconds", json!(round1(took.as_secs_f64())), "s");

        let t = client.path("tty.jsonl");
        let mut term = Term::spawn(
            client.qsh(Some(&t), &[HOST, "--", &format!("seq 1 {lines}")]),
            &client.log("tty.log"),
        );
        let started = Instant::now();
        let code = term.exit_code(secs(900));
        lab.measure("tty_seconds", json!(round1(started.elapsed().as_secs_f64())), "s");
        lab.check("tty_exit_code", json!(code), "0", code == Some(0), None);
        let tail = term.text(term.pos().saturating_sub(4096));
        let last = tail.contains(&format!("\n{lines}\r\n"));
        lab.check("tty_last_line_arrived", json!(last), "true", last, None);
        let c = coverage(&transcript(&t), "out");
        lab.check(
            "tty_bytes_unaccounted",
            json!(c.holes.iter().map(|(a, b)| b - a).sum::<u64>()),
            "0 (every byte delivered or in an announced gap)",
            c.holes.is_empty() && c.end > 0,
            None,
        );
        // 0.2 keeps 8 MiB per session and announces a gap beyond: "catchup = off, no gap" (m2.md
        // 12.2) needs a server that holds the program back instead
        lab.check(
            "tty_gap_bytes",
            json!(c.gap_bytes),
            "0 with catchup = off",
            c.gaps == 0,
            Some("WP-2"),
        );
    }
    lab.finish();
}

/// `flood-interrupt`: Ctrl-C during `yes`, time until the prompt is back on the client's
/// terminal, against S3.
#[test]
fn flood_interrupt() {
    let Some(mut lab) = lab() else { return };
    // At least 9 runs per profile: at 6 % loss about 40 % of runs pay one loss recovery, and a
    // median of 5 would fail about one test in four (m2.md 6.4)
    let runs = env_u64("QSH_CHAOS_RUNS", 9).max(1);
    for p in profiles(&[CROSSBORDER, LOSSY, TERRIBLE]) {
        lab.start("flood-interrupt", p);
        let client = lab.client(&format!("flood-{}", p.name), "");
        let timeout = secs(if p.name == "crossborder" { 180 } else { 120 });
        let result = ctrl_c_runs(&client, runs, timeout, |client, t| {
            client.qsh(Some(t), &[HOST, "--", SHELL])
        });
        // S3, with a 16 KiB snapshot
        let snapshot_ms = 16384.0 * 8.0 / (p.rate_mbit * 1e6) * 1000.0;
        let base = 2.0 * p.rtt_ms + 100.0 + snapshot_ms;
        // Beyond S3's 10 % loss (terrible: 20 % each way) the p50 and p95 pay r50 and r95 loss
        // recoveries of 9/8 R + 25 ms each (m2.md 6.4: k = 4, at 20 % r50 = 1 and r95 = 3); up
        // to 10 % S3's own bounds
        let recovery = 1.125 * p.rtt_ms + 25.0;
        let (budget50, budget95) = if p.loss > 0.10 {
            (
                base + f64::from(recoveries(p.loss, 0.5)) * recovery,
                base + f64::from(recoveries(p.loss, 0.95)) * recovery + 200.0,
            )
        } else {
            (base, 3.0 * p.rtt_ms + 300.0 + snapshot_ms)
        };
        let p50 = quantile(&result.latencies, 0.5);
        let p95 = quantile(&result.latencies, 0.95);
        let (over50, pv50, ok50) = quantile_check(&result.latencies, 0.5, budget50);
        let (over95, pv95, ok95) = quantile_check(&result.latencies, 0.95, budget95);
        let n = result.latencies.len();
        lab.measure(
            "ctrl_c_ms",
            json!(result.latencies.iter().map(|x| round1(*x)).collect::<Vec<_>>()),
            "ms",
        );
        lab.check(
            "ctrl_c_p50_ms",
            json!({"p50": p50.map(round1), "over": over50, "of": n, "p_value": (pv50 * 1000.0).round() / 1000.0}),
            &format!("<= {budget50:.0} (S3; binomial test, alpha {CHECK_ALPHA})"),
            ok50 && result.timeouts == 0,
            Some("WP-2"),
        );
        lab.check(
            "ctrl_c_p95_ms",
            json!({"p95": p95.map(round1), "over": over95, "of": n, "p_value": (pv95 * 1000.0).round() / 1000.0}),
            &format!("<= {budget95:.0} (S3; binomial test, alpha {CHECK_ALPHA})"),
            ok95 && result.timeouts == 0,
            Some("WP-2"),
        );
        lab.check(
            "prompt_back_in_time",
            json!(format!("{} of {runs}", result.latencies.len())),
            &format!("every run within {} s", timeout.as_secs()),
            result.timeouts == 0 && result.latencies.len() as u64 == runs,
            (p.name != "crossborder").then_some("WP-2"),
        );
        lab.check(
            "bytes_unaccounted",
            json!(result.unaccounted),
            "0 (delivered, in a gap or before a snapshot)",
            result.unaccounted == 0,
            None,
        );
        lab.measure("gap_bytes", json!(result.gap_bytes), "bytes");
        lab.measure("snapshots", json!(result.snapshots), "");
    }
    lab.finish();
}

#[derive(Debug, Default)]
struct CtrlC {
    latencies: Vec<f64>,
    timeouts: u64,
    unaccounted: u64,
    gap_bytes: u64,
    snapshots: usize,
}

/// `runs` times: start the measuring shell with `start(client, transcript)`, flood it for 3 s,
/// Ctrl-C, time until the prompt is back.
fn ctrl_c_runs(client: &Client, runs: u64, timeout: Duration, start: impl Fn(&Client, &Path) -> Command) -> CtrlC {
    let mut r = CtrlC::default();
    for i in 0..runs {
        let t = client.path(&format!("ctrl-c-{i}.jsonl"));
        let mut term = Term::spawn(start(client, &t), &client.log(&format!("ctrl-c-{i}.log")));
        if term.wait_for(PROMPT, 0, secs(90)).is_none() {
            eprintln!("chaos: run {i}: no prompt: {:?}", term.text(0));
            r.timeouts += 1;
            continue;
        }
        term.send(FLOOD.as_bytes());
        sleep(secs(3));
        let pos = term.pos();
        let sent = SystemTime::now();
        term.send(b"\x03");
        match term.wait_for(PROMPT, pos, timeout) {
            Some((_, at)) => r.latencies.push(ms_between(sent, at)),
            None => r.timeouts += 1,
        }
        term.close();
        let c = coverage(&transcript(&t), "out");
        r.unaccounted += c.holes.iter().map(|(a, b)| b - a).sum::<u64>();
        r.gap_bytes += c.gap_bytes;
        r.snapshots += c.snapshots;
    }
    r
}

/// `udp-block-midway`, then `udp-blocked-memory`: UDP dropped during a session, then a
/// reconnect on the same network.
#[test]
fn udp_block() {
    let Some(mut lab) = lab() else { return };
    for p in profiles(&[CROSSBORDER]) {
        lab.start("udp-block-midway", p);
        let client = lab.client("udp-block", "");
        let t1 = client.path("t1.jsonl");
        let mut term = Term::spawn(
            client.qsh(Some(&t1), &[HOST, "--", "echo READY; exec cat"]),
            &client.log("t1.log"),
        );
        let ready = term.wait_for("READY", 0, secs(60)).is_some();
        lab.check("session_started", json!(ready), "true", ready, None);
        if !ready {
            continue;
        }
        sleep(secs(1));
        lab.measure(
            "transport_before",
            json!(coverage(&transcript(&t1), "out").connected),
            "",
        );
        let blocked = SystemTime::now();
        lab.net(&["block-udp"]);
        sleep(secs(1));
        let pos = term.pos();
        term.send(b"ping1\r");
        let echo = term.wait_for("ping1", pos, secs(120));
        let recovery = echo.map(|(_, at)| ms_between(blocked, at) / 1000.0);
        lab.check(
            "echo_after_block_s",
            json!(recovery.map(round1)),
            "<= 12 (S4)",
            recovery.is_some_and(|s| s <= 12.0),
            Some("WP-1"),
        );
        lab.check(
            "recovered_within_120s",
            json!(recovery.is_some()),
            "true",
            recovery.is_some(),
            None,
        );
        let c = coverage(&transcript(&t1), "out");
        lab.measure("transports", json!(c.connected), "");
        lab.measure("disconnects", json!(c.disconnects), "");
        if recovery.is_none() {
            continue;
        }

        // The client is lost; `qsh attach` on the same network, UDP still blocked
        lab.scenario = "udp-blocked-memory".into();
        drop(term);
        sleep(secs(1));
        let t2 = client.path("t2.jsonl");
        let started = Instant::now();
        let mut term = Term::spawn(client.qsh(Some(&t2), &["attach", HOST]), &client.log("t2.log"));
        let attached = wait_record(&t2, |r| r["ev"] == "connected", secs(60));
        let attach_s = attached.as_ref().map(|(_, at)| (*at - started).as_secs_f64());
        // S1: TLS starts at once, so attaching takes TLS's own exchanges: the TCP and TLS
        // handshakes, the hello and the attach, 4 round trips (1.08 s here), plus the process
        // start (1.12 - 1.16 s measured, debug build). At 6 % loss a lost packet among them
        // costs TCP a retransmission timeout (1 s for a SYN, about 0.3 s later on): 1.47 -
        // 2.25 s measured. That is the path, not a wait for another transport, so beyond 2 s
        // the transcript must show it inside TLS's exchanges, and the attach must still come
        // before the 3 s pipe stagger.
        let records = transcript(&t2);
        let at = |ev: &str, outcome: Option<&str>| {
            records
                .iter()
                .find(|r| r["ev"] == ev && outcome.is_none_or(|o| r["outcome"] == o))
                .and_then(|r| r["ms"].as_f64())
        };
        let (plan_ms, won_ms, connected_ms) = (at("plan", None), at("attempt", Some("won")), at("connected", None));
        let handshake_hello = plan_ms.zip(won_ms).map(|(p, w)| w - p);
        let attaching = won_ms.zip(connected_ms).map(|(w, c)| c - w);
        lab.measure(
            "attach_breakdown_ms",
            json!({"race_start": plan_ms, "handshake_hello": handshake_hello, "attach": attaching}),
            "",
        );
        let retransmitted = handshake_hello.is_some_and(|ms| ms > 3.0 * p.rtt_ms + 250.0)
            || attaching.is_some_and(|ms| ms > p.rtt_ms + 250.0);
        lab.check(
            "attach_s",
            json!(attach_s.map(|s| (s * 1000.0).round() / 1000.0)),
            "<= 2 (S1), < 3 with a TCP retransmission in TLS's exchanges",
            attach_s.is_some_and(|s| s <= 2.0 || retransmitted && s < 3.0),
            None,
        );
        let c = coverage(&transcript(&t2), "out");
        lab.measure("attempts", json!(c.attempts), "");
        lab.measure("transports", json!(c.connected), "");
        // The race's plan: what starts at 0 ms
        let plan = transcript(&t2).into_iter().find(|r| r["ev"] == "plan");
        let first = plan.as_ref().and_then(|p| {
            p["attempts"]
                .as_array()?
                .iter()
                .min_by_key(|a| a["delay_ms"].as_u64().unwrap_or(u64::MAX))
                .map(|a| {
                    format!(
                        "{}@{}ms",
                        a["transport"].as_str().unwrap_or("?").to_lowercase(),
                        a["delay_ms"]
                    )
                })
        });
        lab.check(
            "planned_first",
            json!(first),
            "tls@0ms (QUIC known to fail here)",
            first.as_deref() == Some("tls@0ms"),
            None,
        );
        let pos = term.pos();
        term.send(b"ping2\r");
        let echoed = term.wait_for("ping2", pos, secs(60)).is_some();
        lab.check("echo_after_attach", json!(echoed), "true", echoed, None);
    }
    lab.finish();
}

/// `address-change`: the client's address changes under a ticker; time until output flows
/// again, and no tick lost.
#[test]
fn address_change() {
    let Some(mut lab) = lab() else { return };
    for p in profiles(&[CLEAN, CROSSBORDER]) {
        lab.start("address-change", p);
        let client = lab.client(&format!("address-{}", p.name), "");
        let t = client.path("t.jsonl");
        let term = Term::spawn(client.qsh(Some(&t), &[HOST, "--", TICKER]), &client.log("t.log"));
        let first = term.wait_tick_after(0, UNIX_EPOCH, secs(60));
        lab.check("session_started", json!(first.is_some()), "true", first.is_some(), None);
        if first.is_none() {
            continue;
        }
        sleep(secs(2));
        let changed = SystemTime::now();
        lab.net(&["move-client"]);
        let next = term.wait_tick_after(0, changed, secs(60));
        let recovery = next.map(|t| ms_between(changed, t.arrived));
        lab.check(
            "output_again_ms",
            json!(recovery.map(round1)),
            "<= 3000 (S4)",
            recovery.is_some_and(|ms| ms <= 3000.0),
            Some("WP-1"),
        );
        lab.check(
            "output_again_within_60s",
            json!(recovery.is_some()),
            "true",
            recovery.is_some(),
            None,
        );
        sleep(secs(3));
        let ticks = term.ticks(0);
        let missing = missing_ticks(&ticks);
        lab.check("ticks_missing", json!(missing), "0", missing == 0, None);
        let c = coverage(&transcript(&t), "out");
        lab.check(
            "gaps",
            json!(c.gaps + c.holes.len()),
            "0 (no gap, nothing unaccounted)",
            c.gaps == 0 && c.holes.is_empty(),
            None,
        );
        lab.measure("transports", json!(c.connected), "");
        lab.measure("remotes", json!(c.remotes), "");
        drop(term);
        lab.net(&["restore-client"]);
    }
    lab.finish();
}

/// `nat-rebinding`: behind a NAT that forgets idle UDP mappings after 15 s, the program prints
/// after a long idle time, twice.
#[test]
fn nat_rebinding() {
    let Some(mut lab) = lab() else { return };
    let idle = env_u64("QSH_CHAOS_NAT_IDLE", 40);
    for p in profiles(&[CROSSBORDER]) {
        lab.start("nat-rebinding", p);
        lab.net(&["nat", "on", "15"]);
        let client = lab.client("nat", "");
        let t = client.path("t.jsonl");
        let program = format!(
            "echo READY; sleep {idle}; echo \"L1:$(date +%s%N)\"; sleep {idle}; echo \"L2:$(date +%s%N)\"; exec cat"
        );
        let term = Term::spawn(client.qsh(Some(&t), &[HOST, "--", &program]), &client.log("t.log"));
        let ready = term.wait_for("READY", 0, secs(60));
        lab.check("session_started", json!(ready.is_some()), "true", ready.is_some(), None);
        let Some((pos, _)) = ready else { continue };
        let first = term.wait_stamp("L1:", pos, secs(idle + 120));
        let delay1 = first.map(|(printed, at)| ms_between(UNIX_EPOCH + Duration::from_nanos(printed as u64), at));
        let second = term.wait_stamp("L2:", pos, secs(idle + 120));
        let delay2 = second.map(|(printed, at)| ms_between(UNIX_EPOCH + Duration::from_nanos(printed as u64), at));
        lab.measure("first_delay_ms", json!(delay1.map(round1)), "ms");
        lab.check(
            "second_delay_ms",
            json!(delay2.map(round1)),
            "<= 1000 (S2)",
            delay2.is_some_and(|ms| ms <= 1000.0),
            Some("WP-1"),
        );
        lab.check(
            "both_delivered",
            json!(first.is_some() && second.is_some()),
            "true",
            first.is_some() && second.is_some(),
            None,
        );
        let c = coverage(&transcript(&t), "out");
        lab.measure("disconnects", json!(c.disconnects), "");
        lab.measure("remotes", json!(c.remotes), "");
        // Learning needs QUIC: a session left on TLS (a lost QUIC packet let TLS win the race,
        // and the late QUIC answer did not take it over) learns nothing
        lab.measure("transports", json!(c.connected), "");
        // The learned keepalive, in the path memory file (WP-1 decides its name and place)
        let ka = learned_keepalive(&client.dir.join("state"));
        lab.check("path_memory_ka_s", json!(ka), "10", ka == Some(10), Some("WP-1"));
    }
    lab.finish();
}

/// The `ka` member of a path memory entry anywhere in `dir` (m2.md 3.3).
fn learned_keepalive(dir: &Path) -> Option<u64> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).ok()?.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(text) = fs::read_to_string(&path) {
                for chunk in text.split("\"ka\":").skip(1) {
                    let digits: String = chunk.trim_start().chars().take_while(char::is_ascii_digit).collect();
                    if let Ok(n) = digits.parse() {
                        return Some(n);
                    }
                }
            }
        }
    }
    None
}

/// The remote address of the first QUIC connection a transcript records within `timeout`.
fn wait_quic(transcript: &Path, timeout: Duration) -> Option<String> {
    wait_record(
        transcript,
        |r| r["ev"] == "connected" && r["transport"].as_str().is_some_and(|t| t.eq_ignore_ascii_case("quic")),
        timeout,
    )
    .map(|(r, _)| r["remote"].as_str().unwrap_or("").to_string())
}

/// `port-fallback`: the daemon's QUIC port is blocked, `extra_ports = [61443]` is not.
#[test]
fn port_fallback() {
    let Some(mut lab) = lab() else { return };
    for p in profiles(&[CROSSBORDER]) {
        lab.start("port-fallback", p);
        lab.user_file(".config/qsh/config", Some("[server]\nextra_ports = [61443]\n"));
        lab.net(&["block-udp", "60443-60542"]);
        let client = lab.client("port-fallback", "");
        let t1 = client.path("t1.jsonl");
        let term = Term::spawn(
            client.qsh(Some(&t1), &[HOST, "--", "echo READY; exec cat"]),
            &client.log("t1.log"),
        );
        let ready = term.wait_for("READY", 0, secs(60)).is_some();
        lab.check("session_started", json!(ready), "true", ready, None);
        // QUIC on 61443 wins the race; or, when a lost QUIC packet let TLS on the primary port
        // win (6 % loss), it answers late and takes the session over (m2.md 3.6, 5.3)
        let quic = wait_quic(&t1, secs(20));
        let c = coverage(&transcript(&t1), "out");
        lab.measure("first_attempts", json!(c.attempts), "");
        lab.measure("first_connected", json!(c.connected), "");
        lab.check(
            "first_connection",
            json!(quic),
            "quic to port 61443 within 20 s",
            quic.as_deref().is_some_and(|r| r.ends_with(":61443")),
            Some("WP-1, WP-4"),
        );
        drop(term);
        sleep(secs(1));
        let t2 = client.path("t2.jsonl");
        let _term = Term::spawn(client.qsh(Some(&t2), &["attach", HOST]), &client.log("t2.log"));
        let attached = wait_record(&t2, |r| r["ev"] == "connected", secs(60)).is_some();
        lab.check("reattached", json!(attached), "true", attached, None);
        // The plan starts with what path memory says worked: QUIC on 61443, at once
        let planned = transcript(&t2)
            .into_iter()
            .find(|r| r["ev"] == "plan")
            .and_then(|r| r["attempts"].get(0).cloned())
            .map(|a| {
                format!(
                    "{}:{}@{}ms",
                    a["transport"].as_str().unwrap_or("?").to_lowercase(),
                    a["port"],
                    a["delay_ms"]
                )
            });
        lab.check(
            "remembered",
            json!(planned),
            "first attempt quic:61443@0ms",
            planned.as_deref() == Some("quic:61443@0ms"),
            Some("WP-1, WP-4"),
        );
        // It wins; or, when a lost packet let TLS win, it answers late and the session moves
        // to it (m2.md 3.6)
        let quic = wait_quic(&t2, secs(20));
        let c = coverage(&transcript(&t2), "out");
        lab.measure("attempts", json!(c.attempts), "");
        lab.measure("connected", json!(c.connected), "");
        lab.check(
            "on_quic",
            json!(quic),
            "a QUIC connection to port 61443 within 20 s",
            quic.as_deref().is_some_and(|r| r.ends_with(":61443")),
            Some("WP-1"),
        );
        lab.user_file(".config/qsh/config", None);
    }
    lab.finish();
}

/// `compression`: a build log over 2 Mbit/s, with and without compression (S5).
#[test]
fn compression() {
    let Some(mut lab) = lab() else { return };
    let mb = env_u64("QSH_CHAOS_LOG_MB", 4);
    for p in profiles(&[SLOW]) {
        lab.start("compression", p);
        let log = lab.build_log(mb);
        let expected = sha256(&log);
        let mut took = Vec::new();
        for mode in ["off", "auto"] {
            let client = lab.client(
                &format!("compression-{mode}"),
                &format!("[defaults]\ncompression = \"{mode}\"\n"),
            );
            let t = client.path("t.jsonl");
            let output = client.path("out");
            let (code, elapsed) = run_to_end(
                client.qsh(Some(&t), &[HOST, "--", "cat", &log.display().to_string()]),
                Stdio::null(),
                File::create(&output).unwrap().into(),
                &client.log("t.log"),
                secs(600),
            );
            let exact = code == Some(0) && sha256(&output) == expected;
            lab.check(&format!("{mode}_exact"), json!(exact), "true", exact, None);
            lab.measure(&format!("{mode}_seconds"), json!(round1(elapsed.as_secs_f64())), "s");
            lab.measure(
                &format!("{mode}_zstd_messages"),
                json!(coverage(&transcript(&t), "out").zstd),
                "",
            );
            took.push(elapsed.as_secs_f64());
        }
        let ratio = took[1] / took[0].max(0.001);
        lab.check(
            "time_ratio",
            json!((ratio * 100.0).round() / 100.0),
            "<= 0.40 (S5)",
            ratio <= 0.4,
            Some("WP-2"),
        );
    }
    lab.finish();
}

/// `upgrade`: under a running tty session and pipe session, qsh-server is replaced by a newer
/// build and a bootstrap runs (m2.md 10.2). The harness binaries need the cargo feature
/// `test-hooks`: the first daemon and the first sessions' bootstraps get `QSH_TEST_VERSION`
/// (through ssh's SetEnv and sshd's AcceptEnv), so the daemon looks older than the new file.
#[test]
fn upgrade() {
    let Some(mut lab) = lab() else { return };
    let old = "0.0.1";
    let as_old = format!("SetEnv=QSH_TEST_VERSION={old}");
    for p in profiles(&[CLEAN, CROSSBORDER]) {
        lab.start("upgrade", p);
        let client = lab.client(&format!("upgrade-{}", p.name), "");
        let t = client.path("t.jsonl");
        let term = Term::spawn(
            client.qsh(Some(&t), &["-o", &as_old, HOST, "--", TICKER]),
            &client.log("t.log"),
        );
        let started = term.wait_tick_after(0, UNIX_EPOCH, secs(60)).is_some();
        lab.check("session_started", json!(started), "true", started, None);
        let mut pipe = client.qsh(None, &["-o", &as_old, HOST, "--", "sleep 8; exit 7"]);
        pipe.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(File::create(client.log("pipe.log")).unwrap());
        let mut pipe = pipe.spawn().unwrap();
        sleep(secs(2));
        let before = lab.server_status(Some(old));
        let server = lab.server.display().to_string();
        // A package upgrade: a new file renamed over the old one
        lab.net(&["install-server", &server]);
        let upgraded = SystemTime::now();
        let (code, _) = run_to_end(
            client.qsh(None, &[HOST, "--", "true"]),
            Stdio::null(),
            Stdio::null(),
            &client.log("bootstrap.log"),
            secs(120),
        );
        lab.check("bootstrap_exit_code", json!(code), "0", code == Some(0), None);
        let exit = wait_child(&mut pipe, secs(120));
        lab.check("pipe_session_exit_code", json!(exit), "7", exit == Some(7), None);
        let next = term.wait_tick_after(0, upgraded, secs(60));
        lab.check(
            "output_after_upgrade_ms",
            json!(next.map(|t| round1(ms_between(upgraded, t.arrived)))),
            "within 60 s",
            next.is_some(),
            None,
        );
        sleep(secs(2));
        let after = lab.server_status(None);
        let field = |s: &Option<Value>, k: &str| s.as_ref().map_or(Value::Null, |s| s[k].clone());
        lab.check(
            "same_daemon_pid",
            json!([field(&before, "pid"), field(&after, "pid")]),
            "equal",
            !field(&before, "pid").is_null() && field(&before, "pid") == field(&after, "pid"),
            None,
        );
        lab.check(
            "daemon_version",
            json!([field(&before, "version"), field(&after, "version")]),
            &format!("{old}, then the new build's"),
            field(&before, "version") == old && field(&after, "version").as_str().is_some_and(|v| v != old),
            None,
        );
        lab.measure(
            "restarts_upgraded_from",
            json!([field(&after, "restarts"), field(&after, "upgraded_from")]),
            "",
        );
        let ticks = term.ticks(0);
        let missing = missing_ticks(&ticks);
        lab.check(
            "counter_contiguous",
            json!(missing),
            "0 ticks missing",
            missing == 0 && !ticks.is_empty(),
            None,
        );
        let c = coverage(&transcript(&t), "out");
        lab.check(
            "bytes_unaccounted",
            json!(c.holes.len() + c.gaps),
            "0 (no gap)",
            c.holes.is_empty() && c.gaps == 0,
            None,
        );
        lab.measure("disconnects", json!(c.disconnects), "");
    }
    lab.finish();
}

/// `throughput`: a pipe session's `cat` against `ssh host cat`.
#[test]
fn throughput() {
    let Some(mut lab) = lab() else { return };
    let window = secs(env_u64("QSH_CHAOS_WINDOW", 20));
    for p in profiles(&[CROSSBORDER, LOSSY]) {
        lab.start("throughput", p);
        let blob = lab.random_file(100).display().to_string();
        let client = lab.client(&format!("throughput-{}", p.name), "");
        let ssh = window_rate(
            client.ssh(&[HOST, "cat", &blob]),
            &client.log("ssh.log"),
            window,
            secs(60),
        );
        lab.net(&["kill-user"]);
        let qsh = window_rate(
            client.qsh(None, &[HOST, "--", "cat", &blob]),
            &client.log("qsh.log"),
            window,
            secs(60),
        );
        let round2 = |x: f64| (x * 100.0).round() / 100.0;
        let (s, q) = (ssh.map(|r| round2(r.0)), qsh.map(|r| round2(r.0)));
        lab.measure("ssh_mbit_s", json!(s), "Mbit/s");
        lab.measure("qsh_mbit_s", json!(q), "Mbit/s");
        lab.check(
            "qsh_vs_ssh",
            json!([q, s]),
            "qsh >= ssh",
            matches!((q, s), (Some(q), Some(s)) if q >= s),
            Some("S8 baseline"),
        );
    }
    lab.finish();
}

// ---------------------------------------------------------------------------------------------
// The benchmark (m2.md 12.4): qsh, ssh and mosh under the same netem profile

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tool {
    Ssh,
    Mosh,
    Qsh,
}

impl Tool {
    fn name(self) -> &'static str {
        match self {
            Tool::Ssh => "ssh",
            Tool::Mosh => "mosh",
            Tool::Qsh => "qsh",
        }
    }

    /// The measuring shell, interactively.
    fn shell(self, client: &Client, transcript: &Path, predict: &str) -> Command {
        match self {
            Tool::Ssh => client.ssh(&["-tt", HOST, SHELL]),
            Tool::Mosh => client.mosh(predict, &SHELL_ARGV),
            Tool::Qsh => client.qsh(Some(transcript), &[HOST, "--", SHELL]),
        }
    }
}

/// The benchmark: `QSH_BENCH=1` (and `QSH_CHAOS=1`, root). `QSH_BENCH_PROFILE` (default
/// crossborder), `QSH_BENCH_TOOLS` (default ssh,mosh,qsh), `QSH_BENCH_RUNS` (Ctrl-C runs,
/// default 5), `QSH_BENCH_KEYS` (keystrokes, default 20), `QSH_BENCH_SEQ` (default 10000000),
/// `QSH_BENCH_CAP` (seconds per long measurement, default 300), `QSH_BENCH_OUTAGE` (seconds,
/// default 60), `QSH_BENCH_WINDOW` (bulk window, seconds, default 30).
#[test]
fn bench_ssh_mosh_qsh() {
    if !env_flag("QSH_BENCH") {
        return;
    }
    let Some(mut lab) = lab() else { return };
    let name = env_str("QSH_BENCH_PROFILE", "crossborder");
    let p = ALL_PROFILES
        .into_iter()
        .find(|p| p.name == name)
        .unwrap_or_else(|| panic!("QSH_BENCH_PROFILE: unknown profile {name}"));
    let tools = env_str("QSH_BENCH_TOOLS", "ssh,mosh,qsh");
    for tool in [Tool::Ssh, Tool::Mosh, Tool::Qsh] {
        if !tools.split(',').any(|t| t.trim() == tool.name()) {
            continue;
        }
        bench_tool(&mut lab, p, tool);
    }
    lab.finish();
}

fn bench_tool(lab: &mut Lab, p: Profile, tool: Tool) {
    let n = tool.name();
    let cap = secs(env_u64("QSH_BENCH_CAP", 300));
    let outage = env_u64("QSH_BENCH_OUTAGE", 60);

    // Keystroke echo
    let modes: &[&str] = if tool == Tool::Mosh {
        &["never", "always"]
    } else {
        &["never"]
    };
    let mut cells = Vec::new();
    let mut values = Vec::new();
    for mode in modes {
        lab.start("bench", p);
        let client = lab.client(&format!("bench-{n}-echo-{mode}"), "");
        let term = Term::spawn(
            tool.shell(&client, &client.path("t.jsonl"), mode),
            &client.log("echo.log"),
        );
        let echo = bench_echo(term, env_u64("QSH_BENCH_KEYS", 20));
        let (p50, p95) = (quantile(&echo, 0.5), quantile(&echo, 0.95));
        values.push(json!({"mode": mode, "p50": p50.map(round1), "p95": p95.map(round1), "n": echo.len()}));
        let label = if tool == Tool::Mosh {
            if *mode == "never" {
                "off: "
            } else {
                "on: "
            }
        } else {
            ""
        };
        cells.push(match (p50, p95) {
            (Some(a), Some(b)) => format!("{label}{a:.0} ms (p95 {b:.0})"),
            _ => format!("{label}no echo"),
        });
    }
    lab.bench(n, "echo", json!(values), &cells.join(" / "));

    // Ctrl-C during a flood
    lab.start("bench", p);
    let client = lab.client(&format!("bench-{n}-ctrl-c"), "");
    let runs = env_u64("QSH_BENCH_RUNS", 5).max(1);
    let r = ctrl_c_runs(&client, runs, secs(120), |c, t| tool.shell(c, t, "never"));
    let p50 = quantile(&r.latencies, 0.5);
    let text = match p50 {
        Some(x) if r.timeouts == 0 => format!("{:.1} s", x / 1000.0),
        Some(x) => format!("{:.1} s ({} of {runs} runs > 120 s)", x / 1000.0, r.timeouts),
        None => format!("> 120 s ({runs} runs)"),
    };
    lab.bench(n, "ctrl_c", json!({"ms": r.latencies, "timeouts": r.timeouts}), &text);
    let scrollback = match tool {
        Tool::Ssh => "full (a byte stream)".to_string(),
        Tool::Mosh => "none (mosh keeps only the screen)".to_string(),
        Tool::Qsh if r.gap_bytes == 0 && r.snapshots == 0 => "full".to_string(),
        Tool::Qsh => format!(
            "full except announced gaps ({:.1} MiB in {runs} runs)",
            r.gap_bytes as f64 / 1048576.0
        ),
    };
    lab.bench(n, "scrollback", json!({"gap_bytes": r.gap_bytes}), &scrollback);

    // seq to the end of its output
    lab.start("bench", p);
    let lines = env_u64("QSH_BENCH_SEQ", 10_000_000);
    let client = lab.client(&format!("bench-{n}-seq"), "");
    let mut term = Term::spawn(
        tool.shell(&client, &client.path("t.jsonl"), "never"),
        &client.log("seq.log"),
    );
    let text = if term.wait_for(PROMPT, 0, secs(90)).is_some() {
        let pos = term.pos();
        let sent = SystemTime::now();
        term.send(format!("seq 1 {lines}; echo SEQ''DONE\r").as_bytes());
        match term.wait_for("SEQDONE", pos, cap) {
            Some((_, at)) => format!("{:.1} s", ms_between(sent, at) / 1000.0),
            None => format!("> {} s", cap.as_secs()),
        }
    } else {
        "no session".to_string()
    };
    lab.bench(n, "seq", json!({"lines": lines}), &text);
    drop(term);

    // Network events under a ticker
    for (row, event) in [
        ("address_change", "move-client"),
        ("udp_block", "block-udp"),
        ("outage", "offline"),
    ] {
        lab.start("bench", p);
        let client = lab.client(&format!("bench-{n}-{row}"), "");
        let mut term = Term::spawn(
            tool.shell(&client, &client.path("t.jsonl"), "never"),
            &client.log("tick.log"),
        );
        if term.wait_for(PROMPT, 0, secs(90)).is_none() {
            lab.bench(n, row, Value::Null, "no session");
            continue;
        }
        let pos = term.pos();
        term.send(format!("{TICKER}\r").as_bytes());
        if term.wait_tick_after(pos, UNIX_EPOCH, secs(60)).is_none() {
            lab.bench(n, row, Value::Null, "no output");
            continue;
        }
        sleep(secs(2));
        let mut at = SystemTime::now();
        lab.net(&[event]);
        if event == "offline" {
            sleep(secs(outage));
            at = SystemTime::now();
            lab.net(&["online"]);
        }
        let next = term.wait_tick_after(pos, at, secs(90));
        sleep(secs(2));
        let ticks = term.ticks(pos);
        let missing = missing_ticks(&ticks);
        let printed = ticks.iter().map(|t| t.seq).max().unwrap_or(0);
        let text = match next {
            Some(t) if row == "outage" => format!(
                "{:.1} s after a {outage} s outage; {missing} of {printed} lines missed",
                ms_between(at, t.arrived) / 1000.0
            ),
            Some(t) => format!("{:.1} s", ms_between(at, t.arrived) / 1000.0),
            None => "no output within 90 s".to_string(),
        };
        lab.bench(
            n,
            row,
            json!({"ms": next.map(|t| ms_between(at, t.arrived)), "missing": missing, "printed": printed}),
            &text,
        );
        drop(term);
    }
    lab.net(&["reset"]);

    // Bulk pipe transfer
    lab.start("bench", p);
    let window = secs(env_u64("QSH_BENCH_WINDOW", 30));
    let client = lab.client(&format!("bench-{n}-bulk"), "");
    let blob = lab.random_file(100).display().to_string();
    let rate = match tool {
        Tool::Ssh => window_rate(
            client.ssh(&[HOST, "cat", &blob]),
            &client.log("bulk.log"),
            window,
            secs(60),
        ),
        Tool::Qsh => window_rate(
            client.qsh(None, &[HOST, "--", "cat", &blob]),
            &client.log("bulk.log"),
            window,
            secs(60),
        ),
        Tool::Mosh => None,
    };
    let text = match (tool, rate) {
        (Tool::Mosh, _) => "n/a: mosh has no pipe mode".to_string(),
        (_, Some((mbit, _))) => format!("{mbit:.2} Mbit/s (100 MB in {:.0} s)", 800.0 / mbit.max(0.001)),
        (_, None) => "no data within 60 s".to_string(),
    };
    lab.bench(n, "bulk", json!(rate.map(|r| r.0)), &text);
}

/// Keystroke echo latencies (ms) at the shell's prompt; ends the client.
fn bench_echo(mut term: Term, keys: u64) -> Vec<f64> {
    let mut latencies = Vec::new();
    if term.wait_for(PROMPT, 0, secs(90)).is_none() {
        return latencies;
    }
    sleep(secs(1));
    for i in 0..keys {
        // Letters that no escape sequence of the terminal output ends with
        let key = [b"vwxyz"[(i % 5) as usize]];
        let pos = term.pos();
        let sent = SystemTime::now();
        term.send(&key);
        if let Some((_, at)) = term.wait_for(std::str::from_utf8(&key).unwrap(), pos, secs(10)) {
            latencies.push(ms_between(sent, at));
        }
        sleep(Duration::from_millis(200));
    }
    term.close();
    latencies
}

#[test]
fn tick_parser() {
    let data = b"xT1:1759000000000000001\r\nT2:17590000000000000\r\nT3:1759000000000000003\x1b[KT4:1759000000000000004";
    let ticks = parse_ticks(data, 0);
    assert_eq!(
        ticks.iter().map(|t| (t.0, t.1)).collect::<Vec<_>>(),
        vec![(1, 1759000000000000001), (3, 1759000000000000003)]
    );
}

#[test]
fn coverage_accounts_for_gaps_and_holes() {
    let records: Vec<Value> = [
        r#"{"ev":"connected","transport":"quic","remote":"10.77.2.2:60443"}"#,
        r#"{"ev":"output","stream":"out","offset":0,"len":10}"#,
        r#"{"ev":"output","stream":"out","offset":5,"len":10}"#,
        r#"{"ev":"gap","from":15,"to":40}"#,
        r#"{"ev":"output","stream":"out","offset":50,"len":5}"#,
        r#"{"ev":"snapshot","offset":80}"#,
        r#"{"ev":"output","stream":"out","offset":80,"len":1,"zstd":9}"#,
    ]
    .iter()
    .map(|l| serde_json::from_str(l).unwrap())
    .collect();
    let c = coverage(&records, "out");
    assert_eq!(c.holes, vec![(40, 50)]);
    assert_eq!((c.end, c.gaps, c.gap_bytes, c.snapshots, c.zstd), (81, 1, 25, 1, 1));
    assert_eq!(c.connected, vec!["quic"]);
    assert_eq!(quantile(&[3.0, 1.0, 2.0, 4.0], 0.5), Some(2.0));
    assert_eq!(quantile(&[3.0, 1.0, 2.0, 4.0], 0.95), Some(4.0));
}

/// The quantile checks and the recovery counts of m2.md 6.4.
#[test]
fn quantile_checks_and_recoveries() {
    // Nine runs: at most 2 over a p95 bound, at most 7 over a p50 bound
    let runs = |over: usize| -> Vec<f64> { (0..9).map(|i| if i < over { 2.0 } else { 0.0 }).collect() };
    assert!(quantile_check(&runs(2), 0.95, 1.0).2);
    assert!(!quantile_check(&runs(3), 0.95, 1.0).2);
    assert!(quantile_check(&runs(7), 0.5, 1.0).2);
    assert!(!quantile_check(&runs(8), 0.5, 1.0).2);
    assert!((binomial_at_least(9, 2, 0.05) - 0.0712).abs() < 1e-3);
    assert!((binomial_at_least(9, 0, 0.3) - 1.0).abs() < 1e-9);
    // k = 4: none for the median up to 15.9 % loss, at 20 % one for the p50 and three for the p95
    assert_eq!((recoveries(0.06, 0.5), recoveries(0.15, 0.5)), (0, 0));
    assert_eq!((recoveries(0.20, 0.5), recoveries(0.20, 0.95)), (1, 3));
}
