//! The reports (m2.md 8.1): for people, one line per check with the fix under each problem
//! and nothing else (DESIGN.md principle 5: quiet and honest); for scripts, one JSON object of
//! schema version 1 with stable check ids.
//!
//! On a terminal the status is a mark (✓ · – ! ✗), coloured unless `NO_COLOR` is set;
//! elsewhere it is the word (`ok`, `info`, `skip`, `warn`, `fail`), so that logs and pipes
//! stay plain ASCII.

use serde_json::{json, Value};

use super::checks::{DaemonState, HostInfo};
use super::{Check, Fix, Status, SCHEMA};

/// How to print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    /// Marks instead of words.
    pub marks: bool,
    /// ANSI colours.
    pub color: bool,
    /// Wrap lines at this width.
    pub width: usize,
}

impl Style {
    /// Plain text (not a terminal).
    pub const PLAIN: Style = Style {
        marks: false,
        color: false,
        width: 100,
    };

    /// The style for standard output: marks and colours on a terminal.
    pub fn for_stdout() -> Style {
        let stdout = std::io::stdout();
        if !qsh_core::sys::is_tty(&stdout) {
            return Style::PLAIN;
        }
        let width = qsh_core::sys::window_size(&stdout)
            .map(|(cols, _)| usize::from(cols))
            .filter(|w| *w >= 40)
            .unwrap_or(80)
            .min(110);
        Style {
            marks: true,
            color: std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
                && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true),
            width,
        }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    /// The status column: a mark or a word, padded.
    fn status(&self, s: Status) -> String {
        if self.marks {
            let (mark, code) = match s {
                Status::Ok => ("✓", "32"),
                Status::Info => ("·", "36"),
                Status::Skip => ("–", "2"),
                Status::Warn => ("!", "33;1"),
                Status::Fail => ("✗", "31;1"),
            };
            format!("{} ", self.paint(code, mark))
        } else {
            format!("{:<6}", s.as_str())
        }
    }

    fn status_width(&self) -> usize {
        if self.marks {
            2
        } else {
            6
        }
    }
}

/// Wrap `text` to lines of at most `width` characters (words longer than that stay whole).
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split(' ') {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// The column the summaries start at, after the status and an id of `id_width`.
fn indent(style: &Style, id_width: usize) -> usize {
    2 + style.status_width() + id_width + 1
}

/// One check: its line, continuation lines, and the fix under a problem.
pub fn check_lines(check: &Check, style: &Style, id_width: usize) -> String {
    line(
        check.status,
        check.id,
        &check.summary,
        check.fix.as_ref(),
        style,
        id_width,
    )
}

/// One line of a report: the status, `label` padded to `id_width`, the summary wrapped
/// under itself, and the fix (for problems, and for info and skip lines that have one).
pub fn line(status: Status, label: &str, summary: &str, fix: Option<&Fix>, style: &Style, id_width: usize) -> String {
    let col = indent(style, id_width);
    let room = style.width.saturating_sub(col).max(30);
    let pad = " ".repeat(col);
    let dim = |text: &str| {
        if status == Status::Skip {
            style.paint("2", text)
        } else {
            text.to_string()
        }
    };
    let mut out = String::new();
    let id = dim(&format!("{label:<id_width$}"));
    for (i, text) in wrap(summary, room).iter().enumerate() {
        if i == 0 {
            out.push_str(&format!("  {}{id} {}\n", style.status(status), dim(text)));
        } else {
            out.push_str(&format!("{pad}{}\n", dim(text)));
        }
    }
    let Some(fix) = fix else {
        return out;
    };
    if status == Status::Ok {
        return out;
    }
    let command = if fix.tune.is_some() && status >= Status::Warn {
        let mut c = "sudo qsh-server tune --apply".to_string();
        for f in &fix.tune_flags {
            c.push(' ');
            c.push_str(f);
        }
        Some(c)
    } else if fix.commands.is_empty() {
        None
    } else {
        Some(fix.commands.join(" && "))
    };
    let label = style.paint("2", "fix:");
    let shown = command.is_some();
    if let Some(command) = command {
        // Commands are never wrapped: they must stay copyable
        out.push_str(&format!("{pad}{label} {command}\n"));
    }
    if let Some(note) = &fix.note {
        // Under the command, indented past "fix: "; alone, it is the fix
        let text = if shown { note.clone() } else { format!("fix: {note}") };
        for (i, text) in wrap(&text, room.saturating_sub(5).max(30)).iter().enumerate() {
            let text = if i == 0 && !shown {
                text.replacen("fix:", &label, 1)
            } else {
                text.clone()
            };
            let lead = if i == 0 && !shown { "" } else { "     " };
            out.push_str(&format!("{pad}{lead}{text}\n"));
        }
    }
    out
}

/// The id column's width for these checks.
pub fn id_width(checks: &[Check]) -> usize {
    checks.iter().map(|c| c.id.len()).max().unwrap_or(8).max(13) + 1
}

/// The closing line: how many problems, and whether tune can help.
pub fn footer(checks: &[Check]) -> String {
    let fails = checks.iter().filter(|c| c.status == Status::Fail).count();
    let warns = checks.iter().filter(|c| c.status == Status::Warn).count();
    let tune = checks
        .iter()
        .any(|c| c.status >= Status::Warn && c.fix.as_ref().is_some_and(|f| f.tune.is_some()));
    let plural = |n: usize, one: &str, many: &str| if n == 1 { one.to_string() } else { many.to_string() };
    let mut text = match (fails, warns) {
        (0, 0) => "Nothing to fix.".to_string(),
        (f, 0) => format!("{f} {} a transport.", plural(f, "problem stops", "problems stop")),
        (0, w) => format!("{w} {} qsh down.", plural(w, "problem slows", "problems slow")),
        (f, w) => format!(
            "{f} {} a transport, {w} {} qsh down.",
            plural(f, "problem stops", "problems stop"),
            plural(w, "slows", "slow")
        ),
    };
    if tune {
        text.push_str(" sudo qsh-server tune shows what it would change.");
    }
    text
}

/// The human report of `qsh-server doctor`.
pub fn human(host: &HostInfo, checks: &[Check], style: &Style) -> String {
    let mut out = format!("qsh-server doctor: {} — {}\n\n", host.name, host.describe());
    let w = id_width(checks);
    for c in checks {
        out.push_str(&check_lines(c, style, w));
    }
    out.push('\n');
    out.push_str(&footer(checks));
    out.push('\n');
    out
}

/// The JSON `daemon` object (m2.md 8.1): ports and certificate only with `--probe`.
pub fn daemon_json(daemon: &DaemonState, probe: bool) -> Value {
    match daemon {
        DaemonState::Running(s) => {
            let mut d = json!({
                "version": s["version"],
                "running": true,
                "pid": s["pid"],
                "sessions": s["session_count"],
                "can_upgrade": s["can_upgrade"],
            });
            if probe {
                d["udp"] = s["udp"].clone();
                d["tcp"] = s["tcp"].clone();
                d["extra_ports"] = if s["extra_ports"].is_array() {
                    s["extra_ports"].clone()
                } else {
                    json!([])
                };
                d["cert_sha256"] = s["cert_sha256"].clone();
            }
            d
        }
        DaemonState::NotRunning => json!({ "running": false }),
        DaemonState::Unreachable(why) => json!({ "running": Value::Null, "error": why }),
        DaemonState::Failed(why, _) => json!({ "running": false, "error": why }),
    }
}

/// The JSON report of `qsh-server doctor --json` (m2.md 8.1).
pub fn json(host: &HostInfo, daemon: &DaemonState, probe: bool, checks: &[Check]) -> Value {
    json!({
        "doctor": SCHEMA,
        "version": qsh_core::server::version(),
        "host": host.to_json(),
        "daemon": daemon_json(daemon, probe),
        "checks": checks.iter().map(Check::to_json).collect::<Vec<_>>(),
    })
}
