//! `qsh ls`, `qsh kill`, and which session `qsh attach` means.
//!
//! Sessions are named on the command line by their id, any unique prefix of it (`qsh ls` shows
//! the first 8 hex digits), or their name.

use std::io::{BufRead as _, Write as _};

use qsh_core::client::store::{now, SavedSession, SessionStore};
use qsh_core::client::{self, ClientError, EXIT_ERROR};
use qsh_core::proto::bootstrap::SessionInfo;
use qsh_core::transport::ssh::SshCommand;
use serde_json::{json, Value};

use crate::terminal::Start;

/// How long ago `created` (seconds since the epoch) was, for people.
pub fn age(created: u64, now: u64) -> String {
    if created == 0 {
        return "-".into();
    }
    let s = now.saturating_sub(created);
    match s {
        0..=59 => "just now".into(),
        60..=3599 => format!("{} min ago", s / 60),
        3600..=86399 => format!("{} h ago", s / 3600),
        _ => format!("{} d ago", s / 86400),
    }
}

/// True when `arg` names the session: its name, or a prefix of its id.
pub fn names(arg: &str, id: &str, name: Option<&str>) -> bool {
    if name == Some(arg) {
        return true;
    }
    let arg = arg.to_ascii_lowercase();
    !arg.is_empty() && arg.bytes().all(|b| b.is_ascii_hexdigit()) && id.starts_with(&arg)
}

fn short(id: &str) -> &str {
    &id[..id.len().min(8)]
}

fn command_text(command: Option<&str>) -> String {
    match command {
        Some(c) => c.replace(['\n', '\r', '\t'], " "),
        None => "(login shell)".into(),
    }
}

/// Lay out rows as columns, two spaces apart; the last column is not padded.
pub fn table(rows: &[Vec<String>]) -> String {
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut widths = vec![0; columns];
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let mut out = String::new();
    for row in rows {
        let mut line = String::new();
        for (i, cell) in row.iter().enumerate() {
            if i + 1 < row.len() {
                line.push_str(&format!("{cell:<width$}  ", width = widths[i]));
            } else {
                line.push_str(cell);
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

fn state_of(info: &SessionInfo, here: bool) -> String {
    match (info.exited, info.attached, here) {
        (true, _, _) => "exited".into(),
        (false, true, true) => "attached here".into(),
        (false, true, false) => "attached".into(),
        (false, false, _) => "detached".into(),
    }
}

fn kind(pipe: bool) -> &'static str {
    if pipe {
        "pipe"
    } else {
        "tty"
    }
}

/// The saved sessions of `destination`, reporting files that could not be read.
fn saved_for(store: &SessionStore, destination: &str) -> Vec<SavedSession> {
    match store.list() {
        Ok(listing) => {
            for u in &listing.unusable {
                eprintln!("qsh: skipped {}: {}", u.path.display(), u.why);
            }
            listing
                .sessions
                .into_iter()
                .filter(|s| s.destination == destination)
                .collect()
        }
        Err(e) => {
            eprintln!("qsh: cannot read the saved sessions in {}: {e}", store.dir().display());
            Vec::new()
        }
    }
}

fn print_error(e: &ClientError) -> i32 {
    match e {
        // ssh said what went wrong
        ClientError::Ssh(_) => {}
        ClientError::NoServer => eprintln!("qsh: qsh-server is not installed on the host"),
        e => eprintln!("qsh: {e}"),
    }
    e.exit_code()
}

/// `qsh ls DESTINATION`: the sessions on the host, over ssh.
pub async fn ls_remote(ssh: &SshCommand, store: &SessionStore, json_out: bool, interactive: bool) -> i32 {
    let sessions = match client::list_sessions(ssh, interactive).await {
        Ok(s) => s,
        Err(e) => return print_error(&e),
    };
    let here = |s: &SessionInfo| {
        qsh_core::crypto::unhex::<16>(&s.session).is_some_and(|id| store.in_use(&ssh.destination, &id))
    };
    if json_out {
        let list: Vec<Value> = sessions
            .iter()
            .map(|s| {
                json!({
                    "session": s.session,
                    "name": s.name,
                    "command": s.command,
                    "created": s.created,
                    "attached": s.attached,
                    "attached_here": s.attached && here(s),
                    "exited": s.exited,
                    "tty": s.tty != Some(false),
                })
            })
            .collect();
        println!("{}", json!({ "destination": ssh.destination, "sessions": list }));
        return 0;
    }
    if sessions.is_empty() {
        println!("no sessions on {}", ssh.destination);
        return 0;
    }
    let now = now();
    let mut rows = vec![["ID", "NAME", "STATE", "KIND", "CREATED", "COMMAND"]
        .map(String::from)
        .to_vec()];
    for s in &sessions {
        rows.push(vec![
            short(&s.session).to_string(),
            s.name.clone().unwrap_or_else(|| "-".into()),
            state_of(s, here(s)),
            kind(s.tty == Some(false)).into(),
            age(s.created, now),
            command_text(s.command.as_deref()),
        ]);
    }
    print!("{}", table(&rows));
    0
}

/// `qsh ls`: the sessions saved on this machine, no network.
pub fn ls_saved(store: &SessionStore, json_out: bool) -> i32 {
    let listing = match store.list() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("qsh: cannot read the saved sessions in {}: {e}", store.dir().display());
            return EXIT_ERROR;
        }
    };
    for u in &listing.unusable {
        eprintln!("qsh: skipped {}: {}", u.path.display(), u.why);
    }
    let in_use = |s: &SavedSession| store.in_use(&s.destination, &s.session);
    if json_out {
        let list: Vec<Value> = listing
            .sessions
            .iter()
            .map(|s| {
                json!({
                    "destination": s.destination,
                    "session": s.id(),
                    "name": s.name,
                    "command": s.command,
                    "created": s.created,
                    "tty": !s.pipe,
                    "in_use": in_use(s),
                })
            })
            .collect();
        println!("{}", json!({ "sessions": list }));
        return 0;
    }
    if listing.sessions.is_empty() {
        println!("no saved sessions (qsh ls DESTINATION asks a host)");
        return 0;
    }
    let now = now();
    let mut rows = vec![["DESTINATION", "ID", "NAME", "STATE", "KIND", "CREATED", "COMMAND"]
        .map(String::from)
        .to_vec()];
    for s in &listing.sessions {
        rows.push(vec![
            s.destination.clone(),
            short(&s.id()).to_string(),
            s.name.clone().unwrap_or_else(|| "-".into()),
            if in_use(s) { "attached here" } else { "saved" }.into(),
            kind(s.pipe).into(),
            age(s.created, now),
            command_text(s.command.as_deref()),
        ]);
    }
    print!("{}", table(&rows));
    0
}

/// `qsh kill DESTINATION SESSION|--all`.
pub async fn kill(ssh: &SshCommand, store: &SessionStore, session: Option<&str>, interactive: bool) -> i32 {
    // Which sessions: a full id or one saved here needs no list from the host
    let targets: Vec<(String, String)> = match session {
        Some(arg) => {
            let saved: Vec<_> = saved_for(store, &ssh.destination)
                .into_iter()
                .filter(|s| names(arg, &s.id(), s.name.as_deref()))
                .collect();
            if arg.len() == 32 && qsh_core::crypto::unhex::<16>(arg).is_some() {
                vec![(arg.to_ascii_lowercase(), describe(None, None))]
            } else if let [one] = saved.as_slice() {
                vec![(one.id(), describe(one.name.as_deref(), one.command.as_deref()))]
            } else {
                let sessions = match client::list_sessions(ssh, interactive).await {
                    Ok(s) => s,
                    Err(e) => return print_error(&e),
                };
                match pick(arg, &sessions, &ssh.destination) {
                    Ok(s) => vec![(s.session.clone(), describe(s.name.as_deref(), s.command.as_deref()))],
                    Err(e) => {
                        eprintln!("qsh: {e}");
                        return EXIT_ERROR;
                    }
                }
            }
        }
        None => match client::list_sessions(ssh, interactive).await {
            Ok(s) if s.is_empty() => {
                println!("no sessions on {}", ssh.destination);
                return 0;
            }
            Ok(s) => s
                .iter()
                .map(|s| (s.session.clone(), describe(s.name.as_deref(), s.command.as_deref())))
                .collect(),
            Err(e) => return print_error(&e),
        },
    };
    let mut code = 0;
    for (id, what) in targets {
        match client::kill_session(ssh, &id, interactive).await {
            Ok(found) => {
                if let Some(raw) = qsh_core::crypto::unhex::<16>(&id) {
                    let _ = store.remove(&ssh.destination, &raw);
                }
                if found {
                    println!("ended session {}{what} on {}", short(&id), ssh.destination);
                } else {
                    eprintln!("qsh: no session {} on {}", short(&id), ssh.destination);
                    code = EXIT_ERROR;
                }
            }
            Err(e) => return print_error(&e),
        }
    }
    code
}

fn describe(name: Option<&str>, command: Option<&str>) -> String {
    match (name, command) {
        (Some(n), _) => format!(" ({n})"),
        (None, Some(c)) => format!(" ({})", command_text(Some(c))),
        (None, None) => String::new(),
    }
}

/// The one session of `sessions` that `arg` names.
fn pick<'a>(arg: &str, sessions: &'a [SessionInfo], destination: &str) -> Result<&'a SessionInfo, String> {
    let hits: Vec<_> = sessions
        .iter()
        .filter(|s| names(arg, &s.session, s.name.as_deref()))
        .collect();
    match hits.as_slice() {
        [one] => Ok(one),
        [] => Err(format!(
            "no session {arg} on {destination} (qsh ls {destination} lists them)"
        )),
        many => Err(format!(
            "{arg} names {} sessions on {destination}; give more of the id:\n{}",
            many.len(),
            listing(many.iter().copied())
        )),
    }
}

/// Indented lines describing sessions.
fn listing<'a>(sessions: impl Iterator<Item = &'a SessionInfo>) -> String {
    let now = now();
    let rows: Vec<Vec<String>> = sessions
        .map(|s| {
            vec![
                format!("  {}", short(&s.session)),
                s.name.clone().unwrap_or_else(|| "-".into()),
                state_of(s, false),
                age(s.created, now),
                command_text(s.command.as_deref()),
            ]
        })
        .collect();
    table(&rows).trim_end().to_string()
}

fn info_of(s: &SavedSession) -> SessionInfo {
    SessionInfo {
        session: s.id(),
        name: s.name.clone(),
        command: s.command.clone(),
        created: s.created,
        attached: false,
        exited: false,
        tty: s.pipe.then_some(false),
    }
}

/// Which of `candidates` to attach: ask on a terminal, otherwise fail with the list.
fn choose(candidates: &[SessionInfo], destination: &str, tty: bool) -> Result<usize, String> {
    let now = now();
    let rows: Vec<Vec<String>> = candidates
        .iter()
        .enumerate()
        .map(|(i, s)| {
            vec![
                format!("  {})", i + 1),
                short(&s.session).to_string(),
                s.name.clone().unwrap_or_else(|| "-".into()),
                age(s.created, now),
                command_text(s.command.as_deref()),
            ]
        })
        .collect();
    let list = table(&rows);
    if !tty {
        return Err(format!(
            "{} detached sessions on {destination}; say which: qsh attach {destination} ID\n{}",
            candidates.len(),
            list.trim_end()
        ));
    }
    eprint!(
        "Detached sessions on {destination}:\n{list}Attach which? [1-{}] ",
        candidates.len()
    );
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    match line.trim().parse::<usize>() {
        Ok(n) if (1..=candidates.len()).contains(&n) => Ok(n - 1),
        _ => Err("no session chosen".into()),
    }
}

/// Which session `qsh attach DESTINATION [SESSION]` means, and how to reach it.
///
/// - With SESSION: the saved session it names, without ssh; else the one the host lists
///   under that id or name, with new credentials over ssh.
/// - Without: the saved sessions of DESTINATION that no `qsh` here is attached to; exactly one
///   is taken, several are offered to choose from. With none saved, the host's detached
///   sessions, the same way.
pub async fn choose_attach(
    ssh: &SshCommand,
    store: &SessionStore,
    session: Option<&str>,
    interactive: bool,
    tty: bool,
) -> Result<Start, i32> {
    let destination = &ssh.destination;
    let saved = saved_for(store, destination);
    let fail = |e: String| {
        eprintln!("qsh: {e}");
        EXIT_ERROR
    };
    if let Some(arg) = session {
        let hits: Vec<_> = saved
            .iter()
            .filter(|s| names(arg, &s.id(), s.name.as_deref()))
            .collect();
        match hits.as_slice() {
            [one] => return Ok(Start::Saved(Box::new((*one).clone()))),
            [] => {}
            many => {
                let infos: Vec<SessionInfo> = many.iter().map(|s| info_of(s)).collect();
                return Err(fail(format!(
                    "{arg} names {} saved sessions of {destination}; give more of the id:\n{}",
                    many.len(),
                    listing(infos.iter())
                )));
            }
        }
        let sessions = client::list_sessions(ssh, interactive)
            .await
            .map_err(|e| print_error(&e))?;
        let s = pick(arg, &sessions, destination).map_err(fail)?;
        return Ok(Start::Remote {
            session: s.session.clone(),
            info: Some(s.clone()),
        });
    }
    let free: Vec<_> = saved
        .into_iter()
        .filter(|s| !store.in_use(&s.destination, &s.session))
        .collect();
    match free.len() {
        1 => return Ok(Start::Saved(Box::new(free.into_iter().next().expect("one")))),
        0 => {}
        _ => {
            let infos: Vec<SessionInfo> = free.iter().map(info_of).collect();
            let i = choose(&infos, destination, tty).map_err(fail)?;
            return Ok(Start::Saved(Box::new(free[i].clone())));
        }
    }
    let sessions = client::list_sessions(ssh, interactive)
        .await
        .map_err(|e| print_error(&e))?;
    let detached: Vec<SessionInfo> = sessions.iter().filter(|s| !s.attached).cloned().collect();
    let chosen = match detached.len() {
        0 if sessions.is_empty() => return Err(fail(format!("no sessions on {destination}"))),
        0 => {
            return Err(fail(format!(
                "no detached session on {destination}; to take an attached one over: qsh attach {destination} ID\n{}",
                listing(sessions.iter())
            )))
        }
        1 => 0,
        _ => choose(&detached, destination, tty).map_err(fail)?,
    };
    let s = &detached[chosen];
    Ok(Start::Remote {
        session: s.session.clone(),
        info: Some(s.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_are_named_by_id_prefix_or_name() {
        let id = "3f2a9c1e00112233445566778899aabb";
        assert!(names("3f2a", id, None));
        assert!(names("3F2A9C1E", id, None));
        assert!(names(id, id, None));
        assert!(!names("3f2b", id, None));
        assert!(!names("", id, None));
        assert!(names("build", id, Some("build")));
        assert!(!names("buil", id, Some("build")));
        // A name that looks like hex still matches as a name
        assert!(names("beef", id, Some("beef")));
    }

    #[test]
    fn ages_and_tables() {
        assert_eq!(age(1000, 1030), "just now");
        assert_eq!(age(1000, 1000 + 125), "2 min ago");
        assert_eq!(age(1000, 1000 + 7200), "2 h ago");
        assert_eq!(age(1000, 1000 + 3 * 86400), "3 d ago");
        assert_eq!(age(2000, 1000), "just now");
        assert_eq!(age(0, 1000), "-");
        let t = table(&[
            vec!["ID".into(), "NAME".into(), "COMMAND".into()],
            vec!["3f2a9c1e".into(), "-".into(), "make -j8".into()],
        ]);
        assert_eq!(t, "ID        NAME  COMMAND\n3f2a9c1e  -     make -j8\n");
    }

    fn info(id: &str, name: Option<&str>, attached: bool) -> SessionInfo {
        SessionInfo {
            session: id.into(),
            name: name.map(Into::into),
            command: None,
            created: 0,
            attached,
            exited: false,
            tty: None,
        }
    }

    #[test]
    fn picking_a_session() {
        let sessions = [
            info("aaaa1111000000000000000000000000", Some("build"), false),
            info("aaaa2222000000000000000000000000", None, true),
        ];
        assert_eq!(pick("build", &sessions, "h").unwrap().session, sessions[0].session);
        assert_eq!(pick("aaaa2", &sessions, "h").unwrap().session, sessions[1].session);
        let e = pick("aaaa", &sessions, "h").unwrap_err();
        assert!(
            e.contains("names 2 sessions") && e.contains("aaaa1111") && e.contains("aaaa2222"),
            "{e}"
        );
        assert!(pick("bbbb", &sessions, "h")
            .unwrap_err()
            .contains("no session bbbb on h"));
        // Without a terminal, a choice is an error that lists the sessions
        let e = choose(&sessions, "h", false).unwrap_err();
        assert!(
            e.contains("2 detached sessions on h") && e.contains("1)") && e.contains("build"),
            "{e}"
        );
    }
}
