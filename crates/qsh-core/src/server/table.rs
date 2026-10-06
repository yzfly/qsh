//! The daemon's sessions, by id, and their lifetime.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::pty::{PtySession, SessionId};
use super::Shared;

/// The sessions of a daemon.
#[derive(Debug, Default)]
pub struct SessionTable {
    sessions: Mutex<HashMap<SessionId, Arc<PtySession>>>,
}

impl SessionTable {
    /// Add a session.
    pub fn insert(&self, session: Arc<PtySession>) {
        self.sessions.lock().unwrap().insert(session.id, session);
    }

    /// The session with `id`.
    pub fn get(&self, id: &SessionId) -> Option<Arc<PtySession>> {
        self.sessions.lock().unwrap().get(id).cloned()
    }

    /// Forget a session; its programs get SIGHUP if they still run.
    pub fn remove(&self, id: &SessionId) -> Option<Arc<PtySession>> {
        let session = self.sessions.lock().unwrap().remove(id);
        if let Some(s) = &session {
            s.hang_up();
        }
        session
    }

    /// Number of sessions.
    pub fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// True without sessions.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// All sessions, oldest first.
    pub fn all(&self) -> Vec<Arc<PtySession>> {
        let mut all: Vec<Arc<PtySession>> = self.sessions.lock().unwrap().values().cloned().collect();
        all.sort_by_key(|s| s.started);
        all
    }

    /// Hang up and remove every session (the daemon stops); the sessions, whose attachments
    /// are still ending.
    pub fn hang_up_all(&self) -> Vec<Arc<PtySession>> {
        let sessions: Vec<_> = self.sessions.lock().unwrap().drain().map(|(_, s)| s).collect();
        for s in &sessions {
            s.hang_up();
        }
        sessions
    }

    /// Forget sessions whose program exited `exited_ttl` ago, and close sessions nobody was
    /// attached to for `detached_ttl`.
    pub fn expire(&self, detached_ttl: Duration, exited_ttl: Duration) {
        self.sessions.lock().unwrap().retain(|_, s| {
            if s.is_removed() {
                return false;
            }
            if s.attached() > 0 {
                return true;
            }
            match s.exited_for() {
                Some(t) if t < exited_ttl => true,
                Some(_) => {
                    // Lets the pty threads end
                    s.hang_up();
                    false
                }
                None if s.last_seen.lock().unwrap().elapsed() > detached_ttl => {
                    s.hang_up();
                    false
                }
                None => true,
            }
        });
    }
}

/// Expire sessions now and then; stop an on-demand daemon that had no sessions for a while.
pub(crate) async fn collect_garbage(shared: Arc<Shared>) {
    let config = &shared.config;
    let tick = config.idle_exit.map_or(Duration::from_secs(60), |d| {
        (d / 4).clamp(Duration::from_millis(250), Duration::from_secs(60))
    });
    let mut idle_since = tokio::time::Instant::now();
    loop {
        tokio::time::sleep(tick).await;
        shared.sessions.expire(config.detached_ttl, config.exited_ttl);
        if !shared.sessions.is_empty() {
            idle_since = tokio::time::Instant::now();
        } else if config.idle_exit.is_some_and(|limit| idle_since.elapsed() >= limit) {
            crate::log::info(format_args!("no sessions for {:?}, exiting", idle_since.elapsed()));
            shared.shutdown.notify_one();
            return;
        }
    }
}
