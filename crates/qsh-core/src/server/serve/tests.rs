//! The attachment's bookkeeping of output in flight (protocol.md 7.6) and its snapshots
//! (7.8.5), against a real session.

use super::*;
use crate::server::pty::{Account, Spawn};

/// A tty session running `command` with an output buffer of `capacity` bytes, once its output
/// reached `len` bytes.
async fn session(command: &str, capacity: usize, len: u64) -> Arc<PtySession> {
    let spawn = Spawn {
        command: Some(command.into()),
        cols: 80,
        rows: 24,
        ..Default::default()
    };
    let account = Account {
        user: "tester".into(),
        shell: "/bin/sh".into(),
        home: "/".into(),
        runtime_dir: None,
    };
    let s = PtySession::start(
        SessionId::generate(),
        SessionKey::generate(),
        &spawn,
        &account,
        capacity,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while s.output.lock().unwrap().end() < len {
        assert!(Instant::now() < deadline, "no output");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    s
}

/// A model fed with everything the session wrote, from offset 0 (the bytes that fell out of
/// its small buffer are written again: the model sees what the program wrote).
fn model_of_output(s: &PtySession, all: &[u8]) -> Arc<Mutex<Live>> {
    let end = s.output.lock().unwrap().end();
    let mut live = Live::new("t", 80, 24);
    live.feed(0, &all[..end as usize]);
    Arc::new(Mutex::new(live))
}

/// M3: after a gap, what was sent before it is still in flight; skipped offsets are not.
/// (`sent − max(last_ack, gap_to)` said nothing was, and a second window went out behind the
/// first.) The data of a snapshot in flight counts until it is acknowledged.
#[test]
fn in_flight_is_what_is_on_the_wire_after_a_gap() {
    let mut out = Out::new(Stream::Output, 0, 1e6, false);
    out.sent = 1000;
    assert_eq!(out.in_flight(), 1000);
    out.skip(5000);
    assert_eq!((out.in_flight(), out.unacked(6000)), (1000, 2000));
    out.sent = 5500;
    assert_eq!((out.in_flight(), out.unacked(6000)), (1500, 2000));
    out.skip(7000);
    out.snapshots.push_back((7000, 300));
    assert!(out.snapshot_in_flight());
    assert_eq!((out.in_flight(), out.unacked(7000)), (1800, 1500));
    // ACKs below, inside and after the skipped ranges
    out.last_ack = 500;
    out.skipped.retain(|r| r.1 > 500);
    assert_eq!(out.in_flight(), 1300);
    out.last_ack = 7000;
    out.skipped.retain(|r| r.1 > 7000);
    assert!(!out.snapshot_in_flight());
    assert_eq!((out.in_flight(), out.unacked(7000)), (0, 0));
}

/// M1: a resync snapshot whose output (from what was sent to the snapshot) fell out of the
/// buffer meanwhile is sent as a skip snapshot: the client gets the screen, where it used to
/// get neither the snapshot nor a redraw. Without a model the resync falls back to a redraw.
#[tokio::test]
async fn a_resync_snapshot_is_sent_even_when_its_output_is_gone() {
    let text: String = (0..200).map(|i| format!("line {i}\r\n")).collect();
    let s = session("seq 0 199 | sed 's/^/line /'; exec sleep 60", 256, text.len() as u64).await;
    let (base, end) = {
        let b = s.output.lock().unwrap();
        (b.base(), b.end())
    };
    assert!(base > 0 && end == text.len() as u64);
    let model = model_of_output(&s, text.as_bytes());
    let mut out = Out::new(Stream::Output, 0, 1e6, false);
    let mut catchup = Catchup::new(Instant::now(), end, false);
    catchup.resync = true;
    let mut batch = Vec::new();
    let redraw = send_snapshot(&s, &model, &mut out, &mut catchup, false, false, &mut batch).await;
    assert!(!redraw);
    assert!(
        matches!(batch.as_slice(), [Message::Snapshot { offset, .. }] if *offset == end),
        "{batch:?}"
    );
    assert_eq!(out.sent, end);
    assert!(out.snapshot_in_flight() && !catchup.resync);
    // Without a model: a redraw
    let gone = Arc::new(Mutex::new(Live::new("t", 2000, 24)));
    let mut out = Out::new(Stream::Output, end, 1e6, false);
    let mut catchup = Catchup::new(Instant::now(), end, false);
    catchup.resync = true;
    let mut batch = Vec::new();
    assert!(send_snapshot(&s, &gone, &mut out, &mut catchup, false, false, &mut batch).await);
    assert!(batch.is_empty() && !catchup.resync);
    s.hang_up();
}

/// A model a chunk behind what was sent (the reader thread feeds it after appending to the
/// buffer) gives no snapshot yet and no fallback: the attachment tries again once it is fed.
#[tokio::test]
async fn a_model_behind_the_buffer_is_waited_for() {
    let s = session("printf 'abc\\n'; exec sleep 60", 1 << 20, 5).await;
    let model = Arc::new(Mutex::new(Live::new("t", 80, 24)));
    lock_model(&model).feed(0, b"ab");
    let mut out = Out::new(Stream::Output, 5, 1e6, false);
    let mut catchup = Catchup::new(Instant::now(), 5, false);
    catchup.resync = true;
    let mut batch = Vec::new();
    assert!(!send_snapshot(&s, &model, &mut out, &mut catchup, false, false, &mut batch).await);
    assert!(batch.is_empty() && catchup.resync);
    lock_model(&model).feed(2, b"c\r\n");
    send_snapshot(&s, &model, &mut out, &mut catchup, false, false, &mut batch).await;
    assert!(
        matches!(batch.as_slice(), [Message::Snapshot { offset: 5, .. }]),
        "{batch:?}"
    );
    s.hang_up();
}
