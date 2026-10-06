//! The screen model and snapshots: protocol.md A.8 byte for byte, the content profile, the
//! round trip (m2.md 12.1: a snapshot written to a terminal in any state reproduces the
//! screen), lazy feeding against direct feeding, and the caps.

use super::snapshot::{check_profile, encode, equivalent};
use super::*;

/// `QSH_SOAK=N` runs the property tests N times longer (with other seeds), for a soak.
pub(crate) fn soak() -> u64 {
    std::env::var("QSH_SOAK").ok().and_then(|s| s.parse().ok()).unwrap_or(1)
}

/// Deterministic randomness for the property tests (xorshift).
pub(crate) struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len() as u64) as usize]
    }
}

/// Output like programs write it: text (wide and combining characters too), line ends, colors,
/// cursor motion, erasing, scroll regions, both screens, modes, titles, resets; and now and then
/// garbage and cut-off sequences.
pub(crate) fn terminal_output(rng: &mut Rng, len: usize) -> Vec<u8> {
    let texts = [
        "hello",
        "x",
        "  ",
        "中文",
        "e\u{301}",
        "ab\tc",
        "—",
        "🙂",
        "$ ls -l",
        "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
    ];
    let sequences = [
        "\r\n",
        "\r\n",
        "\r\n",
        "\n",
        "\r",
        "\x08",
        "\x1b[m",
        "\x1b[1;31m",
        "\x1b[2m",
        "\x1b[3;4;7m",
        "\x1b[22;23;24;27m",
        "\x1b[38;5;200m",
        "\x1b[48;2;1;2;3m",
        "\x1b[39;49m",
        "\x1b[92;104m",
        "\x1b[H",
        "\x1b[5;7H",
        "\x1b[2J",
        "\x1b[K",
        "\x1b[1K",
        "\x1b[3A",
        "\x1b[2B",
        "\x1b[10C",
        "\x1b[4D",
        "\x1b[L",
        "\x1b[2M",
        "\x1b[3P",
        "\x1b[2@",
        "\x1b[S",
        "\x1b[T",
        "\x1b[2X",
        "\x1b[5d",
        "\x1b[12G",
        "\x1b[2;5r",
        "\x1b[r",
        "\x1b[?1049h",
        "\x1b[?1049l",
        "\x1b[?47h",
        "\x1b[?47l",
        "\x1b[?1h",
        "\x1b[?1l",
        "\x1b=",
        "\x1b>",
        "\x1b[?25l",
        "\x1b[?25h",
        "\x1b[?2004h",
        "\x1b[?2004l",
        "\x1b[?1000h",
        "\x1b[?1002h",
        "\x1b[?1003l",
        "\x1b[?1006h",
        "\x1b[?1005h",
        "\x1b[?1015h",
        "\x1b[?1004h",
        "\x1b[?1004l",
        "\x1b]0;title\x07",
        "\x1b]2;only title\x1b\\",
        "\x1b]1;icon\x07",
        "\x1b[3 q",
        "\x1b7",
        "\x1b8",
        "\x1bM",
        "\x1b[!p",
        "\x1b(0",
        "\x1b(B",
        "\x1b[?6h",
        "\x1b[?6l",
        "\x1bc",
        "\x1b[6n",
        "\x1bP1$r\x1b\\",
        "\x1b[",
        "\x1b]",
        "\x1b[?",
        "\u{9b}",
        "\x7f",
        "\x07",
    ];
    let mut out = Vec::new();
    while out.len() < len {
        match rng.below(10) {
            0..=4 => out.extend_from_slice(rng.pick(&texts).as_bytes()),
            5..=8 => out.extend_from_slice(rng.pick(&sequences).as_bytes()),
            _ => {
                for _ in 0..rng.below(4) {
                    out.push(rng.next() as u8);
                }
            }
        }
    }
    out
}

/// Feed `data` in chunks of random sizes.
fn feed_chunked(model: &mut dyn Model, rng: &mut Rng, data: &[u8]) {
    let mut at = 0;
    while at < data.len() {
        let n = (rng.below(64) as usize + 1).min(data.len() - at);
        model.feed(&data[at..at + n]);
        at += n;
    }
}

/// protocol.md A.8: the reference encoding, byte for byte.
#[test]
fn appendix_a8_snapshot() {
    let mut live = Live::new("t", 20, 3);
    live.feed(0, b"$ ls\r\n\x1b[32ma.txt\x1b[m\r\n$ \x1b[?2004h\x1b]2;web1\x07");
    let snapshot = live.snapshot(None).unwrap();
    let expected: &[u8] = b"\x1b[!p\x1b[?1049l\x1b[1;1H$ ls\x1b[K\x1b[2;1H\x1b[32ma.txt\x1b[m\x1b[K\x1b[3;1H$\x1b[K\
\x1b[?9;1000;1002;1003;1004;1005;1006;1015l\x1b[?2004h\x1b]2;web1\x1b\\\x1b[3;3H";
    assert_eq!(
        String::from_utf8_lossy(&snapshot.data),
        String::from_utf8_lossy(expected)
    );
    assert_eq!((snapshot.cols, snapshot.rows), (20, 3));
    // The payload length of the A.8 message: 13 bytes of fields and the data
    assert_eq!(13 + snapshot.data.len(), 134);
    check_profile(&snapshot.data).unwrap();
}

/// Snapshots of every kind of screen follow the profile; the checker refuses what is outside
/// it.
#[test]
fn the_profile_checker() {
    let mut rng = Rng(3);
    for i in 0..300 {
        let mut live = Live::new("t", 2 + rng.below(90) as u16, 2 + rng.below(40) as u16);
        live.feed(0, &terminal_output(&mut rng, 2000));
        let s = live.snapshot((i % 2 == 0).then_some(0)).unwrap();
        if let Err(e) = check_profile(&s.data) {
            panic!("{e}: {:?}", String::from_utf8_lossy(&s.data));
        }
    }
    for bad in [
        &b"plain"[..],
        b"\x1b[!p\x1b[6n",
        b"\x1b[!p\x1b]52;c;aGk=\x07",
        b"\x1b[!p\x07",
        b"\x1b[!p\n",
        b"\x1b[!pa\rb",
        b"\x1b[!p\x1b[1;31m\x1b[K",
        b"\x1b[!p\x1b[?1049;1h",
        b"\x1b[!p\x1b[?47h",
        b"\x1b[!p\x1b[38;5;256m",
        b"\x1b[!p\x1b]2;x\x07",
        b"\x1b[!p\xff",
        b"\x1b[!p\xc2\x9b",
        b"\x1bc",
    ] {
        assert!(check_profile(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
    }
    check_profile(b"\x1b[!p\x1b[1;31mx\x1b[m\x1b[K\x1b]1;\xe4\xb8\xad\x1b\\\x1b[2 q\x1b=\r\n").unwrap();
}

/// The round trip (m2.md 12.1): for arbitrary output and sizes, model₁ ← output; data =
/// encode(model₁); model₂ ← arbitrary prefix ++ data; model₂ equals model₁ on everything the
/// profile carries. Skip snapshots carry the tail into the scrollback as well.
#[test]
fn snapshots_round_trip() {
    let mut rng = Rng(11 + soak());
    for case in 0..500 * soak() {
        let cols = 2 + rng.below(100) as u16;
        let rows = 2 + rng.below(40) as u16;
        let mut one = Vt100Model::new(cols, rows);
        let len = 1 + rng.below(6000) as usize;
        let output = terminal_output(&mut rng, len);
        feed_chunked(&mut one, &mut rng, &output);
        if rng.below(4) == 0 {
            let (c, r) = (2 + rng.below(100) as u16, 2 + rng.below(40) as u16);
            one.resize(c, r);
            let more = terminal_output(&mut rng, 500);
            feed_chunked(&mut one, &mut rng, &more);
        }
        let skip = rng.below(2) == 0;
        let tail = if skip { rng.below(120) as usize } else { 0 };
        let first = one.capture(tail);
        let data = encode(&first, skip);
        check_profile(&data).unwrap_or_else(|e| panic!("case {case}: {e}"));
        let (cols, rows) = one.size();
        let mut two = Vt100Model::new(cols, rows);
        let len = rng.below(3000) as usize;
        let prefix = terminal_output(&mut rng, len);
        feed_chunked(&mut two, &mut rng, &prefix);
        feed_chunked(&mut two, &mut rng, &data);
        let second = two.capture(first.tail.len());
        if let Err(diff) = equivalent(&first, &second, skip) {
            panic!(
                "case {case} ({cols}x{rows}, skip {skip}): {diff}\noutput {:?}\ndata {:?}",
                String::from_utf8_lossy(&output),
                String::from_utf8_lossy(&data)
            );
        }
    }
}

/// Lazy feeding of simple output (a flood of lines, a colored log) gives exactly the screen,
/// scrollback tail, pen and titles of feeding everything.
#[test]
fn lazy_feeding_is_exact() {
    let mut rng = Rng(5);
    let pieces = [
        "y\r\n",
        "\x1b[1;32mok\x1b[m\r\n",
        "warning: a long line that wraps around the screen once or twice\r\n",
        "\t",
        "no newline ",
        "\x1b]0;t\x07",
        "\r\n\r\n",
        "中\r\n",
        "\x1b(B\x1b[m",
    ];
    for case in 0..60 {
        let cols = 5 + rng.below(80) as u16;
        let rows = 2 + rng.below(30) as u16;
        let mut data = Vec::new();
        let n = rng.below(4000) + 100;
        for _ in 0..n {
            data.extend_from_slice(rng.pick(&pieces).as_bytes());
            if rng.below(300) == 0 {
                // Not simple: forces the pending output to be fed
                data.extend_from_slice(b"\x1b[2;3H");
            }
        }
        let mut lazy = Vt100Model::new(cols, rows);
        let mut eager = Vt100Model::new(cols, rows);
        eager.set_lazy(false);
        let mut r1 = Rng(case + 1);
        let mut r2 = Rng(case + 2);
        let mut feeds = (0, 0);
        let mut at = 0;
        while at < data.len() {
            let k = (r1.below(5000) as usize + 1).min(data.len() - at);
            feeds.0 += lazy.feed(&data[at..at + k]);
            at += k;
        }
        let mut at = 0;
        while at < data.len() {
            let k = (r2.below(70) as usize + 1).min(data.len() - at);
            feeds.1 += eager.feed(&data[at..at + k]);
            at += k;
        }
        assert_eq!(feeds.0, feeds.1);
        assert_eq!(
            lazy.capture(SNAPSHOT_TAIL_LINES),
            eager.capture(SNAPSHOT_TAIL_LINES),
            "case {case}"
        );
    }
}

/// What lazy feeding keeps stays small, whatever the output: lines are trimmed, output without
/// line ends is fed.
#[test]
fn lazy_feeding_keeps_little() {
    let mut model = Vt100Model::new(80, 24);
    for _ in 0..2000 {
        model.feed(&b"y\r\n".repeat(1000));
        assert!(model.pending_len() < 3 * 1000 * 3, "{}", model.pending_len());
    }
    for i in 0..2000 {
        model.feed(format!("\rprogress {i}%").repeat(100).as_bytes());
        assert!(model.pending_len() <= 256 * 1024 + 2000);
    }
    let capture = model.capture(0);
    assert!(snapshot::plain(&capture.normal).contains("progress 1999%"));
}

/// Models only within the caps; a session that grows beyond them loses its model for good.
#[test]
fn caps() {
    assert!(fits(80, 24) && fits(1024, 256) && fits(512, 512) && fits(2, 2));
    assert!(!fits(1025, 10) && !fits(10, 513) && !fits(1024, 257) && !fits(1, 10) && !fits(10, 1));
    let mut live = Live::new("t", 2000, 50);
    assert!(!live.usable() && live.snapshot(None).is_none());
    let mut live = Live::new("t", 80, 24);
    live.feed(0, b"x");
    live.resize(2000, 24);
    live.resize(80, 24);
    assert!(!live.usable());
}

/// The tail of a skip snapshot: lines that scrolled since the client's offset, at most 100,
/// fewer than rows when unsure, none for a resync snapshot.
#[test]
fn the_tail_counts_lines_since_the_client_offset() {
    let mut live = Live::new("t", 10, 5);
    let mut offsets = Vec::new();
    let mut offset = 0;
    for i in 0..50 {
        offsets.push(offset);
        let line = format!("{i}\r\n");
        live.feed(offset, line.as_bytes());
        offset += line.len() as u64;
    }
    assert_eq!(live.lines_since(0), 50);
    assert_eq!(live.lines_since(offsets[10]), 40);
    // Since line 10: 40 line feeds, minus the 4 that may not have scrolled: lines 10 to 45
    // (46 to 49 are on the screen)
    let s = live.snapshot(Some(offsets[10])).unwrap();
    let text = String::from_utf8_lossy(&s.data).into_owned();
    assert!(
        text.contains("\r\n10\x1b[m\r\n") && text.contains("\r\n45\x1b[m\r\n"),
        "{text:?}"
    );
    assert!(
        !text.contains("\r\n9\x1b[m\r\n") && !text.contains("46\x1b[m"),
        "{text:?}"
    );
    let s = live.snapshot(Some(offset)).unwrap();
    assert!(!String::from_utf8_lossy(&s.data).contains("\x1b[m\r\n"));
    // A resync snapshot pushes nothing
    let s = live.snapshot(None).unwrap();
    assert!(!String::from_utf8_lossy(&s.data).contains("\r\n"));
    // Replayed bytes (a sink installed after output) are not fed twice
    live.feed(0, b"0\r\n1\r\n");
    assert_eq!(live.lines_since(0), 50);
}

/// The model for an upgrade in place: a fresh model fed the handed-over resync snapshot shows
/// the same screen and continues at the same offset.
#[test]
fn handoff_reproduces_the_model() {
    let mut rng = Rng(99);
    let output = terminal_output(&mut rng, 5000);
    let mut live = Live::new("t", 70, 20);
    live.feed(0, &output);
    let (cols, rows, data) = live.handoff().unwrap();
    let before = live.model.as_mut().unwrap().capture(0);
    let mut resumed = Live::resumed("t", cols, rows, &data, output.len() as u64);
    // The buffer replayed into the new image's sink is skipped
    resumed.feed(0, &output);
    let after = resumed.model.as_mut().unwrap().capture(0);
    equivalent(&before, &after, false).unwrap();
    resumed.feed(output.len() as u64, b"more");
    assert_eq!(resumed.end, Some(output.len() as u64 + 4));
}

/// Which method of [`Panicky`] panics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fail {
    Feed,
    Held,
    Resize,
    Size,
    Alternate,
    Capture,
}

/// A model that panics in one of its methods: the containment of `Live` (crate::fault).
struct Panicky {
    fail: Fail,
    inner: Vt100Model,
}

impl Panicky {
    fn boxed(fail: Fail) -> Box<dyn Model> {
        Box::new(Panicky {
            fail,
            inner: Vt100Model::new(20, 5),
        })
    }

    fn at(&self, method: Fail) {
        if self.fail == method {
            panic!("injected: {method:?}");
        }
    }
}

impl Model for Panicky {
    fn feed(&mut self, bytes: &[u8]) -> u64 {
        self.at(Fail::Feed);
        self.inner.feed(bytes)
    }
    fn held(&self) -> usize {
        self.at(Fail::Held);
        self.inner.held()
    }
    fn resize(&mut self, cols: u16, rows: u16) {
        self.at(Fail::Resize);
        self.inner.resize(cols, rows)
    }
    fn size(&self) -> (u16, u16) {
        self.at(Fail::Size);
        self.inner.size()
    }
    fn alternate(&self) -> bool {
        self.at(Fail::Alternate);
        self.inner.alternate()
    }
    fn capture(&mut self, tail: usize) -> Capture {
        self.at(Fail::Capture);
        self.inner.capture(tail)
    }
}

/// A model that panics in any of its methods is dropped: no panic leaves `Live`, the session
/// has no snapshots from then on, every later call is harmless, and the mutex the daemon keeps
/// the model in is not poisoned.
#[test]
fn a_failing_model_is_dropped_and_nothing_else_fails() {
    type Call = fn(&mut Live);
    let calls: [(Fail, Call); 6] = [
        (Fail::Feed, |l| l.feed(0, b"hello")),
        (Fail::Held, |l| {
            l.snapshot(None);
        }),
        (Fail::Resize, |l| l.resize(30, 6)),
        (Fail::Size, |l| {
            l.snapshot(Some(0));
        }),
        (Fail::Alternate, |l| {
            l.alternate();
        }),
        (Fail::Capture, |l| {
            l.handoff();
        }),
    ];
    for (fail, call) in calls {
        let live = std::sync::Mutex::new(Live::with_model("panicky", Panicky::boxed(fail)));
        if fail != Fail::Feed {
            live.lock().unwrap().feed(0, b"$ ls\r\n");
            assert!(live.lock().unwrap().usable(), "{fail:?}");
        }
        std::thread::scope(|s| {
            // On another thread, as the daemon's reader thread feeds the model
            s.spawn(|| call(&mut live.lock().unwrap())).join().unwrap();
        });
        assert!(!live.is_poisoned(), "{fail:?}");
        let mut live = live.lock().unwrap();
        assert!(!live.usable(), "{fail:?}");
        live.feed(100, b"more");
        live.resize(40, 10);
        assert!(!live.alternate());
        assert!(live.snapshot(None).is_none() && live.snapshot(Some(0)).is_none());
        assert!(live.handoff().is_none());
    }
}

/// The `test-hooks` model fails on its marker, also when the marker comes in two chunks; a
/// model made before the marker was added, or that never sees it, is not affected.
#[test]
fn the_test_hook_model_fails_on_its_marker() {
    let mut before = Live::new("before", 20, 5);
    crate::fault::test_hooks::panic_on(crate::fault::test_hooks::Hook::Model, b"UNIT-MODEL-MARKER");
    let mut hit = Live::new("hit", 20, 5);
    let mut other = Live::new("other", 20, 5);
    hit.feed(0, b"abc UNIT-MODEL");
    assert!(hit.usable());
    hit.feed(14, b"-MARKER def");
    assert!(!hit.usable());
    other.feed(0, b"abc UNIT-MODEL marker");
    before.feed(0, b"UNIT-MODEL-MARKER");
    assert!(other.usable() && before.usable());
    assert!(other.snapshot(None).is_some());
}

/// Output for the filter's differential test: everything `terminal_output` writes, and what
/// the filter rewrites or swallows: counts beyond the screen, sequences too long to hold,
/// controls inside sequences, strings of every kind and terminator, and sequences cut by others.
fn hostile_output(rng: &mut Rng, cols: u16, rows: u16, len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while out.len() < len {
        match rng.below(12) {
            0..=3 => {
                let n = 1 + rng.below(40) as usize;
                out.extend(terminal_output(rng, n));
            }
            4 | 5 => {
                let n = [0, 1, 2, cols - 1, cols, cols + 1, rows - 1, rows, rows + 3, 300][rng.below(10) as usize];
                let f = b"@LMPSTX"[rng.below(7) as usize] as char;
                let tail = ["", ";7", ":3", ";;9"][rng.below(4) as usize];
                out.extend_from_slice(format!("\x1b[{n}{tail}{f}").as_bytes());
                if rng.below(2) == 0 {
                    out.extend_from_slice(
                        format!(
                            "\x1b[{};{}H",
                            rng.below(u64::from(rows) + 2),
                            rng.below(u64::from(cols) + 2)
                        )
                        .as_bytes(),
                    );
                }
            }
            6 => {
                // Too long to hold: leading zeros, many parameters, sub-parameters
                let body = match rng.below(4) {
                    0 => format!("{}{}", "0".repeat(70 + rng.below(40) as usize), rng.below(400)),
                    1 => ";1".repeat(10 + rng.below(40) as usize),
                    2 => format!(
                        "38:2::{}:{}:{};{}",
                        rng.below(256),
                        rng.below(256),
                        rng.below(256),
                        "4;".repeat(30)
                    ),
                    _ => format!("?{}", "1049;25;".repeat(1 + rng.below(12) as usize)),
                };
                let f = b"m@LHhlJKrT"[rng.below(10) as usize] as char;
                out.extend_from_slice(format!("\x1b[{body}{f}").as_bytes());
            }
            7 => {
                // Controls inside sequences, intermediates, ignored forms
                let s = [
                    "\x1b[1\n;2H",
                    "\x1b[\r3\x08@",
                    "\x1b\n7",
                    "\x1b\x07[2J",
                    "\x1b[?1\n049h",
                    "\x1b[1?2h",
                    "\x1b[1 q",
                    "\x1b[ 5q",
                    "\x1b[!p",
                    "\x1b[2!p",
                    "\x1b[1$x",
                    "\x1b[>1;2c",
                    "\x1b(0",
                    "\x1b #8",
                    "\x1b\x1b[31m",
                    "\x1b[1\x1b[32m",
                    "\x1b[5\x18A",
                    "\x1b[\x7f3D",
                    "\x1b[\u{e9}2C",
                    "\x1b(\x1b[33m",
                    "\x1b(\x1b]0;x\x07B",
                    "\u{e4}\x1b[m",
                    "\x1b\x7f\u{e9}c",
                ];
                out.extend_from_slice(rng.pick(&s).as_bytes());
                if rng.below(8) == 0 {
                    // A character cut by a string
                    out.extend_from_slice(b"\xc3\x1b]0;t\x07z");
                }
            }
            8 | 9 => {
                // Strings
                let open = [
                    "\x1b]0;",
                    "\x1b]2;",
                    "\x1b]52;c;",
                    "\x1b]",
                    "\x1bP1$r",
                    "\x1bP",
                    "\x1b_",
                    "\x1b^",
                    "\x1bX",
                    "\x1b\n]1;",
                ];
                out.extend_from_slice(rng.pick(&open).as_bytes());
                for _ in 0..rng.below(200) {
                    out.push([b'a', b';', 0x9c, 0x9b, 0xc3, b'\n', 0x07, 0x7f, b'[', b'1'][rng.below(10) as usize]);
                }
                let close = ["\x07", "\x1b\\", "\x18", "\x1a", "\u{9c}", "", "\x1b[1m"];
                out.extend_from_slice(rng.pick(&close).as_bytes());
            }
            _ => out.extend_from_slice(
                rng.pick(&[
                    "\r\n",
                    "abc",
                    "中",
                    "\x1b[?1049h",
                    "\x1b[?1049l",
                    "\x1b[3;5r",
                    "\x1b7",
                    "\x1b8",
                ])
                .as_bytes(),
            ),
        }
    }
    out
}

/// What a `vt100` screen shows and keeps: every cell (scrollback too), the cursor, the pen, the
/// modes; and the same after leaving the alternate screen, restoring the saved cursor, and
/// scrolling (which shows the scroll region).
fn vt100_state(screen: &vt100::Screen) -> Vec<String> {
    let (rows, cols) = screen.size();
    let mut state = Vec::new();
    for probe in ["", "\x1b8", "\x1b[?1049l\x1b[?47l", "\x1b[999B\n\n\n\n\n\n\n\nz"] {
        let mut p = vt100::Parser::new(rows, cols, SNAPSHOT_TAIL_LINES);
        *p.screen_mut() = screen.clone();
        p.process(probe.as_bytes());
        let s = p.screen_mut();
        s.set_scrollback(usize::MAX);
        let back = s.scrollback();
        for k in (0..=back).rev() {
            s.set_scrollback(k);
            for r in 0..rows {
                let cells: Vec<_> = (0..cols).map(|c| format!("{:?}", s.cell(r, c))).collect();
                state.push(format!("{probe:?} {k} {r} {} {}", s.row_wrapped(r), cells.join("")));
            }
        }
        s.set_scrollback(0);
        state.push(format!(
            "{probe:?} {:?} {} {:?}",
            s.cursor_position(),
            s.alternate_screen(),
            String::from_utf8_lossy(&s.state_formatted())
        ));
    }
    state
}

/// The scanner's output has exactly the effect of the program's output on `vt100` (scan.rs):
/// strings swallowed, sequences held back across chunks, counts clamped, long sequences in
/// canonical form; whatever the chunks.
#[test]
fn the_filter_changes_nothing_vt100_shows() {
    let mut rng = Rng(77);
    for case in 0..300 * soak() {
        let cols = 2 + rng.below(30) as u16;
        let rows = 2 + rng.below(12) as u16;
        let len = 1 + rng.below(3000) as usize;
        let mut data = hostile_output(&mut rng, cols, rows, len);
        // Whatever is unfinished at the end: ended
        data.push(0x18);
        let mut raw = vt100::Parser::new(rows, cols, SNAPSHOT_TAIL_LINES);
        raw.process(&data);
        let mut scanner = super::scan::Scanner::new(cols, rows);
        let mut scanned = super::scan::Scanned::default();
        let mut filtered = Vec::new();
        let mut at = 0;
        while at < data.len() {
            let n = (rng.below(80) as usize + 1).min(data.len() - at);
            scanner.scan(&data[at..at + n], &mut scanned);
            filtered.extend_from_slice(&scanned.bytes);
            at += n;
        }
        assert_eq!(scanner.held(), 0, "case {case}");
        let mut fed = vt100::Parser::new(rows, cols, SNAPSHOT_TAIL_LINES);
        fed.process(&filtered);
        let (a, b) = (vt100_state(raw.screen()), vt100_state(fed.screen()));
        if a != b {
            let i = a.iter().zip(&b).position(|(x, y)| x != y).unwrap_or(0);
            panic!(
                "case {case} ({cols}x{rows}): {:?}\n  vs {:?}\ninput {:?}\nfiltered {:?}",
                a.get(i),
                b.get(i),
                String::from_utf8_lossy(&data),
                String::from_utf8_lossy(&filtered)
            );
        }
    }
}

/// H1: an unterminated string (OSC, DCS, APC) of any length costs the model nothing: `vt100`,
/// whose parser keeps an OSC without limit, never sees it, and the title is the scanner's.
#[test]
fn an_unterminated_string_costs_the_model_nothing() {
    let chunk = vec![b'y'; 16384];
    for (open, total) in [("\x1b]0;", 64usize << 20), ("\x1bP1q", 16 << 20), ("\x1b_", 16 << 20)] {
        let mut live = Live::new("t", 80, 24);
        live.feed(0, b"$ ");
        let mut offset = 2;
        live.feed(offset, open.as_bytes());
        offset += open.len() as u64;
        let mut fed = 0;
        while fed < total {
            live.feed(offset, &chunk);
            offset += chunk.len() as u64;
            fed += chunk.len();
        }
        live.feed(offset, b"\x07\x1b\\done");
        assert!(live.usable(), "{open:?}");
        let bytes = live.model.as_ref().unwrap().vt100_bytes();
        assert!(bytes < 1024, "{open:?}: vt100 got {bytes} bytes");
        let capture = live.model.as_mut().unwrap().capture(0);
        assert!(snapshot::plain(&capture.normal).contains("$ done"), "{open:?}");
        if open.starts_with("\x1b]") {
            assert_eq!(capture.title.len(), 4096 - 2);
        }
    }
}

/// H2: a count far beyond the screen costs what one the size of the screen does (it is
/// clamped, exactly), and a flood of them exhausts the model's budget at once: 64 KiB of them
/// take far less than 50 ms at the largest size, where `vt100` alone took 1.45 s per sequence.
/// (ECH costs a line's worth of cells per sequence, like a line feed: ordinary work.)
#[test]
fn counts_beyond_the_screen_are_cheap() {
    for seq in [
        "\x1b[65535@",
        "\x1b[65535L",
        "\x1b[65535T",
        "\x1b[65535P",
        "\x1b[65535M",
        "\x1b[65535S",
    ] {
        // One: clamped, the model stays
        let mut live = Live::new("one", 1024, 256);
        live.feed(0, b"hello\r\n");
        let start = std::time::Instant::now();
        live.feed(7, seq.as_bytes());
        let one = start.elapsed();
        assert!(live.usable(), "{seq:?}");
        assert!(one < std::time::Duration::from_millis(250), "{seq:?}: {one:?}");
        // A flood: the model is dropped before it does the work
        let flood = seq.repeat(65536 / seq.len());
        let mut live = Live::new("flood", 1024, 256);
        live.feed(0, b"hello\r\n");
        let start = std::time::Instant::now();
        let mut offset = 7;
        for chunk in flood.as_bytes().chunks(16384) {
            live.feed(offset, chunk);
            offset += chunk.len() as u64;
        }
        let all = start.elapsed();
        assert!(all < std::time::Duration::from_millis(50), "{seq:?}: {all:?}");
        assert!(!live.usable(), "{seq:?}");
    }
}

/// The budget lets legitimate output through: a full-screen program repainting the largest
/// screen, `clear`, an editor scrolling a region; at the pace of a program, `clear` with a
/// little output in a loop for a minute. Clearing the largest screen over and over with nothing
/// else exhausts it.
#[test]
fn the_work_budget_spares_programs() {
    let mut live = Live::new("t", 1024, 256);
    let mut offset = 0;
    let mut feed = |live: &mut Live, bytes: &[u8]| {
        live.feed(offset, bytes);
        offset += bytes.len() as u64;
    };
    feed(&mut live, b"\x1b[?1049h");
    for i in 0..10 {
        let mut screen = format!("\x1b[H\x1b[2J\x1b[1;30r\x1b[30H\x1b[3S\x1b[5;1H\x1b[2L\x1b[4@\x1b[1P frame {i}\r\n");
        for row in 0..40 {
            screen.push_str(&format!(
                "\x1b[{};1H\x1b[1;3{}mline {row} of frame {i}\x1b[K",
                row + 2,
                row % 8
            ));
        }
        feed(&mut live, screen.as_bytes());
    }
    feed(&mut live, b"\x1b[?1049l");
    for i in 0..10 {
        feed(&mut live, format!("\x1b[H\x1b[2J\x1b[3J$ ls\r\nfile{i}\r\n").as_bytes());
    }
    assert!(live.usable());

    // `watch -n 0.05` on the largest screen for a minute, on a simulated clock
    let clear = format!("\x1b[H\x1b[2J\x1b[3J{}", "Every 0.1s: date\r\n".repeat(3));
    let mut scanner = super::scan::Scanner::new(1024, 256);
    let mut scanned = super::scan::Scanned::default();
    scanner.scan(clear.as_bytes(), &mut scanned);
    let start = std::time::Instant::now();
    let mut budget = super::model::Budget::new(start);
    for i in 0..1200 {
        let now = start + std::time::Duration::from_millis(50 * i);
        assert!(budget.spend(now, clear.len(), scanned.cost), "after {i}");
    }
    // The same, as fast as it can be written: refused within the first second
    let mut budget = super::model::Budget::new(start);
    let refused = (0..20_000).position(|i| {
        !budget.spend(
            start + std::time::Duration::from_micros(50 * i),
            clear.len(),
            scanned.cost,
        )
    });
    assert!(refused.is_some_and(|i| i < 20_000), "{refused:?}");

    let mut live = Live::new("t", 1024, 256);
    live.feed(0, &b"\x1b[2J".repeat(4096));
    assert!(!live.usable());
}

/// A sequence held back at the end of a chunk is applied whole in the next, also across a
/// resize that rebuilds the model; a snapshot meanwhile is taken before it, so that the client
/// gets the whole sequence after it.
#[test]
fn a_sequence_split_across_chunks_is_held_back() {
    let mut live = Live::new("t", 20, 5);
    live.feed(0, b"ab\x1b[3");
    assert_eq!(live.snapshot(None).unwrap().offset, 2);
    live.resize(10, 5);
    live.feed(5, b"1mX\x1b]0;tit");
    assert_eq!(live.snapshot(None).unwrap().offset, 8);
    live.feed(15, b"le\x07");
    let snapshot = live.snapshot(None).unwrap();
    assert_eq!(snapshot.offset, 18);
    let capture = live.model.as_mut().unwrap().capture(0);
    assert_eq!(capture.title, "title");
    let x = &capture.normal.lines[0].cells[2];
    assert_eq!((x.text.as_str(), x.pen.fg), ("X", snapshot::Color::Index(1)));
}

/// A screen whose snapshot would exceed `MAX_SNAPSHOT` by its text and colors alone is
/// recognised before it is captured and encoded (which took 0.35 s at the caps, for nothing).
#[test]
fn an_oversize_snapshot_is_recognised_before_encoding() {
    let (cols, rows) = (512u16, 256u16);
    let mut live = Live::new("t", cols, rows);
    let mut fill = Vec::new();
    for row in 0..rows {
        fill.extend_from_slice(format!("\x1b[{};1H", row + 1).as_bytes());
        for col in 0..cols {
            fill.extend_from_slice(format!("\x1b[38;5;{}m", (row + col) % 200).as_bytes());
            fill.extend_from_slice("e\u{301}\u{302}\u{303}".as_bytes());
        }
    }
    live.feed(0, &fill);
    assert!(live.usable());
    assert!(live.model.as_mut().unwrap().least_size() > MAX_SNAPSHOT);
    let start = std::time::Instant::now();
    assert!(live.snapshot(None).is_none());
    assert!(live.snapshot_from(0, true).is_err());
    let took = start.elapsed();
    assert!(took < std::time::Duration::from_secs(1), "{took:?}");
    assert!(live.usable());
}

/// The estimate never exceeds the encoding: a snapshot it refuses would have been too large.
#[test]
fn the_size_estimate_is_a_lower_bound() {
    let mut rng = Rng(91);
    for _ in 0..200 * soak() {
        let cols = 2 + rng.below(60) as u16;
        let rows = 2 + rng.below(20) as u16;
        let mut model = Vt100Model::new(cols, rows);
        let len = rng.below(4000) as usize;
        let data = terminal_output(&mut rng, len);
        feed_chunked(&mut model, &mut rng, &data);
        let least = model.least_size();
        let capture = model.capture(SNAPSHOT_TAIL_LINES);
        for skip in [false, true] {
            assert!(least <= encode(&capture, skip).len(), "{least}");
        }
    }
}
