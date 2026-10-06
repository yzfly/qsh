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
    let mut live = Live::new(20, 3);
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
        let mut live = Live::new(2 + rng.below(90) as u16, 2 + rng.below(40) as u16);
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
    let mut live = Live::new(2000, 50);
    assert!(!live.usable() && live.snapshot(None).is_none());
    let mut live = Live::new(80, 24);
    live.feed(0, b"x");
    live.resize(2000, 24);
    live.resize(80, 24);
    assert!(!live.usable());
}

/// The tail of a skip snapshot: lines that scrolled since the client's offset, at most 100,
/// fewer than rows when unsure, none for a resync snapshot.
#[test]
fn the_tail_counts_lines_since_the_client_offset() {
    let mut live = Live::new(10, 5);
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
    let mut live = Live::new(70, 20);
    live.feed(0, &output);
    let (cols, rows, data) = live.handoff().unwrap();
    let before = live.model.as_mut().unwrap().capture(0);
    let mut resumed = Live::resumed(cols, rows, &data, output.len() as u64);
    // The buffer replayed into the new image's sink is skipped
    resumed.feed(0, &output);
    let after = resumed.model.as_mut().unwrap().capture(0);
    equivalent(&before, &after, false).unwrap();
    resumed.feed(output.len() as u64, b"more");
    assert_eq!(resumed.end, Some(output.len() as u64 + 4));
}
