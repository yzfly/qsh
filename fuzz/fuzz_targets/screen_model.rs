//! The screen model and the snapshot encoder (m2.md 6.2, 12.1): arbitrary output and resizes
//! never make them panic (the daemon contains a panic, but the session loses its snapshots;
//! this target uses the model directly, without the containment); every snapshot follows the content
//! profile of protocol.md 7.8.4; written after arbitrary bytes to a fresh model, it reproduces
//! the screen (the round trip); and lazy feeding gives exactly the model of direct feeding.
#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_core::screen::snapshot::{check_profile, encode, equivalent};
use qsh_core::screen::{fits, Model, Vt100Model};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let size = |a: u8, b: u8| (u16::from(a % 120).max(2), u16::from(b % 60).max(2));
    let (cols, rows) = size(data[0], data[1]);
    let skip = data[2] & 1 != 0;
    let prefix_len = usize::from(data[3]);
    let input = &data[4..];
    let mut lazy = Vt100Model::new(cols, rows);
    let mut direct = Vt100Model::new(cols, rows);
    direct.set_lazy(false);
    // Chunks end at 0xff bytes (dropped); a chunk that starts with 0xfe 0xfe a b is a resize
    for chunk in input.split(|&b| b == 0xff) {
        if let [0xfe, 0xfe, a, b, ..] = chunk {
            let (c, r) = size(*a, *b);
            if fits(c, r) {
                lazy.resize(c, r);
                direct.resize(c, r);
            }
            continue;
        }
        let feeds = (lazy.feed(chunk), direct.feed(chunk));
        // Output beyond the work budget is not fed (the daemon then drops the model); the two
        // may run out a chunk apart, as the budget also grows with time
        if lazy.exhausted() || direct.exhausted() {
            return;
        }
        assert_eq!(feeds.0, feeds.1, "line feeds counted differently");
    }
    let first = lazy.capture(100);
    assert_eq!(first, direct.capture(100), "lazy feeding changed the model");
    let snapshot = encode(&first, skip);
    if let Err(e) = check_profile(&snapshot) {
        panic!("{e}");
    }
    // The round trip, after the first bytes of the input as the terminal's previous state
    let (cols, rows) = lazy.size();
    let mut again = Vt100Model::new(cols, rows);
    again.feed(&input[..prefix_len.min(input.len())]);
    again.feed(&snapshot);
    if let Err(diff) = equivalent(&first, &again.capture(first.tail.len()), skip) {
        panic!("the snapshot does not reproduce the screen: {diff}");
    }
});
