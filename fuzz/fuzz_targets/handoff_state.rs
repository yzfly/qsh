//! The state an old daemon image hands to the new one in an upgrade in place (m2.md 10.5):
//! never a panic, whatever the bytes; a state that is accepted is safe to adopt (every
//! descriptor number once, buffers within their capacities) and encodes back to the same
//! bytes. The state is sealed, so these bytes come from a daemon of the same user; the parser
//! is bounded anyway, like every parser of qsh.
#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_core::server::handoff::{decode, encode};

fuzz_target!(|data: &[u8]| {
    if let Ok(state) = decode(data) {
        let mut numbers = state.descriptors();
        let n = numbers.len();
        numbers.sort_unstable();
        numbers.dedup();
        assert_eq!(numbers.len(), n, "a descriptor number twice");
        for s in &state.sessions {
            assert!(s.output.bytes.len() as u64 <= s.output.capacity);
            assert!(s.errors.bytes.len() as u64 <= s.errors.capacity);
        }
        assert_eq!(encode(&state).expect("an accepted state encodes"), data);
    }
});
