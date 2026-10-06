//! The mux frame decoder (protocol.md section 8.1): never a panic, never more than one
//! frame's worth of memory, and round trips.
#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_core::mux::Frame;

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    while let Ok(Some((frame, used))) = Frame::decode(rest) {
        assert!(used > 0 && used <= rest.len());
        let mut out = Vec::new();
        frame.encode(&mut out);
        assert_eq!(Frame::decode(&out), Ok(Some((frame, out.len()))));
        rest = &rest[used..];
    }
});
