//! The zstd frame header check of OUTPUT_ZSTD and compressed SNAPSHOT data (protocol.md 7.12):
//! never a panic, and an accepted header always declares 1 to 65 536 bytes and fits the input.
//! The decoder joins this target when it exists (m2.md 12.1).
#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_core::proto::zstd::{check_frame, parse_header, MAX_ZSTD_CONTENT};

fuzz_target!(|data: &[u8]| {
    match parse_header(data) {
        Ok(h) => {
            assert!((1..=MAX_ZSTD_CONTENT).contains(&h.content_size));
            assert!(h.header_len + 3 <= data.len());
            assert_eq!(check_frame(data), Ok(h.content_size));
        }
        Err(e) => assert_eq!(check_frame(data), Err(e)),
    }
});
