//! OUTPUT_ZSTD and compressed SNAPSHOT data (protocol.md 7.12): the frame header check and the
//! bounded decoder of `codec.rs` never panic; a frame they accept declares 1 to 65 536 bytes
//! and produces exactly that many, and the same bytes as the reference decoder (ruzstd) when
//! that accepts it too; and our own frames of any input decode to exactly that input.
//!
//! `codec` contains panics of the encoder and the decoder (`qsh_core::fault`), but this still
//! finds them: libfuzzer-sys's panic hook aborts before anything unwinds to a `catch_unwind`.
#![no_main]

use std::io::Read as _;

use libfuzzer_sys::fuzz_target;
use qsh_core::codec;
use qsh_core::proto::zstd::{check_frame, parse_header, MAX_ZSTD_CONTENT};

fuzz_target!(|data: &[u8]| {
    match parse_header(data) {
        Ok(h) => {
            assert!((1..=MAX_ZSTD_CONTENT).contains(&h.content_size));
            assert!(h.header_len + 3 <= data.len());
            assert_eq!(check_frame(data), Ok(h.content_size));
            if let Ok(out) = codec::decompress(data, MAX_ZSTD_CONTENT) {
                assert_eq!(out.len(), h.content_size);
                let mut source = data;
                if let Ok(mut reference) = ruzstd::decoding::StreamingDecoder::new(&mut source) {
                    let mut theirs = Vec::new();
                    if reference.read_to_end(&mut theirs).is_ok() {
                        assert_eq!(out, theirs, "the decoders disagree");
                    }
                }
            }
        }
        Err(e) => {
            assert_eq!(check_frame(data), Err(e));
            assert!(codec::decompress(data, MAX_ZSTD_CONTENT).is_err());
        }
    }
    // Our frames, of the input as content
    let content = &data[..data.len().min(MAX_ZSTD_CONTENT)];
    if let Ok(Some(frame)) = codec::compress(content) {
        assert_eq!(codec::decompress(&frame, MAX_ZSTD_CONTENT).as_deref(), Ok(content));
    }
});
