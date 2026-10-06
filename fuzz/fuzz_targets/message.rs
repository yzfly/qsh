//! The qsh/1 message decoder (protocol.md section 3): any type and payload, never a panic, and
//! whatever decodes encodes back to something that decodes the same. The zstd frames of
//! OUTPUT_ZSTD and compressed SNAPSHOT data go through the header check (7.12).
#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_core::proto::message::{decode_from, MAX_TERMINAL, SNAPSHOT_ZSTD};
use qsh_core::proto::{zstd, Message};

fuzz_target!(|data: &[u8]| {
    if let Some((&ty, payload)) = data.split_first() {
        if let Ok(m) = Message::decode(u64::from(ty), payload) {
            match &m {
                Message::OutputZstd { frame, .. } => {
                    let _ = zstd::check_frame(frame);
                }
                Message::Snapshot { flags, data, .. } if flags & SNAPSHOT_ZSTD != 0 => {
                    let _ = zstd::check_frame(data);
                }
                _ => {}
            }
            if !matches!(m, Message::Unknown { .. }) {
                let again = decode_from(&m.encode(), usize::MAX).expect("re-encoded message decodes");
                assert_eq!(again.map(|(m, _)| m), Some(m));
            }
        }
    }
    let _ = decode_from(data, MAX_TERMINAL);
});
