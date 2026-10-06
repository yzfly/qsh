//! The qsh/1 message decoder (protocol.md section 3): any type and payload, never a panic, and
//! whatever decodes encodes back to something that decodes the same.
#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_core::proto::message::{decode_from, MAX_TERMINAL};
use qsh_core::proto::Message;

fuzz_target!(|data: &[u8]| {
    if let Some((&ty, payload)) = data.split_first() {
        if let Ok(m) = Message::decode(u64::from(ty), payload) {
            if !matches!(m, Message::Unknown { .. }) {
                let again = decode_from(&m.encode(), usize::MAX).expect("re-encoded message decodes");
                assert_eq!(again.map(|(m, _)| m), Some(m));
            }
        }
    }
    let _ = decode_from(data, MAX_TERMINAL);
});
