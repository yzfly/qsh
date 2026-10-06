//! Reading messages from a byte stream with the size limits of each place (section 3.2).
#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_core::proto::message::{MAX_ATTACH, MAX_HELLO};
use qsh_core::proto::read_message;

fuzz_target!(|data: &[u8]| {
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    runtime.block_on(async {
        for max in [MAX_ATTACH, MAX_HELLO, 1 << 16] {
            let mut input = data;
            while let Ok(Some(_)) = read_message(&mut input, max).await {}
        }
    });
});
