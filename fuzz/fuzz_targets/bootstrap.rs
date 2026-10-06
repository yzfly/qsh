//! The bootstrap JSON (protocol.md section 10): the server's request parsing and validation,
//! and the client's search for the reply in ssh's output.
#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_core::proto::bootstrap::{parse_reply, Op, Request};

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = serde_json::from_slice::<Request>(data) {
        let _ = request.validate();
        let _ = request.accepted_env();
    }
    for op in [Op::New, Op::Attach, Op::List, Op::Kill] {
        let _ = parse_reply(data, op);
    }
});
