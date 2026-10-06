//! The bootstrap JSON (protocol.md section 10): the server's request parsing and validation,
//! and the client's search for the reply in ssh's output.
#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_core::proto::bootstrap::{parse_reply, ExtraPort, Op, Reply, Request, MAX_EXTRA_PORTS};

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = serde_json::from_slice::<Request>(data) {
        let _ = request.validate();
        let _ = request.accepted_env();
    }
    for op in [Op::New, Op::Attach, Op::List, Op::Kill] {
        if let Ok(Reply::Credentials(c)) = parse_reply(data, op) {
            // extra_ports (10.4): read leniently, never more than eight, all of them valid
            assert!(c.extra_ports.len() <= MAX_EXTRA_PORTS);
            assert!(c.extra_ports.iter().all(|p| p.port != 0 && (p.udp || p.tcp)));
        }
    }
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        assert!(ExtraPort::list_from_json(&value).len() <= MAX_EXTRA_PORTS);
    }
});
