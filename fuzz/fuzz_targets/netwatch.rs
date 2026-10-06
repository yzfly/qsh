//! The kernel's network change messages: rtnetlink datagrams (Linux) and routing socket
//! messages (macOS layout).
#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_core::netwatch::{netlink_relevant, route_message_relevant};

fuzz_target!(|data: &[u8]| {
    let _ = netlink_relevant(data);
    let _ = route_message_relevant(data);
});
