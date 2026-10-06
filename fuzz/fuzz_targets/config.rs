//! qsh_config(5) files: the TOML parser, the validation of every setting, the host patterns
//! and their matching. The first line of the input is the destination to resolve.
#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh_core::config::{destination_host, Config, PatternList};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (destination, _) = text.split_once('\n').unwrap_or((text, ""));
    let _ = destination_host(destination);
    if let Ok(patterns) = PatternList::parse(destination) {
        let _ = patterns.matches(&["host.example.com", destination]);
    }
    if let Ok((config, _warnings)) = Config::parse(text, std::path::Path::new("fuzz")) {
        let host = config.for_host(destination, Some("host.example.com"));
        let _ = host.race();
        let _ = config.server();
    }
});
