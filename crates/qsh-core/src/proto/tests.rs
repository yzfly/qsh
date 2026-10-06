//! Message round trips and malformed input.

use std::net::IpAddr;

use super::message::*;
use super::*;
use crate::testutil::Rng;

fn samples() -> Vec<Message> {
    vec![
        Message::ClientHello {
            versions: vec![1, 2],
            capabilities: vec!["zstd".into(), "org.example.x".into()],
            implementation: "qsh-core/0.1.0".into(),
        },
        Message::ServerHello {
            version: 1,
            nonce: [9; 32],
            capabilities: vec![],
            implementation: "".into(),
        },
        Message::Ping { data: 1 << 50 },
        Message::Pong { data: 7 },
        Message::PathInfo {
            sequence: 0,
            address: None,
            port: 0,
        },
        Message::PathInfo {
            sequence: 3,
            address: Some("192.0.2.1".parse().unwrap()),
            port: 4242,
        },
        Message::PathInfo {
            sequence: 4,
            address: Some("2001:db8::1".parse().unwrap()),
            port: 1,
        },
        Message::GoAway {
            code: ErrorCode::SHUTDOWN,
            message: "bye".into(),
        },
        Message::Error {
            code: ErrorCode::AUTH_FAILED,
            message: "".into(),
        },
        Message::Error {
            code: ErrorCode(0x1234_5678),
            message: "unknown code".into(),
        },
        Message::Attach {
            session: [1; 16],
            proof: [2; 32],
            output_received: 99,
            size: WindowSize {
                cols: 80,
                rows: 24,
                width_px: 640,
                height_px: 480,
            },
            flags: ATTACH_ACCEPT_SNAPSHOT,
        },
        Message::Attached {
            input_received: 5,
            output_start: 7,
            next_key: [3; 32],
            server_proof: [4; 32],
        },
        Message::Attach {
            session: [1; 16],
            proof: [2; 32],
            output_received: LATEST,
            size: WindowSize::new(1, 1),
            flags: ATTACH_FRESH,
        },
        Message::KeyConfirm,
        Message::Input {
            offset: 0,
            data: b"ls\r".to_vec(),
        },
        Message::Output {
            offset: u64::MAX - 2,
            data: b"ab".to_vec(),
        },
        Message::Ack { received: 12345 },
        Message::OutputGap { from: 1, to: 9 },
        Message::Resize(WindowSize::new(120, 40)),
        Message::Snapshot {
            offset: 5,
            flags: SNAPSHOT_FINAL,
            cols: 80,
            rows: 24,
            data: b"\x1b[H".to_vec(),
        },
        Message::Exit {
            output_end: 77,
            status: ExitStatus::Exited(3),
        },
        Message::Exit {
            output_end: 0,
            status: ExitStatus::Signaled {
                signal: "TERM".into(),
                core_dumped: true,
            },
        },
        Message::Detach,
        Message::Hangup,
        Message::OutputZstd {
            offset: 0,
            frame: vec![0x28, 0xb5, 0x2f, 0xfd],
        },
        Message::Unknown { ty: 0x3f00 },
    ]
}

#[test]
fn every_message_round_trips() {
    for m in samples() {
        let encoded = m.encode();
        let (decoded, used) = decode_from(&encoded, MAX_TERMINAL).unwrap().unwrap();
        assert_eq!(decoded, m);
        assert_eq!(used, encoded.len());
        // A prefix is never a message
        for cut in 0..encoded.len() {
            assert!(
                decode_from(&encoded[..cut], MAX_TERMINAL).unwrap().is_none(),
                "{m:?} cut at {cut}"
            );
        }
    }
}

#[test]
fn trailing_bytes_are_ignored_for_fixed_layouts() {
    // 3.3: a later revision may append fields
    let mut p = Message::Ack { received: 4 }.payload();
    p.extend_from_slice(b"future");
    assert_eq!(Message::decode(types::ACK, &p).unwrap(), Message::Ack { received: 4 });
    // but data… takes everything
    let mut p = Message::Input {
        offset: 0,
        data: b"x".to_vec(),
    }
    .payload();
    p.push(b'y');
    assert_eq!(
        Message::decode(types::INPUT, &p).unwrap(),
        Message::Input {
            offset: 0,
            data: b"xy".to_vec()
        }
    );
}

#[test]
fn malformed_payloads_are_frame_errors() {
    // Short payloads
    assert!(Message::decode(types::PING, &[0; 7]).is_err());
    assert!(Message::decode(types::ATTACH, &[0; 63]).is_err());
    assert!(Message::decode(types::INPUT, &[0; 7]).is_err());
    // Version count 0 and 17
    assert!(Message::decode(types::CLIENT_HELLO, &[0, 0, 0]).is_err());
    let mut p = vec![17];
    p.extend(std::iter::repeat_n(1, 17));
    p.extend([0, 0]);
    assert!(Message::decode(types::CLIENT_HELLO, &p).is_err());
    // Capability names
    for bad in ["", "Zstd", "-x", "a b", "é"] {
        let m = Message::ClientHello {
            versions: vec![1],
            capabilities: vec![],
            implementation: String::new(),
        };
        let mut p = m.payload();
        // Rewrite: one capability with a bad name
        p.truncate(2);
        p.push(1);
        varint::encode(bad.len() as u64, &mut p);
        p.extend_from_slice(bad.as_bytes());
        p.push(0);
        assert!(Message::decode(types::CLIENT_HELLO, &p).is_err(), "{bad:?}");
    }
    // Invalid UTF-8 in a capability is an error; in an implementation name it is replaced
    let p = [1, 1, 1, 1, 0xff, 0];
    assert!(Message::decode(types::CLIENT_HELLO, &p).is_err());
    let p = [1, 1, 0, 1, 0xff];
    assert!(
        matches!(Message::decode(types::CLIENT_HELLO, &p), Ok(Message::ClientHello { implementation, .. }) if implementation == "\u{fffd}")
    );
    // LATEST needs FRESH
    let mut p = Message::Attach {
        session: [0; 16],
        proof: [0; 32],
        output_received: LATEST,
        size: WindowSize::new(1, 1),
        flags: ATTACH_FRESH,
    }
    .payload();
    *p.last_mut().unwrap() = 0;
    assert!(Message::decode(types::ATTACH, &p).is_err());
    // Address family
    assert!(Message::decode(types::PATH_INFO, &[0, 5, 0, 0]).is_err());
    // Exit kind
    let mut p = Message::Exit {
        output_end: 0,
        status: ExitStatus::Exited(0),
    }
    .payload();
    p[8] = 2;
    assert!(Message::decode(types::EXIT, &p).is_err());
    // An offset whose data runs past 2^64 - 1
    let mut p = u64::MAX.to_be_bytes().to_vec();
    p.extend_from_slice(b"ab");
    assert!(Message::decode(types::OUTPUT, &p).is_err());
    // Strings over their maximum
    let mut p = vec![0x01];
    varint::encode(257, &mut p);
    p.extend(std::iter::repeat_n(b'a', 257));
    assert!(Message::decode(types::ERROR, &p).is_err());
}

/// protocol.md A.1 and A.2
#[test]
fn appendix_a_encodings() {
    let hello = Message::ClientHello {
        versions: vec![1],
        capabilities: vec!["zstd".into(), "snapshot".into()],
        implementation: "qsh-core/0.1.0".into(),
    };
    let expected = "0120010102047a73746408736e617073686f740e7173682d636f72652f302e312e30";
    assert_eq!(crate::crypto::hex(&hello.encode()), expected);
    let attach = Message::Attach {
        session: crate::crypto::unhex("00112233445566778899aabbccddeeff").unwrap(),
        proof: crate::crypto::unhex("0c95bd8bdd96004ec3f84f7bcc9526ee33491925dae778d32b6b81a42c38fe93").unwrap(),
        output_received: 4096,
        size: WindowSize::new(120, 40),
        flags: 0,
    };
    let expected = "10404100112233445566778899aabbccddeeff0c95bd8bdd96004ec3f84f7bcc9526ee33491925dae778d32b6b81a42c38fe930000000000001000007800280000000000";
    assert_eq!(crate::crypto::hex(&attach.encode()), expected);
    let output = Message::Output {
        offset: 4096,
        data: b"hello\r\n".to_vec(),
    };
    assert_eq!(
        crate::crypto::hex(&output.encode()),
        "140f000000000000100068656c6c6f0d0a"
    );
}

#[test]
fn ipv4_mapped_addresses_go_as_ipv4() {
    let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
    let m = Message::PathInfo {
        sequence: 0,
        address: Some(mapped),
        port: 1,
    };
    let (decoded, _) = decode_from(&m.encode(), MAX_CONTROL).unwrap().unwrap();
    assert_eq!(
        decoded,
        Message::PathInfo {
            sequence: 0,
            address: Some("192.0.2.7".parse().unwrap()),
            port: 1
        }
    );
}

#[test]
fn the_length_limit_is_checked_before_the_payload() {
    let big = Message::Output {
        offset: 0,
        data: vec![0; 1000],
    }
    .encode();
    // Only the header is there, and it is already refused
    assert!(matches!(
        decode_from(&big[..4], MAX_ATTACH),
        Err(FramingError::TooLarge)
    ));
}

#[test]
fn random_input_never_panics() {
    let mut rng = Rng::new(42);
    for _ in 0..20000 {
        let len = rng.range(0, 80) as usize;
        let bytes = rng.bytes(len);
        let ty = rng.range(0, 0x40);
        let _ = Message::decode(ty, &bytes);
        let _ = decode_from(&bytes, MAX_TERMINAL);
    }
    // Mutations of valid messages
    for m in samples() {
        let encoded = m.encode();
        for _ in 0..500 {
            let mut e = encoded.clone();
            let i = rng.range(0, e.len() as u64) as usize;
            e[i] = rng.next() as u8;
            if let Ok(Some((decoded, _))) = decode_from(&e, MAX_TERMINAL) {
                // Whatever decodes re-encodes to something that decodes the same
                let again = decode_from(&decoded.encode(), MAX_TERMINAL).unwrap().unwrap().0;
                if !matches!(decoded, Message::Unknown { .. }) {
                    assert_eq!(again, decoded);
                }
            }
        }
    }
}

#[tokio::test]
async fn reading_from_a_stream() {
    let mut bytes = Vec::new();
    for m in samples() {
        bytes.extend(m.encode());
    }
    let mut r = &bytes[..];
    for m in samples() {
        assert_eq!(read_message(&mut r, MAX_TERMINAL).await.unwrap(), Some(m));
    }
    assert!(read_message(&mut r, MAX_TERMINAL).await.unwrap().is_none());
    // Truncated inside a message
    let one = Message::Ack { received: 1 }.encode();
    let mut r = &one[..one.len() - 1];
    assert!(matches!(
        read_message(&mut r, MAX_TERMINAL).await,
        Err(FramingError::Truncated)
    ));
    // Too large: refused from the header
    let big = Message::Input {
        offset: 0,
        data: vec![0; 300],
    }
    .encode();
    let mut r = &big[..3];
    assert!(matches!(
        read_message(&mut r, MAX_ATTACH).await,
        Err(FramingError::TooLarge)
    ));
}
