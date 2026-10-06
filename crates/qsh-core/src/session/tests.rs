//! Unit and property tests of the session layer.

use super::*;
use crate::testutil::Rng;

#[test]
fn replay_overflow_reads_from_base() {
    let mut replay = ReplayBuffer::new(4);
    replay.push(b"abcdefgh");
    assert_eq!(replay.base(), 4);
    // The peer has 0 bytes: it gets what is left, starting after the gap
    assert_eq!(replay.read_from(0, 100), (4, b"efgh".to_vec()));
}

#[test]
fn replay_resends_from_offset_and_drops_acked() {
    let mut r = ReplayBuffer::new(8);
    r.push(b"abcdef");
    assert_eq!(r.read_from(2, 100), (2, b"cdef".to_vec()));
    r.ack(4);
    assert_eq!(r.base(), 4);
    assert_eq!(r.read_from(0, 100), (4, b"ef".to_vec()));
    r.push(b"ghijklmn");
    assert_eq!(r.base(), 6);
    assert_eq!(r.end(), 14);
    assert_eq!(r.read_from(100, 10), (14, Vec::new()));
    // Acknowledging past the end is clamped
    r.ack(1000);
    assert_eq!((r.base(), r.end()), (14, 14));
}

/// Review L3: a buffer started near the end of the offset space (a hostile server's `Input
/// Received`) must neither overflow nor panic; bytes past 2^64 - 1 are not kept.
#[test]
fn replay_near_the_end_of_offsets_neither_overflows_nor_panics() {
    let mut r = ReplayBuffer::starting_at(16, u64::MAX - 4);
    assert_eq!(r.room(), 4);
    r.push(b"0123456789");
    assert_eq!((r.base(), r.end(), r.len()), (u64::MAX - 4, u64::MAX, 4));
    assert_eq!(r.room(), 0);
    r.push(b"more");
    assert_eq!(r.end(), u64::MAX);
    assert_eq!(r.read_from(0, 100), (u64::MAX - 4, b"0123".to_vec()));
    assert_eq!(r.read_from(u64::MAX, 100), (u64::MAX, Vec::new()));
    r.ack(u64::MAX);
    assert!(r.is_empty());
    // Pushing more than the capacity near the end
    let mut r = ReplayBuffer::starting_at(4, u64::MAX - 10);
    r.push(&[7; 100]);
    assert_eq!((r.base(), r.end()), (u64::MAX - 4, u64::MAX));
}

#[test]
fn inbound_skips_duplicates_and_takes_gaps() {
    let mut i = Inbound::default();
    assert_eq!(i.accept(0, b"abcde"), Accepted::New(b"abcde"));
    assert_eq!(i.accept(0, b"abcdefg"), Accepted::New(b"fg"));
    assert_eq!(i.accept(3, b"de"), Accepted::Duplicate);
    assert_eq!(i.accept(7, b""), Accepted::Duplicate);
    assert_eq!(
        i.accept(9, b"xy"),
        Accepted::AfterGap {
            missing: 2,
            bytes: b"xy"
        }
    );
    assert_eq!(i.received(), 11);
    assert_eq!(i.accept(u64::MAX, b"zz"), Accepted::Duplicate);
}

/// A sender and a receiver over a connection that breaks at random points, losing whatever
/// was in flight. After every break both resume from what the other received. Unless more
/// than the capacity went unacknowledged, the receiver gets exactly the stream that was sent;
/// with overflow, what it gets is the stream with gaps, each gap reported with its size.
#[test]
fn property_resume_delivers_the_stream_exactly() {
    for seed in 1..300u64 {
        let mut rng = Rng::new(seed);
        let capacity = rng.range(1, 4096) as usize;
        let mut sender = ReplayBuffer::new(capacity);
        let mut receiver = Inbound::default();
        let mut sent_stream: Vec<u8> = Vec::new();
        let mut delivered: Vec<u8> = Vec::new();
        let mut gaps = 0u64;
        // In flight on the current connection: (seq, bytes)
        let mut in_flight: Vec<(u64, Vec<u8>)> = Vec::new();
        // Where the sender continues on the current connection
        let mut next_send = 0u64;
        for _ in 0..rng.range(10, 200) {
            match rng.range(0, 10) {
                // Produce data
                0..=3 => {
                    let n = rng.range(0, 700) as usize;
                    let bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                    sent_stream.extend_from_slice(&bytes);
                    sender.push(&bytes);
                }
                // Send what is pending, in chunks
                4..=5 => {
                    let chunk = rng.range(1, 1000) as usize;
                    loop {
                        let (start, bytes) = sender.read_from(next_send, chunk);
                        if bytes.is_empty() {
                            break;
                        }
                        next_send = start + bytes.len() as u64;
                        in_flight.push((start, bytes));
                    }
                }
                // Deliver some of what is in flight, in order
                6..=7 => {
                    let n = rng.range(0, in_flight.len() as u64 + 1) as usize;
                    for (seq, bytes) in in_flight.drain(..n) {
                        match receiver.accept(seq, &bytes) {
                            Accepted::New(b) => delivered.extend_from_slice(b),
                            Accepted::AfterGap { missing, bytes } => {
                                gaps += missing;
                                delivered.extend(std::iter::repeat_n(0xEE, missing as usize));
                                delivered.extend_from_slice(bytes);
                            }
                            Accepted::Duplicate => {}
                        }
                    }
                }
                // Acknowledge
                8 => sender.ack(receiver.received()),
                // The connection breaks: in flight is lost, resume from what was received
                _ => {
                    in_flight.clear();
                    sender.ack(receiver.received());
                    next_send = receiver.received();
                }
            }
            assert!(sender.len() <= capacity);
            assert!(receiver.received() <= sender.end());
        }
        // Drain everything over a final connection that does not break
        in_flight.clear();
        next_send = receiver.received();
        loop {
            let (start, bytes) = sender.read_from(next_send, 512);
            if bytes.is_empty() {
                break;
            }
            next_send = start + bytes.len() as u64;
            match receiver.accept(start, &bytes) {
                Accepted::New(b) => delivered.extend_from_slice(b),
                Accepted::AfterGap { missing, bytes } => {
                    gaps += missing;
                    delivered.extend(std::iter::repeat_n(0xEE, missing as usize));
                    delivered.extend_from_slice(bytes);
                }
                Accepted::Duplicate => {}
            }
        }
        assert_eq!(delivered.len(), sent_stream.len(), "seed {seed}: delivered length");
        if gaps == 0 {
            assert_eq!(delivered, sent_stream, "seed {seed}: stream differs without gaps");
        } else {
            // Everything outside the gaps is exact
            let differing = delivered.iter().zip(&sent_stream).filter(|(a, b)| a != b).count() as u64;
            assert!(differing <= gaps, "seed {seed}: {differing} bytes differ, gaps {gaps}");
        }
    }
}

#[test]
fn property_read_from_matches_a_plain_vector() {
    for seed in 1..200u64 {
        let mut rng = Rng::new(seed);
        let capacity = rng.range(1, 300) as usize;
        let mut buffer = ReplayBuffer::new(capacity);
        let mut model: Vec<u8> = Vec::new();
        for _ in 0..100 {
            if rng.range(0, 3) == 0 {
                let ack = rng.range(0, buffer.end() + 5);
                buffer.ack(ack);
            } else {
                let n = rng.range(0, 400) as usize;
                let bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                model.extend_from_slice(&bytes);
                buffer.push(&bytes);
            }
            let offset = rng.range(0, buffer.end() + 10);
            let max = rng.range(0, 500) as usize;
            let (start, bytes) = buffer.read_from(offset, max);
            let expected_start = offset.clamp(buffer.base(), buffer.end());
            assert_eq!(start, expected_start, "seed {seed}");
            let s = start as usize;
            let expected = &model[s..(s + max).min(model.len())];
            assert_eq!(bytes, expected, "seed {seed}");
        }
    }
}
