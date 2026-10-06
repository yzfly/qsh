//! Tests of the mux layer: frames, streams, flow control, errors.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::testutil::Rng;

fn pair() -> (Mux, Mux) {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    (
        Mux::new(Role::Client, ar, aw, None),
        Mux::new(Role::Server, br, bw, None),
    )
}

#[test]
fn frames_round_trip_and_reject_bad_input() {
    let frames = vec![
        Frame::Data {
            stream: 4,
            data: b"hello".to_vec(),
        },
        Frame::Data {
            stream: 1 << 40,
            data: vec![7; MAX_DATA],
        },
        Frame::Fin { stream: 0 },
        Frame::Reset {
            stream: 8,
            code: ErrorCode::SESSION_ENDED,
        },
        Frame::Window {
            stream: 12,
            increment: 1 << 30,
        },
        Frame::ConnWindow { increment: 0 },
    ];
    for f in frames {
        let mut out = Vec::new();
        f.encode(&mut out);
        assert_eq!(Frame::decode(&out).unwrap(), Some((f.clone(), out.len())));
        for cut in 0..out.len() {
            assert_eq!(Frame::decode(&out[..cut]).unwrap(), None);
        }
    }
    assert!(Frame::decode(&[0x05]).is_err());
    assert!(Frame::decode(&[0x00, 0x00, 0x00]).is_err(), "empty DATA");
    assert!(
        Frame::decode(&[0x00, 0x00, 0x80, 0x00, 0x40, 0x01]).is_err(),
        "DATA above MAX_DATA"
    );
    // protocol.md A.3: OUTPUT on stream 4
    let bytes = [
        0x00, 0x04, 0x11, 0x14, 0x0f, 0, 0, 0, 0, 0, 0, 0x10, 0, b'h', b'e', b'l', b'l', b'o', b'\r', b'\n',
    ];
    let (frame, used) = Frame::decode(&bytes).unwrap().unwrap();
    assert_eq!(used, bytes.len());
    assert!(matches!(frame, Frame::Data { stream: 4, ref data } if data.len() == 17));
}

#[test]
fn random_frames_never_panic() {
    let mut rng = Rng::new(3);
    for _ in 0..50000 {
        let len = rng.range(0, 24) as usize;
        let mut bytes = rng.bytes(len);
        if let Some(b) = bytes.first_mut() {
            *b %= 6;
        }
        let _ = Frame::decode(&bytes);
    }
}

#[tokio::test]
async fn streams_carry_data_both_ways_with_ids_like_quic() {
    let (client, server) = pair();
    let (id0, mut s0, mut r0) = client.open().await.unwrap();
    let (id4, mut s4, _r4) = client.open().await.unwrap();
    assert_eq!((id0, id4), (0, 4));
    s4.write_all(b"four").await.unwrap();
    s0.write_all(b"zero").await.unwrap();
    s0.flush().await.unwrap();
    // Streams are announced in id order: 0 was opened first
    let (a, mut sa, mut ra) = server.accept().await.unwrap();
    let (b, _sb, mut rb) = server.accept().await.unwrap();
    assert_eq!((a, b), (0, 4));
    let mut buf = [0u8; 4];
    ra.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"zero");
    rb.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"four");
    sa.write_all(b"back").await.unwrap();
    sa.shutdown().await.unwrap();
    let mut back = Vec::new();
    r0.read_to_end(&mut back).await.unwrap();
    assert_eq!(back, b"back");
}

/// A stream whose reader stalls blocks only itself: the connection window is returned on
/// demultiplexing (section 8.3).
#[tokio::test]
async fn a_stalled_stream_does_not_block_the_others() {
    let (client, server) = pair();
    let (_, mut stalled, _r) = client.open().await.unwrap();
    let (_, mut live, _r2) = client.open().await.unwrap();
    // More than the connection window, less than... no: the stream window bounds it
    let writer = tokio::spawn(async move {
        let chunk = vec![1u8; 64 * 1024];
        let mut sent = 0u64;
        // Blocks once the stream credit (256 KiB) and the queue are used up
        while sent < 4 * STREAM_WINDOW {
            if tokio::time::timeout(Duration::from_millis(500), stalled.write_all(&chunk))
                .await
                .is_err()
            {
                break;
            }
            sent += chunk.len() as u64;
        }
        sent
    });
    let sent = writer.await.unwrap();
    assert!(
        sent <= STREAM_WINDOW + SEND_QUEUE as u64 + 64 * 1024,
        "sent {sent} past the stream window"
    );
    // The other stream still moves several connection windows of data
    let total = 3 * CONN_WINDOW as usize;
    let send = tokio::spawn(async move {
        let chunk = vec![2u8; 32 * 1024];
        let mut n = 0;
        while n < total {
            live.write_all(&chunk).await.unwrap();
            n += chunk.len();
        }
        live.shutdown().await.unwrap();
    });
    let (_, _s0, _stalled_reader) = server.accept().await.unwrap();
    let (_, _s4, mut live_reader) = server.accept().await.unwrap();
    let mut got = 0usize;
    let mut buf = vec![0u8; 65536];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), live_reader.read(&mut buf))
            .await
            .expect("live stream stalled")
            .unwrap();
        if n == 0 {
            break;
        }
        got += n;
    }
    assert_eq!(got, total);
    send.await.unwrap();
}

#[tokio::test]
async fn reset_reaches_the_peer_and_the_connection_survives() {
    let (client, server) = pair();
    let (_, mut s, mut r) = client.open().await.unwrap();
    s.write_all(b"x").await.unwrap();
    let (_, ss, _sr) = server.accept().await.unwrap();
    ss.reset(ErrorCode::SESSION_UNKNOWN);
    let e = r.read(&mut [0u8; 8]).await.unwrap_err();
    assert!(e.to_string().contains("SESSION_UNKNOWN"), "{e}");
    // Another stream still works
    let (_, mut s2, mut r2) = client.open().await.unwrap();
    s2.write_all(b"y").await.unwrap();
    let (_, mut ss2, mut sr2) = server.accept().await.unwrap();
    let mut b = [0u8; 1];
    sr2.read_exact(&mut b).await.unwrap();
    ss2.write_all(b"z").await.unwrap();
    r2.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"z");
}

#[tokio::test]
async fn closing_ends_every_stream() {
    let (client, server) = pair();
    let (_, mut s, mut r) = client.open().await.unwrap();
    s.write_all(b"x").await.unwrap();
    let _accepted = server.accept().await.unwrap();
    server.close(ErrorCode::NO_ERROR);
    assert!(r.read(&mut [0u8; 8]).await.is_err());
    tokio::time::timeout(Duration::from_secs(5), client.closed())
        .await
        .unwrap();
    assert!(client.open().await.is_err());
    assert!(server.accept().await.is_none());
}

/// Raw frames from a misbehaving peer.
async fn peer_sends(frames: &[Frame]) -> Mux {
    let (a, b) = tokio::io::duplex(1 << 20);
    let (ar, aw) = tokio::io::split(a);
    let server = Mux::new(Role::Server, ar, aw, None);
    let (_br, mut bw) = tokio::io::split(b);
    let mut out = Vec::new();
    for f in frames {
        f.encode(&mut out);
    }
    bw.write_all(&out).await.unwrap();
    // Keep the peer's side open: only a protocol error may close the connection
    std::mem::forget(bw);
    server
}

#[tokio::test]
async fn protocol_errors_close_the_connection() {
    let data = |stream, n| Frame::Data {
        stream,
        data: vec![0; n],
    };
    let cases: Vec<(&str, Vec<Frame>)> = vec![
        ("ids out of order", vec![data(4, 1)]),
        ("server's own id not opened", vec![data(1, 1)]),
        ("unidirectional id", vec![data(2, 1)]),
        ("data after fin", vec![data(0, 1), Frame::Fin { stream: 0 }, data(0, 1)]),
        ("stream credit", (0..17).map(|_| data(0, MAX_DATA)).collect()),
        ("credit overflow", vec![Frame::ConnWindow { increment: varint::MAX }]),
    ];
    for (name, frames) in cases {
        let server = peer_sends(&frames).await;
        tokio::time::timeout(Duration::from_secs(5), server.closed())
            .await
            .unwrap_or_else(|_| panic!("{name}: not closed"));
    }
    // The pre-authentication budget
    let (a, b) = tokio::io::duplex(1 << 20);
    let (ar, aw) = tokio::io::split(a);
    let server = Mux::new(Role::Server, ar, aw, None);
    server.set_byte_budget(Some(100));
    let (_br, mut bw) = tokio::io::split(b);
    let mut out = Vec::new();
    data(0, 101).encode(&mut out);
    bw.write_all(&out).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), server.closed())
        .await
        .unwrap();
}

#[tokio::test]
async fn too_many_streams_is_a_connection_error() {
    let frames: Vec<Frame> = (0..=MAX_STREAMS as u64)
        .map(|i| Frame::Data {
            stream: i * 4,
            data: vec![1],
        })
        .collect();
    let server = peer_sends(&frames).await;
    tokio::time::timeout(Duration::from_secs(5), server.closed())
        .await
        .unwrap();
}

/// Property: random writes on several streams arrive complete and in order per stream.
#[tokio::test]
async fn property_interleaved_streams_arrive_intact() {
    for seed in 1..6u64 {
        let (client, server) = pair();
        let mut rng = Rng::new(seed);
        let streams = rng.range(1, 6) as usize;
        let mut expected = Vec::new();
        let mut writers = Vec::new();
        for _ in 0..streams {
            let (_, s, _r) = client.open().await.unwrap();
            let len = rng.range(1, 400_000) as usize;
            let data = rng.bytes(len);
            expected.push(data.clone());
            let chunk = rng.range(1, 70_000) as usize;
            writers.push(tokio::spawn(async move {
                let mut s = s;
                let _keep = _r;
                for c in data.chunks(chunk) {
                    s.write_all(c).await.unwrap();
                }
                s.shutdown().await.unwrap();
            }));
        }
        for (i, want) in expected.iter().enumerate() {
            let (id, _s, mut r) = server.accept().await.unwrap();
            assert_eq!(id, (i * 4) as u64);
            let mut got = Vec::new();
            tokio::time::timeout(Duration::from_secs(20), r.read_to_end(&mut got))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&got, want, "seed {seed} stream {i}");
        }
        for w in writers {
            w.await.unwrap();
        }
    }
}

/// Review L6: the pre-authentication budget of a daemon's connection applies from the first byte,
/// not from whenever the code that serves the connection gets to set it.
#[tokio::test]
async fn the_daemon_budget_applies_from_the_first_byte() {
    let (a, b) = tokio::io::duplex(1 << 20);
    let (_br, mut bw) = tokio::io::split(b);
    // Everything is already there when the connection starts
    let mut out = Vec::new();
    for _ in 0..2 {
        Frame::Data {
            stream: 0,
            data: vec![0; MAX_DATA],
        }
        .encode(&mut out);
    }
    bw.write_all(&out).await.unwrap();
    let (ar, aw) = tokio::io::split(a);
    let server = crate::transport::Connection::pipe(Role::Server, ar, aw, None, None);
    tokio::time::timeout(Duration::from_secs(5), server.closed())
        .await
        .expect("closed for exceeding MAX_PREAUTH_BYTES");
    std::mem::forget(bw);
}

/// Raw frames written by the test's `peer`, and every frame the mux under test sent back.
async fn frames_from(mux_out: &mut (impl tokio::io::AsyncRead + Unpin), wait: Duration) -> Vec<Frame> {
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(wait, async {
        let mut chunk = [0u8; 4096];
        loop {
            match mux_out.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await;
    let mut frames = Vec::new();
    let mut at = 0;
    while let Ok(Some((f, n))) = Frame::decode(&buf[at..]) {
        frames.push(f);
        at += n;
    }
    frames
}

/// Review L7 / protocol.md 4.3: a client resets the streams a server opens with UNKNOWN_CHANNEL
/// and keeps nothing of them, so a hostile server cannot make it buffer 128 × 256 KiB.
#[tokio::test]
async fn a_client_refuses_streams_the_server_opens() {
    let (a, b) = tokio::io::duplex(1 << 20);
    let (ar, aw) = tokio::io::split(a);
    let client = Mux::new(Role::Client, ar, aw, None);
    let (mut br, mut bw) = tokio::io::split(b);
    let mut out = Vec::new();
    for stream in [1u64, 5, 9] {
        for _ in 0..4 {
            Frame::Data {
                stream,
                data: vec![7; MAX_DATA],
            }
            .encode(&mut out);
        }
    }
    bw.write_all(&out).await.unwrap();
    let frames = frames_from(&mut br, Duration::from_millis(500)).await;
    for stream in [1u64, 5, 9] {
        assert!(
            frames.contains(&Frame::Reset {
                stream,
                code: ErrorCode::UNKNOWN_CHANNEL
            }),
            "{frames:?}"
        );
    }
    {
        let st = client.inner.state.lock().unwrap();
        assert!(st.streams.is_empty() && st.accept.is_empty(), "{:?}", st.streams.keys());
    }
    assert!(!client.is_closed());
    // The client's own streams still work
    let (id, _send, _recv) = client.open().await.unwrap();
    assert_eq!(id, 0);
    std::mem::forget(bw);
}

/// Review L7: credit for data nobody reads is given back in one WINDOW, not one per frame, so a
/// peer that does not read what the mux sends cannot make its queue of frames grow.
#[tokio::test]
async fn credit_for_discarded_data_is_coalesced() {
    // A tiny pipe: the mux's writes block as soon as the peer stops reading
    let (a, b) = tokio::io::duplex(64);
    let (ar, aw) = tokio::io::split(a);
    let server = Mux::new(Role::Server, ar, aw, None);
    let (_br, mut bw) = tokio::io::split(b);
    let mut out = Vec::new();
    Frame::Data {
        stream: 0,
        data: vec![1],
    }
    .encode(&mut out);
    bw.write_all(&out).await.unwrap();
    let (_, send, recv) = server.accept().await.unwrap();
    drop(recv);
    let frames = 5000u64;
    let writer = tokio::spawn(async move {
        let mut out = Vec::new();
        for _ in 0..frames {
            Frame::Data {
                stream: 0,
                data: vec![2],
            }
            .encode(&mut out);
        }
        bw.write_all(&out).await.unwrap();
        bw
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let (received, queued) = {
            let st = server.inner.state.lock().unwrap();
            (st.conn_recv_total, st.control.len())
        };
        if received == frames + 1 {
            // Before: one queued WINDOW per discarded frame
            assert_eq!(queued, 0, "{queued} frames queued");
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "received {received}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(send);
    std::mem::forget(writer.await.unwrap());
}

/// Review L7: a stream of the peer that the daemon finished and let go of is forgotten even if
/// the peer never finishes its side.
#[tokio::test]
async fn peer_streams_that_never_finish_are_forgotten() {
    let (client, server) = pair();
    let (_, mut send, _recv) = client.open().await.unwrap();
    send.write_all(b"hello").await.unwrap();
    send.flush().await.unwrap();
    let (_, mut s_send, mut s_recv) = server.accept().await.unwrap();
    let mut buf = [0u8; 5];
    s_recv.read_exact(&mut buf).await.unwrap();
    s_send.write_all(b"bye").await.unwrap();
    s_send.shutdown().await.unwrap();
    drop(s_send);
    drop(s_recv);
    // The client keeps its halves and never finishes
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !server.inner.state.lock().unwrap().streams.is_empty() {
        assert!(tokio::time::Instant::now() < deadline, "the stream is still kept");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Later data of the client on it is ignored, and the connection goes on
    send.write_all(b"late").await.unwrap();
    send.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!server.is_closed());
}
