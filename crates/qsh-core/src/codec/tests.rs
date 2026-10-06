//! The codec: frames of the reference zstd (libzstd 1.5.5, every block and literal type, FSE
//! and Huffman tables, repeat modes, checksums), our own frames, the rules of protocol.md 7.12
//! and decompression bombs.

use super::*;
use crate::proto::zstd::{parse_header, MAX_ZSTD_CONTENT};

fn sha256(data: &[u8]) -> String {
    crate::crypto::hex(ring::digest::digest(&ring::digest::SHA256, data).as_ref())
}

/// What ruzstd's decoder makes of a frame (for frames it accepts, it must agree with ours).
fn ruzstd_decode(frame: &[u8]) -> Option<Vec<u8>> {
    std::panic::catch_unwind(|| {
        use std::io::Read as _;
        let mut source = frame;
        let mut decoder = ruzstd::decoding::StreamingDecoder::new(&mut source).ok()?;
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).ok()?;
        Some(out)
    })
    .ok()
    .flatten()
}

/// A deterministic byte generator for the tests (xorshift).
pub(crate) struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

/// Text like a build log: what compression is for.
fn build_log(len: usize, seed: u64) -> Vec<u8> {
    let words = [
        "Compiling",
        "warning:",
        "unused",
        "variable",
        "src/server/serve.rs:42:7",
        "\x1b[1m\x1b[32m",
        "\x1b[0m",
        "Finished",
        "dev",
        "target(s)",
    ];
    let mut rng = Rng(seed);
    let mut out = Vec::new();
    while out.len() < len {
        for _ in 0..rng.below(10) + 1 {
            out.extend_from_slice(words[rng.below(words.len() as u64) as usize].as_bytes());
            out.push(b' ');
        }
        out.extend_from_slice(format!("{}\r\n", rng.below(100000)).as_bytes());
    }
    out.truncate(len);
    out
}

/// libzstd's frames decode to exactly what was compressed, as ruzstd decodes them too.
#[test]
fn reference_frames_decode_exactly() {
    let vectors: [(&[u8], usize, &str); 8] = [
        (
            include_bytes!("vectors/log.19.zst"),
            40000,
            "c3abaf0f1af49b80e50d1dc700852f91e4d1400fe15702c655717ab61370b45c",
        ),
        (
            include_bytes!("vectors/log.check.zst"),
            40000,
            "c3abaf0f1af49b80e50d1dc700852f91e4d1400fe15702c655717ab61370b45c",
        ),
        (
            include_bytes!("vectors/log.blocks.zst"),
            40000,
            "c3abaf0f1af49b80e50d1dc700852f91e4d1400fe15702c655717ab61370b45c",
        ),
        (
            include_bytes!("vectors/mixed.blocks.zst"),
            65536,
            "8e867fb27c0d3a2fcfc12b5d9f78092977fcf263468f9e61ab15c59548690c16",
        ),
        (
            include_bytes!("vectors/mixed.22.zst"),
            65536,
            "8e867fb27c0d3a2fcfc12b5d9f78092977fcf263468f9e61ab15c59548690c16",
        ),
        (
            include_bytes!("vectors/random.3.zst"),
            3000,
            "41217509b9870e9359b1c3a00dad091691ceb33c1d9ad93c8db4902934a5e95e",
        ),
        (
            include_bytes!("vectors/rle.3.zst"),
            50000,
            "27e8d8ede52e1f9fea260861fa06dc35bdfd91e71ad4f535d2160b4df51316d8",
        ),
        (
            include_bytes!("vectors/small.19.zst"),
            43,
            "a89c031077be27ba08b90cc701ce618d307c1eaa5fc0bcca7a7b3c2d2f2f151e",
        ),
    ];
    for (frame, len, digest) in vectors {
        let out = decompress(frame, MAX_ZSTD_CONTENT).unwrap();
        assert_eq!((out.len(), sha256(&out).as_str()), (len, digest));
        assert_eq!(ruzstd_decode(frame).as_deref(), Some(&out[..]));
        // A receiver that takes less refuses the frame before decoding anything
        assert!(matches!(decompress(frame, len - 1), Err(DecodeError::TooLarge { .. })));
    }
}

/// The two OUTPUT_ZSTD frames of protocol.md A.9.
#[test]
fn appendix_a9_frames() {
    let raw = [
        0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x07, 0x39, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o', b'\r', b'\n',
    ];
    assert_eq!(decompress(&raw, MAX_ZSTD_CONTENT).unwrap(), b"hello\r\n");
    let rle = [0x28, 0xb5, 0x2f, 0xfd, 0x60, 0xe8, 0x02, 0x43, 0x1f, 0x00, 0x3d];
    assert_eq!(decompress(&rle, MAX_ZSTD_CONTENT).unwrap(), vec![b'='; 1000]);
    // Producing more or fewer bytes than declared is a FRAME_ERROR (rule 4)
    let mut short = rle;
    short[5] = 0xe9; // declares 1001
    assert!(matches!(
        decompress(&short, MAX_ZSTD_CONTENT),
        Err(DecodeError::Length { .. })
    ));
    let mut long = rle;
    long[5] = 0xe7; // declares 999: the RLE block alone is larger than the window
    assert!(decompress(&long, MAX_ZSTD_CONTENT).is_err());
}

/// Our frames follow 7.12 (single segment, content size declared) and decode, with our decoder
/// and with ruzstd's, to exactly the input; ratios on a build log are those of zstd level 1.
#[test]
fn our_frames_round_trip() {
    let mut rng = Rng(42);
    let mut inputs: Vec<Vec<u8>> = vec![
        b"x".to_vec(),
        b"hello\r\n".to_vec(),
        vec![b'y'; 255],
        vec![b'y'; 256],
        build_log(MAX_ZSTD_CONTENT, 1),
        build_log(1000, 2),
        (0..5000).map(|_| rng.next() as u8).collect(),
    ];
    for len in [17usize, 300, 4096, 30000, 65535] {
        inputs.push(build_log(len, len as u64));
    }
    for input in &inputs {
        let frame = compress(input).unwrap();
        let header = parse_header(&frame).unwrap();
        assert_eq!(header.content_size, input.len());
        assert!(!header.checksum);
        assert_eq!(&decompress(&frame, MAX_ZSTD_CONTENT).unwrap(), input);
        assert_eq!(ruzstd_decode(&frame).as_ref(), Some(input));
    }
    let log = build_log(MAX_ZSTD_CONTENT, 9);
    let ratio = compress(&log).unwrap().len() as f64 / log.len() as f64;
    assert!(ratio < 0.4, "a build log compresses to {ratio}");
    assert_eq!(compress(&[]), None);
    assert_eq!(compress(&vec![0; MAX_ZSTD_CONTENT + 1]), None);
}

/// A frame whose blocks would produce far more than it declares is stopped at the declared
/// size, before the copy that would exceed it, however much the sequences ask for.
#[test]
fn decompression_bombs_are_stopped() {
    // 64 KiB of a short pattern compresses to a few bytes: ten literals and a long match
    let frame = compress(&b"0123456789".repeat(6553)).unwrap();
    assert!(frame.len() < 200, "{}", frame.len());
    // Declare less (a two-byte size, minus 256): the block still fits the smaller window
    let mut bomb = frame.clone();
    bomb[5..7].copy_from_slice(&(300u16 - 256).to_le_bytes());
    match decompress(&bomb, MAX_ZSTD_CONTENT) {
        Err(DecodeError::Length {
            declared: 300,
            produced,
        }) => assert!(produced > 300),
        other => panic!("{other:?}"),
    }
    // Content size over the limit, not single segment, a dictionary, a skippable frame
    let mut big = frame.clone();
    big[4] = 0xa0; // four-byte size
    let mut with_size = big[..5].to_vec();
    with_size.extend_from_slice(&65537u32.to_le_bytes());
    with_size.extend_from_slice(&frame[7..]);
    assert!(matches!(
        decompress(&with_size, MAX_ZSTD_CONTENT),
        Err(DecodeError::Frame(_))
    ));
    let mut segmented = frame.clone();
    segmented[4] &= !0x20;
    assert!(matches!(
        decompress(&segmented, MAX_ZSTD_CONTENT),
        Err(DecodeError::Frame(_))
    ));
    let mut dictionary = frame.clone();
    dictionary[4] |= 0x01;
    assert!(matches!(
        decompress(&dictionary, MAX_ZSTD_CONTENT),
        Err(DecodeError::Frame(_))
    ));
    let skippable = [0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0];
    assert!(decompress(&skippable, MAX_ZSTD_CONTENT).is_err());
    // Bytes after the frame, a bad checksum
    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(decompress(&trailing, MAX_ZSTD_CONTENT).is_err());
    let checked = include_bytes!("vectors/log.check.zst");
    let mut bad = checked.to_vec();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(decompress(&bad, MAX_ZSTD_CONTENT), Err(DecodeError::Checksum));
}

/// Every prefix and thousands of mutations of real frames: errors, never a panic, and never
/// more output than declared; where ruzstd accepts a mutated frame, we agree with it.
#[test]
fn damaged_frames_fail_cleanly() {
    let frames: [&[u8]; 4] = [
        include_bytes!("vectors/log.blocks.zst"),
        include_bytes!("vectors/mixed.blocks.zst"),
        include_bytes!("vectors/small.19.zst"),
        include_bytes!("vectors/log.check.zst"),
    ];
    let soak: u64 = std::env::var("QSH_SOAK").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    let mut rng = Rng(7 + soak);
    for frame in frames {
        for cut in 0..frame.len().min(600) {
            assert!(decompress(&frame[..cut], MAX_ZSTD_CONTENT).is_err());
        }
        for _ in 0..1500 * soak {
            let mut damaged = frame.to_vec();
            for _ in 0..rng.below(4) + 1 {
                let i = rng.below(damaged.len() as u64) as usize;
                damaged[i] ^= 1 << rng.below(8);
            }
            if let Ok(out) = decompress(&damaged, MAX_ZSTD_CONTENT) {
                assert_eq!(out.len(), parse_header(&damaged).unwrap().content_size);
                if let Some(theirs) = ruzstd_decode(&damaged) {
                    assert_eq!(out, theirs);
                }
            }
        }
    }
}
