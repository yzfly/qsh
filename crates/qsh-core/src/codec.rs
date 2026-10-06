//! Compression of terminal output (protocol.md 7.12, m2.md section 7): independent zstd
//! frames, one per OUTPUT_ZSTD message or compressed SNAPSHOT part.
//!
//! Two functions, so that the codec can be replaced locally:
//!
//! - [`compress`]: one single-segment frame with its content size declared, as protocol.md
//!   7.12 requires, made with `ruzstd` at its fastest level (about zstd level 1: speed over
//!   ratio, which is right for interactive streaming). `ruzstd` writes frames with a window
//!   descriptor and no content size; [`compress`] rewrites the header (the blocks are valid in
//!   a single-segment frame: every match refers to the frame's own content, which is the
//!   window).
//! - [`decompress`]: the receiver's side, with every rule of 7.12 enforced **before** any
//!   output is produced: the header check of [`crate::proto::zstd::parse_header`] (magic,
//!   single segment, no dictionary, declared size 1 to 65 536), every block at most the
//!   window (the declared size), and a decoder that stops as soon as it would produce more than
//!   declared. The decoder is our own (`codec/decode.rs`): `ruzstd`'s decoder does not bound
//!   what one compressed block produces, so a message of a few kilobytes could make a receiver
//!   allocate gigabytes. It is memory safe, allocates at most the declared size plus the
//!   block's literals, and is fuzzed against `ruzstd` (fuzz target `zstd_frame`).
//!
//! Both contain a panic of the code they call ([`crate::fault`]): the encoder's is an
//! [`Err`] of [`compress`] (the caller sends the data uncompressed), the decoder's is
//! [`DecodeError::Fault`] (the client treats the connection as broken, and stops asking that
//! server for compression if it happens again). A panic costs one message, never the process.
//!
//! Without the cargo feature `zstd` both return nothing: such a build never offers the
//! capability ([`AVAILABLE`]).

#[cfg(feature = "zstd")]
mod decode;
#[cfg(all(test, feature = "zstd"))]
mod tests;

use std::fmt;

use crate::fault::{self, Fault};
use crate::proto::zstd::{FrameError, MAX_ZSTD_CONTENT};

/// This build can compress and decompress (cargo feature `zstd`).
pub const AVAILABLE: bool = cfg!(feature = "zstd");

/// Why a frame could not be decompressed: always a FRAME_ERROR stream error (7.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The frame header breaks rules 1 to 3 of 7.12.
    Frame(FrameError),
    /// The frame declares more than the receiver accepts here.
    TooLarge {
        /// Frame_Content_Size.
        declared: usize,
        /// The most the receiver takes.
        max: usize,
    },
    /// The frame's content is not valid zstd.
    Corrupt(&'static str),
    /// The frame produced more or fewer bytes than it declared (rule 4).
    Length {
        /// Frame_Content_Size.
        declared: usize,
        /// What it produced, or would have (at least).
        produced: usize,
    },
    /// The content checksum does not match.
    Checksum,
    /// This build has no zstd (cargo feature `zstd`).
    Unsupported,
    /// The decoder panicked (contained, [`crate::fault`]): a bug of ours, not necessarily a bad
    /// frame.
    Fault(Fault),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Frame(e) => e.fmt(f),
            DecodeError::TooLarge { declared, max } => {
                write!(f, "zstd frame declares {declared} bytes, more than {max}")
            }
            DecodeError::Corrupt(why) => write!(f, "corrupt zstd frame: {why}"),
            DecodeError::Length { declared, produced } => {
                write!(f, "zstd frame declares {declared} bytes but produces {produced}")
            }
            DecodeError::Checksum => f.write_str("zstd frame checksum mismatch"),
            DecodeError::Unsupported => f.write_str("zstd is not supported by this build"),
            DecodeError::Fault(fault) => write!(f, "the zstd decoder failed ({fault})"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl From<FrameError> for DecodeError {
    fn from(e: FrameError) -> DecodeError {
        DecodeError::Frame(e)
    }
}

/// `data` (1 to [`MAX_ZSTD_CONTENT`] bytes) as one independent zstd frame that follows the
/// rules of protocol.md 7.12. None without the `zstd` feature, or for an empty or larger
/// input. The frame may be larger than `data` (incompressible input): the caller compares.
/// A panic in the encoder is an error: the caller sends `data` uncompressed.
pub fn compress(data: &[u8]) -> Result<Option<Vec<u8>>, Fault> {
    if data.is_empty() || data.len() > MAX_ZSTD_CONTENT {
        return Ok(None);
    }
    // Contained: the encoder's state lives and dies within the call, nothing of it is reused
    fault::contain(|| {
        #[cfg(any(test, feature = "test-hooks"))]
        fault::test_hooks::check(fault::test_hooks::Hook::Encoder, data);
        compress_frame(data)
    })
}

#[cfg(feature = "zstd")]
fn compress_frame(data: &[u8]) -> Option<Vec<u8>> {
    use crate::proto::zstd::MAGIC;
    use ruzstd::encoding::{compress_to_vec, CompressionLevel};
    let encoded = compress_to_vec(data, CompressionLevel::Fastest);
    // ruzstd's header: magic, descriptor, window descriptor (not single segment), no
    // dictionary, no content size; then the blocks, then a checksum when its `hash` feature
    // is on (it is not here, but stay correct either way)
    let descriptor = *encoded.get(4)?;
    if encoded.get(..4)? != MAGIC || descriptor & 0x08 != 0 {
        return None;
    }
    let single = descriptor & 0x20 != 0;
    let dictionary = [0, 1, 2, 4][usize::from(descriptor & 0x03)];
    let content_size = match (descriptor >> 6, single) {
        (0, false) => 0,
        (0, true) => 1,
        (1, _) => 2,
        (2, _) => 4,
        _ => 8,
    };
    let header = 5 + usize::from(!single) + dictionary + content_size;
    let checksum = if descriptor & 0x04 != 0 { 4 } else { 0 };
    let mut blocks = encoded.get(header..encoded.len().checked_sub(checksum)?)?;
    // In a single-segment frame no block may be larger than the content (the window): ruzstd
    // may write a compressed block larger than a tiny input. Then one raw block instead.
    let raw;
    if !blocks_fit(blocks, data.len()) {
        let header = ((data.len() as u32) << 3) | 1; // Last_Block, Raw_Block
        raw = [&header.to_le_bytes()[..3], data].concat();
        blocks = &raw;
    }
    let mut frame = Vec::with_capacity(blocks.len() + 8);
    frame.extend_from_slice(&MAGIC);
    let n = data.len();
    if n < 256 {
        // Single segment, a one-byte content size
        frame.push(0x20);
        frame.push(n as u8);
    } else {
        // Single segment, a two-byte content size, which stores the size minus 256
        frame.push(0x60);
        frame.extend_from_slice(&((n - 256) as u16).to_le_bytes());
    }
    frame.extend_from_slice(blocks);
    Some(frame)
}

/// Whether every block of `blocks` (a frame's blocks, up to its last) is at most `window`
/// bytes, as a single-segment frame of that content size requires.
#[cfg(feature = "zstd")]
fn blocks_fit(blocks: &[u8], window: usize) -> bool {
    let mut at = 0;
    while let Some(h) = blocks.get(at..at + 3) {
        let h = usize::from(h[0]) | usize::from(h[1]) << 8 | usize::from(h[2]) << 16;
        let size = h >> 3;
        if size > window {
            return false;
        }
        at += 3 + if (h >> 1) & 3 == 1 { 1 } else { size };
        if h & 1 != 0 {
            return at == blocks.len();
        }
    }
    false
}

#[cfg(not(feature = "zstd"))]
fn compress_frame(_data: &[u8]) -> Option<Vec<u8>> {
    None
}

/// Decompress one frame of OUTPUT_ZSTD or compressed SNAPSHOT data, declaring at most `max`
/// bytes (at most [`MAX_ZSTD_CONTENT`]), under every rule of protocol.md 7.12. A panic in
/// the decoder is [`DecodeError::Fault`].
pub fn decompress(frame: &[u8], max: usize) -> Result<Vec<u8>, DecodeError> {
    #[cfg(feature = "zstd")]
    {
        // Contained: the decoder's state lives and dies within the call
        fault::contain(|| {
            let data = decode::decode(frame, max.min(MAX_ZSTD_CONTENT));
            #[cfg(any(test, feature = "test-hooks"))]
            if let Ok(data) = &data {
                fault::test_hooks::check(fault::test_hooks::Hook::Decoder, data);
            }
            data
        })
        .unwrap_or_else(|fault| Err(DecodeError::Fault(fault)))
    }
    #[cfg(not(feature = "zstd"))]
    {
        let _ = (frame, max);
        Err(DecodeError::Unsupported)
    }
}
