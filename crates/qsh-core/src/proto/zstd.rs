//! The zstd frame rules of OUTPUT_ZSTD and compressed SNAPSHOT data (protocol.md 7.12 and
//! 7.8.3): the frame header check a receiver makes **before** it decompresses anything.
//!
//! A frame [RFC 8878, section 3.1.1] starts with the magic number, then the
//! Frame_Header_Descriptor:
//!
//! | Bits | Field | qsh/1 requires |
//! |---|---|---|
//! | 7–6 | Frame_Content_Size_flag | any: the field is 1 (flag 0, single segment), 2, 4 or 8 bytes |
//! | 5 | Single_Segment_flag | 1: no Window_Descriptor, the window is the content size |
//! | 4 | Unused_bit | ignored |
//! | 3 | Reserved_bit | 0 |
//! | 2 | Content_Checksum_flag | any (the decoder then verifies the checksum) |
//! | 1–0 | Dictionary_ID_flag | 0: no dictionary |
//!
//! and Frame_Content_Size (little-endian; the 2-byte form stores the size minus 256) between 1
//! and [`MAX_ZSTD_CONTENT`]. That bounds what one message can make a receiver commit to: a
//! 64 KiB window and 64 KiB of output.
//!
//! This module only parses the header; decompression (which must also check rule 4 of 7.12:
//! the last block ends exactly at the end of the payload, with exactly Frame_Content_Size bytes
//! produced) belongs to the codec (m2.md section 7.3).

use std::fmt;

/// The zstd frame magic number, as it appears on the wire (0xFD2FB528 little-endian).
pub const MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// The largest declared content size of a frame (`MAX_ZSTD_CONTENT`, 7.12).
pub const MAX_ZSTD_CONTENT: usize = 65536;

/// The size of a block header, which must follow the frame header (RFC 8878 3.1.1.2).
const BLOCK_HEADER: usize = 3;

/// Why a frame is refused: always a FRAME_ERROR stream error (7.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The frame ends before its header and first block header do.
    Truncated,
    /// No zstd magic number (a skippable frame, or no zstd at all).
    BadMagic,
    /// Single_Segment_flag is 0: the frame would choose its own window.
    NotSingleSegment,
    /// The Reserved bit is set.
    ReservedBit,
    /// A dictionary is named.
    Dictionary,
    /// Frame_Content_Size is 0 or above [`MAX_ZSTD_CONTENT`].
    ContentSize(u64),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Truncated => f.write_str("zstd frame cut off"),
            FrameError::BadMagic => f.write_str("not a zstd frame"),
            FrameError::NotSingleSegment => f.write_str("zstd frame is not single-segment"),
            FrameError::ReservedBit => f.write_str("zstd frame sets the reserved bit"),
            FrameError::Dictionary => f.write_str("zstd frame uses a dictionary"),
            FrameError::ContentSize(n) => write!(f, "zstd frame declares {n} bytes (1 to {MAX_ZSTD_CONTENT})"),
        }
    }
}

impl std::error::Error for FrameError {}

/// What the header of an acceptable frame says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Frame_Content_Size: exactly this many bytes must come out, 1 to [`MAX_ZSTD_CONTENT`].
    pub content_size: usize,
    /// The frame header's length, magic number included: the first block starts here.
    pub header_len: usize,
    /// Content_Checksum_flag: a 4-byte checksum follows the last block.
    pub checksum: bool,
}

/// Parse and check the header of `frame` (7.12, rules 1 to 3).
pub fn parse_header(frame: &[u8]) -> Result<FrameHeader, FrameError> {
    if frame.len() < MAGIC.len() {
        return Err(if MAGIC.starts_with(frame) {
            FrameError::Truncated
        } else {
            FrameError::BadMagic
        });
    }
    if frame[..4] != MAGIC {
        return Err(FrameError::BadMagic);
    }
    let Some(&descriptor) = frame.get(4) else {
        return Err(FrameError::Truncated);
    };
    if descriptor & 0x20 == 0 {
        return Err(FrameError::NotSingleSegment);
    }
    if descriptor & 0x08 != 0 {
        return Err(FrameError::ReservedBit);
    }
    if descriptor & 0x03 != 0 {
        return Err(FrameError::Dictionary);
    }
    let checksum = descriptor & 0x04 != 0;
    // Single-segment: no Window_Descriptor, no Dictionary_ID (flag 0), then the content size
    let size_len = match descriptor >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let start = 5;
    let field = frame.get(start..start + size_len).ok_or(FrameError::Truncated)?;
    let mut le = [0u8; 8];
    le[..size_len].copy_from_slice(field);
    let mut content_size = u64::from_le_bytes(le);
    if size_len == 2 {
        content_size += 256;
    }
    if content_size == 0 || content_size > MAX_ZSTD_CONTENT as u64 {
        return Err(FrameError::ContentSize(content_size));
    }
    let header_len = start + size_len;
    if frame.len() < header_len + BLOCK_HEADER {
        return Err(FrameError::Truncated);
    }
    Ok(FrameHeader {
        content_size: content_size as usize,
        header_len,
        checksum,
    })
}

/// Check the header of `frame` before decompressing it (7.12, rules 1 to 3): its declared
/// content size, 1 to [`MAX_ZSTD_CONTENT`].
pub fn check_frame(frame: &[u8]) -> Result<usize, FrameError> {
    parse_header(frame).map(|h| h.content_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Rng;

    /// protocol.md A.9, both frames.
    #[test]
    fn appendix_a9_frames() {
        let hello = [
            0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x07, 0x39, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o', b'\r', b'\n',
        ];
        assert_eq!(
            parse_header(&hello),
            Ok(FrameHeader {
                content_size: 7,
                header_len: 6,
                checksum: false
            })
        );
        let equals = [0x28, 0xb5, 0x2f, 0xfd, 0x60, 0xe8, 0x02, 0x43, 0x1f, 0x00, 0x3d];
        assert_eq!(check_frame(&equals), Ok(1000));
        assert_eq!(parse_header(&equals).unwrap().header_len, 7);
    }

    fn frame(descriptor: u8, size: &[u8]) -> Vec<u8> {
        let mut f = MAGIC.to_vec();
        f.push(descriptor);
        f.extend_from_slice(size);
        // A raw last block of 0 bytes
        f.extend_from_slice(&[0x01, 0x00, 0x00]);
        f
    }

    #[test]
    fn content_sizes_in_every_field_width() {
        // 1 byte (single segment, flag 0): 1 to 255
        assert_eq!(check_frame(&frame(0x20, &[1])), Ok(1));
        assert_eq!(check_frame(&frame(0x20, &[255])), Ok(255));
        assert_eq!(check_frame(&frame(0x20, &[0])), Err(FrameError::ContentSize(0)));
        // 2 bytes: value + 256, so 256 to 65 791; the limit is 65 536 = 0xff00 + 256
        assert_eq!(check_frame(&frame(0x60, &[0, 0])), Ok(256));
        assert_eq!(check_frame(&frame(0x60, &[0x00, 0xff])), Ok(65536));
        assert_eq!(
            check_frame(&frame(0x60, &[0x01, 0xff])),
            Err(FrameError::ContentSize(65537))
        );
        // 4 bytes
        assert_eq!(check_frame(&frame(0xa0, &[0x00, 0x00, 0x01, 0x00])), Ok(65536));
        assert_eq!(
            check_frame(&frame(0xa0, &[0x01, 0x00, 0x01, 0x00])),
            Err(FrameError::ContentSize(65537))
        );
        assert_eq!(check_frame(&frame(0xa0, &[0; 4])), Err(FrameError::ContentSize(0)));
        // 8 bytes
        assert_eq!(check_frame(&frame(0xe0, &[7, 0, 0, 0, 0, 0, 0, 0])), Ok(7));
        assert_eq!(
            check_frame(&frame(0xe0, &[0, 0, 0, 0, 0, 0, 0, 0x80])),
            Err(FrameError::ContentSize(1 << 63))
        );
        // The checksum flag is allowed, the unused bit ignored
        assert!(parse_header(&frame(0x24, &[9])).unwrap().checksum);
        assert_eq!(check_frame(&frame(0x30, &[9])), Ok(9));
    }

    #[test]
    fn frames_that_break_the_rules_are_refused() {
        assert_eq!(check_frame(&frame(0x00, &[7])), Err(FrameError::NotSingleSegment));
        assert_eq!(check_frame(&frame(0x28, &[7])), Err(FrameError::ReservedBit));
        for dictionary in 1..=3 {
            assert_eq!(
                check_frame(&frame(0x20 | dictionary, &[7])),
                Err(FrameError::Dictionary)
            );
        }
        // A skippable frame (magic 0x184D2A50..5F)
        assert_eq!(
            check_frame(&[0x50, 0x2a, 0x4d, 0x18, 4, 0, 0, 0, 1, 2, 3, 4]),
            Err(FrameError::BadMagic)
        );
        assert_eq!(check_frame(b"hello, world"), Err(FrameError::BadMagic));
        assert_eq!(check_frame(&[0x28, 0xb6]), Err(FrameError::BadMagic));
        // Cut off anywhere before the end of the first block header
        let whole = frame(0xa0, &[1, 0, 0, 0]);
        for n in 0..whole.len() {
            assert_eq!(check_frame(&whole[..n]), Err(FrameError::Truncated), "{n}");
        }
        assert_eq!(check_frame(&whole), Ok(1));
    }

    #[test]
    fn random_frames_never_panic() {
        let mut rng = Rng::new(0x25b5);
        for _ in 0..100_000 {
            let len = rng.range(0, 24) as usize;
            let mut f = rng.bytes(len);
            if rng.range(0, 2) == 0 && f.len() >= 4 {
                f[..4].copy_from_slice(&MAGIC);
            }
            if let Ok(h) = parse_header(&f) {
                assert!((1..=MAX_ZSTD_CONTENT).contains(&h.content_size));
                assert!(h.header_len + 3 <= f.len());
            }
        }
    }
}
