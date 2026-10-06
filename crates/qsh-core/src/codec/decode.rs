//! A bounded zstd decoder for the frames qsh accepts (RFC 8878; protocol.md 7.12): single
//! segment, no dictionary, at most 64 KiB of content.
//!
//! Every copy is checked against the declared content size before it is made, so a frame
//! never makes the decoder produce (or allocate for) more than it declared; a block that would
//! produce more than the window (the declared size) is refused as well. Everything else is
//! RFC 8878 section 3 and 4: raw, RLE and compressed blocks; raw, RLE, Huffman-compressed and
//! treeless literals in one or four streams, with Huffman weights direct or FSE-compressed;
//! sequences with predefined, RLE, FSE-compressed and repeated tables; repeat offsets; the
//! optional XXH64 content checksum.
//!
//! Plain code over slices, no unsafe; speed is secondary (a frame is at most 64 KiB).

use super::DecodeError;
use crate::proto::zstd::parse_header;

/// The largest block (Block_Maximum_Size is the smaller of this and the window).
const MAX_BLOCK: usize = 128 * 1024;
/// Huffman codes are at most this long.
const MAX_HUFFMAN_BITS: u32 = 11;

fn corrupt<T>(why: &'static str) -> Result<T, DecodeError> {
    Err(DecodeError::Corrupt(why))
}

/// Decode `frame`, declaring at most `max` bytes.
pub(super) fn decode(frame: &[u8], max: usize) -> Result<Vec<u8>, DecodeError> {
    let header = parse_header(frame)?;
    let declared = header.content_size;
    if declared > max {
        return Err(DecodeError::TooLarge { declared, max });
    }
    // Single segment: the window is the content size
    let block_max = declared.min(MAX_BLOCK);
    let mut out = Out {
        bytes: Vec::with_capacity(declared),
        limit: declared,
    };
    let mut state = FrameState::default();
    let mut at = header.header_len;
    loop {
        let Some(h) = frame.get(at..at + 3) else {
            return corrupt("block header cut off");
        };
        let h = u32::from(h[0]) | u32::from(h[1]) << 8 | u32::from(h[2]) << 16;
        at += 3;
        let last = h & 1 != 0;
        let size = (h >> 3) as usize;
        if size > block_max {
            return corrupt("block larger than the window");
        }
        match (h >> 1) & 3 {
            0 => {
                let Some(raw) = frame.get(at..at + size) else {
                    return corrupt("raw block cut off");
                };
                out.extend(raw)?;
                at += size;
            }
            1 => {
                let Some(&byte) = frame.get(at) else {
                    return corrupt("RLE block cut off");
                };
                out.fill(byte, size)?;
                at += 1;
            }
            2 => {
                let Some(block) = frame.get(at..at + size) else {
                    return corrupt("compressed block cut off");
                };
                let before = out.bytes.len();
                compressed_block(&mut state, block, &mut out, block_max)?;
                if out.bytes.len() - before > block_max {
                    return corrupt("block produces more than the window");
                }
                at += size;
            }
            _ => return corrupt("reserved block type"),
        }
        if last {
            break;
        }
    }
    if header.checksum {
        let Some(sum) = frame.get(at..at + 4) else {
            return corrupt("checksum cut off");
        };
        let sum = u32::from_le_bytes([sum[0], sum[1], sum[2], sum[3]]);
        if twox_hash::XxHash64::oneshot(0, &out.bytes) as u32 != sum {
            return Err(DecodeError::Checksum);
        }
        at += 4;
    }
    if at != frame.len() {
        return corrupt("bytes after the last block");
    }
    if out.bytes.len() != declared {
        return Err(DecodeError::Length {
            declared,
            produced: out.bytes.len(),
        });
    }
    Ok(out.bytes)
}

/// The output, which never grows past the declared size.
struct Out {
    bytes: Vec<u8>,
    limit: usize,
}

impl Out {
    fn room(&self, n: usize) -> Result<(), DecodeError> {
        if n > self.limit - self.bytes.len() {
            return Err(DecodeError::Length {
                declared: self.limit,
                produced: self.bytes.len().saturating_add(n),
            });
        }
        Ok(())
    }

    fn extend(&mut self, data: &[u8]) -> Result<(), DecodeError> {
        self.room(data.len())?;
        self.bytes.extend_from_slice(data);
        Ok(())
    }

    fn fill(&mut self, byte: u8, n: usize) -> Result<(), DecodeError> {
        self.room(n)?;
        self.bytes.resize(self.bytes.len() + n, byte);
        Ok(())
    }

    /// Copy `n` bytes from `offset` back (they may overlap what is being written).
    fn copy_match(&mut self, offset: usize, n: usize) -> Result<(), DecodeError> {
        if offset == 0 || offset > self.bytes.len() {
            return corrupt("match offset outside the frame");
        }
        self.room(n)?;
        let start = self.bytes.len() - offset;
        if offset >= n {
            self.bytes.extend_from_within(start..start + n);
        } else {
            for i in 0..n {
                let b = self.bytes[start + i];
                self.bytes.push(b);
            }
        }
        Ok(())
    }
}

/// What carries over from one block to the next within a frame.
#[derive(Default)]
struct FrameState {
    huffman: Option<Huffman>,
    /// Literal lengths, offsets, match lengths: the last tables, for Repeat_Mode.
    tables: [Option<Fse>; 3],
    repeat: Option<[usize; 3]>,
}

// ---- bits ----

/// `n` (≤ 57) bits of `data` read as a little-endian number, from bit `start` on; bits outside
/// the data read as zero.
fn bits_at(data: &[u8], start: i64, n: u32) -> u64 {
    if n == 0 {
        return 0;
    }
    let end = start + i64::from(n); // exclusive
    let mut value = 0u64;
    let first_byte = start.max(0) / 8;
    let last_byte = (end - 1) / 8;
    if last_byte < 0 {
        return 0;
    }
    for byte in first_byte..=last_byte {
        let Some(&b) = usize::try_from(byte).ok().and_then(|i| data.get(i)) else {
            continue;
        };
        // Where this byte's bit 0 lands in the result
        let shift = byte * 8 - start;
        let b = u64::from(b);
        if shift >= 0 {
            if shift < 64 {
                value |= b << shift;
            }
        } else {
            value |= b >> (-shift);
        }
    }
    value & ((1u64 << n) - 1)
}

/// A stream read backwards from its end (Huffman streams, FSE weights, sequences): the last
/// byte's highest set bit marks the end; bits are taken from the top.
struct Backward<'a> {
    data: &'a [u8],
    /// Bits not consumed yet (may go below zero: reading past the start yields zeros, and the
    /// stream is then overflowed).
    left: i64,
}

impl<'a> Backward<'a> {
    fn new(data: &'a [u8]) -> Result<Backward<'a>, DecodeError> {
        let Some(&last) = data.last() else {
            return corrupt("empty bitstream");
        };
        if last == 0 {
            return corrupt("bitstream without its end mark");
        }
        let marker = 7 - last.leading_zeros() as i64;
        Ok(Backward {
            data,
            left: (data.len() as i64 - 1) * 8 + marker,
        })
    }

    fn peek(&self, n: u32) -> u64 {
        bits_at(self.data, self.left - i64::from(n), n)
    }

    fn consume(&mut self, n: u32) {
        self.left -= i64::from(n);
    }

    fn read(&mut self, n: u32) -> u64 {
        let v = self.peek(n);
        self.consume(n);
        v
    }

    fn overflowed(&self) -> bool {
        self.left < 0
    }

    fn finished(&self) -> bool {
        self.left == 0
    }
}

// ---- FSE ----

#[derive(Clone, Copy, Default)]
struct FseEntry {
    symbol: u8,
    bits: u8,
    base: u16,
}

#[derive(Clone)]
struct Fse {
    log: u32,
    table: Vec<FseEntry>,
}

impl Fse {
    /// A one-state table that always decodes `symbol` (RLE mode).
    fn rle(symbol: u8) -> Fse {
        Fse {
            log: 0,
            table: vec![FseEntry {
                symbol,
                bits: 0,
                base: 0,
            }],
        }
    }

    /// The decoding table of normalized counts `norm` (-1: "less than one") at accuracy `log`.
    fn build(norm: &[i16], log: u32) -> Result<Fse, DecodeError> {
        let size = 1usize << log;
        let mut table = vec![FseEntry::default(); size];
        let mut next = vec![0u32; norm.len()];
        let mut high = size - 1;
        for (s, &n) in norm.iter().enumerate() {
            if n == -1 {
                table[high].symbol = s as u8;
                high = high.wrapping_sub(1);
                next[s] = 1;
            } else {
                next[s] = n.max(0) as u32;
            }
        }
        let step = (size >> 1) + (size >> 3) + 3;
        let mask = size - 1;
        let mut position = 0usize;
        for (s, &n) in norm.iter().enumerate() {
            for _ in 0..n.max(0) {
                table[position].symbol = s as u8;
                position = (position + step) & mask;
                while high < size && position > high {
                    position = (position + step) & mask;
                }
            }
        }
        if position != 0 {
            return corrupt("FSE probabilities do not fill the table");
        }
        for entry in table.iter_mut() {
            let s = usize::from(entry.symbol);
            let state = next[s];
            next[s] += 1;
            if state == 0 {
                return corrupt("FSE symbol without probability");
            }
            let bits = log - (31 - state.leading_zeros());
            entry.bits = bits as u8;
            entry.base = ((state << bits) as usize - size) as u16;
        }
        Ok(Fse { log, table })
    }
}

/// Read an FSE table description (normalized counts) from the start of `data`: the counts of
/// symbols 0 to `max_symbol` and the accuracy log (at most `max_log`), and the bytes used.
fn read_counts(data: &[u8], max_symbol: usize, max_log: u32) -> Result<(Vec<i16>, u32, usize), DecodeError> {
    let mut at: i64 = 0;
    let read = |at: &mut i64, n: u32| {
        let v = bits_at(data, *at, n);
        *at += i64::from(n);
        v
    };
    let peek = |at: i64, n: u32| bits_at(data, at, n);
    let log = read(&mut at, 4) as u32 + 5;
    if log > max_log {
        return corrupt("FSE accuracy log too large");
    }
    let mut remaining: i32 = (1 << log) + 1;
    let mut threshold: i32 = 1 << log;
    let mut nbits = log + 1;
    let mut norm: Vec<i16> = Vec::new();
    let mut previous_zero = false;
    while remaining > 1 && norm.len() <= max_symbol {
        if previous_zero {
            // Runs of zero probabilities: two bits each, 3 means "three more, and go on"
            loop {
                let repeat = read(&mut at, 2) as usize;
                norm.extend(std::iter::repeat_n(0, repeat));
                if norm.len() > max_symbol + 1 {
                    return corrupt("FSE zeros past the last symbol");
                }
                if repeat != 3 {
                    break;
                }
            }
            if norm.len() > max_symbol {
                break;
            }
        }
        let max = 2 * threshold - 1 - remaining;
        let low = peek(at, nbits - 1) as i32;
        let mut count = if low < max {
            at += i64::from(nbits - 1);
            low
        } else {
            let mut c = peek(at, nbits) as i32;
            if c >= threshold {
                c -= max;
            }
            at += i64::from(nbits);
            c
        };
        count -= 1;
        remaining -= count.abs();
        norm.push(count as i16);
        previous_zero = count == 0;
        if remaining < 1 {
            return corrupt("FSE probabilities exceed the total");
        }
        while remaining < threshold {
            nbits -= 1;
            threshold >>= 1;
        }
    }
    if remaining != 1 || norm.len() > max_symbol + 1 {
        return corrupt("FSE probabilities do not add up");
    }
    let used = ((at + 7) / 8) as usize;
    if used > data.len() {
        return corrupt("FSE table description cut off");
    }
    Ok((norm, log, used))
}

// ---- Huffman ----

#[derive(Clone)]
struct Huffman {
    max_bits: u32,
    /// Indexed by the next `max_bits` bits: (symbol, code length).
    table: Vec<(u8, u8)>,
}

impl Huffman {
    /// The table described at the start of `data` (RFC 8878 4.2.1), and the bytes used.
    fn read(data: &[u8]) -> Result<(Huffman, usize), DecodeError> {
        let Some(&head) = data.first() else {
            return corrupt("Huffman description missing");
        };
        let (mut weights, used) = if head < 128 {
            let size = usize::from(head);
            let Some(compressed) = data.get(1..1 + size) else {
                return corrupt("Huffman weights cut off");
            };
            (fse_weights(compressed)?, 1 + size)
        } else {
            let n = usize::from(head - 127);
            let Some(packed) = data.get(1..1 + n.div_ceil(2)) else {
                return corrupt("Huffman weights cut off");
            };
            let weights = (0..n)
                .map(|i| {
                    let b = packed[i / 2];
                    if i % 2 == 0 {
                        b >> 4
                    } else {
                        b & 0xf
                    }
                })
                .collect();
            (weights, 1 + n.div_ceil(2))
        };
        if weights.len() > 255 {
            return corrupt("too many Huffman weights");
        }
        let mut total: u32 = 0;
        for &w in &weights {
            if u32::from(w) > MAX_HUFFMAN_BITS {
                return corrupt("Huffman weight too large");
            }
            if w > 0 {
                total += 1 << (w - 1);
            }
        }
        if total == 0 {
            return corrupt("Huffman weights all zero");
        }
        let max_bits = 32 - total.leading_zeros(); // highest bit of total, plus one
        if max_bits > MAX_HUFFMAN_BITS {
            return corrupt("Huffman codes too long");
        }
        let left = (1u32 << max_bits) - total;
        if !left.is_power_of_two() {
            return corrupt("Huffman weights do not complete a tree");
        }
        // The last symbol's weight is implied
        weights.push((left.trailing_zeros() + 1) as u8);
        let size = 1usize << max_bits;
        let mut table = Vec::with_capacity(size);
        for w in 1..=max_bits as u8 {
            for (symbol, &weight) in weights.iter().enumerate() {
                if weight == w {
                    let count = 1usize << (w - 1);
                    let length = (max_bits + 1 - u32::from(w)) as u8;
                    table.extend(std::iter::repeat_n((symbol as u8, length), count));
                }
            }
        }
        if table.len() != size {
            return corrupt("Huffman table incomplete");
        }
        Ok((Huffman { max_bits, table }, used))
    }

    /// Decode exactly `count` symbols from one stream, which they must use up exactly.
    fn stream(&self, data: &[u8], count: usize, into: &mut Vec<u8>) -> Result<(), DecodeError> {
        let mut bits = Backward::new(data)?;
        for _ in 0..count {
            let (symbol, length) = self.table[bits.peek(self.max_bits) as usize];
            bits.consume(u32::from(length));
            if bits.overflowed() {
                return corrupt("Huffman stream too short");
            }
            into.push(symbol);
        }
        if !bits.finished() {
            return corrupt("Huffman stream not used up");
        }
        Ok(())
    }
}

/// Huffman weights compressed with FSE (two interleaved states, accuracy log at most 6).
fn fse_weights(data: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let (norm, log, used) = read_counts(data, 255, 6)?;
    let fse = Fse::build(&norm, log)?;
    let mut bits = Backward::new(&data[used..])?;
    let mut states = [bits.read(log) as usize, bits.read(log) as usize];
    if bits.overflowed() {
        return corrupt("FSE weights too short");
    }
    let mut weights = Vec::new();
    let mut which = 0;
    loop {
        if weights.len() >= 255 {
            return corrupt("too many Huffman weights");
        }
        let entry = fse.table[states[which]];
        weights.push(entry.symbol);
        states[which] = usize::from(entry.base) + bits.read(u32::from(entry.bits)) as usize;
        if bits.overflowed() {
            // The other state's last symbol, and done
            weights.push(fse.table[states[1 - which]].symbol);
            break;
        }
        which = 1 - which;
    }
    Ok(weights)
}

// ---- literals ----

/// The literals section at the start of a compressed block: the literals and the bytes used.
fn literals(state: &mut FrameState, block: &[u8], block_max: usize) -> Result<(Vec<u8>, usize), DecodeError> {
    // Header fields as u64: the five-byte form has 40 bits
    let b = |i: usize| {
        block
            .get(i)
            .copied()
            .map(u64::from)
            .ok_or(DecodeError::Corrupt("literals header cut off"))
    };
    let b0 = b(0)?;
    let kind = b0 & 3;
    let format = (b0 >> 2) & 3;
    if kind < 2 {
        let (size, header) = match format {
            0 | 2 => (b0 >> 3, 1),
            1 => ((b0 >> 4) | b(1)? << 4, 2),
            _ => ((b0 >> 4) | b(1)? << 4 | b(2)? << 12, 3),
        };
        let size = size as usize;
        if size > block_max {
            return corrupt("literals larger than the block");
        }
        if kind == 0 {
            let Some(raw) = block.get(header..header + size) else {
                return corrupt("raw literals cut off");
            };
            return Ok((raw.to_vec(), header + size));
        }
        let byte = b(header)? as u8;
        return Ok((vec![byte; size], header + 1));
    }
    let (four, header, size, compressed) = match format {
        0 | 1 => {
            let h = b0 | b(1)? << 8 | b(2)? << 16;
            (format == 1, 3, (h >> 4) & 0x3ff, (h >> 14) & 0x3ff)
        }
        2 => {
            let h = b0 | b(1)? << 8 | b(2)? << 16 | b(3)? << 24;
            (true, 4, (h >> 4) & 0x3fff, (h >> 18) & 0x3fff)
        }
        _ => {
            let h = b0 | b(1)? << 8 | b(2)? << 16 | b(3)? << 24 | b(4)? << 32;
            (true, 5, (h >> 4) & 0x3ffff, (h >> 22) & 0x3ffff)
        }
    };
    let (size, compressed) = (size as usize, compressed as usize);
    if size > block_max {
        return corrupt("literals larger than the block");
    }
    let Some(mut body) = block.get(header..header + compressed) else {
        return corrupt("compressed literals cut off");
    };
    if kind == 2 {
        let (table, used) = Huffman::read(body)?;
        state.huffman = Some(table);
        body = &body[used..];
    }
    let Some(huffman) = state.huffman.as_ref() else {
        return corrupt("treeless literals without a previous table");
    };
    let mut out = Vec::with_capacity(size);
    if four {
        let Some(jump) = body.get(..6) else {
            return corrupt("jump table cut off");
        };
        let sizes = [
            usize::from(u16::from_le_bytes([jump[0], jump[1]])),
            usize::from(u16::from_le_bytes([jump[2], jump[3]])),
            usize::from(u16::from_le_bytes([jump[4], jump[5]])),
        ];
        let streams = &body[6..];
        let Some(fourth) = streams.len().checked_sub(sizes[0] + sizes[1] + sizes[2]) else {
            return corrupt("jump table beyond the literals");
        };
        let segment = size.div_ceil(4);
        let Some(last) = size.checked_sub(3 * segment) else {
            return corrupt("too few literals for four streams");
        };
        let mut at = 0;
        for (i, len) in [sizes[0], sizes[1], sizes[2], fourth].into_iter().enumerate() {
            let count = if i == 3 { last } else { segment };
            huffman.stream(&streams[at..at + len], count, &mut out)?;
            at += len;
        }
    } else {
        huffman.stream(body, size, &mut out)?;
    }
    Ok((out, header + compressed))
}

// ---- sequences ----

const LL_MAX: usize = 35;
const ML_MAX: usize = 52;
const OF_MAX: usize = 31;

const LL_DEFAULT: [i16; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1,
];
const ML_DEFAULT: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
const OF_DEFAULT: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];

/// Literal length codes: (baseline, extra bits).
const LL_CODES: [(u32, u32); 36] = [
    (0, 0),
    (1, 0),
    (2, 0),
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 0),
    (11, 0),
    (12, 0),
    (13, 0),
    (14, 0),
    (15, 0),
    (16, 1),
    (18, 1),
    (20, 1),
    (22, 1),
    (24, 2),
    (28, 2),
    (32, 3),
    (40, 3),
    (48, 4),
    (64, 6),
    (128, 7),
    (256, 8),
    (512, 9),
    (1024, 10),
    (2048, 11),
    (4096, 12),
    (8192, 13),
    (16384, 14),
    (32768, 15),
    (65536, 16),
];

/// Match length codes: (baseline, extra bits).
const ML_CODES: [(u32, u32); 53] = [
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 0),
    (11, 0),
    (12, 0),
    (13, 0),
    (14, 0),
    (15, 0),
    (16, 0),
    (17, 0),
    (18, 0),
    (19, 0),
    (20, 0),
    (21, 0),
    (22, 0),
    (23, 0),
    (24, 0),
    (25, 0),
    (26, 0),
    (27, 0),
    (28, 0),
    (29, 0),
    (30, 0),
    (31, 0),
    (32, 0),
    (33, 0),
    (34, 0),
    (35, 1),
    (37, 1),
    (39, 1),
    (41, 1),
    (43, 2),
    (47, 2),
    (51, 3),
    (59, 3),
    (67, 4),
    (83, 4),
    (99, 5),
    (131, 7),
    (259, 8),
    (515, 9),
    (1027, 10),
    (2051, 11),
    (4099, 12),
    (8195, 13),
    (16387, 14),
    (32771, 15),
    (65539, 16),
];

/// One compressed block: literals, then sequences, executed into `out`.
fn compressed_block(state: &mut FrameState, block: &[u8], out: &mut Out, block_max: usize) -> Result<(), DecodeError> {
    let (literals, used) = literals(state, block, block_max)?;
    let data = &block[used..];
    let b = |i: usize| {
        data.get(i)
            .copied()
            .map(usize::from)
            .ok_or(DecodeError::Corrupt("sequences header cut off"))
    };
    let b0 = b(0)?;
    let (count, mut at) = match b0 {
        0 => {
            if data.len() != 1 {
                return corrupt("bytes after an empty sequences section");
            }
            return out.extend(&literals);
        }
        1..=127 => (b0, 1),
        128..=254 => (((b0 - 128) << 8) + b(1)?, 2),
        _ => (b(1)? + (b(2)? << 8) + 0x7f00, 3),
    };
    let modes = b(at)?;
    at += 1;
    if modes & 3 != 0 {
        return corrupt("reserved bits in the sequence modes");
    }
    let kinds: [(usize, &[i16], u32, usize, u32); 3] = [
        ((modes >> 6) & 3, &LL_DEFAULT, 6, LL_MAX, 9),
        ((modes >> 4) & 3, &OF_DEFAULT, 5, OF_MAX, 8),
        ((modes >> 2) & 3, &ML_DEFAULT, 6, ML_MAX, 9),
    ];
    for (i, (mode, default, default_log, max_symbol, max_log)) in kinds.into_iter().enumerate() {
        let table = match mode {
            0 => Fse::build(default, default_log)?,
            1 => {
                let symbol = b(at)?;
                at += 1;
                if symbol > max_symbol {
                    return corrupt("RLE code out of range");
                }
                Fse::rle(symbol as u8)
            }
            2 => {
                let (norm, log, used) = read_counts(&data[at..], max_symbol, max_log)?;
                at += used;
                Fse::build(&norm, log)?
            }
            _ => match state.tables[i].clone() {
                Some(t) => t,
                None => return corrupt("repeated table without a previous one"),
            },
        };
        state.tables[i] = Some(table);
    }
    let [Some(ll), Some(of), Some(ml)] = &state.tables else {
        return corrupt("missing table");
    };
    let mut bits = Backward::new(&data[at..])?;
    let mut ll_state = bits.read(ll.log) as usize;
    let mut of_state = bits.read(of.log) as usize;
    let mut ml_state = bits.read(ml.log) as usize;
    let repeat = state.repeat.get_or_insert([1, 4, 8]);
    let mut lit = 0usize;
    for i in 0..count {
        let of_code = u32::from(of.table[of_state].symbol);
        let ml_code = usize::from(ml.table[ml_state].symbol);
        let ll_code = usize::from(ll.table[ll_state].symbol);
        if of_code as usize > OF_MAX {
            return corrupt("offset code out of range");
        }
        let offset_value = (1u64 << of_code) + bits.read(of_code);
        let (ml_base, ml_bits) = ML_CODES[ml_code];
        let match_length = (u64::from(ml_base) + bits.read(ml_bits)) as usize;
        let (ll_base, ll_bits) = LL_CODES[ll_code];
        let literal_length = (u64::from(ll_base) + bits.read(ll_bits)) as usize;
        let offset = if offset_value > 3 {
            let o = usize::try_from(offset_value - 3).unwrap_or(usize::MAX);
            *repeat = [o, repeat[0], repeat[1]];
            o
        } else {
            let index = offset_value as usize - 1 + usize::from(literal_length == 0);
            match index {
                0 => repeat[0],
                1 => {
                    *repeat = [repeat[1], repeat[0], repeat[2]];
                    repeat[0]
                }
                2 => {
                    *repeat = [repeat[2], repeat[0], repeat[1]];
                    repeat[0]
                }
                _ => {
                    let o = repeat[0].wrapping_sub(1);
                    *repeat = [o, repeat[0], repeat[1]];
                    o
                }
            }
        };
        // Bounded before anything is copied
        let Some(literal) = literals.get(lit..lit + literal_length) else {
            return corrupt("sequence beyond the literals");
        };
        out.room(literal_length.saturating_add(match_length))?;
        out.extend(literal)?;
        lit += literal_length;
        out.copy_match(offset, match_length)?;
        if i + 1 < count {
            let e = ll.table[ll_state];
            ll_state = usize::from(e.base) + bits.read(u32::from(e.bits)) as usize;
            let e = ml.table[ml_state];
            ml_state = usize::from(e.base) + bits.read(u32::from(e.bits)) as usize;
            let e = of.table[of_state];
            of_state = usize::from(e.base) + bits.read(u32::from(e.bits)) as usize;
        }
        if bits.overflowed() {
            return corrupt("sequences bitstream too short");
        }
    }
    if !bits.finished() {
        return corrupt("sequences bitstream not used up");
    }
    out.extend(&literals[lit..])
}
