//! QUIC variable-length integers (RFC 9000 section 16; protocol.md section 2.4).

/// The largest value a varint holds: 2^62 - 1.
pub const MAX: u64 = (1 << 62) - 1;

/// Why a varint could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarintError {
    /// The input ended inside the varint.
    Truncated,
}

/// The encoded length of `value`: 1, 2, 4 or 8. Values above [`MAX`] cannot be encoded.
pub fn len(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16383 => 2,
        16384..=1_073_741_823 => 4,
        _ => 8,
    }
}

/// Append the shortest encoding of `value`.
///
/// # Panics
///
/// When `value` exceeds [`MAX`]: the protocol never needs such values, so it is a bug.
pub fn encode(value: u64, out: &mut Vec<u8>) {
    assert!(value <= MAX, "varint out of range: {value}");
    match len(value) {
        1 => out.push(value as u8),
        2 => out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        4 => out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// The length of a varint from its first byte.
pub fn len_from_first(first: u8) -> usize {
    1 << (first >> 6)
}

/// Decode a varint at the start of `input`: the value and the bytes it took. Any valid encoding
/// is accepted, shortest or not.
pub fn decode(input: &[u8]) -> Result<(u64, usize), VarintError> {
    let first = *input.first().ok_or(VarintError::Truncated)?;
    let n = len_from_first(first);
    let bytes = input.get(..n).ok_or(VarintError::Truncated)?;
    let mut value = u64::from(first & 0x3f);
    for b in &bytes[1..] {
        value = (value << 8) | u64::from(*b);
    }
    Ok((value, n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Rng;

    #[test]
    fn rfc9000_examples() {
        assert_eq!(decode(&[0x25]), Ok((37, 1)));
        assert_eq!(decode(&[0x40, 0x25]), Ok((37, 2)));
        assert_eq!(decode(&[0x7b, 0xbd]), Ok((15293, 2)));
        assert_eq!(decode(&[0x9d, 0x7f, 0x3e, 0x7d]), Ok((494_878_333, 4)));
        assert_eq!(
            decode(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]),
            Ok((151_288_809_941_952_652, 8))
        );
        let mut out = Vec::new();
        encode(151_288_809_941_952_652, &mut out);
        assert_eq!(out, [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]);
    }

    #[test]
    fn truncated_input_is_an_error() {
        assert_eq!(decode(&[]), Err(VarintError::Truncated));
        assert_eq!(decode(&[0x40]), Err(VarintError::Truncated));
        assert_eq!(decode(&[0xc0, 0, 0, 0, 0, 0, 0]), Err(VarintError::Truncated));
    }

    #[test]
    fn roundtrip_boundaries_and_random_values() {
        let mut values = vec![0, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824, MAX];
        let mut rng = Rng::new(7);
        values.extend((0..1000).map(|_| rng.next() & MAX));
        values.extend((0..1000).map(|_| rng.next() >> (2 + rng.range(0, 62))));
        for v in values {
            let mut out = Vec::new();
            encode(v, &mut out);
            assert_eq!(out.len(), len(v));
            assert_eq!(decode(&out), Ok((v, out.len())));
        }
    }

    #[test]
    #[should_panic]
    fn encoding_too_large_a_value_panics() {
        encode(MAX + 1, &mut Vec::new());
    }
}
