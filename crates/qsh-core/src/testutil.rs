//! Helpers for tests.

/// A small deterministic pseudo random generator (xorshift64*), for property tests without a
/// dependency.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// A generator from a seed (any value but 0 works; 0 is mapped to 1).
    pub fn new(seed: u64) -> Rng {
        Rng(seed.max(1).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    /// The next 64 random bits.
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A number in `low..high` (`low` when the range is empty).
    pub fn range(&mut self, low: u64, high: u64) -> u64 {
        if high <= low {
            low
        } else {
            low + self.next() % (high - low)
        }
    }

    /// `n` random bytes.
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}
