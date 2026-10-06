//! Release signatures in the minisign format (DESIGN.md section 3, security.md section 8):
//! `qsh install` downloads a release's `SHA256SUMS` and checks its signature,
//! `SHA256SUMS.minisig`, against the release public key compiled into qsh, before trusting any
//! checksum in it. The format is minisign's (<https://jedisct1.github.io/minisign/>), so that
//! people can check a download with the stock tool: `minisign -Vm SHA256SUMS -P <key>`.
//!
//! Ed25519 comes from `ring`, already a dependency; minisign hashes what it signs with
//! BLAKE2b-512 (signature algorithm `ED`), which `ring` does not have, so this module has a
//! small BLAKE2b (RFC 7693), tested against the reference vectors. Legacy signatures over the
//! whole file (algorithm `Ed`) are accepted too. Nothing here is secret: verification only
//! ([`sign`] exists for the tests and has no secret of its own).

use ring::signature::{self, KeyPair};

/// What is wrong with a key or a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn err(text: impl Into<String>) -> Error {
    Error(text.into())
}

// ---------------------------------------------------------------------------------------------
// BLAKE2b (RFC 7693), unkeyed

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

fn compress(h: &mut [u64; 8], block: &[u8; 128], counter: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, word) in m.iter_mut().enumerate() {
        *word = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= counter as u64;
    v[13] ^= (counter >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(63);
    }
    for round in 0..12 {
        let s = &SIGMA[round % 10];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// BLAKE2b of `data` with an `out_len`-byte digest (1 to 64), without a key.
pub fn blake2b(out_len: usize, data: &[u8]) -> Vec<u8> {
    assert!((1..=64).contains(&out_len), "BLAKE2b digests are 1 to 64 bytes");
    let mut h = IV;
    h[0] ^= 0x0101_0000 ^ out_len as u64;
    let mut counter: u128 = 0;
    let mut rest = data;
    // Every block but the last; the last (possibly partial, or empty for empty data) is final
    while rest.len() > 128 {
        let (block, tail) = rest.split_at(128);
        counter += 128;
        compress(&mut h, block.try_into().expect("128 bytes"), counter, false);
        rest = tail;
    }
    let mut last = [0u8; 128];
    last[..rest.len()].copy_from_slice(rest);
    counter += rest.len() as u128;
    compress(&mut h, &last, counter, true);
    let mut out: Vec<u8> = h.iter().flat_map(|w| w.to_le_bytes()).collect();
    out.truncate(out_len);
    out
}

// ---------------------------------------------------------------------------------------------
// Base64 (RFC 4648, standard alphabet, padded)

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 of `data`, padded.
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The bytes of padded base64 `text` (surrounding whitespace ignored); None when it is not
/// exactly that.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim().as_bytes();
    if text.len() % 4 != 0 {
        return None;
    }
    let value = |c: u8| ALPHABET.iter().position(|a| *a == c).map(|v| v as u32);
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for (i, chunk) in text.chunks(4).enumerate() {
        let last = i == text.len() / 4 - 1;
        let pad = chunk.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for (j, c) in chunk.iter().enumerate() {
            let v = if j >= 4 - pad { 0 } else { value(*c)? };
            n = n << 6 | v;
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        // Exactly one encoding: the bits padding drops must be zero
        if (pad == 1 && bytes[2] != 0) || (pad == 2 && bytes[1] != 0) {
            return None;
        }
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Some(out)
}

// ---------------------------------------------------------------------------------------------
// Keys and signatures

/// The signature algorithm over the BLAKE2b-512 of the file (minisign's default).
const PREHASHED: &[u8; 2] = b"ED";
/// The signature algorithm over the file itself (minisign's legacy format).
const LEGACY: &[u8; 2] = b"Ed";

/// A minisign public key: an 8-byte key id and an Ed25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    /// The key id, which a signature names.
    pub id: [u8; 8],
    /// The Ed25519 public key.
    pub key: [u8; 32],
}

impl PublicKey {
    /// The key from its base64 form (`RW…`, what `minisign -P` takes), or from a whole public
    /// key file (its last line).
    pub fn parse(text: &str) -> Result<PublicKey, Error> {
        let line = text.lines().rfind(|l| !l.trim().is_empty()).unwrap_or("");
        let bytes = base64_decode(line).ok_or_else(|| err("the public key is not base64"))?;
        if bytes.len() != 42 || &bytes[..2] != LEGACY {
            return Err(err("not a minisign Ed25519 public key"));
        }
        Ok(PublicKey {
            id: bytes[2..10].try_into().expect("8 bytes"),
            key: bytes[10..].try_into().expect("32 bytes"),
        })
    }

    /// The base64 form.
    pub fn to_base64(&self) -> String {
        let mut bytes = LEGACY.to_vec();
        bytes.extend_from_slice(&self.id);
        bytes.extend_from_slice(&self.key);
        base64_encode(&bytes)
    }

    /// The key id as minisign prints it (hexadecimal, of the id read as a little-endian
    /// number).
    pub fn id_hex(&self) -> String {
        format!("{:016X}", u64::from_le_bytes(self.id))
    }

    fn verify(&self, message: &[u8], sig: &[u8]) -> bool {
        signature::UnparsedPublicKey::new(&signature::ED25519, &self.key)
            .verify(message, sig)
            .is_ok()
    }
}

/// Check `minisig` (the text of a `.minisig` file) as `key`'s signature of `message`: the
/// signature of the file (or of its BLAKE2b-512), by this key id, and the signature of the
/// trusted comment. Returns the trusted comment.
pub fn verify(key: &PublicKey, message: &[u8], minisig: &str) -> Result<String, Error> {
    let mut lines = minisig.lines();
    let mut next = |what: &str| lines.next().ok_or_else(|| err(format!("the signature has no {what}")));
    let untrusted = next("comment")?;
    if !untrusted.starts_with("untrusted comment:") {
        return Err(err("not a minisign signature"));
    }
    let sig = base64_decode(next("signature")?).ok_or_else(|| err("the signature is not base64"))?;
    let trusted = next("trusted comment")?
        .strip_prefix("trusted comment: ")
        .ok_or_else(|| err("the signature has no trusted comment"))?
        .to_string();
    let global = base64_decode(next("comment signature")?).ok_or_else(|| err("the comment signature is not base64"))?;
    if sig.len() != 74 || global.len() != 64 {
        return Err(err("the signature has the wrong length"));
    }
    if sig[2..10] != key.id {
        return Err(err(format!(
            "signed with another key ({:016X}, not {})",
            u64::from_le_bytes(sig[2..10].try_into().expect("8 bytes")),
            key.id_hex()
        )));
    }
    let signed = match &sig[..2] {
        a if a == PREHASHED => blake2b(64, message),
        a if a == LEGACY => message.to_vec(),
        _ => return Err(err("an unknown signature algorithm")),
    };
    if !key.verify(&signed, &sig[10..]) {
        return Err(err("the signature does not match the file"));
    }
    let mut comment = sig[10..].to_vec();
    comment.extend_from_slice(trusted.as_bytes());
    if !key.verify(&comment, &global) {
        return Err(err("the signature of the trusted comment does not match"));
    }
    Ok(trusted)
}

/// Sign `message` as minisign does (BLAKE2b-512 prehashed), with the Ed25519 key of 32-byte
/// `seed` and key id `id`. For the tests, and for signing with a key whose seed is at hand;
/// the release workflow signs with `scripts/sign-release.py`.
pub fn sign(seed: &[u8; 32], id: [u8; 8], message: &[u8], trusted_comment: &str) -> Result<String, Error> {
    let pair = signature::Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| err("a bad seed"))?;
    let sig = pair.sign(&blake2b(64, message));
    let mut first = PREHASHED.to_vec();
    first.extend_from_slice(&id);
    first.extend_from_slice(sig.as_ref());
    let mut comment = sig.as_ref().to_vec();
    comment.extend_from_slice(trusted_comment.as_bytes());
    let global = pair.sign(&comment);
    Ok(format!(
        "untrusted comment: signature from minisign secret key\n{}\ntrusted comment: {trusted_comment}\n{}\n",
        base64_encode(&first),
        base64_encode(global.as_ref())
    ))
}

/// The public key of the Ed25519 key of 32-byte `seed`, with key id `id`.
pub fn public_key(seed: &[u8; 32], id: [u8; 8]) -> Result<PublicKey, Error> {
    let pair = signature::Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| err("a bad seed"))?;
    Ok(PublicKey {
        id,
        key: pair.public_key().as_ref().try_into().expect("32 bytes"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// RFC 7693 appendix A, and digests of Python's hashlib (the reference implementation).
    #[test]
    fn blake2b_matches_the_reference() {
        let cases: [(Vec<u8>, &str); 5] = [
            (vec![], "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"),
            (b"abc".to_vec(), "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"),
            ((0..128).collect(), "2319e3789c47e2daa5fe807f61bec2a1a6537fa03f19ff32e87eecbfd64b7e0e8ccff439ac333b040f19b0c4ddd11a61e24ac1fe0f10a039806c5dcc0da3d115"),
            ((0..129).collect(), "f59711d44a031d5f97a9413c065d1e614c417ede998590325f49bad2fd444d3e4418be19aec4e11449ac1a57207898bc57d76a1bcf3566292c20c683a5c4648f"),
            ((0..1000).map(|i| (i % 251) as u8).collect(), "c11e1c0340bd7e5a1b275f1230c962fad215ecb1391486e74e31b960a2f2996381a5fad092da06841d5f26e38f6ecfeaf441acbcd1c2de61aef121e7927175f5"),
        ];
        for (data, digest) in cases {
            assert_eq!(hex(&blake2b(64, &data)), digest, "{} bytes", data.len());
        }
        assert_eq!(
            hex(&blake2b(32, b"abc")),
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
        );
    }

    #[test]
    fn base64_round_trips_and_is_strict() {
        for n in 0..20 {
            let data: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(base64_decode(&base64_encode(&data)), Some(data));
        }
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        for bad in ["Zm9", "Zm9v!mFy", "Zg=a", "Z===", "Zm9=Zm9v", "Zh=="] {
            assert_eq!(base64_decode(bad), None, "{bad}");
        }
    }

    /// A signature made here verifies, and every change to the file, the comment or the key
    /// is caught; legacy (non-prehashed) signatures verify too.
    #[test]
    fn signatures_verify_and_tampering_is_caught() {
        let seed = [7u8; 32];
        let key = public_key(&seed, *b"qshtest1").unwrap();
        assert_eq!(PublicKey::parse(&key.to_base64()), Ok(key));
        let file = b"0123  qsh-0.5.0-x86_64-unknown-linux-musl.tar.gz\n";
        let sig = sign(&seed, key.id, file, "qsh 0.5.0 SHA256SUMS").unwrap();
        assert_eq!(verify(&key, file, &sig).as_deref(), Ok("qsh 0.5.0 SHA256SUMS"));
        assert!(verify(&key, b"other", &sig).is_err());
        let comment = sig.replace("qsh 0.5.0", "qsh 0.4.0");
        assert!(verify(&key, file, &comment).unwrap_err().0.contains("trusted comment"));
        let other = public_key(&[8u8; 32], *b"qshtest1").unwrap();
        assert!(verify(&other, file, &sig).is_err());
        let other_id = public_key(&seed, *b"qshtest2").unwrap();
        assert!(verify(&other_id, file, &sig).unwrap_err().0.contains("another key"));
        assert!(verify(&key, file, "").is_err());
        assert!(verify(&key, file, "untrusted comment: x\nAAAA\n").is_err());
        // Legacy: the file itself signed
        let pair = signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let s = pair.sign(file);
        let mut first = LEGACY.to_vec();
        first.extend_from_slice(&key.id);
        first.extend_from_slice(s.as_ref());
        let mut c = s.as_ref().to_vec();
        c.extend_from_slice(b"legacy");
        let legacy = format!(
            "untrusted comment: x\n{}\ntrusted comment: legacy\n{}\n",
            base64_encode(&first),
            base64_encode(pair.sign(&c).as_ref())
        );
        assert_eq!(verify(&key, file, &legacy).as_deref(), Ok("legacy"));
    }

    /// A signature made by scripts/sign-release.py (Python's BLAKE2b, OpenSSL's Ed25519), with a
    /// throwaway key: the release workflow's signatures verify here.
    #[test]
    fn a_signature_of_the_release_script_verifies() {
        let key = PublicKey::parse(
            "untrusted comment: minisign public key FA2898DDD46EC75D\nRWRdx27U3Zgo+sGDQN0JTNHEt1Q8bPVj1zFmLjww0BpjvfL4Huk+utET\n",
        )
        .unwrap();
        assert_eq!(key.id_hex(), "FA2898DDD46EC75D");
        let sig = "untrusted comment: signature from the qsh release key
RURdx27U3Zgo+vP2GOZFoyhMFUdBq9QSL1iyev8ne8thMzHUiAesnfbqq2PV3jARhguHbBCkedyxSglJnpyjiIYGevNzTeOSCAE=
trusted comment: qsh 0.5.0 SHA256SUMS
p4JFPFOcyNmNHPrH6KtL52mWduYH+Rvb43w7VHMx/tmB1oi71eXHBuL4cCw/3Gw5rTIpOYa4DQzVQcRaWghLAg==
";
        let file = b"abc  qsh-0.5.0-x.tar.gz\n";
        assert_eq!(verify(&key, file, sig).as_deref(), Ok("qsh 0.5.0 SHA256SUMS"));
        assert!(verify(&key, b"abd  qsh-0.5.0-x.tar.gz\n", sig).is_err());
    }
}
