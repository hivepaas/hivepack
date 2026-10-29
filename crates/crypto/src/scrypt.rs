//! scrypt, as RFC 7914 defines it: the Salsa20/8 core (section 3),
//! scryptBlockMix (section 4), scryptROMix (section 5) and scrypt itself
//! (section 6), which age derives the key of a passphrase with. BearSSL
//! has no scrypt.

use crate::clear::clear;
use crate::pbkdf2::pbkdf2;
use crate::sha2small::Sha256;

/// Why [`scrypt`] did not derive a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScryptError {
    /// The parameters are outside what RFC 7914 allows, or need more
    /// memory than the machine can address.
    Parameters,
    /// The memory could not be allocated.
    Memory,
}

impl std::fmt::Display for ScryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ScryptError::Parameters => "scrypt parameters out of range",
            ScryptError::Memory => "not enough memory for scrypt",
        })
    }
}

impl std::error::Error for ScryptError {}

/// The Salsa20/8 core, on 16 words, in place.
fn salsa20_8(b: &mut [u32; 16]) {
    let mut x = *b;
    macro_rules! r {
        ($a:expr, $s:expr, $c:expr, $n:expr) => {
            x[$a] ^= x[$s].wrapping_add(x[$c]).rotate_left($n)
        };
    }
    for _ in 0..4 {
        r!(4, 0, 12, 7);
        r!(8, 4, 0, 9);
        r!(12, 8, 4, 13);
        r!(0, 12, 8, 18);
        r!(9, 5, 1, 7);
        r!(13, 9, 5, 9);
        r!(1, 13, 9, 13);
        r!(5, 1, 13, 18);
        r!(14, 10, 6, 7);
        r!(2, 14, 10, 9);
        r!(6, 2, 14, 13);
        r!(10, 6, 2, 18);
        r!(3, 15, 11, 7);
        r!(7, 3, 15, 9);
        r!(11, 7, 3, 13);
        r!(15, 11, 7, 18);
        r!(1, 0, 3, 7);
        r!(2, 1, 0, 9);
        r!(3, 2, 1, 13);
        r!(0, 3, 2, 18);
        r!(6, 5, 4, 7);
        r!(7, 6, 5, 9);
        r!(4, 7, 6, 13);
        r!(5, 4, 7, 18);
        r!(11, 10, 9, 7);
        r!(8, 11, 10, 9);
        r!(9, 8, 11, 13);
        r!(10, 9, 8, 18);
        r!(12, 15, 14, 7);
        r!(13, 12, 15, 9);
        r!(14, 13, 12, 13);
        r!(15, 14, 13, 18);
    }
    for (out, x) in b.iter_mut().zip(x) {
        *out = out.wrapping_add(x);
    }
}

/// scryptBlockMix of the `2r` 64-byte blocks of `b`, as words, into `y`:
/// the even outputs first, then the odd.
fn block_mix(b: &[u32], y: &mut [u32], r: usize) {
    let mut x = [0u32; 16];
    x.copy_from_slice(&b[(2 * r - 1) * 16..]);
    for (i, block) in b.as_chunks::<16>().0.iter().enumerate() {
        for (x, &w) in x.iter_mut().zip(block) {
            *x ^= w;
        }
        salsa20_8(&mut x);
        let at = (i / 2 + (i & 1) * r) * 16;
        y[at..at + 16].copy_from_slice(&x);
    }
}

/// scryptROMix of the `128r` bytes of `b`, in place, with the `N` × `32r`
/// words of `v` and the `64r` of `xy` to work in.
fn ro_mix(b: &mut [u8], n: u64, r: usize, v: &mut [u32], xy: &mut [u32]) {
    let words = 32 * r;
    let (x, y) = xy.split_at_mut(words);
    for (w, bytes) in x.iter_mut().zip(b.as_chunks().0) {
        *w = u32::from_le_bytes(*bytes);
    }
    for vi in v.chunks_exact_mut(words) {
        vi.copy_from_slice(x);
        block_mix(x, y, r);
        x.copy_from_slice(y);
    }
    // Integerify: the last 64-byte block as a little-endian integer, of
    // which only the low 64 bits matter, N being at most 2^63.
    let last = (2 * r - 1) * 16;
    for _ in 0..n {
        let integer = u64::from(x[last]) | u64::from(x[last + 1]) << 32;
        let j = (integer & (n - 1)) as usize;
        for (x, &w) in x.iter_mut().zip(&v[j * words..(j + 1) * words]) {
            *x ^= w;
        }
        block_mix(x, y, r);
        x.copy_from_slice(y);
    }
    for (bytes, w) in b.as_chunks_mut().0.iter_mut().zip(x.iter()) {
        *bytes = w.to_le_bytes();
    }
}

/// Fills `out` with the key that scrypt derives from `password` and `salt`
/// with the cost N = 2^`log_n`, the block size `r` and the
/// parallelization `p`. It takes 128 × `r` × N bytes of memory.
///
/// The parameters are those RFC 7914 allows: N above 1, `r` and `p` at
/// least 1 and `r` × `p` below 2^30, and an output of at most
/// (2³² − 1) × 32 bytes, as PBKDF2 allows. RFC 7914 also asks for N below
/// 2^(16`r`), which only matters for `r` below 4; Go's
/// `golang.org/x/crypto/scrypt`, which age uses, does not check it, and
/// neither does this. A memory allocation that fails is an error, not an
/// abort.
pub fn scrypt(
    password: &[u8],
    salt: &[u8],
    log_n: u8,
    r: u32,
    p: u32,
    out: &mut [u8],
) -> Result<(), ScryptError> {
    if log_n == 0
        || log_n > 63
        || r == 0
        || p == 0
        || u64::from(r) * u64::from(p) >= 1 << 30
        || out.len() as u64 > u64::from(u32::MAX) * 32
    {
        return Err(ScryptError::Parameters);
    }
    let n = 1u64 << log_n;
    let r = usize::try_from(r).map_err(|_| ScryptError::Parameters)?;
    let p = usize::try_from(p).map_err(|_| ScryptError::Parameters)?;
    let block = r.checked_mul(128).ok_or(ScryptError::Parameters)?;
    let v_words = usize::try_from(n)
        .ok()
        .and_then(|n| n.checked_mul(32 * r))
        .ok_or(ScryptError::Parameters)?;
    let b_len = block.checked_mul(p).ok_or(ScryptError::Parameters)?;

    let mut v = Vec::new();
    v.try_reserve_exact(v_words)
        .map_err(|_| ScryptError::Memory)?;
    v.resize(v_words, 0u32);
    let mut b = Vec::new();
    b.try_reserve_exact(b_len)
        .map_err(|_| ScryptError::Memory)?;
    b.resize(b_len, 0u8);
    let mut xy = vec![0u32; 64 * r];

    pbkdf2::<Sha256>(password, salt, 1, &mut b);
    for bi in b.chunks_exact_mut(block) {
        ro_mix(bi, n, r, &mut v, &mut xy);
    }
    pbkdf2::<Sha256>(password, &b, 1, out);

    clear(&mut v);
    clear(&mut b);
    clear(&mut xy);
    Ok(())
}
