//! PBKDF2, as RFC 8018 defines it (section 5.2): with HMAC-SHA1, which
//! WinZip AES derives its keys with, and with HMAC-SHA256, which scrypt
//! starts and ends with. BearSSL has no PBKDF2.

use crate::clear::clear;
use crate::digest::Digest;
use crate::hmac::{Hmac, HmacKey};

/// Fills `out` with the key derived from `password` and `salt` in
/// `iterations` rounds of HMAC with the hash `H`, as libzip's
/// `_zip_crypto_pbkdf2` does with SHA-1.
///
/// RFC 8018 asks for at least one round: 0 counts as 1. It also refuses
/// keys longer than (2³² − 1) blocks of the hash's output (about 86 GB with
/// SHA-1), whose block numbers no longer fit 32 bits; here they would
/// start again from 1.
pub fn pbkdf2<H: Digest>(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let key = HmacKey::<H>::new(password);
    for (i, block) in out.chunks_mut(H::OUTPUT_LENGTH).enumerate() {
        let mut hmac = Hmac::new(&key);
        hmac.update(salt);
        hmac.update(&(i as u32).wrapping_add(1).to_be_bytes());
        let mut u = hmac.out();
        let mut t = u;
        for _ in 1..iterations {
            let mut hmac = Hmac::new(&key);
            hmac.update(u.as_ref());
            u = hmac.out();
            for (x, y) in t.as_mut().iter_mut().zip(u.as_ref()) {
                *x ^= y;
            }
        }
        block.copy_from_slice(&t.as_ref()[..block.len()]);
        clear(u.as_mut());
        clear(t.as_mut());
    }
}
