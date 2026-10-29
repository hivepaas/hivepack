//! PBKDF2 with HMAC-SHA1, as RFC 8018 defines it (section 5.2), which
//! WinZip AES derives its keys with. BearSSL has no PBKDF2.

use crate::clear::clear;
use crate::hmac::{Hmac, HmacKey};
use crate::sha1::SHA1_LENGTH;

/// Fills `out` with the key derived from `password` and `salt` in
/// `iterations` rounds, as libzip's `_zip_crypto_pbkdf2` does.
///
/// RFC 8018 asks for at least one round: 0 counts as 1. It also refuses
/// keys longer than (2³² − 1) × 20 bytes, about 86 GB, whose block numbers
/// no longer fit 32 bits; here they would start again from 1.
pub fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let key = HmacKey::new(password);
    for (i, block) in out.chunks_mut(SHA1_LENGTH).enumerate() {
        let mut hmac = Hmac::new(&key);
        hmac.update(salt);
        hmac.update(&(i as u32).wrapping_add(1).to_be_bytes());
        let mut u = hmac.out();
        let mut t = u;
        for _ in 1..iterations {
            let mut hmac = Hmac::new(&key);
            hmac.update(&u);
            u = hmac.out();
            for (x, y) in t.iter_mut().zip(u) {
                *x ^= y;
            }
        }
        block.copy_from_slice(&t[..block.len()]);
        clear(&mut u);
        clear(&mut t);
    }
}
