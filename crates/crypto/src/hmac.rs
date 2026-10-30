//! HMAC: port of `hmac.c`.
//!
//! Differs from BearSSL: the whole output (BearSSL's `out_len` 0); libzip
//! cuts HMAC-SHA1 to 10 bytes itself.

use crate::clear::clear;
use crate::digest::Digest;

/// The longest block of the hashes here, SHA-512's.
const MAX_BLOCK_LENGTH: usize = 128;

/// `process_key`: the state of the hash after a block of the key XORed
/// with `bb`.
fn process_key<H: Digest>(key: &[u8], bb: u8) -> H::Output {
    let mut tmp = [bb; MAX_BLOCK_LENGTH];
    for (byte, &k) in tmp.iter_mut().zip(key) {
        *byte ^= k;
    }
    let mut hc = H::new();
    hc.update(&tmp[..H::BLOCK_LENGTH]);
    clear(&mut tmp);
    hc.state().0
}

/// An HMAC key, prepared: `br_hmac_key_context`, the states of the hash
/// after the inner and the outer padded keys. Many computations with the
/// same key, as in PBKDF2, start from it.
///
/// It is overwritten when it is dropped (best effort).
#[derive(Clone)]
pub struct HmacKey<H: Digest> {
    ksi: H::Output,
    kso: H::Output,
}

impl<H: Digest> HmacKey<H> {
    /// `br_hmac_key_init`: a key of any length; one longer than a block of
    /// the hash (64 bytes, 128 for SHA-512) is hashed first.
    pub fn new(key: &[u8]) -> HmacKey<H> {
        if key.len() > H::BLOCK_LENGTH {
            let mut hc = H::new();
            hc.update(key);
            let mut kbuf = hc.out();
            let kc = HmacKey::new(kbuf.as_ref());
            clear(kbuf.as_mut());
            return kc;
        }
        HmacKey {
            ksi: process_key::<H>(key, 0x36),
            kso: process_key::<H>(key, 0x5C),
        }
    }
}

impl<H: Digest> Drop for HmacKey<H> {
    fn drop(&mut self) {
        clear(self.ksi.as_mut());
        clear(self.kso.as_mut());
    }
}

/// Shows nothing of the key.
impl<H: Digest> std::fmt::Debug for HmacKey<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacKey").finish_non_exhaustive()
    }
}

/// An HMAC computation: `br_hmac_context`.
///
/// It is overwritten when it is dropped (best effort).
#[derive(Clone)]
pub struct Hmac<H: Digest> {
    dig: H,
    kso: H::Output,
}

impl<H: Digest> Hmac<H> {
    /// `br_hmac_init`: a computation with the key `kc`.
    pub fn new(kc: &HmacKey<H>) -> Hmac<H> {
        let mut dig = H::new();
        dig.set_state(&kc.ksi, H::BLOCK_LENGTH as u64);
        Hmac { dig, kso: kc.kso }
    }

    /// `br_hmac_update`: more data.
    pub fn update(&mut self, data: &[u8]) {
        self.dig.update(data);
    }

    /// `br_hmac_out`: the HMAC of the data so far. The computation can go
    /// on with more data.
    pub fn out(&self) -> H::Output {
        let mut tmp = self.dig.out();
        let mut hc = H::new();
        hc.set_state(&self.kso, H::BLOCK_LENGTH as u64);
        hc.update(tmp.as_ref());
        clear(tmp.as_mut());
        hc.out()
    }
}

impl<H: Digest> Drop for Hmac<H> {
    fn drop(&mut self) {
        clear(self.kso.as_mut());
    }
}

/// Shows how much was given, not the key or the data.
impl<H: Digest> std::fmt::Debug for Hmac<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hmac")
            .field("dig", &self.dig)
            .finish_non_exhaustive()
    }
}
