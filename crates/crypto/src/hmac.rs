//! HMAC: port of `hmac.c`, with SHA-1.
//!
//! Differs from BearSSL: SHA-1 only, the hash WinZip AES uses, where
//! BearSSL takes any of its hashes; and the whole 20-byte output (BearSSL's
//! `out_len` 0), which libzip cuts to 10 bytes itself.

use crate::clear::clear;
use crate::sha1::{BLOCK_LENGTH, SHA1_LENGTH, Sha1};

/// `process_key`: the state of SHA-1 after a block of the key XORed with
/// `bb`.
fn process_key(key: &[u8], bb: u8) -> [u8; SHA1_LENGTH] {
    let mut tmp = [bb; BLOCK_LENGTH];
    for (byte, &k) in tmp.iter_mut().zip(key) {
        *byte ^= k;
    }
    let mut hc = Sha1::new();
    hc.update(&tmp);
    clear(&mut tmp);
    hc.state().0
}

/// An HMAC key, prepared: `br_hmac_key_context`, the states of SHA-1 after
/// the inner and the outer padded keys. Many computations with the same
/// key, as in PBKDF2, start from it.
///
/// It is overwritten when it is dropped (best effort).
#[derive(Clone)]
pub struct HmacKey {
    ksi: [u8; SHA1_LENGTH],
    kso: [u8; SHA1_LENGTH],
}

impl HmacKey {
    /// `br_hmac_key_init`: a key of any length; one longer than a block of
    /// SHA-1 (64 bytes) is hashed first.
    pub fn new(key: &[u8]) -> HmacKey {
        let mut kbuf = [0u8; SHA1_LENGTH];
        let key = if key.len() > BLOCK_LENGTH {
            let mut hc = Sha1::new();
            hc.update(key);
            kbuf = hc.out();
            &kbuf[..]
        } else {
            key
        };
        let kc = HmacKey {
            ksi: process_key(key, 0x36),
            kso: process_key(key, 0x5C),
        };
        clear(&mut kbuf);
        kc
    }
}

impl Drop for HmacKey {
    fn drop(&mut self) {
        clear(&mut self.ksi);
        clear(&mut self.kso);
    }
}

/// Shows nothing of the key.
impl std::fmt::Debug for HmacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacKey").finish_non_exhaustive()
    }
}

/// An HMAC computation: `br_hmac_context`.
///
/// It is overwritten when it is dropped (best effort).
#[derive(Clone)]
pub struct Hmac {
    dig: Sha1,
    kso: [u8; SHA1_LENGTH],
}

impl Hmac {
    /// `br_hmac_init`: a computation with the key `kc`.
    pub fn new(kc: &HmacKey) -> Hmac {
        let mut dig = Sha1::new();
        dig.set_state(&kc.ksi, BLOCK_LENGTH as u64);
        Hmac { dig, kso: kc.kso }
    }

    /// `br_hmac_update`: more data.
    pub fn update(&mut self, data: &[u8]) {
        self.dig.update(data);
    }

    /// `br_hmac_out`: the HMAC of the data so far. The computation can go
    /// on with more data.
    pub fn out(&self) -> [u8; SHA1_LENGTH] {
        let mut tmp = self.dig.out();
        let mut hc = Sha1::new();
        hc.set_state(&self.kso, BLOCK_LENGTH as u64);
        hc.update(&tmp);
        clear(&mut tmp);
        hc.out()
    }
}

impl Drop for Hmac {
    fn drop(&mut self) {
        clear(&mut self.kso);
    }
}

/// Shows how much was given, not the key or the data.
impl std::fmt::Debug for Hmac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hmac")
            .field("dig", &self.dig)
            .finish_non_exhaustive()
    }
}
