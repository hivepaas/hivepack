//! HKDF (RFC 5869): port of `hkdf.c`, which age derives its keys with.
//!
//! Differs from BearSSL: the context is two types, [`Hkdf`] before
//! `br_hkdf_flip` and [`HkdfExpand`] after it, where BearSSL keeps a union
//! of the two.

use crate::clear::clear;
use crate::digest::Digest;
use crate::hmac::{Hmac, HmacKey};

/// The longest output of the hashes here, SHA-512's.
const MAX_OUTPUT_LENGTH: usize = 64;

/// HKDF's extract step, the input key material still coming:
/// `br_hkdf_context` before `br_hkdf_flip`.
#[derive(Clone, Debug)]
pub struct Hkdf<H: Digest> {
    hmac_ctx: Hmac<H>,
}

impl<H: Digest> Hkdf<H> {
    /// `br_hkdf_init`: HKDF with the hash `H` and `salt`. `None` is
    /// `BR_HKDF_NO_SALT`, which RFC 5869 makes a string of zeros as long as
    /// the hash's output; an empty salt is the same, as HMAC pads the key
    /// with zeros.
    pub fn new(salt: Option<&[u8]>) -> Hkdf<H> {
        let tmp = [0u8; MAX_OUTPUT_LENGTH];
        let salt = salt.unwrap_or(&tmp[..H::OUTPUT_LENGTH]);
        let kc = HmacKey::new(salt);
        Hkdf {
            hmac_ctx: Hmac::new(&kc),
        }
    }

    /// `br_hkdf_inject`: more input key material.
    pub fn inject(&mut self, ikm: &[u8]) {
        self.hmac_ctx.update(ikm);
    }

    /// `br_hkdf_flip`: the end of the input key material, and the
    /// pseudorandom key that the output is expanded from.
    pub fn flip(self) -> HkdfExpand<H> {
        let mut tmp = self.hmac_ctx.out();
        let prk_ctx = HmacKey::new(tmp.as_ref());
        clear(tmp.as_mut());
        HkdfExpand {
            prk_ctx,
            buf: [0; MAX_OUTPUT_LENGTH],
            ptr: H::OUTPUT_LENGTH,
            chunk_num: 0,
        }
    }
}

/// HKDF's expand step: `br_hkdf_context` after `br_hkdf_flip`.
///
/// It is overwritten when it is dropped (best effort).
#[derive(Clone)]
pub struct HkdfExpand<H: Digest> {
    prk_ctx: HmacKey<H>,
    buf: [u8; MAX_OUTPUT_LENGTH],
    ptr: usize,
    chunk_num: u32,
}

impl<H: Digest> HkdfExpand<H> {
    /// `br_hkdf_produce`: the next bytes of output, with `info`. Returns how
    /// many were written to `out`: all of them, unless the output reached
    /// 255 times the hash's length, the most RFC 5869 allows.
    ///
    /// The output can be taken in pieces. As in BearSSL, each block of the
    /// hash's length is computed with the `info` given when it is reached,
    /// so every call should give the same.
    pub fn produce(&mut self, info: &[u8], out: &mut [u8]) -> usize {
        let dig_len = H::OUTPUT_LENGTH;
        let mut tlen = 0;
        while tlen < out.len() {
            if self.ptr == dig_len {
                self.chunk_num += 1;
                if self.chunk_num == 256 {
                    // Differs from BearSSL: later calls stop here too.
                    // BearSSL's counter goes on to 257 at the next call,
                    // whose block number byte is 1 again.
                    self.chunk_num = 255;
                    return tlen;
                }
                let x = self.chunk_num as u8;
                let mut hmac_ctx = Hmac::new(&self.prk_ctx);
                if x != 1 {
                    hmac_ctx.update(&self.buf[..dig_len]);
                }
                hmac_ctx.update(info);
                hmac_ctx.update(&[x]);
                let mut block = hmac_ctx.out();
                self.buf[..dig_len].copy_from_slice(block.as_ref());
                clear(block.as_mut());
                self.ptr = 0;
            }
            let clen = (dig_len - self.ptr).min(out.len() - tlen);
            out[tlen..tlen + clen].copy_from_slice(&self.buf[self.ptr..self.ptr + clen]);
            self.ptr += clen;
            tlen += clen;
        }
        tlen
    }
}

impl<H: Digest> Drop for HkdfExpand<H> {
    fn drop(&mut self) {
        clear(&mut self.buf);
    }
}

/// Shows nothing of the key or the output.
impl<H: Digest> std::fmt::Debug for HkdfExpand<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HkdfExpand")
            .field("chunk_num", &self.chunk_num)
            .finish_non_exhaustive()
    }
}
