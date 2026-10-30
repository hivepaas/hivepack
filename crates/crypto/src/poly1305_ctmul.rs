//! ChaCha20-Poly1305 (RFC 8439, section 2.8): port of `poly1305_ctmul.c`,
//! BearSSL's Poly1305 with 32-bit operands and 64-bit products, in the AEAD
//! construction with ChaCha20.
//!
//! Differs from BearSSL: the ChaCha20 is always [`chacha20`], where BearSSL
//! takes it as a function pointer (`ichacha`).

use crate::chacha20_ct::{CHACHA20_KEY_LENGTH, CHACHA20_NONCE_LENGTH, chacha20};
use crate::clear::clear;
use crate::ct::{eq, gt, mux};

/// The length of a Poly1305 tag, in bytes.
pub const POLY1305_TAG_LENGTH: usize = 16;

fn dec32le<const N: usize>(buf: &[u8; N], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

/// `poly1305_inner`: the blocks of `data` into the accumulator `acc`, a
/// partial block padded with zeros. The accumulator and `r` are in 26-bit
/// words, which may have an extra bit.
fn poly1305_inner(acc: &mut [u32; 5], r: &[u32; 5], data: &[u8]) {
    let [r0, r1, r2, r3, r4] = *r;
    let u1 = r1 * 5;
    let u2 = r2 * 5;
    let u3 = r3 * 5;
    let u4 = r4 * 5;
    let [mut a0, mut a1, mut a2, mut a3, mut a4] = *acc;

    // Whole blocks as they are; a partial block padded with zeros.
    let (blocks, rest) = data.as_chunks::<16>();
    let mut last = [0u8; 16];
    last[..rest.len()].copy_from_slice(rest);
    let last = (!rest.is_empty()).then_some(&last);
    for buf in blocks.iter().chain(last) {
        a0 += dec32le(buf, 0) & 0x03FF_FFFF;
        a1 += (dec32le(buf, 3) >> 2) & 0x03FF_FFFF;
        a2 += (dec32le(buf, 6) >> 4) & 0x03FF_FFFF;
        a3 += (dec32le(buf, 9) >> 6) & 0x03FF_FFFF;
        a4 += (dec32le(buf, 12) >> 8) | 0x0100_0000;

        let m = |x: u32, y: u32| u64::from(x) * u64::from(y);
        let w0 = m(a0, r0) + m(a1, u4) + m(a2, u3) + m(a3, u2) + m(a4, u1);
        let mut w1 = m(a0, r1) + m(a1, r0) + m(a2, u4) + m(a3, u3) + m(a4, u2);
        let mut w2 = m(a0, r2) + m(a1, r1) + m(a2, r0) + m(a3, u4) + m(a4, u3);
        let mut w3 = m(a0, r3) + m(a1, r2) + m(a2, r1) + m(a3, r0) + m(a4, u4);
        let mut w4 = m(a0, r4) + m(a1, r3) + m(a2, r2) + m(a3, r1) + m(a4, r0);

        // Partial reduction: enough to keep the values from overflowing.
        let mut c = w0 >> 26;
        a0 = w0 as u32 & 0x03FF_FFFF;
        w1 += c;
        c = w1 >> 26;
        a1 = w1 as u32 & 0x03FF_FFFF;
        w2 += c;
        c = w2 >> 26;
        a2 = w2 as u32 & 0x03FF_FFFF;
        w3 += c;
        c = w3 >> 26;
        a3 = w3 as u32 & 0x03FF_FFFF;
        w4 += c;
        c = w4 >> 26;
        a4 = w4 as u32 & 0x03FF_FFFF;
        a0 += c as u32 * 5;
        a1 += a0 >> 26;
        a0 &= 0x03FF_FFFF;
    }

    *acc = [a0, a1, a2, a3, a4];
}

/// `br_poly1305_ctmul_run`: ChaCha20-Poly1305 with `key` and the nonce
/// `iv`. Encrypts `data` in place when `encrypt` is true, and decrypts it
/// otherwise; either way, returns the tag of `aad` and the encrypted data.
///
/// After decrypting, the caller compares the tag with the one it was given,
/// with [`equal`](crate::equal), and throws the data away if they differ.
pub fn chacha20_poly1305(
    key: &[u8; CHACHA20_KEY_LENGTH],
    iv: &[u8; CHACHA20_NONCE_LENGTH],
    data: &mut [u8],
    aad: &[u8],
    encrypt: bool,
) -> [u8; POLY1305_TAG_LENGTH] {
    // The MAC key: `r` is its first 16 bytes, `s` the last 16.
    let mut pkey = [0u8; 32];
    chacha20(key, iv, 0, &mut pkey);

    // Encrypting, ChaCha20 runs first; decrypting, Poly1305 does.
    if encrypt {
        chacha20(key, iv, 1, data);
    }

    // `r`, in 26-bit words, clamped.
    let mut r = [
        dec32le(&pkey, 0) & 0x03FF_FFFF,
        (dec32le(&pkey, 3) >> 2) & 0x03FF_FF03,
        (dec32le(&pkey, 6) >> 4) & 0x03FF_C0FF,
        (dec32le(&pkey, 9) >> 6) & 0x03F0_3FFF,
        (dec32le(&pkey, 12) >> 8) & 0x000F_FFFF,
    ];

    let mut acc = [0u32; 5];
    let mut foot = [0u8; 16];
    foot[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    foot[8..].copy_from_slice(&(data.len() as u64).to_le_bytes());
    poly1305_inner(&mut acc, &r, aad);
    poly1305_inner(&mut acc, &r, data);
    poly1305_inner(&mut acc, &r, &foot);

    // The last of the reduction: carries, with 2^130 = 5 mod p. Only
    // acc[1] can be above 2^26, so one loop back to it is enough.
    let mut cc = 0;
    for i in 1..=6 {
        let j = if i >= 5 { i - 5 } else { i };
        acc[j] += cc;
        cc = acc[j] >> 26;
        acc[j] &= 0x03FF_FFFF;
    }

    // A value from 2^130 - 5 to 2^130 - 1 is reduced again, chosen in
    // constant time.
    let mut ctl = gt(acc[0], 0x03FF_FFFA);
    for &a in &acc[1..] {
        ctl &= eq(a, 0x03FF_FFFF);
    }
    cc = 5;
    for a in &mut acc {
        let mut t = *a + cc;
        cc = t >> 26;
        t &= 0x03FF_FFFF;
        *a = mux(ctl, t, *a);
    }

    // Back to 32-bit words, plus `s`, modulo 2^128.
    let mut tag = [0u8; POLY1305_TAG_LENGTH];
    let mut w = u64::from(acc[0]) + (u64::from(acc[1]) << 26) + u64::from(dec32le(&pkey, 16));
    tag[0..4].copy_from_slice(&(w as u32).to_le_bytes());
    w = (w >> 32) + (u64::from(acc[2]) << 20) + u64::from(dec32le(&pkey, 20));
    tag[4..8].copy_from_slice(&(w as u32).to_le_bytes());
    w = (w >> 32) + (u64::from(acc[3]) << 14) + u64::from(dec32le(&pkey, 24));
    tag[8..12].copy_from_slice(&(w as u32).to_le_bytes());
    let hi = ((w >> 32) as u32)
        .wrapping_add(acc[4] << 8)
        .wrapping_add(dec32le(&pkey, 28));
    tag[12..16].copy_from_slice(&hi.to_le_bytes());

    if !encrypt {
        chacha20(key, iv, 1, data);
    }
    clear(&mut pkey);
    clear(&mut r);
    tag
}
