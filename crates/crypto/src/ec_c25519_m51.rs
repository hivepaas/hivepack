//! X25519 (RFC 7748) for 64-bit machines, with five 51-bit words and 128-bit
//! products. The Montgomery ladder runs in constant time, and the same steps
//! as in `ec_c25519_m31.rs`, which 32-bit machines use.
//!
//! Not a port of BearSSL: the field is the usual radix 2^51 one for this curve.
//!
//! The bounds: `mul`, `square` and `mul_a24` return words below 2^51 + 2^19.
//! `add` of two such gives words below 2^53, and `sub` below 2^54 + 2^52,
//! with no carry. Products of those, with the factors of 19 and 2, stay below
//! 2^116 in a column.

use crate::clear::clear;
use crate::ec_c25519_m31::X25519_LENGTH;

const MASK: u64 = (1 << 51) - 1;

/// An element of the field: the sum of `f[i]` × 2^(51 i).
type Fe = [u64; 5];

fn mul64(x: u64, y: u64) -> u128 {
    u128::from(x) * u128::from(y)
}

/// Little-endian bytes into words. The top bit of `s` is expected to be clear.
fn load(s: &[u8; X25519_LENGTH]) -> Fe {
    let word = |at: usize| {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&s[at..at + 8]);
        u64::from_le_bytes(bytes)
    };
    [
        word(0) & MASK,
        (word(6) >> 3) & MASK,
        (word(12) >> 6) & MASK,
        (word(19) >> 1) & MASK,
        (word(24) >> 12) & MASK,
    ]
}

/// The value below the modulus, as little-endian bytes. `f` comes from
/// [`carry`], so it is below twice the modulus.
fn store(f: &Fe) -> [u8; X25519_LENGTH] {
    // One if the value is at least the modulus: if adding 19 reaches 2^255.
    let mut q = (f[0] + 19) >> 51;
    for &word in &f[1..] {
        q = (word + q) >> 51;
    }
    let mut h = *f;
    h[0] += 19 * q;
    for i in 0..4 {
        h[i + 1] += h[i] >> 51;
        h[i] &= MASK;
    }
    h[4] &= MASK;

    let mut s = [0; X25519_LENGTH];
    let mut acc = 0u128;
    let mut acc_len = 0;
    let mut words = h.iter();
    for byte in &mut s {
        if acc_len < 8
            && let Some(&word) = words.next()
        {
            acc |= u128::from(word) << acc_len;
            acc_len += 51;
        }
        *byte = acc as u8;
        acc >>= 8;
        acc_len -= 8;
    }
    s
}

/// Five columns into words below 2^51 + 2^19.
fn carry(mut t: [u128; 5]) -> Fe {
    for i in 0..4 {
        t[i + 1] += t[i] >> 51;
        t[i] &= u128::from(MASK);
    }
    t[0] += (t[4] >> 51) * 19;
    t[4] &= u128::from(MASK);
    t[1] += t[0] >> 51;
    t[0] &= u128::from(MASK);
    t.map(|column| column as u64)
}

fn mul(a: &Fe, b: &Fe) -> Fe {
    let [a0, a1, a2, a3, a4] = *a;
    let [b0, b1, b2, b3, b4] = *b;
    let (b1_19, b2_19, b3_19, b4_19) = (b1 * 19, b2 * 19, b3 * 19, b4 * 19);
    carry([
        mul64(a0, b0) + mul64(a1, b4_19) + mul64(a2, b3_19) + mul64(a3, b2_19) + mul64(a4, b1_19),
        mul64(a0, b1) + mul64(a1, b0) + mul64(a2, b4_19) + mul64(a3, b3_19) + mul64(a4, b2_19),
        mul64(a0, b2) + mul64(a1, b1) + mul64(a2, b0) + mul64(a3, b4_19) + mul64(a4, b3_19),
        mul64(a0, b3) + mul64(a1, b2) + mul64(a2, b1) + mul64(a3, b0) + mul64(a4, b4_19),
        mul64(a0, b4) + mul64(a1, b3) + mul64(a2, b2) + mul64(a3, b1) + mul64(a4, b0),
    ])
}

fn square(a: &Fe) -> Fe {
    let [a0, a1, a2, a3, a4] = *a;
    let (d0, d1, d2) = (a0 * 2, a1 * 2, a2 * 2);
    let (a3_19, a4_19) = (a3 * 19, a4 * 19);
    carry([
        mul64(a0, a0) + mul64(d1, a4_19) + mul64(d2, a3_19),
        mul64(d0, a1) + mul64(d2, a4_19) + mul64(a3, a3_19),
        mul64(d0, a2) + mul64(a1, a1) + mul64(a3 * 2, a4_19),
        mul64(d0, a3) + mul64(d1, a2) + mul64(a4, a4_19),
        mul64(d0, a4) + mul64(d1, a3) + mul64(a2, a2),
    ])
}

fn square_times(a: &Fe, times: usize) -> Fe {
    let mut r = *a;
    for _ in 0..times {
        r = square(&r);
    }
    r
}

fn add(a: &Fe, b: &Fe) -> Fe {
    std::array::from_fn(|i| a[i] + b[i])
}

/// `a` - `b` + 8p, whose words are all positive, as those of `b` are below
/// those of 8p.
fn sub(a: &Fe, b: &Fe) -> Fe {
    const P8_0: u64 = (1 << 54) - 152;
    const P8_N: u64 = (1 << 54) - 8;
    [
        a[0] + P8_0 - b[0],
        a[1] + P8_N - b[1],
        a[2] + P8_N - b[2],
        a[3] + P8_N - b[3],
        a[4] + P8_N - b[4],
    ]
}

/// `a` × 121665 (the curve's `A24`).
fn mul_a24(a: &Fe) -> Fe {
    carry(a.map(|word| mul64(word, 121_665)))
}

/// `cswap`: swaps `a` and `b` if `ctl` is 1, in the same time either way.
fn cswap(a: &mut Fe, b: &mut Fe, ctl: u64) {
    let ctl = ctl.wrapping_neg();
    for (aw, bw) in a.iter_mut().zip(b.iter_mut()) {
        let tw = ctl & (*aw ^ *bw);
        *aw ^= tw;
        *bw ^= tw;
    }
}

/// `z` raised to p - 2 = 2^255 - 21: its inverse.
fn invert(z: &Fe) -> Fe {
    let z2 = square(z);
    let z9 = mul(&square_times(&z2, 2), z);
    let z11 = mul(&z9, &z2);
    let z_5_0 = mul(&square(&z11), &z9);
    let z_10_0 = mul(&square_times(&z_5_0, 5), &z_5_0);
    let z_20_0 = mul(&square_times(&z_10_0, 10), &z_10_0);
    let z_40_0 = mul(&square_times(&z_20_0, 20), &z_20_0);
    let z_50_0 = mul(&square_times(&z_40_0, 10), &z_10_0);
    let z_100_0 = mul(&square_times(&z_50_0, 50), &z_50_0);
    let z_200_0 = mul(&square_times(&z_100_0, 100), &z_100_0);
    let z_250_0 = mul(&square_times(&z_200_0, 50), &z_50_0);
    mul(&square_times(&z_250_0, 5), &z11)
}

/// X25519 of the scalar `kb` and the u-coordinate `g`, as RFC 7748 defines
/// it: the scalar is clamped, and the top bit of the coordinate ignored.
///
/// It does not look at the result: a point of small order gives all zeros,
/// which callers that need a shared secret refuse (RFC 7748, section 6.1).
pub fn x25519(kb: &[u8; X25519_LENGTH], g: &[u8; X25519_LENGTH]) -> [u8; X25519_LENGTH] {
    let mut g = *g;
    g[31] &= 0x7F;

    let x1 = load(&g);
    let mut x2 = [1, 0, 0, 0, 0];
    let mut z2 = [0; 5];
    let mut x3 = x1;
    let mut z3 = [1, 0, 0, 0, 0];

    let mut k = *kb;
    k[0] &= 0xF8;
    k[31] &= 0x7F;
    k[31] |= 0x40;

    let mut swap = 0;
    for i in (0..=254).rev() {
        let kt = u64::from(k[i >> 3] >> (i & 7)) & 1;
        swap ^= kt;
        cswap(&mut x2, &mut x3, swap);
        cswap(&mut z2, &mut z3, swap);
        swap = kt;

        let a = add(&x2, &z2);
        let aa = square(&a);
        let b = sub(&x2, &z2);
        let bb = square(&b);
        let e = sub(&aa, &bb);
        let c = add(&x3, &z3);
        let d = sub(&x3, &z3);
        let da = mul(&d, &a);
        let cb = mul(&c, &b);

        x3 = square(&add(&da, &cb));
        z3 = mul(&square(&sub(&da, &cb)), &x1);
        x2 = mul(&aa, &bb);
        z2 = mul(&e, &add(&mul_a24(&e), &aa));
    }
    cswap(&mut x2, &mut x3, swap);
    cswap(&mut z2, &mut z3, swap);

    let out = store(&mul(&x2, &invert(&z2)));
    clear(&mut k);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec_c25519_m31;

    /// xorshift64*, enough to walk over scalars and points.
    fn fill(state: &mut u64, out: &mut [u8; 32]) {
        for chunk in out.chunks_mut(8) {
            *state ^= *state >> 12;
            *state ^= *state << 25;
            *state ^= *state >> 27;
            let word = state.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes();
            chunk.copy_from_slice(&word);
        }
    }

    #[test]
    fn same_as_the_31_bit_field() {
        let mut state = 0x0123_4567_89AB_CDEF;
        let (mut k, mut u) = ([0; 32], [0; 32]);
        for _ in 0..2000 {
            fill(&mut state, &mut k);
            fill(&mut state, &mut u);
            assert_eq!(x25519(&k, &u), ec_c25519_m31::x25519(&k, &u));
        }
    }

    /// Coordinates at the edges: small ones, those around the modulus and
    /// 2^255, and those of the points of small order.
    #[test]
    fn same_as_the_31_bit_field_at_the_edges() {
        let mut p = [0xFF; 32];
        p[31] = 0x7F;
        let mut points = Vec::new();
        for low in [0xED, 0xEC, 0xEE, 0xEF, 0xFF, 0xDA, 0xDB] {
            let mut u = p;
            u[0] = low;
            points.push(u);
            u[31] = 0xFF;
            points.push(u);
        }
        for low in [0, 1, 2, 9] {
            let mut u = [0; 32];
            u[0] = low;
            points.push(u);
        }
        // The two points of order 8 that RFC 7748 implementations meet.
        points.push([
            0xE0, 0xEB, 0x7A, 0x7C, 0x3B, 0x41, 0xB8, 0xAE, 0x16, 0x56, 0xE3, 0xFA, 0xF1, 0x9F,
            0xC4, 0x6A, 0xDA, 0x09, 0x8D, 0xEB, 0x9C, 0x32, 0xB1, 0xFD, 0x86, 0x62, 0x05, 0x16,
            0x5F, 0x49, 0xB8, 0x00,
        ]);
        points.push([
            0x5F, 0x9C, 0x95, 0xBC, 0xA3, 0x50, 0x8C, 0x24, 0xB1, 0xD0, 0xB1, 0x55, 0x9C, 0x83,
            0xEF, 0x5B, 0x04, 0x44, 0x5C, 0xC4, 0x58, 0x1C, 0x8E, 0x86, 0xD8, 0x22, 0x4E, 0xDD,
            0xD0, 0x9F, 0x11, 0x57,
        ]);
        let mut state = 0xFEED_FACE_CAFE_BEEF;
        let mut k = [0; 32];
        for u in &points {
            for _ in 0..4 {
                fill(&mut state, &mut k);
                assert_eq!(x25519(&k, u), ec_c25519_m31::x25519(&k, u), "{u:02x?}");
            }
            for k in [[0; 32], [0xFF; 32]] {
                assert_eq!(x25519(&k, u), ec_c25519_m31::x25519(&k, u), "{u:02x?}");
            }
        }
    }

    /// Words at the bounds the top comment gives, through every operation,
    /// with `overflow-checks` on in the test profile.
    #[test]
    fn the_bounds_hold() {
        let top = (1 << 51) + (1 << 19) - 1;
        let big = [top; 5];
        let sum = add(&big, &big);
        let difference = sub(&big, &[0; 5]);
        for a in [&big, &sum, &difference] {
            assert!(square(a).iter().all(|&word| word < top + 1));
            assert!(mul_a24(a).iter().all(|&word| word < top + 1));
            for b in [&big, &sum, &difference] {
                assert!(mul(a, b).iter().all(|&word| word < top + 1));
            }
        }
    }
}
