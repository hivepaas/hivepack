//! MD5: port of `md5.c`.
//!
//! MD5 is broken for signatures and certificates, where collisions matter;
//! it is here because archives check their data with it (XAR's TOC and
//! files, as libarchive reads them).

use crate::clear::clear;
use crate::digest::Digest;

/// The length of an MD5 digest, in bytes.
pub const MD5_LENGTH: usize = 16;

/// The length of a block of MD5's input, in bytes.
const BLOCK_LENGTH: usize = 64;

fn f(b: u32, c: u32, d: u32) -> u32 {
    ((c ^ d) & b) ^ d
}

fn g(b: u32, c: u32, d: u32) -> u32 {
    ((c ^ b) & d) ^ c
}

fn h(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

fn i(b: u32, c: u32, d: u32) -> u32 {
    c ^ (b | !d)
}

/// `br_md5_IV`.
const IV: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];

/// `K`: the sines of RFC 1321, one per step.
const K: [u32; 64] = [
    0xD76A_A478,
    0xE8C7_B756,
    0x2420_70DB,
    0xC1BD_CEEE,
    0xF57C_0FAF,
    0x4787_C62A,
    0xA830_4613,
    0xFD46_9501,
    0x6980_98D8,
    0x8B44_F7AF,
    0xFFFF_5BB1,
    0x895C_D7BE,
    0x6B90_1122,
    0xFD98_7193,
    0xA679_438E,
    0x49B4_0821,
    0xF61E_2562,
    0xC040_B340,
    0x265E_5A51,
    0xE9B6_C7AA,
    0xD62F_105D,
    0x0244_1453,
    0xD8A1_E681,
    0xE7D3_FBC8,
    0x21E1_CDE6,
    0xC337_07D6,
    0xF4D5_0D87,
    0x455A_14ED,
    0xA9E3_E905,
    0xFCEF_A3F8,
    0x676F_02D9,
    0x8D2A_4C8A,
    0xFFFA_3942,
    0x8771_F681,
    0x6D9D_6122,
    0xFDE5_380C,
    0xA4BE_EA44,
    0x4BDE_CFA9,
    0xF6BB_4B60,
    0xBEBF_BC70,
    0x289B_7EC6,
    0xEAA1_27FA,
    0xD4EF_3085,
    0x0488_1D05,
    0xD9D4_D039,
    0xE6DB_99E5,
    0x1FA2_7CF8,
    0xC4AC_5665,
    0xF429_2244,
    0x432A_FF97,
    0xAB94_23A7,
    0xFC93_A039,
    0x655B_59C3,
    0x8F0C_CC92,
    0xFFEF_F47D,
    0x8584_5DD1,
    0x6FA8_7E4F,
    0xFE2C_E6E0,
    0xA301_4314,
    0x4E08_11A1,
    0xF753_7E82,
    0xBD3A_F235,
    0x2AD7_D2BB,
    0xEB86_D391,
];

/// `MP`: which word of the block each step of rounds 2 to 4 takes.
const MP: [usize; 48] = [
    1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6,
    9, 12, 15, 2, 0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9,
];

/// `br_md5_round`: one block into the state.
fn round(buf: &[u8; BLOCK_LENGTH], val: &mut [u32; 4]) {
    let mut m = [0u32; 16];
    let [mut a, mut b, mut c, mut d] = *val;
    for (word, bytes) in m.iter_mut().zip(buf.as_chunks().0) {
        *word = u32::from_le_bytes(*bytes);
    }

    // Four steps at a time, with the roles of the variables rotating, as
    // BearSSL writes them.
    macro_rules! steps {
        ($func:ident, $k:expr, $w:expr, $s:expr) => {
            a = b.wrapping_add(
                a.wrapping_add($func(b, c, d))
                    .wrapping_add($w[0])
                    .wrapping_add($k[0])
                    .rotate_left($s[0]),
            );
            d = a.wrapping_add(
                d.wrapping_add($func(a, b, c))
                    .wrapping_add($w[1])
                    .wrapping_add($k[1])
                    .rotate_left($s[1]),
            );
            c = d.wrapping_add(
                c.wrapping_add($func(d, a, b))
                    .wrapping_add($w[2])
                    .wrapping_add($k[2])
                    .rotate_left($s[2]),
            );
            b = c.wrapping_add(
                b.wrapping_add($func(c, d, a))
                    .wrapping_add($w[3])
                    .wrapping_add($k[3])
                    .rotate_left($s[3]),
            );
        };
    }
    for j in (0..16).step_by(4) {
        let w = [m[j], m[j + 1], m[j + 2], m[j + 3]];
        steps!(f, K[j..], w, [7, 12, 17, 22]);
    }
    for j in (16..32).step_by(4) {
        let w = [m[MP[j - 16]], m[MP[j - 15]], m[MP[j - 14]], m[MP[j - 13]]];
        steps!(g, K[j..], w, [5, 9, 14, 20]);
    }
    for j in (32..48).step_by(4) {
        let w = [m[MP[j - 16]], m[MP[j - 15]], m[MP[j - 14]], m[MP[j - 13]]];
        steps!(h, K[j..], w, [4, 11, 16, 23]);
    }
    for j in (48..64).step_by(4) {
        let w = [m[MP[j - 16]], m[MP[j - 15]], m[MP[j - 14]], m[MP[j - 13]]];
        steps!(i, K[j..], w, [6, 10, 15, 21]);
    }

    val[0] = val[0].wrapping_add(a);
    val[1] = val[1].wrapping_add(b);
    val[2] = val[2].wrapping_add(c);
    val[3] = val[3].wrapping_add(d);
}

/// An MD5 computation: `br_md5_context`.
///
/// What it has hashed is overwritten when it is dropped (best effort).
#[derive(Clone)]
pub struct Md5 {
    buf: [u8; BLOCK_LENGTH],
    count: u64,
    val: [u32; 4],
}

impl Md5 {
    /// `br_md5_init`.
    pub fn new() -> Md5 {
        Md5 {
            buf: [0; BLOCK_LENGTH],
            count: 0,
            val: IV,
        }
    }

    /// `br_md5_update`: more data.
    pub fn update(&mut self, mut data: &[u8]) {
        let mut ptr = (self.count & 63) as usize;
        while !data.is_empty() {
            let clen = (BLOCK_LENGTH - ptr).min(data.len());
            self.buf[ptr..ptr + clen].copy_from_slice(&data[..clen]);
            ptr += clen;
            data = &data[clen..];
            self.count = self.count.wrapping_add(clen as u64);
            if ptr == BLOCK_LENGTH {
                round(&self.buf, &mut self.val);
                ptr = 0;
            }
        }
    }

    /// `br_md5_out`: the digest of the data so far. The computation can go
    /// on with more data.
    pub fn out(&self) -> [u8; MD5_LENGTH] {
        let mut buf = [0u8; BLOCK_LENGTH];
        let mut val = self.val;
        let mut ptr = (self.count & 63) as usize;
        buf[..ptr].copy_from_slice(&self.buf[..ptr]);
        buf[ptr] = 0x80;
        ptr += 1;
        if ptr > 56 {
            round(&buf, &mut val);
            buf[..56].fill(0);
        }
        buf[56..].copy_from_slice(&(self.count << 3).to_le_bytes());
        round(&buf, &mut val);
        let mut dst = [0u8; MD5_LENGTH];
        for (bytes, word) in dst.as_chunks_mut().0.iter_mut().zip(val) {
            *bytes = word.to_le_bytes();
        }
        clear(&mut buf);
        clear(&mut val);
        dst
    }
}

impl Digest for Md5 {
    type Output = [u8; MD5_LENGTH];
    const OUTPUT_LENGTH: usize = MD5_LENGTH;
    const BLOCK_LENGTH: usize = BLOCK_LENGTH;

    fn new() -> Md5 {
        Md5::new()
    }

    fn update(&mut self, data: &[u8]) {
        self.update(data);
    }

    fn out(&self) -> [u8; MD5_LENGTH] {
        self.out()
    }

    /// `br_md5_state`.
    fn state(&self) -> ([u8; MD5_LENGTH], u64) {
        let mut dst = [0u8; MD5_LENGTH];
        for (bytes, word) in dst.as_chunks_mut().0.iter_mut().zip(self.val) {
            *bytes = word.to_le_bytes();
        }
        (dst, self.count)
    }

    /// `br_md5_set_state`.
    fn set_state(&mut self, stb: &[u8; MD5_LENGTH], count: u64) {
        for (word, bytes) in self.val.iter_mut().zip(stb.as_chunks().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        self.count = count;
    }
}

impl Default for Md5 {
    fn default() -> Md5 {
        Md5::new()
    }
}

impl Drop for Md5 {
    fn drop(&mut self) {
        clear(&mut self.buf);
        clear(&mut self.val);
    }
}

/// Shows how much was hashed, not the data or the state.
impl std::fmt::Debug for Md5 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Md5")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}
