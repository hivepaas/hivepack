//! SHA-512: port of `sha2big.c`.
//!
//! Differs from BearSSL: SHA-512 only, without SHA-384, which nothing here
//! uses.

use crate::clear::clear;
use crate::digest::Digest;

/// The length of a SHA-512 digest, in bytes.
pub const SHA512_LENGTH: usize = 64;

/// The length of a block of SHA-512's input, in bytes.
const BLOCK_LENGTH: usize = 128;

fn ch(x: u64, y: u64, z: u64) -> u64 {
    ((y ^ z) & x) ^ z
}

fn maj(x: u64, y: u64, z: u64) -> u64 {
    (y & z) | ((y | z) & x)
}

fn bsg5_0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

fn bsg5_1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

fn ssg5_0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

fn ssg5_1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

/// `IV512`.
const IV: [u64; 8] = [
    0x6A09_E667_F3BC_C908,
    0xBB67_AE85_84CA_A73B,
    0x3C6E_F372_FE94_F82B,
    0xA54F_F53A_5F1D_36F1,
    0x510E_527F_ADE6_82D1,
    0x9B05_688C_2B3E_6C1F,
    0x1F83_D9AB_FB41_BD6B,
    0x5BE0_CD19_137E_2179,
];

#[rustfmt::skip]
const K: [u64; 80] = [
    0x428A_2F98_D728_AE22, 0x7137_4491_23EF_65CD,
    0xB5C0_FBCF_EC4D_3B2F, 0xE9B5_DBA5_8189_DBBC,
    0x3956_C25B_F348_B538, 0x59F1_11F1_B605_D019,
    0x923F_82A4_AF19_4F9B, 0xAB1C_5ED5_DA6D_8118,
    0xD807_AA98_A303_0242, 0x1283_5B01_4570_6FBE,
    0x2431_85BE_4EE4_B28C, 0x550C_7DC3_D5FF_B4E2,
    0x72BE_5D74_F27B_896F, 0x80DE_B1FE_3B16_96B1,
    0x9BDC_06A7_25C7_1235, 0xC19B_F174_CF69_2694,
    0xE49B_69C1_9EF1_4AD2, 0xEFBE_4786_384F_25E3,
    0x0FC1_9DC6_8B8C_D5B5, 0x240C_A1CC_77AC_9C65,
    0x2DE9_2C6F_592B_0275, 0x4A74_84AA_6EA6_E483,
    0x5CB0_A9DC_BD41_FBD4, 0x76F9_88DA_8311_53B5,
    0x983E_5152_EE66_DFAB, 0xA831_C66D_2DB4_3210,
    0xB003_27C8_98FB_213F, 0xBF59_7FC7_BEEF_0EE4,
    0xC6E0_0BF3_3DA8_8FC2, 0xD5A7_9147_930A_A725,
    0x06CA_6351_E003_826F, 0x1429_2967_0A0E_6E70,
    0x27B7_0A85_46D2_2FFC, 0x2E1B_2138_5C26_C926,
    0x4D2C_6DFC_5AC4_2AED, 0x5338_0D13_9D95_B3DF,
    0x650A_7354_8BAF_63DE, 0x766A_0ABB_3C77_B2A8,
    0x81C2_C92E_47ED_AEE6, 0x9272_2C85_1482_353B,
    0xA2BF_E8A1_4CF1_0364, 0xA81A_664B_BC42_3001,
    0xC24B_8B70_D0F8_9791, 0xC76C_51A3_0654_BE30,
    0xD192_E819_D6EF_5218, 0xD699_0624_5565_A910,
    0xF40E_3585_5771_202A, 0x106A_A070_32BB_D1B8,
    0x19A4_C116_B8D2_D0C8, 0x1E37_6C08_5141_AB53,
    0x2748_774C_DF8E_EB99, 0x34B0_BCB5_E19B_48A8,
    0x391C_0CB3_C5C9_5A63, 0x4ED8_AA4A_E341_8ACB,
    0x5B9C_CA4F_7763_E373, 0x682E_6FF3_D6B2_B8A3,
    0x748F_82EE_5DEF_B2FC, 0x78A5_636F_4317_2F60,
    0x84C8_7814_A1F0_AB72, 0x8CC7_0208_1A64_39EC,
    0x90BE_FFFA_2363_1E28, 0xA450_6CEB_DE82_BDE9,
    0xBEF9_A3F7_B2C6_7915, 0xC671_78F2_E372_532B,
    0xCA27_3ECE_EA26_619C, 0xD186_B8C7_21C0_C207,
    0xEADA_7DD6_CDE0_EB1E, 0xF57D_4F7F_EE6E_D178,
    0x06F0_67AA_7217_6FBA, 0x0A63_7DC5_A2C8_98A6,
    0x113F_9804_BEF9_0DAE, 0x1B71_0B35_131C_471B,
    0x28DB_77F5_2304_7D84, 0x32CA_AB7B_40C7_2493,
    0x3C9E_BE0A_15C9_BEBC, 0x431D_67C4_9C10_0D4C,
    0x4CC5_D4BE_CB3E_42B6, 0x597F_299C_FC65_7E2A,
    0x5FCB_6FAB_3AD6_FAEC, 0x6C44_198C_4A47_5817,
];

/// `sha2big_round`: one block into the state.
fn round(buf: &[u8; BLOCK_LENGTH], val: &mut [u64; 8]) {
    let mut w = [0u64; 80];
    for (word, bytes) in w.iter_mut().zip(buf.as_chunks().0) {
        *word = u64::from_be_bytes(*bytes);
    }
    for i in 16..80 {
        w[i] = ssg5_1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(ssg5_0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *val;

    // `SHA2BIG_STEP`, with the roles of the variables rotating, as BearSSL
    // writes it.
    macro_rules! step {
        ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $j:expr) => {
            let t1 = $h
                .wrapping_add(bsg5_1($e))
                .wrapping_add(ch($e, $f, $g))
                .wrapping_add(K[$j])
                .wrapping_add(w[$j]);
            let t2 = bsg5_0($a).wrapping_add(maj($a, $b, $c));
            $d = $d.wrapping_add(t1);
            $h = t1.wrapping_add(t2);
        };
    }
    for i in (0..80).step_by(8) {
        step!(a, b, c, d, e, f, g, h, i);
        step!(h, a, b, c, d, e, f, g, i + 1);
        step!(g, h, a, b, c, d, e, f, i + 2);
        step!(f, g, h, a, b, c, d, e, i + 3);
        step!(e, f, g, h, a, b, c, d, i + 4);
        step!(d, e, f, g, h, a, b, c, i + 5);
        step!(c, d, e, f, g, h, a, b, i + 6);
        step!(b, c, d, e, f, g, h, a, i + 7);
    }
    for (v, x) in val.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *v = v.wrapping_add(x);
    }
}

/// A SHA-512 computation: `br_sha512_context`.
///
/// What it has hashed is overwritten when it is dropped (best effort).
#[derive(Clone)]
pub struct Sha512 {
    buf: [u8; BLOCK_LENGTH],
    count: u64,
    val: [u64; 8],
}

impl Sha512 {
    /// `br_sha512_init`.
    pub fn new() -> Sha512 {
        Sha512 {
            buf: [0; BLOCK_LENGTH],
            count: 0,
            val: IV,
        }
    }

    /// `br_sha512_update` (`sha2big_update`): more data.
    pub fn update(&mut self, mut data: &[u8]) {
        let mut ptr = (self.count & 127) as usize;
        self.count = self.count.wrapping_add(data.len() as u64);
        while !data.is_empty() {
            let clen = (BLOCK_LENGTH - ptr).min(data.len());
            self.buf[ptr..ptr + clen].copy_from_slice(&data[..clen]);
            ptr += clen;
            data = &data[clen..];
            if ptr == BLOCK_LENGTH {
                round(&self.buf, &mut self.val);
                ptr = 0;
            }
        }
    }

    /// `br_sha512_out` (`sha2big_out`): the digest of the data so far.
    /// The computation can go on with more data.
    pub fn out(&self) -> [u8; SHA512_LENGTH] {
        let mut buf = [0u8; BLOCK_LENGTH];
        let mut val = self.val;
        let mut ptr = (self.count & 127) as usize;
        buf[..ptr].copy_from_slice(&self.buf[..ptr]);
        buf[ptr] = 0x80;
        ptr += 1;
        if ptr > 112 {
            round(&buf, &mut val);
            buf[..112].fill(0);
        }
        buf[112..120].copy_from_slice(&(self.count >> 61).to_be_bytes());
        buf[120..].copy_from_slice(&(self.count << 3).to_be_bytes());
        round(&buf, &mut val);
        let mut dst = [0u8; SHA512_LENGTH];
        for (bytes, word) in dst.as_chunks_mut().0.iter_mut().zip(val) {
            *bytes = word.to_be_bytes();
        }
        clear(&mut buf);
        clear(&mut val);
        dst
    }
}

impl Digest for Sha512 {
    type Output = [u8; SHA512_LENGTH];
    const OUTPUT_LENGTH: usize = SHA512_LENGTH;
    const BLOCK_LENGTH: usize = BLOCK_LENGTH;

    fn new() -> Sha512 {
        Sha512::new()
    }

    fn update(&mut self, data: &[u8]) {
        self.update(data);
    }

    fn out(&self) -> [u8; SHA512_LENGTH] {
        self.out()
    }

    /// `br_sha384_state`, which SHA-512 shares.
    fn state(&self) -> ([u8; SHA512_LENGTH], u64) {
        let mut dst = [0u8; SHA512_LENGTH];
        for (bytes, word) in dst.as_chunks_mut().0.iter_mut().zip(self.val) {
            *bytes = word.to_be_bytes();
        }
        (dst, self.count)
    }

    /// `br_sha384_set_state`, which SHA-512 shares.
    fn set_state(&mut self, stb: &[u8; SHA512_LENGTH], count: u64) {
        for (word, bytes) in self.val.iter_mut().zip(stb.as_chunks().0) {
            *word = u64::from_be_bytes(*bytes);
        }
        self.count = count;
    }
}

impl Default for Sha512 {
    fn default() -> Sha512 {
        Sha512::new()
    }
}

impl Drop for Sha512 {
    fn drop(&mut self) {
        clear(&mut self.buf);
        clear(&mut self.val);
    }
}

/// Shows how much was hashed, not the data or the state.
impl std::fmt::Debug for Sha512 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha512")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}
