//! BLAKE2s (RFC 7693), ported from the BLAKE2 reference implementation's
//! `ref/blake2s-ref.c`, by Samuel Neves, under CC0 1.0 (or the OpenSSL or
//! Apache 2.0 licenses), at commit ed1974ea of github.com/BLAKE2/BLAKE2.
//! RAR 5 hashes files with BLAKE2sp, which is built of it (`blake2sp`).

use crate::clear::clear;

/// The length of a BLAKE2s digest, in bytes.
pub const BLAKE2S_LENGTH: usize = 32;
/// The largest BLAKE2s key, in bytes.
pub const BLAKE2S_KEY_LENGTH: usize = 32;
pub(crate) const BLOCK_LENGTH: usize = 64;

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// The parameter block's fields that BLAKE2s and BLAKE2sp set
/// (`blake2s_param`); the salt and personalization are zero.
#[derive(Clone, Copy)]
pub(crate) struct Params {
    pub digest_length: u8,
    pub key_length: u8,
    pub fanout: u8,
    pub depth: u8,
    pub node_offset: u32,
    pub node_depth: u8,
    pub inner_length: u8,
}

impl Params {
    /// The parameter block, 32 bytes, as eight little-endian words.
    fn words(&self) -> [u32; 8] {
        let mut block = [0u8; 32];
        block[0] = self.digest_length;
        block[1] = self.key_length;
        block[2] = self.fanout;
        block[3] = self.depth;
        // leaf_length (4..8) and xof_length (12..14) are zero.
        block[8..12].copy_from_slice(&self.node_offset.to_le_bytes());
        block[14] = self.node_depth;
        block[15] = self.inner_length;
        let mut words = [0u32; 8];
        for (word, bytes) in words.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        words
    }
}

/// `blake2s_state`.
#[derive(Clone)]
pub(crate) struct State {
    h: [u32; 8],
    t: [u32; 2],
    f: [u32; 2],
    buf: [u8; BLOCK_LENGTH],
    buflen: usize,
    pub(crate) outlen: usize,
    pub(crate) last_node: bool,
}

impl State {
    /// `blake2s_init_param`: the IV xored with the parameter block.
    pub(crate) fn with_params(params: &Params) -> State {
        let mut h = IV;
        for (h, p) in h.iter_mut().zip(params.words()) {
            *h ^= p;
        }
        State {
            h,
            t: [0; 2],
            f: [0; 2],
            buf: [0; BLOCK_LENGTH],
            buflen: 0,
            outlen: usize::from(params.digest_length),
            last_node: false,
        }
    }

    fn increment_counter(&mut self, inc: u32) {
        self.t[0] = self.t[0].wrapping_add(inc);
        self.t[1] = self.t[1].wrapping_add(u32::from(self.t[0] < inc));
    }

    fn set_lastblock(&mut self) {
        if self.last_node {
            self.f[1] = u32::MAX;
        }
        self.f[0] = u32::MAX;
    }

    fn compress(&mut self, block: &[u8; BLOCK_LENGTH]) {
        let mut m = [0u32; 16];
        for (m, bytes) in m.iter_mut().zip(block.as_chunks::<4>().0) {
            *m = u32::from_le_bytes(*bytes);
        }
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..12].copy_from_slice(&IV[..4]);
        v[12] = self.t[0] ^ IV[4];
        v[13] = self.t[1] ^ IV[5];
        v[14] = self.f[0] ^ IV[6];
        v[15] = self.f[1] ^ IV[7];
        let g = |v: &mut [u32; 16],
                 s: &[usize; 16],
                 i: usize,
                 a: usize,
                 b: usize,
                 c: usize,
                 d: usize| {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[s[2 * i]]);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(12);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[s[2 * i + 1]]);
            v[d] = (v[d] ^ v[a]).rotate_right(8);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(7);
        };
        for s in &SIGMA {
            g(&mut v, s, 0, 0, 4, 8, 12);
            g(&mut v, s, 1, 1, 5, 9, 13);
            g(&mut v, s, 2, 2, 6, 10, 14);
            g(&mut v, s, 3, 3, 7, 11, 15);
            g(&mut v, s, 4, 0, 5, 10, 15);
            g(&mut v, s, 5, 1, 6, 11, 12);
            g(&mut v, s, 6, 2, 7, 8, 13);
            g(&mut v, s, 7, 3, 4, 9, 14);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
        clear(&mut m);
        clear(&mut v);
    }

    /// `blake2s_update`. The last block is kept back for `finish`, which
    /// marks it as last.
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let left = self.buflen;
        let fill = BLOCK_LENGTH - left;
        if data.len() > fill {
            self.buflen = 0;
            self.buf[left..].copy_from_slice(&data[..fill]);
            self.increment_counter(BLOCK_LENGTH as u32);
            let block = self.buf;
            self.compress(&block);
            data = &data[fill..];
            while data.len() > BLOCK_LENGTH {
                self.increment_counter(BLOCK_LENGTH as u32);
                let (block, rest) = data.split_at(BLOCK_LENGTH);
                let mut copy = [0u8; BLOCK_LENGTH];
                copy.copy_from_slice(block);
                self.compress(&copy);
                data = rest;
            }
        }
        self.buf[self.buflen..self.buflen + data.len()].copy_from_slice(data);
        self.buflen += data.len();
    }

    /// `blake2s_final`: the whole 32 bytes of the hash, of which the first
    /// `outlen` are the digest.
    pub(crate) fn finish(mut self) -> [u8; BLAKE2S_LENGTH] {
        self.increment_counter(self.buflen as u32);
        self.set_lastblock();
        self.buf[self.buflen..].fill(0);
        let block = self.buf;
        self.compress(&block);
        let mut out = [0u8; BLAKE2S_LENGTH];
        for (bytes, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.h) {
            *bytes = word.to_le_bytes();
        }
        out
    }
}

impl Drop for State {
    fn drop(&mut self) {
        clear(&mut self.h);
        clear(&mut self.buf);
    }
}

/// A BLAKE2s computation with a 32-byte digest, keyed or not.
///
/// What it has hashed is overwritten when it is dropped (best effort).
#[derive(Clone)]
pub struct Blake2s {
    state: State,
}

impl Default for Blake2s {
    fn default() -> Blake2s {
        Blake2s::new()
    }
}

impl Blake2s {
    /// `blake2s_init(S, 32)`.
    pub fn new() -> Blake2s {
        Blake2s {
            state: State::with_params(&Params {
                digest_length: BLAKE2S_LENGTH as u8,
                key_length: 0,
                fanout: 1,
                depth: 1,
                node_offset: 0,
                node_depth: 0,
                inner_length: 0,
            }),
        }
    }

    /// `blake2s_init_key(S, 32, key)`: `None` for a key longer than 32
    /// bytes. An empty key is no key.
    pub fn with_key(key: &[u8]) -> Option<Blake2s> {
        if key.len() > BLAKE2S_KEY_LENGTH {
            return None;
        }
        if key.is_empty() {
            return Some(Blake2s::new());
        }
        let mut hash = Blake2s {
            state: State::with_params(&Params {
                digest_length: BLAKE2S_LENGTH as u8,
                key_length: key.len() as u8,
                fanout: 1,
                depth: 1,
                node_offset: 0,
                node_depth: 0,
                inner_length: 0,
            }),
        };
        let mut block = [0u8; BLOCK_LENGTH];
        block[..key.len()].copy_from_slice(key);
        hash.state.update(&block);
        clear(&mut block);
        Some(hash)
    }

    /// More data.
    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    /// The digest of the data so far. The computation can go on with more
    /// data.
    pub fn out(&self) -> [u8; BLAKE2S_LENGTH] {
        self.state.clone().finish()
    }
}
