//! BLAKE2sp: eight BLAKE2s leaves, each taking every eighth 64-byte block,
//! and a root that hashes their digests. Ported from the BLAKE2 reference
//! implementation's `ref/blake2sp-ref.c`, by Samuel Neves, under CC0 1.0
//! (or the OpenSSL or Apache 2.0 licenses), at commit ed1974ea of
//! github.com/BLAKE2/BLAKE2. RAR 5 hashes files with it, unkeyed.

use crate::blake2s::{BLAKE2S_KEY_LENGTH, BLAKE2S_LENGTH, BLOCK_LENGTH, Params, State};
use crate::clear::clear;

/// The length of a BLAKE2sp digest, in bytes.
pub const BLAKE2SP_LENGTH: usize = BLAKE2S_LENGTH;

const PARALLELISM_DEGREE: usize = 8;

/// A BLAKE2sp computation with a 32-byte digest, keyed or not.
///
/// What it has hashed is overwritten when it is dropped (best effort).
#[derive(Clone)]
pub struct Blake2sp {
    leaves: [State; PARALLELISM_DEGREE],
    root: State,
    buf: [u8; PARALLELISM_DEGREE * BLOCK_LENGTH],
    buflen: usize,
}

impl Default for Blake2sp {
    fn default() -> Blake2sp {
        Blake2sp::new()
    }
}

/// `blake2sp_init_leaf` and `blake2sp_init_root`: depth 2, fanout 8.
fn params(key_length: u8, node_offset: u32, node_depth: u8) -> Params {
    Params {
        digest_length: BLAKE2SP_LENGTH as u8,
        key_length,
        fanout: PARALLELISM_DEGREE as u8,
        depth: 2,
        node_offset,
        node_depth,
        inner_length: BLAKE2S_LENGTH as u8,
    }
}

impl Blake2sp {
    fn init(key_length: u8) -> Blake2sp {
        let mut root = State::with_params(&params(key_length, 0, 1));
        root.last_node = true;
        let mut leaves: [State; PARALLELISM_DEGREE] = std::array::from_fn(|i| {
            let mut leaf = State::with_params(&params(key_length, i as u32, 0));
            // `blake2sp_init_leaf_param`: a leaf's digest is the inner one.
            leaf.outlen = BLAKE2S_LENGTH;
            leaf
        });
        leaves[PARALLELISM_DEGREE - 1].last_node = true;
        Blake2sp {
            leaves,
            root,
            buf: [0; PARALLELISM_DEGREE * BLOCK_LENGTH],
            buflen: 0,
        }
    }

    /// `blake2sp_init(S, 32)`.
    pub fn new() -> Blake2sp {
        Blake2sp::init(0)
    }

    /// `blake2sp_init_key(S, 32, key)`: `None` for a key longer than 32
    /// bytes. An empty key is no key.
    pub fn with_key(key: &[u8]) -> Option<Blake2sp> {
        if key.len() > BLAKE2S_KEY_LENGTH {
            return None;
        }
        if key.is_empty() {
            return Some(Blake2sp::new());
        }
        let mut hash = Blake2sp::init(key.len() as u8);
        let mut block = [0u8; BLOCK_LENGTH];
        block[..key.len()].copy_from_slice(key);
        for leaf in &mut hash.leaves {
            leaf.update(&block);
        }
        clear(&mut block);
        Some(hash)
    }

    /// `blake2sp_update`: more data.
    pub fn update(&mut self, mut data: &[u8]) {
        let mut left = self.buflen;
        let fill = self.buf.len() - left;
        if left > 0 && data.len() >= fill {
            self.buf[left..].copy_from_slice(&data[..fill]);
            for (i, leaf) in self.leaves.iter_mut().enumerate() {
                leaf.update(&self.buf[i * BLOCK_LENGTH..(i + 1) * BLOCK_LENGTH]);
            }
            data = &data[fill..];
            left = 0;
        }
        let stride = PARALLELISM_DEGREE * BLOCK_LENGTH;
        for (i, leaf) in self.leaves.iter_mut().enumerate() {
            let mut at = i * BLOCK_LENGTH;
            let mut remaining = data.len();
            while remaining >= stride {
                leaf.update(&data[at..at + BLOCK_LENGTH]);
                at += stride;
                remaining -= stride;
            }
        }
        let whole = data.len() - data.len() % stride;
        data = &data[whole..];
        if !data.is_empty() {
            self.buf[left..left + data.len()].copy_from_slice(data);
        }
        self.buflen = left + data.len();
    }

    /// `blake2sp_final`: the digest of the data so far. The computation can
    /// go on with more data.
    pub fn out(&self) -> [u8; BLAKE2SP_LENGTH] {
        let mut this = self.clone();
        let mut root = this.root.clone();
        for (i, leaf) in this.leaves.iter_mut().enumerate() {
            if this.buflen > i * BLOCK_LENGTH {
                let left = (this.buflen - i * BLOCK_LENGTH).min(BLOCK_LENGTH);
                leaf.update(&this.buf[i * BLOCK_LENGTH..i * BLOCK_LENGTH + left]);
            }
            let mut hash = leaf.clone().finish();
            root.update(&hash);
            clear(&mut hash);
        }
        root.finish()
    }
}

impl Drop for Blake2sp {
    fn drop(&mut self) {
        clear(&mut self.buf);
    }
}
