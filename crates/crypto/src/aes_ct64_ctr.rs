//! The AES block cipher, encrypting four blocks at a time: the core of
//! `aes_ct64_ctr.c`'s `br_aes_ct64_ctr_run`, without its counter.
//!
//! Differs from BearSSL: BearSSL offers AES with its modes (CBC, CTR, CCM,
//! GCM); WinZip AES uses a counter of its own (little-endian, as libzip
//! increments it), so this module gives the blocks encrypted, and the
//! caller XORs them into the data. BearSSL expands the subkeys at every
//! call; [`Aes`] keeps them expanded.

use crate::aes_ct64::{interleave_in, interleave_out, keysched, ortho, skey_expand};
use crate::aes_ct64_enc::bitslice_encrypt;
use crate::clear::clear;

/// The length of an AES block, in bytes.
pub const AES_BLOCK_LENGTH: usize = 16;

/// An AES key, ready to encrypt.
///
/// The key and the subkeys derived from it are overwritten when it is
/// dropped (best effort: see the crate's documentation).
pub struct Aes {
    num_rounds: usize,
    skey: [u64; 120],
}

impl Aes {
    /// The key schedule of `key`, AES-128, AES-192 or AES-256 for a key of
    /// 16, 24 or 32 bytes; `None` for any other length.
    pub fn new(key: &[u8]) -> Option<Aes> {
        let (num_rounds, mut comp_skey) = keysched(key)?;
        let skey = skey_expand(num_rounds, &comp_skey);
        clear(&mut comp_skey);
        Some(Aes { num_rounds, skey })
    }

    /// Encrypts four blocks in place, one after the other in `blocks`.
    pub fn encrypt4(&self, blocks: &mut [u8; 4 * AES_BLOCK_LENGTH]) {
        let mut w = [0u32; 16];
        for (word, bytes) in w.iter_mut().zip(blocks.as_chunks().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        let mut q = [0u64; 8];
        for (i, block) in w.as_chunks().0.iter().enumerate() {
            (q[i], q[i + 4]) = interleave_in(block);
        }
        ortho(&mut q);
        bitslice_encrypt(self.num_rounds, &self.skey, &mut q);
        ortho(&mut q);
        for (i, block) in w.as_chunks_mut().0.iter_mut().enumerate() {
            *block = interleave_out(q[i], q[i + 4]);
        }
        for (bytes, word) in blocks.as_chunks_mut().0.iter_mut().zip(w) {
            *bytes = word.to_le_bytes();
        }
    }

    /// Encrypts one block in place: [`Aes::encrypt4`], with the other three
    /// blocks empty, so it takes as long.
    pub fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_LENGTH]) {
        let mut blocks = [0u8; 4 * AES_BLOCK_LENGTH];
        blocks[..AES_BLOCK_LENGTH].copy_from_slice(block);
        self.encrypt4(&mut blocks);
        block.copy_from_slice(&blocks[..AES_BLOCK_LENGTH]);
    }
}

impl Drop for Aes {
    fn drop(&mut self) {
        clear(&mut self.skey);
    }
}

/// Shows the number of rounds, not the subkeys.
impl std::fmt::Debug for Aes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aes")
            .field("num_rounds", &self.num_rounds)
            .finish_non_exhaustive()
    }
}
