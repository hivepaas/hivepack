//! The AES block cipher, on four blocks at a time: the core of
//! `aes_ct64_ctr.c`'s `br_aes_ct64_ctr_run`, without its counter, and of
//! `aes_ct64_cbcdec.c`'s `br_aes_ct64_cbcdec_run`.
//!
//! Differs from BearSSL: BearSSL offers AES with its modes (CBC, CTR, CCM,
//! GCM); WinZip AES uses a counter of its own (little-endian, as libzip
//! increments it), so this module gives the blocks encrypted, and the
//! caller XORs them into the data. BearSSL expands the subkeys at every
//! call; [`Aes`] keeps them expanded.

use crate::aes_ct64::{interleave_in, interleave_out, keysched, ortho, skey_expand};
use crate::aes_ct64_dec::bitslice_decrypt;
use crate::aes_ct64_enc::bitslice_encrypt;
use crate::clear::clear;

/// The length of an AES block, in bytes.
pub const AES_BLOCK_LENGTH: usize = 16;

/// An AES key, ready to encrypt and decrypt.
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

    /// Decrypts four blocks in place, one after the other in `blocks`.
    pub fn decrypt4(&self, blocks: &mut [u8; 4 * AES_BLOCK_LENGTH]) {
        let mut w = [0u32; 16];
        for (word, bytes) in w.iter_mut().zip(blocks.as_chunks().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        let mut q = [0u64; 8];
        for (i, block) in w.as_chunks().0.iter().enumerate() {
            (q[i], q[i + 4]) = interleave_in(block);
        }
        ortho(&mut q);
        bitslice_decrypt(self.num_rounds, &self.skey, &mut q);
        ortho(&mut q);
        for (i, block) in w.as_chunks_mut().0.iter_mut().enumerate() {
            *block = interleave_out(q[i], q[i + 4]);
        }
        for (bytes, word) in blocks.as_chunks_mut().0.iter_mut().zip(w) {
            *bytes = word.to_le_bytes();
        }
    }

    /// `br_aes_ct64_cbcdec_run`: decrypts whole blocks of `data` in place, in
    /// CBC mode, and leaves in `iv` what the next ones go on from. Bytes past
    /// the last whole block are left as they are.
    pub fn cbc_decrypt(&self, iv: &mut [u8; AES_BLOCK_LENGTH], data: &mut [u8]) {
        let whole = data.len() / AES_BLOCK_LENGTH * AES_BLOCK_LENGTH;
        for chunk in data[..whole].chunks_mut(4 * AES_BLOCK_LENGTH) {
            let mut blocks = [0u8; 4 * AES_BLOCK_LENGTH];
            blocks[..chunk.len()].copy_from_slice(chunk);
            let cipher = blocks;
            self.decrypt4(&mut blocks);
            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte = blocks[i]
                    ^ if i < AES_BLOCK_LENGTH {
                        iv[i]
                    } else {
                        cipher[i - AES_BLOCK_LENGTH]
                    };
            }
            let last = chunk.len() - AES_BLOCK_LENGTH;
            iv.copy_from_slice(&cipher[last..last + AES_BLOCK_LENGTH]);
            clear(&mut blocks);
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
