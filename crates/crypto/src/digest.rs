//! What HMAC, HKDF and PBKDF2 need of a hash function: BearSSL's
//! `br_hash_class`, as a trait.

use std::fmt::Debug;

/// A hash function with Merkle–Damgård padding: [`Sha1`](crate::Sha1),
/// [`Sha256`](crate::Sha256) or [`Sha512`](crate::Sha512). BearSSL's
/// `br_hash_class`, whose `init`, `update`, `out`, `state` and `set_state`
/// are the methods here.
///
/// For these three the state after whole blocks is as long as the digest,
/// so both are [`Digest::Output`].
pub trait Digest: Clone + Debug {
    /// The digest, `[u8; OUTPUT_LENGTH]`.
    type Output: Copy + AsRef<[u8]> + AsMut<[u8]>;

    /// The length of the digest, in bytes (`br_digest_size`).
    const OUTPUT_LENGTH: usize;

    /// The length of a block of input, in bytes (`BR_HASHDESC_LBLEN`).
    const BLOCK_LENGTH: usize;

    /// `init`: a computation with nothing hashed.
    fn new() -> Self;

    /// `update`: more data.
    fn update(&mut self, data: &[u8]);

    /// `out`: the digest of the data so far. The computation can go on with
    /// more data.
    fn out(&self) -> Self::Output;

    /// `state`: the state after whole blocks, and the length hashed.
    fn state(&self) -> (Self::Output, u64);

    /// `set_state`: a computation that goes on from a state that
    /// [`Digest::state`] gave after `count` bytes, a multiple of the block
    /// length.
    fn set_state(&mut self, stb: &Self::Output, count: u64);
}
