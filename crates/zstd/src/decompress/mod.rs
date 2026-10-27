//! Port of `lib/decompress`.

pub(crate) mod huf_decompress;
/// The `unsafe-fast` feature's unchecked copies.
#[cfg(feature = "unsafe-fast")]
pub(crate) mod unchecked;
pub(crate) mod zstd_ddict;
pub(crate) mod zstd_decompress;
pub(crate) mod zstd_decompress_block;
pub(crate) mod zstd_decompress_internal;
