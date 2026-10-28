//! Port of `lib/compress`.

pub(crate) mod clevels;
pub(crate) mod fse_compress;
pub(crate) mod hist;
pub(crate) mod huf_compress;
#[cfg(test)]
mod tests;
pub(crate) mod zstd_compress;
pub(crate) mod zstd_compress_internal;
pub(crate) mod zstd_compress_literals;
pub(crate) mod zstd_compress_sequences;
pub(crate) mod zstd_double_fast;
pub(crate) mod zstd_fast;
pub(crate) mod zstd_pre_split;
