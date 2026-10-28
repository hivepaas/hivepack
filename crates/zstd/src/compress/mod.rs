//! Port of `lib/compress`.

pub(crate) mod fse_compress;
pub(crate) mod hist;
pub(crate) mod huf_compress;
pub(crate) mod zstd_compress;
pub(crate) mod zstd_compress_internal;
pub(crate) mod zstd_compress_literals;
pub(crate) mod zstd_compress_sequences;
