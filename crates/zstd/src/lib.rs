//! Zstandard compression and decompression in safe Rust, ported from the
//! official library, [libzstd](https://github.com/facebook/zstd).
//!
//! Work in progress: so far the pieces that decoding builds on are ported
//! (bit reading, FSE and Huffman tables, XXH64), and nothing is public but
//! the error type. The plan, and the rules the port follows, are in the
//! repository: `docs/porting.md` and `docs/safety.md`.

// The ported pieces are for the decoder, which comes next. Until it uses
// them, some are used only by the tests, and some not yet at all.
#![allow(dead_code)]
// Loops keep libzstd's indices, so the port reads side by side with the C.
#![allow(clippy::needless_range_loop)]

mod common;
mod decompress;

#[cfg(test)]
mod oracle;

pub use common::error_private::{Error, ErrorCode};

/// The libzstd release this crate follows, as libzstd's
/// `ZSTD_VERSION_STRING` gives it.
pub const UPSTREAM_VERSION: &str = "1.5.7";
