//! Zstandard compression and decompression in safe Rust, ported from the
//! official library, [libzstd](https://github.com/facebook/zstd).
//!
//! Nothing is implemented yet. The plan, and the rules the port follows, are
//! in the repository: `docs/porting.md` and `docs/safety.md`.

/// The libzstd release this crate follows, as libzstd's
/// `ZSTD_VERSION_STRING` gives it.
pub const UPSTREAM_VERSION: &str = "1.5.7";
