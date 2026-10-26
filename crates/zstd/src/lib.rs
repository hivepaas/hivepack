//! Zstandard compression and decompression in safe Rust, ported from the
//! official library, [libzstd](https://github.com/facebook/zstd).
//!
//! Work in progress: decompressing whole frames in one call works
//! ([`decompress`], [`DCtx`], with dictionaries through [`DDict`]);
//! streaming and compression come next. The plan, and the rules the port
//! follows, are in the repository: `docs/porting.md` and `docs/safety.md`.
//!
//! ```
//! # fn main() -> Result<(), hivepack_zstd::Error> {
//! # let frame = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x05, 0x29, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o'];
//! let mut out = vec![0; 5];
//! let size = hivepack_zstd::decompress(&mut out, &frame)?;
//! assert_eq!(&out[..size], b"hello");
//! # Ok(())
//! # }
//! ```

// The common files are ported whole, with what only the encoder (still to
// come) or the tests use.
#![allow(dead_code)]
// Loops keep libzstd's indices, so the port reads side by side with the C.
#![allow(clippy::needless_range_loop)]

mod common;
mod decompress;

#[cfg(test)]
mod oracle;

pub use common::error_private::{Error, ErrorCode, Result};
pub use decompress::zstd_ddict::{DDict, DictContentType};
pub use decompress::zstd_decompress::{
    BLOCKSIZE_MAX_MIN, ContentSize, DParameter, DParameterKind, FRAMEHEADER_SIZE_MAX,
    FrameHeaderState, ResetDirective, SKIPPABLE_HEADER_SIZE, WINDOWLOG_MAX, decompress,
    decompress_bound, find_decompressed_size, find_frame_compressed_size, frame_header_size,
    get_dict_id_from_dict, get_dict_id_from_frame, get_frame_content_size, get_frame_header,
    get_frame_header_advanced, is_frame, is_skippable_frame, read_skippable_frame,
};
pub use decompress::zstd_decompress_internal::{
    CONTENTSIZE_UNKNOWN, DCtx, Format, FrameHeader, FrameType,
};

/// The libzstd release this crate follows, as libzstd's
/// `ZSTD_VERSION_STRING` gives it.
pub const UPSTREAM_VERSION: &str = "1.5.7";
