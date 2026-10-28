//! Zstandard compression and decompression in safe Rust, ported from the
//! official library, [libzstd](https://github.com/facebook/zstd).
//!
//! Work in progress: decompression works, of whole frames in one call
//! ([`decompress`], [`DCtx::decompress`]) or streaming
//! ([`DCtx::decompress_stream`]), with dictionaries through [`DDict`];
//! compression comes next. The plan, and the rules the port follows, are in
//! the repository: `docs/porting.md` and `docs/safety.md`.
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
//!
//! Streaming, when the output's size is not known or too large to hold:
//!
//! ```
//! # fn main() -> Result<(), hivepack_zstd::Error> {
//! # let frame = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x05, 0x29, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o'];
//! use hivepack_zstd::{DCtx, InBuffer, OutBuffer};
//!
//! let mut dctx = DCtx::new();
//! let mut decoded = Vec::new();
//! let mut piece = vec![0; hivepack_zstd::dstream_out_size()];
//! // The input can come in pieces too: each call reads what it can.
//! let mut input = InBuffer::new(&frame);
//! loop {
//!     let mut output = OutBuffer::new(&mut piece);
//!     let hint = dctx.decompress_stream(&mut output, &mut input)?;
//!     let written = output.pos;
//!     decoded.extend_from_slice(&piece[..written]);
//!     if hint == 0 && input.pos == input.src.len() {
//!         // The last frame is done, and all of it written out. Input that
//!         // stops inside a frame ends in an error instead.
//!         break;
//!     }
//! }
//! assert_eq!(decoded, b"hello");
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! - `unsafe-fast`, off by default: the decoder's main sequence loop copies
//!   without a bounds check per piece, as libzstd does, once per block it
//!   has checked that its buffers allow it. Decompression is a few percent
//!   faster; the crate then has some `unsafe` code, which without the
//!   feature it forbids. It changes nothing on 32-bit machines.
//!   [`UNSAFE_FAST`] says whether a build has it. See `docs/unsafe.md` in
//!   the repository.

// No unsafe code at all, unless the `unsafe-fast` feature is on: then only
// in `decompress/unchecked.rs`, and the one block of the main sequence loop
// that turns it on (see `docs/unsafe.md`).
#![cfg_attr(not(feature = "unsafe-fast"), forbid(unsafe_code))]
// The common files are ported whole, with what only the encoder (still to
// come) or the tests use.
#![allow(dead_code)]
// Loops keep libzstd's indices, so the port reads side by side with the C.
#![allow(clippy::needless_range_loop)]

mod common;
mod compress;
mod decompress;

#[cfg(test)]
mod oracle;
#[cfg(test)]
mod oracle_compress;

pub use common::error_private::{Error, ErrorCode, Result};
pub use decompress::zstd_ddict::{DDict, DictContentType};
pub use decompress::zstd_decompress::{
    BLOCKSIZE_MAX_MIN, ContentSize, DParameter, DParameterKind, FRAMEHEADER_SIZE_MAX,
    FrameHeaderState, InBuffer, OutBuffer, ResetDirective, SKIPPABLE_HEADER_SIZE, WINDOWLOG_MAX,
    decoding_buffer_size_min, decompress, decompress_bound, dstream_in_size, dstream_out_size,
    find_decompressed_size, find_frame_compressed_size, frame_header_size, get_dict_id_from_dict,
    get_dict_id_from_frame, get_frame_content_size, get_frame_header, get_frame_header_advanced,
    is_frame, is_skippable_frame, read_skippable_frame,
};
pub use decompress::zstd_decompress_internal::{
    CONTENTSIZE_UNKNOWN, DCtx, Format, FrameHeader, FrameType,
};

/// The libzstd release this crate follows, as libzstd's
/// `ZSTD_VERSION_STRING` gives it.
pub const UPSTREAM_VERSION: &str = "1.5.7";

/// Whether this build has the `unsafe-fast` feature: the decoder's copies
/// without per-piece bounds checks. Cargo turns a feature on for the whole
/// build when any crate asks for it, so this says which one a program got.
pub const UNSAFE_FAST: bool = cfg!(feature = "unsafe-fast");
