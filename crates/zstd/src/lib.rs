//! Zstandard compression and decompression in safe Rust, ported from the
//! official library, [libzstd](https://github.com/facebook/zstd).
//!
//! Work in progress: decompression works, of whole frames in one call
//! ([`decompress`], [`DCtx::decompress`]) or streaming
//! ([`DCtx::decompress_stream`]), with dictionaries through [`DDict`].
//! Compression works at every level, with every strategy, the block
//! splitter after the sequences and long distance matching, in one call
//! ([`compress`], [`CCtx::compress`], [`CCtx::compress2`]) or streaming
//! ([`CCtx::compress_stream2`]), with libzstd's parameters
//! ([`CCtx::set_parameter`]), giving the frames libzstd gives; with
//! dictionaries too ([`CCtx::load_dictionary`], [`CDict`],
//! [`CCtx::ref_prefix`], [`CCtx::compress_using_dict`]), attached, copied
//! in or loaded again as libzstd decides; and on several threads
//! ([`CParameter::NbWorkers`]), as libzstd's `ZSTD_c_nbWorkers`. The plan,
//! and the rules the port follows, are in the repository: `docs/porting.md`
//! and `docs/safety.md`.
//!
//! ```
//! # fn main() -> Result<(), hivepack_zstd::Error> {
//! let data = b"hello, hello, hello, hello";
//! let mut frame = vec![0; hivepack_zstd::compress_bound(data.len()).unwrap_or(0)];
//! let size = hivepack_zstd::compress(&mut frame, data, 3)?;
//! let mut out = vec![0; data.len()];
//! assert_eq!(hivepack_zstd::decompress(&mut out, &frame[..size])?, data.len());
//! assert_eq!(&out, data);
//! # Ok(())
//! # }
//! ```
//!
//! Compressing as a stream, with a checksum:
//!
//! ```
//! # fn main() -> Result<(), hivepack_zstd::Error> {
//! use hivepack_zstd::{CCtx, CParameter, EndDirective, InBuffer, OutBuffer};
//!
//! let mut cctx = CCtx::new();
//! cctx.set_parameter(CParameter::CompressionLevel(1))?;
//! cctx.set_parameter(CParameter::ChecksumFlag(true))?;
//! let mut frame = Vec::new();
//! let mut piece = vec![0; hivepack_zstd::cstream_out_size()];
//! for chunk in [&b"hello, "[..], b"hello, ", b"hello"] {
//!     let mut input = InBuffer::new(chunk);
//!     while input.pos < chunk.len() {
//!         let mut output = OutBuffer::new(&mut piece);
//!         cctx.compress_stream2(&mut output, &mut input, EndDirective::Continue)?;
//!         let written = output.pos;
//!         frame.extend_from_slice(&piece[..written]);
//!     }
//! }
//! // End the frame: until nothing is left to write out.
//! loop {
//!     let mut output = OutBuffer::new(&mut piece);
//!     let remaining = cctx.end_stream(&mut output)?;
//!     let written = output.pos;
//!     frame.extend_from_slice(&piece[..written]);
//!     if remaining == 0 {
//!         break;
//!     }
//! }
//! let mut out = vec![0; 19];
//! assert_eq!(hivepack_zstd::decompress(&mut out, &frame)?, 19);
//! assert_eq!(&out, b"hello, hello, hello");
//! # Ok(())
//! # }
//! ```
//!
//! Compressing on worker threads: the frames depend on whether there are
//! workers, not on how many, and are those libzstd writes with workers. A
//! frame of a known size of 512 KB or less takes none.
//!
//! ```
//! # fn main() -> Result<(), hivepack_zstd::Error> {
//! use hivepack_zstd::{CCtx, CParameter};
//!
//! let data: Vec<u8> = (0..2_000_000u32).map(|i| (i % 251) as u8 ^ (i >> 13) as u8).collect();
//! let mut frames = Vec::new();
//! for workers in [2, 4] {
//!     let mut cctx = CCtx::new();
//!     cctx.set_parameter(CParameter::NbWorkers(workers))?;
//!     // Jobs of 512 KB, the smallest, for the threads to share.
//!     cctx.set_parameter(CParameter::JobSize(512 << 10))?;
//!     let mut frame = vec![0; hivepack_zstd::compress_bound(data.len()).unwrap_or(0)];
//!     let size = cctx.compress2(&mut frame, &data)?;
//!     frame.truncate(size);
//!     frames.push(frame);
//! }
//! assert_eq!(frames[0], frames[1]);
//! let mut out = vec![0; data.len()];
//! assert_eq!(hivepack_zstd::decompress(&mut out, &frames[0])?, data.len());
//! assert_eq!(out, data);
//! # Ok(())
//! # }
//! ```
//!
//! Decompressing a frame:
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
//!   has checked that its buffers allow it, which changes nothing on 32-bit
//!   machines; and the encoder's row match finder (levels 5 to 12)
//!   prefetches its rows and candidates as libzstd does, on aarch64 and
//!   x86-64. Decompression is a few percent faster, and compression at
//!   those levels faster still; the output is the same. The crate then has
//!   some `unsafe` code, which without the feature it forbids.
//!   [`UNSAFE_FAST`] says whether a build has it. See `docs/unsafe.md` in
//!   the repository.

// No unsafe code at all, unless the `unsafe-fast` feature is on: then only
// in `decompress/unchecked.rs`, the one block of the main sequence loop
// that turns it on, and the prefetch of `common/prefetch.rs` (see
// `docs/unsafe.md`).
#![cfg_attr(not(feature = "unsafe-fast"), forbid(unsafe_code))]
// The common files are ported whole, with what only parts still to come or
// the tests use.
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
pub use compress::zstd_cdict::CDict;
pub use compress::zstd_compress::{
    CCtx, CParameter, CParameterKind, EndDirective, compress, compress_bound, cstream_in_size,
    cstream_out_size, default_c_level, max_c_level, min_c_level,
};
pub use compress::zstd_compress_internal::{DictAttachPref, ParamSwitch, Strategy};
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
/// without per-piece bounds checks, and the row match finder's prefetching.
/// Cargo turns a feature on for the whole
/// build when any crate asks for it, so this says which one a program got.
pub const UNSAFE_FAST: bool = cfg!(feature = "unsafe-fast");
