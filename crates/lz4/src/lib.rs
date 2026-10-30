//! LZ4 compression and decompression in safe Rust, ported from the
//! official library, [liblz4](https://github.com/lz4/lz4) 1.10.0.
//!
//! Two formats, as in liblz4:
//!
//! - **Blocks** ([`block`], `lz4.h`): compressed data alone, which the
//!   caller must know the size of to decode. [`block::decompress_safe`]
//!   gives liblz4's result, the error position included, and what it
//!   writes.
//! - **Frames** ([`frame`], `lz4frame.h`): the `.lz4` file format, with
//!   its header, blocks, checksums and skippable frames.
//!   [`frame::DecompressionContext`] decodes them in as many calls as the
//!   input and output come in, each reading, writing and returning what
//!   `LZ4F_decompress` does.
//! - **`.lz4` files** ([`Decoder`]): what `lz4 -d` decodes, as an
//!   [`std::io::Read`]: frames one after another, skippable frames, and the
//!   legacy format.
//!
//! The rules the port follows, and how it is checked, are in the
//! repository: `docs/lz4.md` and `docs/safety.md`.
//!
//! # Features
//!
//! - `unsafe-fast`, off by default: the decoder's fast loop reads and writes
//!   without bounds checks, as liblz4 does, which makes it faster, with
//!   some `unsafe` code, which without the feature the crate forbids.
//!   [`UNSAFE_FAST`] says whether a build has it. See `docs/unsafe.md` in
//!   the repository.
//!
//! ```
//! # fn main() -> Result<(), hivepack_lz4::frame::Error> {
//! use hivepack_lz4::frame::{DecompressionContext, DecompressOptions, InBuffer, OutBuffer};
//!
//! // "hello, hello, hello\n" in a frame, as `lz4` writes it.
//! let lz4 = [
//!     0x04, 0x22, 0x4d, 0x18, 0x64, 0x40, 0xa7, 0x10, 0x00, 0x00, 0x00, 0x74,
//!     0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x07, 0x00, 0x50, 0x65, 0x6c,
//!     0x6c, 0x6f, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x27, 0x7b, 0x7a, 0x9f,
//! ];
//! let mut dctx = DecompressionContext::new();
//! let mut input = InBuffer::new(&lz4);
//! let mut text = Vec::new();
//! let mut piece = [0; 8];
//! loop {
//!     // The output can come in pieces, and so can the input: each call
//!     // reads and writes what it can, and hints at what it wants next.
//!     let mut output = OutBuffer::new(&mut piece);
//!     let hint = dctx.decompress(&mut output, &mut input, DecompressOptions::default())?;
//!     let written = output.pos;
//!     text.extend_from_slice(&piece[..written]);
//!     if hint == 0 {
//!         break;
//!     }
//! }
//! assert_eq!(text, b"hello, hello, hello\n");
//! # Ok(())
//! # }
//! ```

// No unsafe code at all, unless the `unsafe-fast` feature is on: then only
// in `unchecked.rs` and the block of `lz4.rs` that uses it (see
// `docs/unsafe.md`).
#![cfg_attr(not(feature = "unsafe-fast"), forbid(unsafe_code))]

mod decoder;
mod lz4;
mod lz4frame;
#[cfg(feature = "unsafe-fast")]
mod unchecked;
mod xxhash;

pub use decoder::{Decoder, LEGACY_BLOCKSIZE, LEGACY_MAGICNUMBER};

/// The block format: `lz4.h`.
pub mod block {
    pub use crate::lz4::{
        DecodeError, MAX_INPUT_SIZE, StreamDecode, VERSION_NUMBER, compress_bound, decompress_safe,
        decompress_safe_partial, decompress_safe_partial_using_dict,
        decompress_safe_partial_with_prefix, decompress_safe_using_dict,
        decompress_safe_with_prefix, version_number, version_string,
    };
}

/// The frame format: `lz4frame.h`.
pub mod frame {
    pub use crate::lz4frame::{
        BLOCK_CHECKSUM_SIZE, BLOCK_HEADER_SIZE, BlockMode, BlockSizeId, CONTENT_CHECKSUM_SIZE,
        DecompressOptions, DecompressionContext, Error, FrameInfo, FrameType, HEADER_SIZE_MAX,
        HEADER_SIZE_MIN, InBuffer, MAGIC_SKIPPABLE_START, MAGICNUMBER,
        MIN_SIZE_TO_KNOW_HEADER_LENGTH, OutBuffer, Result, VERSION, get_block_size, get_version,
        header_size,
    };
}

/// XXH32, the checksum of the frame format, from the xxHash 0.6.5 that
/// liblz4 ships.
pub use xxhash::{Xxh32, xxh32};

/// Whether this build has the `unsafe-fast` feature: the decoder's fast
/// loop without bounds checks. Cargo turns a feature on for the whole build
/// as soon as one crate asks for it, so a program can check which it got.
pub const UNSAFE_FAST: bool = cfg!(feature = "unsafe-fast");

/// The liblz4 release this crate follows.
pub const UPSTREAM_VERSION: &str = "1.10.0";
