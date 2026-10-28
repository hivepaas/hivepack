//! Deflate, zlib and gzip decompression in safe Rust, ported from the
//! official library, [zlib](https://zlib.net).
//!
//! Work in progress: decompression works ([`Inflate`]), with the zlib and
//! gzip wrappers, dictionaries and gzip headers, and so do the checksums
//! ([`crc32`], [`adler32`]); compression comes next. The plan, and the rules
//! the port follows, are in the repository: `docs/deflate.md` and
//! `docs/safety.md`.
//!
//! ```
//! # fn main() -> Result<(), hivepack_deflate::Error> {
//! use hivepack_deflate::{Flush, InBuffer, Inflate, OutBuffer, Status};
//!
//! // "hello", deflated with no header or trailer, as in a ZIP archive.
//! let raw = [0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];
//! let mut inflate = Inflate::new(-15)?;
//! let mut decoded = Vec::new();
//! let mut piece = [0; 2];
//! let mut input = InBuffer::new(&raw);
//! loop {
//!     // The output can come in pieces, and so can the input: each call
//!     // reads and writes what it can.
//!     let mut output = OutBuffer::new(&mut piece);
//!     let status = inflate.inflate(&mut output, &mut input, Flush::NoFlush)?;
//!     let written = output.pos;
//!     decoded.extend_from_slice(&piece[..written]);
//!     if status == Status::StreamEnd {
//!         break;
//!     }
//! }
//! assert_eq!(decoded, b"hello");
//! assert_eq!(hivepack_deflate::crc32(0, &decoded), 0x3610_a686);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
// Loops keep zlib's indices, so the port reads side by side with the C.
#![allow(clippy::needless_range_loop)]

mod adler32;
mod crc32;
mod inffast;
mod inffixed;
mod inflate;
mod inftrees;
mod zutil;

pub use adler32::{ADLER32_INIT, adler32, adler32_combine};
pub use crc32::{crc32, crc32_combine, crc32_combine_gen, crc32_combine_op, get_crc_table};
pub use inflate::{GzHeader, InBuffer, Inflate, OutBuffer};
pub use zutil::{Error, ErrorCode, Flush, MAX_WBITS, Result, Status};

/// The zlib release this crate follows, as zlib's `ZLIB_VERSION` gives it.
pub const UPSTREAM_VERSION: &str = "1.3.2";
