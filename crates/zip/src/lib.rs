//! ZIP archives in safe Rust, the container logic ported from
//! [libzip](https://libzip.org).
//!
//! It opens archives and reads what their central directory and local
//! headers say, with libzip's rules and errors: where the end of central
//! directory record is looked for and which one is taken, the Zip64
//! records, Info-ZIP's count of entries modulo 65,536, file names in UTF-8
//! or CP437 and the Info-ZIP Unicode extra fields, WinZip AES headers,
//! torrentzip, and, with [`OpenFlags::CHECKCONS`], the comparison of every
//! local header with the central directory. It reads stored and deflated
//! entries, and checks the CRC-32 and length of an entry read to its end,
//! as libzip does. The rules the port follows are in the repository's
//! `docs/zip.md`.
//!
//! ```
//! use std::io::Read;
//!
//! use hivepack_zip::{Archive, Flags, OpenFlags};
//!
//! // An archive with one stored file, "hi.txt".
//! let zip: &[u8] = &[
//!     0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x5d, 0x5d, 0x1b, 0x38,
//!     0x72, 0xcb, 0x0b, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x68, 0x69,
//!     0x2e, 0x74, 0x78, 0x74, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x7a, 0x69, 0x70, 0x0a, 0x50,
//!     0x4b, 0x01, 0x02, 0x14, 0x03, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x5d, 0x5d, 0x1b,
//!     0x38, 0x72, 0xcb, 0x0b, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x68, 0x69, 0x2e,
//!     0x74, 0x78, 0x74, 0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x34,
//!     0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00,
//! ];
//! let archive = Archive::open(zip, OpenFlags::CHECKCONS)?;
//! assert_eq!(archive.get_num_entries(Flags::NONE), 1);
//! assert_eq!(archive.get_name(0, Flags::NONE)?, b"hi.txt");
//!
//! let mut text = String::new();
//! let mut file = archive.fopen(b"hi.txt", Flags::NONE)?;
//! file.read_to_string(&mut text)?;
//! assert_eq!(text, "hello, zip\n");
//! file.fclose()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod algorithm_deflate;
mod buffer;
mod dirent;
mod error;
mod extra_field;
mod extra_field_api;
mod fclose;
mod file_get_comment;
mod file_get_external_attributes;
mod file_get_offset;
mod fopen;
mod fopen_index;
mod fopen_index_encrypted;
mod fread;
mod get_archive_comment;
mod get_archive_flag;
mod get_name;
mod get_num_entries;
mod hash;
mod io_util;
mod name_locate;
mod open;
mod source;
mod source_compress;
mod source_crc;
mod source_stack;
mod source_window;
mod source_zip_new;
mod stat_index;
mod string;
mod utf_8;
mod zip;
mod zipint;

pub use error::{Detail, Error, ErrorCode, Result, SystemType};
pub use fopen_index_encrypted::ZipFile;
pub use open::Archive;
pub use source::ReadAt;
pub use zip::{ArchiveFlags, Flags, OpenFlags, Stat, cm, em, opsys, stat};

/// The libzip release this crate follows.
pub const UPSTREAM_VERSION: &str = "1.12.1";
