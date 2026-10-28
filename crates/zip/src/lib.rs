//! ZIP archives in safe Rust, the container logic ported from
//! [libzip](https://libzip.org).
//!
//! This first part opens archives and reads what their central directory
//! and local headers say, with libzip's rules and errors: where the end of
//! central directory record is looked for and which one is taken, the Zip64
//! records, Info-ZIP's count of entries modulo 65,536, file names in UTF-8
//! or CP437 and the Info-ZIP Unicode extra fields, WinZip AES headers,
//! torrentzip, and, with [`OpenFlags::CHECKCONS`], the comparison of every
//! local header with the central directory. Reading the entries' data comes
//! next. The rules the port follows are in the repository's
//! `docs/zip.md`.
//!
//! ```
//! use hivepack_zip::{Archive, Flags, OpenFlags};
//!
//! // An empty archive: an end of central directory record and nothing else.
//! let empty = b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
//! let archive = Archive::open(&empty[..], OpenFlags::CHECKCONS)?;
//! assert_eq!(archive.get_num_entries(Flags::NONE), 0);
//! # Ok::<(), hivepack_zip::Error>(())
//! ```

#![forbid(unsafe_code)]

mod buffer;
mod dirent;
mod error;
mod extra_field;
mod extra_field_api;
mod file_get_comment;
mod file_get_external_attributes;
mod file_get_offset;
mod get_archive_comment;
mod get_archive_flag;
mod get_name;
mod get_num_entries;
mod hash;
mod io_util;
mod name_locate;
mod open;
mod source;
mod stat_index;
mod string;
mod utf_8;
mod zip;
mod zipint;

pub use error::{Detail, Error, ErrorCode, Result, SystemType};
pub use open::Archive;
pub use source::ReadAt;
pub use zip::{ArchiveFlags, Flags, OpenFlags, Stat, cm, em, opsys, stat};

/// The libzip release this crate follows.
pub const UPSTREAM_VERSION: &str = "1.12.1";
