//! Extracting archives to disk, safe by default: nothing is written
//! outside the destination, through a link, over what is there, or past
//! limits set against archive bombs.
//!
//! What extractors get wrong is logic, not memory: names that climb out of
//! the destination (`../`, `/etc`, `C:`, `a:stream`), links in the archive
//! or already on disk that lead elsewhere, the same path given twice,
//! setuid bits, and archives whose entries share one compressed stream to
//! write terabytes. This crate refuses rather than repairs, so that an
//! archive extracts the same everywhere:
//!
//! - **Names**: [`check_name`] refuses names that are absolute, climb with
//!   `..`, carry a backslash, a colon, a control character or a Windows
//!   device name, or end a component with a space or a dot, on every
//!   system alike. Two entries may not name the same path, ignoring case.
//! - **Links** are not created, unless [`Options::links`] says to create
//!   those that stay inside the destination; a device or FIFO in a ZIP
//!   archive, only a mode with data, is written as a file.
//! - **Writing** goes through handles: each directory is opened from its
//!   parent without following a link, and each file is created new, so a
//!   link already in the destination, or put there while extracting, is
//!   not followed, and nothing is overwritten.
//! - **Limits** ([`Limits`]) count entries, the bytes each writes and all
//!   write, and the bytes written for each compressed byte; entries whose
//!   compressed data overlap are refused before anything is written.
//! - **Integrity**: a file whose data fails its check (CRC-32, or WinZip
//!   AES's authentication code) is removed.
//! - **Permissions** are masked: no setuid, setgid or sticky bit, and
//!   nothing writable by group or others.
//!
//! ```no_run
//! use hivepack_extract::{Options, extract_zip};
//! use hivepack_zip::{Archive, OpenFlags};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let file = std::fs::File::open("archive.zip")?;
//! let archive = Archive::open(file, OpenFlags::CHECKCONS)?;
//! let summary = extract_zip(&archive, "out".as_ref(), &Options::default())?;
//! println!("{} files, {} bytes", summary.files, summary.bytes);
//! # Ok(())
//! # }
//! ```
//!
//! The design, and what comes next (tar and RAR, links kept inside the
//! destination, marks of origin), are in the repository's
//! `docs/extract.md`.

mod destination;
mod error;
mod name;
mod plan;
mod zip;

pub use error::{Error, ErrorKind};
pub use name::{MAX_COMPONENT, Name, NameError, check_name};
pub use plan::{Limits, Links, Names, OnRefused, Options, Permissions};
pub use zip::{Summary, extract_zip};
