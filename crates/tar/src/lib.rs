//! Reading tar archives in safe Rust, ported from Go's `archive/tar` (Go
//! 1.27.2), its reading half.
//!
//! [`Reader`] reads an archive in order: V7, USTAR, PAX (POSIX.1-2001, its
//! records merged into the entries they describe), GNU (long names, and
//! the sparse formats 0.0, 0.1 and 1.0 and the old one), and STAR. Sparse
//! files' holes read as zeros. Names are bytes, as tar keeps them. With a file
//! that is only listed, [`Reader::seekable`] seeks past the data.
//!
//! The rules the port follows, and how it is checked against Go, are in
//! the repository: `docs/tar.md`.
//!
//! ```no_run
//! use std::io::Read;
//!
//! let mut tar = hivepack_tar::Reader::new(std::fs::File::open("backup.tar")?);
//! while let Some(header) = tar.next()? {
//!     let mut data = Vec::new();
//!     tar.read_to_end(&mut data)?;
//!     println!("{} {} bytes", String::from_utf8_lossy(&header.name), data.len());
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod common;
mod format;
mod reader;
mod strconv;

pub use common::{
    Error, Format, Header, Records, TYPE_BLOCK, TYPE_CHAR, TYPE_CONT, TYPE_DIR, TYPE_FIFO,
    TYPE_GNU_LONG_LINK, TYPE_GNU_LONG_NAME, TYPE_GNU_SPARSE, TYPE_LINK, TYPE_REG, TYPE_REG_A,
    TYPE_SYMLINK, TYPE_X_GLOBAL_HEADER, TYPE_X_HEADER, Time,
};
pub use reader::Reader;

/// The Go release whose `archive/tar` this crate follows.
pub const UPSTREAM_VERSION: &str = "1.27.2";
