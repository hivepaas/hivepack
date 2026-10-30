//! Opening what hivepack reads, through the layers around it: age
//! encryption and zstd, xz, lzip, .lzma, gzip or bzip2 compression, found
//! by their first bytes and taken off one after the other, as many as
//! there are, until what is under them is a tar or ZIP archive, or plain
//! data.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use hivepack_age::{BoxedIdentity, LazyScryptIdentity};
//! use hivepack_open::{Container, Opener};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let path = "backup.tar.zst.age";
//! let ask = Arc::new(|_| Ok(b"correct horse battery staple".to_vec()));
//! let identities: Vec<BoxedIdentity> = vec![Box::new(LazyScryptIdentity::new(ask))];
//! let mut opener = Opener::new(|| std::fs::File::open(path))
//!     .name(path)
//!     .identities(identities);
//! // The passphrase is asked for here, and only here.
//! let opened = opener.open()?;
//! println!("{:?} under {:?}", opened.container(), opened.layers());
//! if opened.container() == Container::Tar {
//!     drop(opened);
//!     let options = hivepack_extract::Options::default();
//!     hivepack_extract::extract_tar(|| Ok(opener.open()?), "out".as_ref(), &options)?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Each [`Opener::open`] reads the file from its start again: the age
//! layers' file keys are kept from the first, so that a passphrase is asked
//! for once. A ZIP archive is read by random access; under layers, it must
//! be taken out to a file first.
//!
//! The design is in the repository's `docs/open.md`.

mod decode;
mod detect;
mod error;
mod open;

pub use decode::DecodeError;
pub use detect::{Container, Detected, HEAD_LEN, Layer, detect};
pub use error::Error;
pub use open::{Limits, Opened, Opener};
