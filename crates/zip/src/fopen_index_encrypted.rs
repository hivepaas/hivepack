//! Port of `zip_fopen_index_encrypted.c`, with `zip_file_t`.

use crate::error::{Error, Result};
use crate::open::Archive;
use crate::source::ReadAt;
use crate::source_stack::Stack;
use crate::zip::Flags;

/// An entry open for reading: `zip_file_t`. It reads through
/// [`ZipFile::fread`] or [`std::io::Read`], and, at the end of an entry
/// read whole, checks its CRC-32 and length.
pub struct ZipFile<'a, R: ?Sized> {
    /// error information
    pub(crate) error: Error,
    /// data source, until closed
    pub(crate) src: Option<Stack<'a, R>>,
}

impl<R: ReadAt> Archive<R> {
    /// Opens `len` bytes of entry `index` from byte `start` (or all from
    /// there, if `len` is `None`) for reading, decompressed: port of
    /// `zip_source_zip_file_create` with `start` and `len`, then
    /// `zip_source_open`. A part of the data has no CRC-32 to
    /// check; all of it, from 0 with `len` its size, is checked as
    /// [`Archive::fopen_index`] checks it.
    pub fn fopen_index_range(
        &self,
        index: u64,
        flags: Flags,
        start: u64,
        len: Option<u64>,
    ) -> Result<ZipFile<'_, R>> {
        let len = match len {
            None => -1,
            Some(len) => match i64::try_from(len) {
                Ok(len) => len,
                Err(_) => return Err(Error::new(crate::ErrorCode::Inval, 0)),
            },
        };
        let mut src = self.source_zip_file_create(index, flags, start, len, None)?;
        src.open()?;
        Ok(ZipFile {
            error: Error::OK,
            src: Some(src),
        })
    }

    /// Opens entry `index` for reading with a password: port of
    /// `zip_fopen_index_encrypted`. An empty password is none.
    ///
    /// Differs from libzip: decryption comes later; an encrypted entry is
    /// refused (see [`Archive::fopen_index`]).
    pub fn fopen_index_encrypted(
        &self,
        index: u64,
        flags: Flags,
        password: Option<&[u8]>,
    ) -> Result<ZipFile<'_, R>> {
        let password = password.filter(|p| !p.is_empty());
        let mut src = self.source_zip_file_create(index, flags, 0, -1, password)?;
        src.open()?;
        Ok(ZipFile {
            error: Error::OK,
            src: Some(src),
        })
    }
}
