//! Port of `zip_file_get_offset.c`, its first function.

use crate::dirent::dirent_size;
use crate::error::{Error, ErrorCode, Result};
use crate::extra_field::EFBIG;
use crate::open::Archive;
use crate::source::{ReadAt, Whence};

impl<R: ReadAt> Archive<R> {
    /// Where the data of entry `idx` starts, past its local header: port of
    /// `_zip_file_get_offset`.
    pub fn file_get_offset(&mut self, idx: u64) -> Result<u64> {
        let Some(orig) = self
            .entry
            .get(usize::try_from(idx).unwrap_or(usize::MAX))
            .and_then(|e| e.orig.as_deref())
        else {
            return Err(Error::new(ErrorCode::Internal, 0));
        };
        let offset = orig.offset;

        self.src.seek(offset as i64, Whence::Set)?;

        let size = dirent_size(&mut self.src, true)?;

        if offset + u64::from(size) > i64::MAX as u64 {
            return Err(Error::new(ErrorCode::Seek, EFBIG));
        }

        Ok(offset + u64::from(size))
    }
}
