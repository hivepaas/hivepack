//! Where a closed archive is written: the writing commands of a source as
//! `zip_close` uses them (`zip_source_write.c`, `zip_source_tell_write.c`,
//! `zip_source_seek_write.c` and `zip_source_commit_write.c`, with the
//! errors of libzip's file sources), on a [`Write`] and [`Seek`], and
//! `_zip_write` of `zip_io_util.c`.

use std::io::{self, Seek, SeekFrom, Write};

use hivepack_deflate::crc32;

use crate::error::{Error, ErrorCode, Result};

/// The output of `zip_close`, and the CRC-32 of what is written while it is
/// asked for (`za->write_crc`, for torrentzip's central directory).
pub(crate) struct Output<W> {
    w: W,
    pub write_crc: Option<u32>,
}

/// The error of a failed system call: `errno`, or 0 if it has none.
fn errno(error: &io::Error) -> i32 {
    error.raw_os_error().unwrap_or(0)
}

impl<W: Write + Seek> Output<W> {
    pub(crate) fn new(w: W) -> Output<W> {
        Output { w, write_crc: None }
    }

    /// The position: `zip_source_tell_write`.
    pub(crate) fn tell_write(&mut self) -> Result<u64> {
        self.w
            .stream_position()
            .map_err(|e| Error::new(ErrorCode::Tell, errno(&e)))
    }

    /// Moves to `offset`: `zip_source_seek_write` with `SEEK_SET`.
    pub(crate) fn seek_write(&mut self, offset: u64) -> Result<()> {
        self.w
            .seek(SeekFrom::Start(offset))
            .map(|_| ())
            .map_err(|e| Error::new(ErrorCode::Seek, errno(&e)))
    }

    /// Writes all of `data`: port of `_zip_write`.
    pub(crate) fn write(&mut self, data: &[u8]) -> Result<()> {
        self.w
            .write_all(data)
            .map_err(|e| Error::new(ErrorCode::Write, errno(&e)))?;
        if let Some(crc) = self.write_crc.as_mut() {
            *crc = crc32(*crc, data);
        }
        Ok(())
    }

    /// Writes what is buffered: `zip_source_commit_write`.
    pub(crate) fn commit_write(&mut self) -> Result<()> {
        self.w
            .flush()
            .map_err(|e| Error::new(ErrorCode::Write, errno(&e)))
    }
}
