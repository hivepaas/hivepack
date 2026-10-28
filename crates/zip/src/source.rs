//! What an archive is read from.
//!
//! libzip reads an archive through a `zip_source_t`, a stack of callbacks
//! with a position. The port reads through [`ReadAt`], reads at a position,
//! and [`Source`] keeps the position and the rules libzip's file and buffer
//! sources follow: port of the reading parts of `zip_source_seek.c`,
//! `zip_source_read.c`, `zip_source_tell.c`, `zip_source_stat.c` and
//! `zip_source_accept_empty.c`, with the commands of
//! `zip_source_file_common.c` and `zip_source_buffer.c`.

use std::io;

use crate::error::{Error, ErrorCode, Result};

/// Something an archive can be read from, at any position.
///
/// Reads may run in parallel: they take `&self`.
pub trait ReadAt {
    /// The length in bytes, read once when an archive is opened, as
    /// libzip's sources `stat` it.
    fn size(&self) -> io::Result<u64>;

    /// Reads bytes at `offset` into `buf`, as many as there are, up to its
    /// length. Fewer only at the end.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// Whether an empty source is an empty archive: `ZIP_SOURCE_ACCEPT_EMPTY`.
    /// libzip's file sources say no, so `zip_open` refuses an empty file as
    /// not a zip archive, and its buffer sources say yes.
    fn accept_empty(&self) -> bool {
        false
    }
}

impl ReadAt for [u8] {
    fn size(&self) -> io::Result<u64> {
        Ok(self.len() as u64)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(self.len());
        let n = buf.len().min(self.len() - start);
        buf[..n].copy_from_slice(&self[start..start + n]);
        Ok(n)
    }

    fn accept_empty(&self) -> bool {
        true
    }
}

impl ReadAt for Vec<u8> {
    fn size(&self) -> io::Result<u64> {
        self.as_slice().size()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.as_slice().read_at(offset, buf)
    }

    fn accept_empty(&self) -> bool {
        true
    }
}

impl<T: ReadAt + ?Sized> ReadAt for &T {
    fn size(&self) -> io::Result<u64> {
        (**self).size()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read_at(offset, buf)
    }

    fn accept_empty(&self) -> bool {
        (**self).accept_empty()
    }
}

#[cfg(any(unix, windows))]
impl ReadAt for std::fs::File {
    fn size(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let mut done = 0;
        while done < buf.len() {
            #[cfg(unix)]
            let n =
                std::os::unix::fs::FileExt::read_at(self, &mut buf[done..], offset + done as u64);
            #[cfg(windows)]
            let n = std::os::windows::fs::FileExt::seek_read(
                self,
                &mut buf[done..],
                offset + done as u64,
            );
            match n {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(done)
    }
}

/// Where a seek counts from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Whence {
    Set,
    Cur,
    End,
}

/// An archive's source while it is read: its length when opened, the
/// position, and whether a read has failed.
pub(crate) struct Source<R: ?Sized> {
    /// The length the source had when opened (`ctx->len`); reads stop
    /// there.
    size: u64,
    offset: u64,
    /// The error of a failed read: libzip's sources fail every read after
    /// one (`had_read_error`).
    read_error: Option<Error>,
    inner: R,
}

impl<R: ReadAt> Source<R> {
    /// The source, its length read: `zip_source_stat`.
    pub(crate) fn new(inner: R) -> Result<Source<R>> {
        let size = inner.size().map_err(read_error)?;
        Ok(Source {
            size,
            offset: 0,
            read_error: None,
            inner,
        })
    }
}

impl<R: ReadAt + ?Sized> Source<R> {
    /// `st.size` of `zip_source_stat`.
    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    /// `zip_source_accept_empty`.
    pub(crate) fn accept_empty(&self) -> bool {
        self.inner.accept_empty()
    }

    /// Moves the position: port of `zip_source_seek`, with
    /// `zip_source_seek_compute_offset` and `_zip_offset_add`. A position
    /// before the start or past the end is refused with `ZIP_ER_INVAL`.
    pub(crate) fn seek(&mut self, offset: i64, whence: Whence) -> Result<()> {
        let new_offset = match whence {
            Whence::Cur => offset_add(self.offset, offset),
            Whence::End => offset_add(self.size, offset),
            Whence::Set => u64::try_from(offset).ok().filter(|&o| o <= self.size),
        };
        match new_offset {
            Some(new_offset) if new_offset <= self.size => {
                self.offset = new_offset;
                Ok(())
            }
            _ => Err(Error::new(ErrorCode::Inval, 0)),
        }
    }

    /// `zip_source_tell`.
    pub(crate) fn tell(&self) -> u64 {
        self.offset
    }

    /// Reads up to `buf.len()` bytes, fewer only at the end: port of
    /// `zip_source_read`, and the file source's `ZIP_SOURCE_READ`, which
    /// stops at the length the file had when opened.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if let Some(error) = self.read_error {
            return Err(error);
        }
        let n = (buf.len() as u64).min(self.size - self.offset) as usize;
        let mut done = 0;
        while done < n {
            match self.inner.read_at(self.offset, &mut buf[done..n]) {
                Ok(0) => break,
                Ok(got) => {
                    done += got;
                    self.offset += got as u64;
                }
                Err(e) => {
                    let error = read_error(e);
                    self.read_error = Some(error);
                    if done == 0 {
                        return Err(error);
                    }
                    break;
                }
            }
        }
        Ok(done)
    }
}

/// `_zip_offset_add`: `None` where libzip gives `ZIP_UINT64_MAX`.
fn offset_add(offset: u64, delta: i64) -> Option<u64> {
    if delta >= 0 {
        let delta = delta as u64;
        if offset > i64::MAX as u64 - delta {
            return None;
        }
        Some(offset + delta)
    } else {
        offset.checked_sub(delta.unsigned_abs())
    }
}

/// A failed read, as the file source reports it: `ZIP_ER_READ` with
/// `errno`.
fn read_error(error: io::Error) -> Error {
    Error::new(ErrorCode::Read, error.raw_os_error().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeks_as_libzip() {
        let data = [0u8; 10];
        let mut src = Source::new(&data[..]).unwrap();
        assert!(src.seek(-4, Whence::End).is_ok());
        assert_eq!(src.tell(), 6);
        let mut buf = [0; 8];
        assert_eq!(src.read(&mut buf).ok(), Some(4));
        assert_eq!(src.read(&mut buf).ok(), Some(0));
        assert_eq!(
            src.seek(11, Whence::Set).map_err(|e| e.code()),
            Err(ErrorCode::Inval)
        );
        assert_eq!(
            src.seek(-11, Whence::End).map_err(|e| e.code()),
            Err(ErrorCode::Inval)
        );
        assert_eq!(
            src.seek(1, Whence::Cur).map_err(|e| e.code()),
            Err(ErrorCode::Inval)
        );
        assert!(src.seek(0, Whence::Set).is_ok());
        assert!(src.seek(i64::MIN, Whence::Cur).is_err());
    }
}
