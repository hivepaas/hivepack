//! Bounds-checked reads from a byte array: port of `zip_buffer.c`, the
//! reading half (the writer will need `_zip_buffer_put*`).
//!
//! A read past the end returns nothing and clears `ok`; later reads then
//! fail too, until `set_offset` moves the buffer back in bounds, as in
//! libzip. Reading a number past the end gives 0.

use std::borrow::Cow;

use crate::error::{Error, Result};
use crate::io_util::read;
use crate::source::{ReadAt, Source};

/// `zip_buffer_t`: the data, whether reads are still in bounds, and the
/// position of the next read.
pub(crate) struct Buffer<'a> {
    ok: bool,
    data: Cow<'a, [u8]>,
    offset: u64,
}

impl<'a> Buffer<'a> {
    /// A buffer over `data`: `_zip_buffer_new` with data.
    pub(crate) fn new(data: &'a [u8]) -> Buffer<'a> {
        Buffer {
            ok: true,
            data: Cow::Borrowed(data),
            offset: 0,
        }
    }

    /// `size` bytes read from `src` at its position: port of
    /// `_zip_buffer_new_from_source`.
    pub(crate) fn from_source<R: ReadAt + ?Sized>(
        src: &mut Source<R>,
        size: u64,
    ) -> Result<Buffer<'static>> {
        let Ok(len) = usize::try_from(size) else {
            return Err(Error::new(crate::ErrorCode::Memory, 0));
        };
        let mut data = vec![0; len];
        read(src, &mut data)?;
        Ok(Buffer {
            ok: true,
            data: Cow::Owned(data),
            offset: 0,
        })
    }

    /// All the data: `_zip_buffer_data`.
    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }

    /// Whether the buffer was read exactly to its end: `_zip_buffer_eof`.
    pub(crate) fn eof(&self) -> bool {
        self.ok && self.offset == self.size()
    }

    /// The next `length` bytes, or `None` past the end: `_zip_buffer_get`.
    pub(crate) fn get(&mut self, length: u64) -> Option<&[u8]> {
        let start = self.peek_start(length)?;
        self.offset += length;
        Some(&self.data[start..start + length as usize])
    }

    pub(crate) fn get_8(&mut self) -> u8 {
        self.get(1).map_or(0, |d| d[0])
    }

    pub(crate) fn get_16(&mut self) -> u16 {
        self.get(2).map_or(0, |d| u16::from_le_bytes([d[0], d[1]]))
    }

    pub(crate) fn get_32(&mut self) -> u32 {
        self.get(4)
            .map_or(0, |d| u32::from_le_bytes([d[0], d[1], d[2], d[3]]))
    }

    pub(crate) fn get_64(&mut self) -> u64 {
        self.get(8).map_or(0, |d| {
            u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
        })
    }

    /// The bytes left, or 0 once a read failed: `_zip_buffer_left`.
    pub(crate) fn left(&self) -> u64 {
        if self.ok {
            self.size() - self.offset
        } else {
            0
        }
    }

    /// The position, or 0 once a read failed: `_zip_buffer_offset`.
    pub(crate) fn offset(&self) -> u64 {
        if self.ok { self.offset } else { 0 }
    }

    /// `_zip_buffer_ok`.
    pub(crate) fn ok(&self) -> bool {
        self.ok
    }

    /// The next `length` bytes, without moving past them:
    /// `_zip_buffer_peek`.
    pub(crate) fn peek(&mut self, length: u64) -> Option<&[u8]> {
        let start = self.peek_start(length)?;
        Some(&self.data[start..start + length as usize])
    }

    fn peek_start(&mut self, length: u64) -> Option<usize> {
        match self.offset.checked_add(length) {
            Some(end) if self.ok && end <= self.size() => Some(self.offset as usize),
            _ => {
                self.ok = false;
                None
            }
        }
    }

    /// Moves to `offset`, which makes the buffer usable again if it is in
    /// bounds: `_zip_buffer_set_offset`.
    pub(crate) fn set_offset(&mut self, offset: u64) -> bool {
        if offset > self.size() {
            self.ok = false;
            return false;
        }
        self.ok = true;
        self.offset = offset;
        true
    }

    /// `_zip_buffer_skip`.
    pub(crate) fn skip(&mut self, length: u64) -> bool {
        match self.offset.checked_add(length) {
            Some(offset) => self.set_offset(offset),
            None => {
                self.ok = false;
                false
            }
        }
    }

    /// `_zip_buffer_size`.
    pub(crate) fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian_and_stops_at_the_end() {
        let data = [1, 2, 3, 4, 5, 6, 7];
        let mut buffer = Buffer::new(&data);
        assert_eq!(buffer.get_16(), 0x0201);
        assert_eq!(buffer.get_32(), 0x0605_0403);
        assert_eq!(buffer.get_16(), 0);
        assert!(!buffer.ok());
        assert_eq!((buffer.left(), buffer.offset()), (0, 0));
        assert_eq!(buffer.get_8(), 0);
        assert!(buffer.set_offset(6));
        assert_eq!(buffer.get_8(), 7);
        assert!(buffer.eof());
        assert!(!buffer.skip(u64::MAX));
    }
}
