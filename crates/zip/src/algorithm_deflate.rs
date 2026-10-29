//! Deflate through hivepack-deflate, whose inflate gives zlib's results:
//! port of `zip_algorithm_deflate.c`, the decompressing half.

use hivepack_deflate::{ErrorCode as ZErrorCode, Flush, InBuffer, Inflate, OutBuffer, Status};

use crate::error::{Error, ErrorCode};

/// `zip_compression_status_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompressionStatus {
    Ok,
    End,
    /// with the error the algorithm sets
    Error(Error),
    NeedData,
}

/// `struct ctx`, for decompressing: the stream, and the input it holds,
/// a range of the compression source's buffer.
pub(crate) struct DeflateDecompress {
    zstr: Option<Inflate>,
    end_of_input: bool,
    /// `next_in` and `avail_in`, as positions in the buffer given to
    /// `process`.
    next_in: usize,
    avail_in: usize,
}

impl DeflateDecompress {
    /// `decompress_allocate`.
    pub(crate) fn new() -> DeflateDecompress {
        DeflateDecompress {
            zstr: None,
            end_of_input: false,
            next_in: 0,
            avail_in: 0,
        }
    }

    /// `start`: a raw inflate stream (`windowBits` -15).
    pub(crate) fn start(&mut self) -> Result<(), Error> {
        self.next_in = 0;
        self.avail_in = 0;
        match Inflate::new(-15) {
            Ok(zstr) => {
                self.zstr = Some(zstr);
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorCode::Zlib, e.code().number())),
        }
    }

    /// `end`.
    pub(crate) fn end(&mut self) -> Result<(), Error> {
        self.zstr = None;
        Ok(())
    }

    /// `input`: `length` bytes at the start of the buffer.
    pub(crate) fn input(&mut self, length: usize) -> Result<(), Error> {
        if length as u64 > u64::from(u32::MAX) || self.avail_in > 0 {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        self.next_in = 0;
        self.avail_in = length;
        Ok(())
    }

    /// `end_of_input`: whether input is left over.
    pub(crate) fn end_of_input(&mut self) -> bool {
        self.end_of_input = true;
        self.avail_in != 0
    }

    /// `process`: inflates from `buffer` into `data` with `Z_SYNC_FLUSH`,
    /// returning the status and the bytes written.
    pub(crate) fn process(&mut self, buffer: &[u8], data: &mut [u8]) -> (CompressionStatus, usize) {
        let Some(zstr) = self.zstr.as_mut() else {
            return (
                CompressionStatus::Error(Error::new(ErrorCode::Internal, 0)),
                0,
            );
        };
        let avail_out = data.len().min(u32::MAX as usize);
        let mut output = OutBuffer::new(&mut data[..avail_out]);
        let mut input = InBuffer::new(&buffer[self.next_in..self.next_in + self.avail_in]);
        let ret = zstr.inflate(&mut output, &mut input, Flush::SyncFlush);
        self.next_in += input.pos;
        self.avail_in -= input.pos;
        let length = output.pos;

        let status = match ret {
            Ok(Status::Ok) => CompressionStatus::Ok,
            Ok(Status::StreamEnd) => CompressionStatus::End,
            Err(e) if e.code() == ZErrorCode::Buf && self.avail_in == 0 => {
                CompressionStatus::NeedData
            }
            Err(e) => CompressionStatus::Error(Error::new(ErrorCode::Zlib, e.code().number())),
            // A raw stream never asks for a dictionary.
            Ok(Status::NeedDict) => CompressionStatus::Error(Error::new(ErrorCode::Zlib, 2)),
        };
        (status, length)
    }
}
