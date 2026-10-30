//! .xz, .lzma and .lz decompression in safe Rust, ported from the official
//! library, liblzma of [XZ Utils](https://tukaani.org/xz/) 5.8.4.
//!
//! A [`Stream`] decodes as an `lzma_stream` does, with the decoder it was
//! made with: `.xz` ([`Stream::stream_decoder`]), `.lzma`
//! ([`Stream::alone_decoder`]), `.lz` ([`Stream::lzip_decoder`]), any of
//! them by their first byte ([`Stream::auto_decoder`]), or raw LZMA1 and
//! LZMA2 ([`Stream::raw_decoder`]). Each call gives liblzma's result and
//! reads and writes what liblzma reads and writes. The rules the port
//! follows, and how it is checked, are in the repository: `docs/xz.md` and
//! `docs/safety.md`.
//!
//! ```
//! # fn main() -> Result<(), hivepack_xz::Error> {
//! use hivepack_xz::{Action, InBuffer, OutBuffer, Status, Stream};
//!
//! // "hello\n" in an .xz Stream with a CRC64, as liblzma writes it.
//! let xz = [
//!     0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46,
//!     0x02, 0xc0, 0x0a, 0x06, 0x21, 0x01, 0x16, 0x00, 0xe2, 0x86, 0x15, 0xc0,
//!     0x01, 0x00, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x0a, 0x00, 0x00, 0x00,
//!     0xa5, 0x60, 0x97, 0xf1, 0x94, 0xf6, 0xfd, 0xe0, 0x00, 0x01, 0x1e, 0x06,
//!     0xc1, 0x2f, 0xa4, 0x1d, 0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0x00, 0x00, 0x00,
//!     0x00, 0x04, 0x59, 0x5a,
//! ];
//! let mut stream = Stream::stream_decoder(u64::MAX, 0)?;
//! let mut out = [0; 16];
//! let mut output = OutBuffer::new(&mut out);
//! let status = stream.code(&mut output, &mut InBuffer::new(&xz), Action::Finish)?;
//! assert_eq!(status, Status::StreamEnd);
//! let written = output.pos;
//! assert_eq!(&out[..written], b"hello\n");
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
// Loops keep liblzma's indices, so the port reads side by side with the C.
#![allow(clippy::needless_range_loop)]

mod alone_decoder;
mod auto_decoder;
mod block;
mod check;
mod common;
mod filter;
mod index_hash;
mod lz_decoder;
mod lzip_decoder;
mod lzma2_decoder;
mod lzma_common;
mod lzma_decoder;
mod range_decoder;
mod stream_decoder;
mod stream_flags;
mod vli;

use core::fmt;

pub use check::{CHECK_ID_MAX, Check};
pub use common::{
    Action, CONCATENATED, FAIL_FAST, IGNORE_CHECK, TELL_ANY_CHECK, TELL_NO_CHECK,
    TELL_UNSUPPORTED_CHECK,
};
pub use filter::{
    FILTER_LZMA1, FILTER_LZMA1EXT, FILTER_LZMA2, FILTERS_MAX, Filter, decoder_is_supported,
    raw_decoder_memusage,
};
pub use lzma_common::{DICT_SIZE_MIN, LCLP_MAX, LZMA1EXT_ALLOW_EOPM, LzmaOptions, PB_MAX};

use common::{Internal, Ret};

/// The XZ Utils release this crate follows.
pub const UPSTREAM_VERSION: &str = "5.8.4";

/// `lzma_version_number()`: `LZMA_VERSION` of the release the port
/// follows, 50080042 for 5.8.4 stable.
pub fn version_number() -> u32 {
    50_080_042
}

/// `lzma_version_string()`.
pub fn version_string() -> &'static str {
    "5.8.4"
}

/// The input of a call: `src[pos..]` is what may be read
/// (`next_in`/`avail_in`).
#[derive(Debug)]
pub struct InBuffer<'a> {
    pub src: &'a [u8],
    /// How much of `src` has been read. Each call moves it forward.
    pub pos: usize,
}

impl<'a> InBuffer<'a> {
    /// All of `src`, from its start.
    pub fn new(src: &'a [u8]) -> Self {
        InBuffer { src, pos: 0 }
    }
}

/// The output of a call: `dst[pos..]` is the space it may write
/// (`next_out`/`avail_out`).
#[derive(Debug)]
pub struct OutBuffer<'a> {
    pub dst: &'a mut [u8],
    /// How much of `dst` has been written. Each call moves it forward.
    pub pos: usize,
}

impl<'a> OutBuffer<'a> {
    /// All of `dst`, from its start.
    pub fn new(dst: &'a mut [u8]) -> Self {
        OutBuffer { dst, pos: 0 }
    }
}

/// Success, or something to know: liblzma's return codes that are not
/// errors, with the same numbers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Status {
    /// `LZMA_OK`: progress was made, and the stream goes on.
    Ok,
    /// `LZMA_STREAM_END`: the end of the stream.
    StreamEnd,
    /// `LZMA_NO_CHECK`: the Stream has no integrity check
    /// ([`TELL_NO_CHECK`]). Decoding can go on.
    NoCheck,
    /// `LZMA_UNSUPPORTED_CHECK`: the Stream's integrity check cannot be
    /// computed ([`TELL_UNSUPPORTED_CHECK`]). Decoding can go on.
    UnsupportedCheck,
    /// `LZMA_GET_CHECK`: [`Stream::get_check`] can now tell the Stream's
    /// integrity check ([`TELL_ANY_CHECK`]). Decoding can go on.
    GetCheck,
}

impl Status {
    /// The number liblzma gives this result.
    pub fn number(self) -> i32 {
        match self {
            Status::Ok => 0,
            Status::StreamEnd => 1,
            Status::NoCheck => 2,
            Status::UnsupportedCheck => 3,
            Status::GetCheck => 4,
        }
    }
}

/// liblzma's error codes, with the same numbers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum Error {
    /// `LZMA_MEM_ERROR`: not enough memory.
    Mem = 5,
    /// `LZMA_MEMLIMIT_ERROR`: the memory usage limit was reached. Not
    /// fatal: decoding goes on once [`Stream::memlimit_set`] raises it.
    Memlimit = 6,
    /// `LZMA_FORMAT_ERROR`: the input is not in the format of the decoder.
    Format = 7,
    /// `LZMA_OPTIONS_ERROR`: an option or a feature is not supported.
    Options = 8,
    /// `LZMA_DATA_ERROR`: the data is corrupt.
    Data = 9,
    /// `LZMA_BUF_ERROR`: no progress was possible, twice in a row.
    Buf = 10,
    /// `LZMA_PROG_ERROR`: the calls were not as liblzma allows.
    Prog = 11,
}

impl Error {
    /// The number liblzma gives this error.
    pub fn number(self) -> i32 {
        self as i32
    }

    /// A short description of the error.
    pub fn message(self) -> &'static str {
        match self {
            Error::Mem => "cannot allocate memory",
            Error::Memlimit => "memory usage limit reached",
            Error::Format => "file format not recognized",
            Error::Options => "unsupported options",
            Error::Data => "compressed data is corrupt",
            Error::Buf => "unexpected end of input",
            Error::Prog => "programming error",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl core::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

/// liblzma's return code as the port returns it.
fn result(ret: Ret) -> Result<Status> {
    match ret {
        Ret::Ok => Ok(Status::Ok),
        Ret::StreamEnd => Ok(Status::StreamEnd),
        Ret::NoCheck => Ok(Status::NoCheck),
        Ret::UnsupportedCheck => Ok(Status::UnsupportedCheck),
        Ret::GetCheck => Ok(Status::GetCheck),
        Ret::MemError => Err(Error::Mem),
        Ret::MemlimitError => Err(Error::Memlimit),
        Ret::FormatError => Err(Error::Format),
        Ret::OptionsError => Err(Error::Options),
        Ret::DataError => Err(Error::Data),
        Ret::BufError => Err(Error::Buf),
        Ret::ProgError => Err(Error::Prog),
    }
}

/// An error code where initialization failed.
fn init_error(ret: Ret) -> Error {
    match result(ret) {
        Err(e) => e,
        Ok(_) => Error::Prog,
    }
}

/// An `lzma_stream` with its decoder, made by one of liblzma's
/// initialization functions.
pub struct Stream {
    internal: Internal,
}

// A stream can be moved to another thread.
const _: fn() = || {
    fn send<T: Send>() {}
    send::<Stream>();
};

impl Stream {
    fn new(next: Box<dyn common::NextCoder>) -> Stream {
        Stream {
            internal: Internal::new(next, &[Action::Run, Action::Finish]),
        }
    }

    /// `lzma_stream_decoder`: a .xz decoder, with a memory usage limit and
    /// the flags [`TELL_NO_CHECK`], [`TELL_UNSUPPORTED_CHECK`],
    /// [`TELL_ANY_CHECK`], [`IGNORE_CHECK`], [`CONCATENATED`] and
    /// [`FAIL_FAST`] (which only the multithreaded decoder uses).
    pub fn stream_decoder(memlimit: u64, flags: u32) -> Result<Stream> {
        let decoder = stream_decoder::StreamDecoder::new(memlimit, flags).map_err(init_error)?;
        Ok(Stream::new(Box::new(decoder)))
    }

    /// `lzma_alone_decoder`: a .lzma decoder, with a memory usage limit.
    pub fn alone_decoder(memlimit: u64) -> Result<Stream> {
        Ok(Stream::new(Box::new(alone_decoder::AloneDecoder::new(
            memlimit, false,
        ))))
    }

    /// `lzma_lzip_decoder`: a .lz decoder, with a memory usage limit and
    /// the flags of [`Stream::stream_decoder`].
    pub fn lzip_decoder(memlimit: u64, flags: u32) -> Result<Stream> {
        let decoder = lzip_decoder::LzipDecoder::new(memlimit, flags).map_err(init_error)?;
        Ok(Stream::new(Box::new(decoder)))
    }

    /// `lzma_auto_decoder`: a decoder of .xz, .lzma or .lz, whichever the
    /// first byte says.
    pub fn auto_decoder(memlimit: u64, flags: u32) -> Result<Stream> {
        let decoder = auto_decoder::AutoDecoder::new(memlimit, flags).map_err(init_error)?;
        Ok(Stream::new(Box::new(decoder)))
    }

    /// `lzma_raw_decoder`: a decoder of the raw data of a filter chain.
    pub fn raw_decoder(filters: &[Filter]) -> Result<Stream> {
        let next = filter::raw_decoder_init(filters).map_err(init_error)?;
        Ok(Stream::new(next))
    }

    /// `lzma_code`: reads what it can of `input` and writes what it can to
    /// `output`.
    ///
    /// Differs from liblzma: there are no null pointers to check, nor
    /// reserved members, but a buffer whose `pos` is past its end fails
    /// with [`Error::Prog`].
    pub fn code(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        action: Action,
    ) -> Result<Status> {
        if output.pos > output.dst.len() || input.pos > input.src.len() {
            return Err(Error::Prog);
        }
        result(self.internal.code(
            input.src,
            &mut input.pos,
            output.dst,
            &mut output.pos,
            action,
        ))
    }

    /// `lzma_get_check`: the integrity check of the Stream, once its header
    /// is decoded; `Check::NONE` where the decoder cannot tell.
    pub fn get_check(&self) -> Check {
        self.internal.get_check()
    }

    /// `lzma_memusage`: the memory the decoder needs now, as liblzma
    /// counts it; 0 where it cannot tell.
    pub fn memusage(&mut self) -> u64 {
        self.internal.memconfig_get().0
    }

    /// `lzma_memlimit_get`: the memory usage limit; 0 where the decoder has
    /// none.
    pub fn memlimit_get(&mut self) -> u64 {
        self.internal.memconfig_get().1
    }

    /// `lzma_memlimit_set`: a new memory usage limit (0 counts as 1).
    pub fn memlimit_set(&mut self, new_memlimit: u64) -> Result<()> {
        result(self.internal.memlimit_set(new_memlimit)).map(|_| ())
    }

    /// `lzma_get_progress`: the input read and output written so far.
    pub fn get_progress(&self) -> (u64, u64) {
        self.internal.get_progress()
    }

    /// `total_in`: the bytes read so far.
    pub fn total_in(&self) -> u64 {
        self.internal.total_in
    }

    /// `total_out`: the bytes written so far.
    pub fn total_out(&self) -> u64 {
        self.internal.total_out
    }
}

impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stream")
            .field("total_in", &self.internal.total_in)
            .field("total_out", &self.internal.total_out)
            .finish_non_exhaustive()
    }
}
