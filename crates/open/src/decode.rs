//! The decompressors as `io::Read`: zstd, xz (and lzip and .lzma), gzip and
//! bzip2, each over hivepack's port of its library.
//!
//! A file can hold several streams one after the other, as their tools
//! make and read them: zstd frames (skippable ones too), gzip members,
//! bzip2 streams (pbzip2 writes one per block), xz streams with their
//! padding, lzip members. After the last, gzip and bzip2 allow zeros, which
//! tar's blocking leaves; lzip allows anything, as its format says, which
//! is read and ignored. Anything else after a stream is an error, as is a
//! stream cut short.

use std::io::{self, Read};

use crate::detect::Layer;

/// An error of a layer's data, inside the `io::Error` a read returns.
#[derive(Debug)]
pub struct DecodeError {
    /// The layer whose data failed.
    pub layer: Layer,
    /// What its library said.
    pub message: String,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.layer, self.message)
    }
}

impl std::error::Error for DecodeError {}

/// What a step of a codec did.
#[derive(Default)]
struct Step {
    consumed: usize,
    produced: usize,
    /// A stream (a frame, a member) ended.
    ended: bool,
    /// The data failed: what was produced before is given out first, as
    /// the tools write it before they stop.
    error: Option<String>,
}

/// A decompressor, a step at a time.
trait Codec {
    /// From `input` into `output`; `finish` once the input has no more.
    fn step(&mut self, input: &[u8], output: &mut [u8], finish: bool) -> Step;

    /// After a stream ended: whether `next`, the bytes after it (as many
    /// as [`MAGIC_LEN`] when there are), starts another, which is begun.
    fn restart(&mut self, _next: &[u8]) -> bool {
        false
    }

    /// What may follow the last stream.
    fn after_last(&self) -> After {
        After::Nothing
    }
}

/// What may follow the last stream.
#[derive(Clone, Copy, PartialEq, Eq)]
enum After {
    Nothing,
    Zeros,
    /// Anything, read to its end and ignored, so that the layers around
    /// are read to theirs.
    Anything,
}

/// The bytes [`Codec::restart`] looks at.
const MAGIC_LEN: usize = 6;

const BUFFER: usize = 64 * 1024;

/// A codec over a reader.
struct Decoder<R, C> {
    inner: R,
    codec: C,
    layer: Layer,
    buf: Box<[u8]>,
    start: usize,
    end: usize,
    eof: bool,
    /// The last stream ended, and nothing follows yet.
    ended: bool,
    done: bool,
    /// The error every later read returns.
    failed: Option<String>,
}

impl<R: Read, C: Codec> Decoder<R, C> {
    fn new(inner: R, codec: C, layer: Layer) -> Decoder<R, C> {
        Decoder {
            inner,
            codec,
            layer,
            buf: vec![0; BUFFER].into_boxed_slice(),
            start: 0,
            end: 0,
            eof: false,
            ended: false,
            done: false,
            failed: None,
        }
    }

    fn error(&mut self, message: String) -> io::Error {
        self.failed = Some(message.clone());
        io::Error::new(
            io::ErrorKind::InvalidData,
            DecodeError {
                layer: self.layer,
                message,
            },
        )
    }

    /// At least `want` bytes in the buffer, unless the input ends first.
    fn fill(&mut self, want: usize) -> io::Result<()> {
        if self.end - self.start >= want || self.eof {
            return Ok(());
        }
        // Move what is left to the start.
        self.buf.copy_within(self.start..self.end, 0);
        self.end -= self.start;
        self.start = 0;
        while self.end - self.start < want && !self.eof {
            match self.inner.read(&mut self.buf[self.end..]) {
                Ok(0) => self.eof = true,
                Ok(n) => self.end += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// After a stream: another, what may follow the last ([`After`]), or
    /// an error.
    fn after_stream(&mut self) -> io::Result<()> {
        self.fill(MAGIC_LEN)?;
        if self.start == self.end {
            self.done = true;
            return Ok(());
        }
        if self.codec.restart(&self.buf[self.start..self.end]) {
            self.ended = false;
            return Ok(());
        }
        if self.codec.after_last() == After::Anything {
            while self.start < self.end {
                self.start = self.end;
                self.fill(1)?;
            }
            self.done = true;
            return Ok(());
        }
        if self.codec.after_last() == After::Zeros {
            loop {
                if self.buf[self.start..self.end].iter().any(|&c| c != 0) {
                    break;
                }
                self.start = self.end;
                self.fill(1)?;
                if self.start == self.end {
                    self.done = true;
                    return Ok(());
                }
            }
        }
        Err(self.error("trailing data after the end of the stream".into()))
    }
}

impl<R: Read, C: Codec> Read for Decoder<R, C> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if let Some(message) = &self.failed {
            let message = message.clone();
            return Err(self.error(message));
        }
        if out.is_empty() || self.done {
            return Ok(0);
        }
        loop {
            if self.ended {
                self.after_stream()?;
                if self.done {
                    return Ok(0);
                }
            }
            self.fill(1)?;
            let finish = self.eof;
            let step = self
                .codec
                .step(&self.buf[self.start..self.end], out, finish);
            self.start += step.consumed;
            if let Some(e) = step.error {
                if step.produced > 0 {
                    self.failed = Some(e);
                    return Ok(step.produced);
                }
                return Err(self.error(e));
            }
            if step.ended {
                self.ended = true;
            }
            if step.produced > 0 {
                return Ok(step.produced);
            }
            if step.ended {
                continue;
            }
            if step.consumed == 0 && self.start == self.end && self.eof {
                return Err(self.error("the stream is cut short".into()));
            }
            if step.consumed == 0 && self.start < self.end {
                // Input there, room for output, and no progress.
                return Err(self.error("no progress".into()));
            }
        }
    }
}

/// zstd: a context that goes on from one frame to the next.
struct ZstdCodec {
    dctx: hivepack_zstd::DCtx,
}

impl Codec for ZstdCodec {
    fn step(&mut self, input: &[u8], output: &mut [u8], _finish: bool) -> Step {
        let mut i = hivepack_zstd::InBuffer::new(input);
        let mut o = hivepack_zstd::OutBuffer::new(output);
        let result = self.dctx.decompress_stream(&mut o, &mut i);
        let mut step = Step {
            consumed: i.pos,
            produced: o.pos,
            ..Step::default()
        };
        match result {
            Ok(hint) => step.ended = hint == 0,
            Err(e) => step.error = Some(e.to_string()),
        }
        step
    }

    fn restart(&mut self, next: &[u8]) -> bool {
        // Another frame, or a skippable one: the context reads on.
        let frame = next.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]);
        let skippable =
            next.len() >= 4 && next[0] & 0xF0 == 0x50 && next[1..4] == [0x2A, 0x4D, 0x18];
        frame || skippable
    }
}

/// gzip: members one after the other, zeros after them.
struct GzipCodec {
    z: hivepack_deflate::Inflate,
}

impl Codec for GzipCodec {
    fn step(&mut self, input: &[u8], output: &mut [u8], _finish: bool) -> Step {
        let mut i = hivepack_deflate::InBuffer::new(input);
        let mut o = hivepack_deflate::OutBuffer::new(output);
        let status = self
            .z
            .inflate(&mut o, &mut i, hivepack_deflate::Flush::NoFlush);
        let mut step = Step {
            consumed: i.pos,
            produced: o.pos,
            ..Step::default()
        };
        match status {
            Ok(hivepack_deflate::Status::StreamEnd) => step.ended = true,
            Ok(hivepack_deflate::Status::Ok) => {}
            Ok(hivepack_deflate::Status::NeedDict) => {
                step.error = Some("needs a dictionary".into())
            }
            Err(e) if e.code() == hivepack_deflate::ErrorCode::Buf => {}
            Err(e) => step.error = Some(e.to_string()),
        }
        step
    }

    fn restart(&mut self, next: &[u8]) -> bool {
        if next.starts_with(&[0x1F, 0x8B]) {
            self.z.reset();
            return true;
        }
        false
    }

    fn after_last(&self) -> After {
        After::Zeros
    }
}

/// bzip2: streams one after the other, zeros after them.
struct Bzip2Codec {
    d: hivepack_bzip2::Decompress,
}

impl Codec for Bzip2Codec {
    fn step(&mut self, input: &[u8], output: &mut [u8], _finish: bool) -> Step {
        let mut i = hivepack_bzip2::InBuffer::new(input);
        let mut o = hivepack_bzip2::OutBuffer::new(output);
        let result = self.d.decompress(&mut o, &mut i);
        let mut step = Step {
            consumed: i.pos,
            produced: o.pos,
            ..Step::default()
        };
        match result {
            Ok(status) => step.ended = status == hivepack_bzip2::Status::StreamEnd,
            Err(e) => step.error = Some(e.to_string()),
        }
        step
    }

    fn restart(&mut self, next: &[u8]) -> bool {
        if next.len() >= 4 && next.starts_with(b"BZh") && (b'1'..=b'9').contains(&next[3]) {
            self.d = hivepack_bzip2::Decompress::new(false);
            return true;
        }
        false
    }

    fn after_last(&self) -> After {
        After::Zeros
    }
}

/// xz, lzip and .lzma: liblzma's decoders, xz's and lzip's concatenated
/// streams read by the decoder itself.
struct XzCodec {
    s: hivepack_xz::Stream,
    after: After,
}

impl Codec for XzCodec {
    fn step(&mut self, input: &[u8], output: &mut [u8], finish: bool) -> Step {
        let mut i = hivepack_xz::InBuffer::new(input);
        let mut o = hivepack_xz::OutBuffer::new(output);
        let action = if finish {
            hivepack_xz::Action::Finish
        } else {
            hivepack_xz::Action::Run
        };
        let result = self.s.code(&mut o, &mut i, action);
        let mut step = Step {
            consumed: i.pos,
            produced: o.pos,
            ..Step::default()
        };
        match result {
            Ok(status) => step.ended = status == hivepack_xz::Status::StreamEnd,
            Err(hivepack_xz::Error::Buf) => {}
            Err(e) => step.error = Some(e.to_string()),
        }
        step
    }

    fn after_last(&self) -> After {
        self.after
    }
}

/// The limits of the decoders.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DecodeLimits {
    pub(crate) zstd_window_log_max: u32,
    pub(crate) xz_memlimit: u64,
}

/// The decoder of `layer` over `inner`.
pub(crate) fn decoder<'a, R: Read + Send + 'a>(
    layer: Layer,
    inner: R,
    limits: DecodeLimits,
) -> io::Result<Box<dyn Read + Send + 'a>> {
    let invalid = |e: String| io::Error::new(io::ErrorKind::InvalidInput, e);
    Ok(match layer {
        Layer::Zstd => {
            let mut dctx = hivepack_zstd::DCtx::new();
            dctx.set_parameter(hivepack_zstd::DParameter::WindowLogMax(
                limits.zstd_window_log_max,
            ))
            .map_err(|e| invalid(e.to_string()))?;
            Box::new(Decoder::new(inner, ZstdCodec { dctx }, layer))
        }
        Layer::Gzip => {
            let z = hivepack_deflate::Inflate::new(16 + 15).map_err(|e| invalid(e.to_string()))?;
            Box::new(Decoder::new(inner, GzipCodec { z }, layer))
        }
        Layer::Bzip2 => Box::new(Decoder::new(
            inner,
            Bzip2Codec {
                d: hivepack_bzip2::Decompress::new(false),
            },
            layer,
        )),
        Layer::Xz | Layer::Lzip | Layer::Lzma => {
            let flags = hivepack_xz::CONCATENATED;
            let s = match layer {
                Layer::Xz => hivepack_xz::Stream::stream_decoder(limits.xz_memlimit, flags),
                Layer::Lzip => hivepack_xz::Stream::lzip_decoder(limits.xz_memlimit, flags),
                _ => hivepack_xz::Stream::alone_decoder(limits.xz_memlimit),
            }
            .map_err(|e| invalid(e.to_string()))?;
            // lzip and xz ignore what follows a .lz file's last member.
            let after = if layer == Layer::Lzip {
                After::Anything
            } else {
                After::Nothing
            };
            Box::new(Decoder::new(inner, XzCodec { s, after }, layer))
        }
        Layer::Age => return Err(invalid("age is not a compressor".into())),
    })
}
