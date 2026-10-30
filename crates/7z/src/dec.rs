//! Decoding a folder: `7zDec.c`.
//!
//! Differs from the LZMA SDK, whose decoder writes a whole folder into one
//! buffer, then runs its filter over it: the port's folder is a reader,
//! which decodes as much as it is asked for, so that a solid folder of any
//! size can be read in pieces. Its checks are the SDK's, made when each
//! stream ends rather than when the whole buffer is decoded. LZMA and LZMA2
//! are decoded by `hivepack-xz`, a port of liblzma's decoders, rather than
//! by the SDK's `LzmaDec.c`: the output is the same, but liblzma takes no
//! LZMA properties with `lc + lp` above 4 (7-Zip's encoder makes them only
//! when asked), which are then `SZ_ERROR_UNSUPPORTED`, and on damaged data
//! either may stop at another byte, with the same error.

use std::io::{Read, Seek};

use hivepack_xz::{
    Action, FILTER_LZMA1EXT, Filter, FilterOptions, InBuffer, LZMA1EXT_ALLOW_EOPM, LzmaOptions,
    OutBuffer, Status, Stream,
};

use crate::arc_in::{self, Ar, Folder, Sd};
use crate::bcj2::{self, Bcj2Dec, Delta};
use crate::bra;
use crate::error::{Error, Result};

/// `k_Copy`.
const K_COPY: u32 = 0;
/// `k_LZMA2`.
const K_LZMA2: u32 = 0x21;
/// `k_LZMA`.
const K_LZMA: u32 = 0x30101;
/// `k_BCJ2`.
const K_BCJ2: u32 = 0x303011B;
/// `k_ARM64`.
const K_ARM64: u32 = 0xa;
/// `k_ARMT`.
const K_ARMT: u32 = 0x3030701;
/// `k_Delta`.
const K_DELTA: u32 = 3;
/// `k_RISCV`.
const K_RISCV: u32 = 0xb;
/// `k_BCJ`.
const K_BCJ: u32 = 0x3030103;
/// `k_PPC`.
const K_PPC: u32 = 0x3030205;
/// `k_IA64`.
const K_IA64: u32 = 0x3030401;
/// `k_ARM`.
const K_ARM: u32 = 0x3030501;
/// `k_SPARC`.
const K_SPARC: u32 = 0x3030805;

/// How much of a packed stream is read at a time.
const PACK_BUF_SIZE: usize = 1 << 16;

/// `IS_MAIN_METHOD`.
fn is_main_method(m: u32) -> bool {
    matches!(m, K_COPY | K_LZMA | K_LZMA2)
}

/// `IS_SUPPORTED_CODER`.
fn is_supported_coder(c: &arc_in::CoderInfo) -> bool {
    c.num_streams == 1 && is_main_method(c.method_id)
}

/// `IS_BCJ2`.
fn is_bcj2(c: &arc_in::CoderInfo) -> bool {
    c.method_id == K_BCJ2 && c.num_streams == 4
}

/// `CheckSupportedFolder`.
fn check_supported_folder(f: &Folder) -> Result<()> {
    if f.num_coders < 1 || f.num_coders > 4 {
        return Err(Error::Unsupported);
    }
    if !is_supported_coder(&f.coders[0]) {
        return Err(Error::Unsupported);
    }
    if f.num_coders == 1 {
        if f.num_pack_streams != 1 || f.pack_streams[0] != 0 || f.num_bonds != 0 {
            return Err(Error::Unsupported);
        }
        return Ok(());
    }
    if f.num_coders == 2 {
        let c = &f.coders[1];
        if c.num_streams != 1
            || f.num_pack_streams != 1
            || f.pack_streams[0] != 0
            || f.num_bonds != 1
            || f.bonds[0].in_index != 1
            || f.bonds[0].out_index != 0
        {
            return Err(Error::Unsupported);
        }
        return match c.method_id {
            K_DELTA | K_BCJ | K_PPC | K_IA64 | K_SPARC | K_ARM | K_RISCV | K_ARM64 | K_ARMT => {
                Ok(())
            }
            _ => Err(Error::Unsupported),
        };
    }
    if f.num_coders == 4 {
        if !is_supported_coder(&f.coders[1])
            || !is_supported_coder(&f.coders[2])
            || !is_bcj2(&f.coders[3])
        {
            return Err(Error::Unsupported);
        }
        if f.num_pack_streams != 4
            || f.pack_streams[0] != 2
            || f.pack_streams[1] != 6
            || f.pack_streams[2] != 1
            || f.pack_streams[3] != 0
            || f.num_bonds != 3
            || f.bonds[0].in_index != 5
            || f.bonds[0].out_index != 0
            || f.bonds[1].in_index != 4
            || f.bonds[1].out_index != 1
            || f.bonds[2].in_index != 3
            || f.bonds[2].out_index != 2
        {
            return Err(Error::Unsupported);
        }
        return Ok(());
    }
    Err(Error::Unsupported)
}

/// A packed stream: a range of the archive, read through a buffer of its
/// own, so that several can be read in turns.
struct PackReader {
    pos: u64,
    end: u64,
    buf: Vec<u8>,
    start: usize,
    len: usize,
}

impl PackReader {
    fn new(pos: u64, size: u64) -> Self {
        PackReader {
            pos,
            end: pos.saturating_add(size),
            buf: Vec::new(),
            start: 0,
            len: 0,
        }
    }

    /// What is left of the stream, read or not.
    fn remaining(&self) -> u64 {
        (self.len - self.start) as u64 + (self.end - self.pos)
    }

    /// The buffered bytes, read from the archive when there are none; empty
    /// at the stream's end. A short archive is `eof`.
    fn fill<R: Read + Seek>(&mut self, r: &mut R, eof: Error) -> Result<&[u8]> {
        if self.start == self.len && self.pos < self.end {
            if self.buf.is_empty() {
                self.buf = vec![0; PACK_BUF_SIZE];
            }
            let want = (self.end - self.pos).min(PACK_BUF_SIZE as u64) as usize;
            arc_in::seek_to(r, self.pos)?;
            let mut got = 0;
            while got < want {
                match r.read(&mut self.buf[got..want]) {
                    Ok(0) => break,
                    Ok(n) => got += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => return Err(Error::Read),
                }
            }
            if got == 0 {
                return Err(eof);
            }
            self.pos += got as u64;
            self.start = 0;
            self.len = got;
        }
        Ok(&self.buf[self.start..self.len])
    }

    fn consume(&mut self, n: usize) {
        self.start += n;
    }
}

/// A main method: a packed stream decoded into `out_size` bytes.
enum Main {
    /// `SzDecodeCopy`.
    Copy,
    /// `SzDecodeLzma` and `SzDecodeLzma2`.
    Lzma(Box<Stream>),
}

struct MainCoder {
    method: Main,
    input: PackReader,
    out_size: u64,
    out_pos: u64,
    /// liblzma's decoder has ended its stream.
    ended: bool,
}

/// `LzmaProps_Decode`'s checks, and the decoder for them. The dictionary
/// needs to be no larger than the output.
fn lzma_decoder(props: &[u8], out_size: u64, lzma2: bool) -> Result<Stream> {
    let dict_cap = out_size.clamp(4096, u64::from(u32::MAX)) as u32;
    let filter = if lzma2 {
        // SzDecodeLzma2, Lzma2Dec_AllocateProbs.
        if props.len() != 1 {
            return Err(Error::Data);
        }
        let prop = u32::from(props[0]);
        if prop > 40 {
            return Err(Error::Unsupported);
        }
        let dict_size = if prop == 40 {
            u32::MAX
        } else {
            (2 | (prop & 1)) << (prop / 2 + 11)
        };
        let options = LzmaOptions {
            dict_size: dict_size.min(dict_cap).max(4096),
            ..LzmaOptions::preset(0).ok_or(Error::Fail)?
        };
        Filter::lzma2(options)
    } else {
        // LzmaDec_AllocateProbs, LzmaProps_Decode.
        if props.len() < 5 {
            return Err(Error::Unsupported);
        }
        let mut dict_size = u32::from_le_bytes([props[1], props[2], props[3], props[4]]);
        if dict_size < 4096 {
            dict_size = 4096;
        }
        let mut d = u32::from(props[0]);
        if d >= 9 * 5 * 5 {
            return Err(Error::Unsupported);
        }
        let lc = d % 9;
        d /= 9;
        let pb = d / 5;
        let lp = d % 5;
        if lc + lp > 4 {
            return Err(Error::Unsupported);
        }
        let options = LzmaOptions {
            dict_size: dict_size.min(dict_cap).max(4096),
            lc,
            lp,
            pb,
            ext_flags: LZMA1EXT_ALLOW_EOPM,
            ext_size_low: out_size as u32,
            ext_size_high: (out_size >> 32) as u32,
            ..LzmaOptions::preset(0).ok_or(Error::Fail)?
        };
        Filter {
            id: FILTER_LZMA1EXT,
            options: Some(FilterOptions::Lzma(options)),
        }
    };
    Stream::raw_decoder(&[filter]).map_err(|e| match e {
        hivepack_xz::Error::Mem => Error::Mem,
        _ => Error::Unsupported,
    })
}

impl MainCoder {
    fn new(method_id: u32, props: &[u8], pos: u64, in_size: u64, out_size: u64) -> Result<Self> {
        let method = match method_id {
            K_COPY => {
                // Check it.
                if in_size != out_size {
                    return Err(Error::Data);
                }
                Main::Copy
            }
            K_LZMA => Main::Lzma(Box::new(lzma_decoder(props, out_size, false)?)),
            K_LZMA2 => Main::Lzma(Box::new(lzma_decoder(props, out_size, true)?)),
            _ => return Err(Error::Unsupported),
        };
        Ok(MainCoder {
            method,
            input: PackReader::new(pos, in_size),
            out_size,
            out_pos: 0,
            ended: false,
        })
    }

    /// Up to `out.len()` bytes; 0 at the end of the output, once the input
    /// is checked to end there too.
    fn read<R: Read + Seek>(&mut self, r: &mut R, out: &mut [u8]) -> Result<usize> {
        let want = (out.len() as u64).min(self.out_size - self.out_pos) as usize;
        if want == 0 {
            if !out.is_empty() {
                self.finish(r)?;
            }
            return Ok(0);
        }
        let out = &mut out[..want];
        match &mut self.method {
            Main::Copy => {
                let buf = self.input.fill(r, Error::InputEof)?;
                let n = buf.len().min(want);
                out[..n].copy_from_slice(&buf[..n]);
                self.input.consume(n);
                self.out_pos += n as u64;
                Ok(n)
            }
            Main::Lzma(stream) => loop {
                let buf = if self.input.remaining() == 0 {
                    &[][..]
                } else {
                    self.input.fill(r, Error::Data)?
                };
                let mut input = InBuffer::new(buf);
                let mut output = OutBuffer::new(out);
                let action = if buf.is_empty() {
                    Action::Finish
                } else {
                    Action::Run
                };
                let status = stream
                    .code(&mut output, &mut input, action)
                    .map_err(|e| match e {
                        hivepack_xz::Error::Mem => Error::Mem,
                        _ => Error::Data,
                    })?;
                let (read, written) = (input.pos, output.pos);
                self.input.consume(read);
                self.out_pos += written as u64;
                if status == Status::StreamEnd {
                    self.ended = true;
                    if self.out_pos != self.out_size {
                        return Err(Error::Data);
                    }
                }
                if written > 0 {
                    return Ok(written);
                }
                if self.ended || read == 0 {
                    // No progress.
                    return Err(Error::Data);
                }
            },
        }
    }

    /// The checks at the end of the output: all of the input read, and, for
    /// LZMA, the end of its stream.
    fn finish<R: Read + Seek>(&mut self, r: &mut R) -> Result<()> {
        if let Main::Lzma(stream) = &mut self.method
            && !self.ended
        {
            // The decoder stops at the size: an end marker may follow.
            let buf = if self.input.remaining() == 0 {
                &[][..]
            } else {
                self.input.fill(r, Error::Data)?
            };
            let mut input = InBuffer::new(buf);
            let mut out = [0u8; 1];
            let mut output = OutBuffer::new(&mut out);
            let status = stream
                .code(&mut output, &mut input, Action::Finish)
                .map_err(|_| Error::Data)?;
            let read = input.pos;
            self.input.consume(read);
            if status != Status::StreamEnd || output.pos != 0 {
                return Err(Error::Data);
            }
            self.ended = true;
        }
        if self.input.remaining() != 0 {
            return Err(Error::Data);
        }
        Ok(())
    }
}

/// A branch converter or the delta filter, on the main coder's output.
enum FilterKind {
    X86(u32),
    Arm,
    Armt,
    Arm64,
    Ppc,
    Sparc,
    Ia64,
    Riscv,
    Delta(Box<Delta>),
}

/// How many bytes past the converted ones a branch converter keeps for its
/// next call, at most.
const FILTER_BUF_SIZE: usize = 1 << 16;

struct FilterCoder {
    kind: FilterKind,
    pc: u32,
    /// Output of the main coder: `buf[..converted]` converted, up to
    /// `filled` read.
    buf: Vec<u8>,
    start: usize,
    converted: usize,
    filled: usize,
    /// The main coder has ended.
    eof: bool,
}

impl FilterCoder {
    /// The filter of the 2-coder folder, with `SzFolder_Decode2`'s checks of
    /// its properties.
    fn new(method_id: u32, props: &[u8]) -> Result<Self> {
        let mut pc = 0;
        let kind = match method_id {
            K_DELTA => {
                if props.len() != 1 {
                    return Err(Error::Unsupported);
                }
                FilterKind::Delta(Box::new(Delta::new(usize::from(props[0]) + 1)))
            }
            K_ARM64 | K_RISCV => {
                if props.len() == 4 {
                    pc = u32::from_le_bytes([props[0], props[1], props[2], props[3]]);
                    let align = if method_id == K_ARM64 { 3 } else { 1 };
                    if pc & align != 0 {
                        return Err(Error::Unsupported);
                    }
                } else if !props.is_empty() {
                    return Err(Error::Unsupported);
                }
                if method_id == K_ARM64 {
                    FilterKind::Arm64
                } else {
                    FilterKind::Riscv
                }
            }
            _ => {
                if !props.is_empty() {
                    return Err(Error::Unsupported);
                }
                match method_id {
                    K_BCJ => FilterKind::X86(bra::X86_STATE_INIT),
                    K_PPC => FilterKind::Ppc,
                    K_IA64 => FilterKind::Ia64,
                    K_SPARC => FilterKind::Sparc,
                    K_ARM => FilterKind::Arm,
                    K_ARMT => FilterKind::Armt,
                    _ => return Err(Error::Unsupported),
                }
            }
        };
        Ok(FilterCoder {
            kind,
            pc,
            buf: vec![0; FILTER_BUF_SIZE],
            start: 0,
            converted: 0,
            filled: 0,
            eof: false,
        })
    }

    /// Converts what it can of `buf[converted..filled]`.
    fn convert(&mut self) {
        let data = &mut self.buf[self.converted..self.filled];
        let n = match &mut self.kind {
            FilterKind::Delta(delta) => {
                delta.decode(data);
                data.len()
            }
            FilterKind::X86(state) => bra::x86_dec(data, self.pc, state),
            FilterKind::Arm => bra::arm_dec(data, self.pc),
            FilterKind::Armt => bra::armt_dec(data, self.pc),
            FilterKind::Arm64 => bra::arm64_dec(data, self.pc),
            FilterKind::Ppc => bra::ppc_dec(data, self.pc),
            FilterKind::Sparc => bra::sparc_dec(data, self.pc),
            FilterKind::Ia64 => bra::ia64_dec(data, self.pc),
            FilterKind::Riscv => bra::riscv_dec(data, self.pc),
        };
        self.pc = self.pc.wrapping_add(n as u32);
        self.converted += n;
        if self.eof {
            // The rest stays as it is, as the SDK leaves the end of its
            // buffer.
            self.converted = self.filled;
        }
    }

    fn read<R: Read + Seek>(
        &mut self,
        inner: &mut MainCoder,
        r: &mut R,
        out: &mut [u8],
    ) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.start < self.converted {
                let n = (self.converted - self.start).min(out.len());
                out[..n].copy_from_slice(&self.buf[self.start..self.start + n]);
                self.start += n;
                return Ok(n);
            }
            if self.eof {
                return Ok(0);
            }
            // Move what is not converted to the front, and read more.
            self.buf.copy_within(self.start..self.filled, 0);
            self.filled -= self.start;
            self.converted -= self.start;
            self.start = 0;
            let n = inner.read(r, &mut self.buf[self.filled..])?;
            if n == 0 {
                self.eof = true;
            }
            self.filled += n;
            self.convert();
        }
    }
}

/// The BCJ2 coder's inputs: three main coders and the raw RC stream.
struct Bcj2Coder {
    dec: Bcj2Dec,
    /// MAIN, CALL, JUMP: the outputs of coders 2, 1 and 0.
    coders: [MainCoder; 3],
    rc: PackReader,
    /// Buffered input of each stream: `bufs[i][starts[i]..lens[i]]`.
    bufs: [Vec<u8>; bcj2::NUM_STREAMS],
    starts: [usize; bcj2::NUM_STREAMS],
    lens: [usize; bcj2::NUM_STREAMS],
    /// The stream has no more input.
    ends: [bool; bcj2::NUM_STREAMS],
    out_size: u64,
    out_pos: u64,
}

impl Bcj2Coder {
    /// Whether stream `s` has nothing buffered the decoder can take: CALL
    /// and JUMP are read 4 bytes at a time.
    fn is_empty(&self, s: usize) -> bool {
        let left = self.lens[s] - self.starts[s];
        if s == bcj2::STREAM_CALL || s == bcj2::STREAM_JUMP {
            left < 4
        } else {
            left == 0
        }
    }

    /// More input for stream `s`, whose buffer is empty.
    fn refill<R: Read + Seek>(&mut self, s: usize, r: &mut R) -> Result<()> {
        let buf = &mut self.bufs[s];
        if buf.is_empty() {
            buf.resize(PACK_BUF_SIZE, 0);
        }
        buf.copy_within(self.starts[s]..self.lens[s], 0);
        self.lens[s] -= self.starts[s];
        self.starts[s] = 0;
        let before = self.lens[s];
        let mut len = before;
        if s == bcj2::STREAM_RC {
            let src = self.rc.fill(r, Error::InputEof)?;
            let n = src.len().min(PACK_BUF_SIZE - len);
            buf[len..len + n].copy_from_slice(&src[..n]);
            self.rc.consume(n);
            len += n;
            if self.rc.remaining() == 0 {
                self.ends[s] = true;
            }
        } else {
            let coder = &mut self.coders[s];
            // Whole addresses for CALL and JUMP: their sizes are checked to
            // be multiples of 4.
            loop {
                let n = coder.read(r, &mut buf[len..])?;
                len += n;
                if n == 0 {
                    self.ends[s] = true;
                    break;
                }
                if s == bcj2::STREAM_MAIN || len.is_multiple_of(4) {
                    break;
                }
            }
        }
        self.lens[s] = len;
        Ok(())
    }

    /// Each empty buffer refilled, while its stream has more: then an empty
    /// buffer is a stream at its end, as the SDK's decoder, given whole
    /// streams, sees it.
    fn top_up<R: Read + Seek>(&mut self, r: &mut R) -> Result<()> {
        for s in 0..bcj2::NUM_STREAMS {
            if self.is_empty(s) && !self.ends[s] {
                self.refill(s, r)?;
            }
        }
        Ok(())
    }

    fn read<R: Read + Seek>(&mut self, r: &mut R, out: &mut [u8]) -> Result<usize> {
        let want = (out.len() as u64).min(self.out_size - self.out_pos) as usize;
        if want == 0 {
            if !out.is_empty() {
                self.finish(r)?;
            }
            return Ok(0);
        }
        loop {
            self.top_up(r)?;
            let mut p = bcj2::Bufs {
                bufs: [
                    &self.bufs[0][self.starts[0]..self.lens[0]],
                    &self.bufs[1][self.starts[1]..self.lens[1]],
                    &self.bufs[2][self.starts[2]..self.lens[2]],
                    &self.bufs[3][self.starts[3]..self.lens[3]],
                ],
                dest: &mut out[..want],
                dest_pos: 0,
            };
            let res = self.dec.decode(&mut p);
            let left = p.bufs.map(<[u8]>::len);
            let written = p.dest_pos;
            for (s, left) in left.into_iter().enumerate() {
                self.starts[s] = self.lens[s] - left;
            }
            res?;
            self.out_pos += written as u64;
            if written > 0 {
                return Ok(written);
            }
            // The output is not full: the decoder needs a stream that has
            // no more.
            let s = self.dec.state;
            if s >= bcj2::NUM_STREAMS || self.ends[s] {
                return Err(Error::Data);
            }
        }
    }

    /// The checks of `SzFolder_Decode2` once the output is full: every
    /// stream read to its end, and the decoder at a place it may end.
    fn finish<R: Read + Seek>(&mut self, r: &mut R) -> Result<()> {
        self.top_up(r)?;
        for s in 0..bcj2::NUM_STREAMS {
            if self.starts[s] != self.lens[s] || !self.ends[s] {
                return Err(Error::Data);
            }
        }
        if !self.dec.is_maybe_finished() {
            return Err(Error::Data);
        }
        Ok(())
    }
}

enum Root {
    Main(MainCoder),
    Filter(Box<FilterCoder>, MainCoder),
    Bcj2(Box<Bcj2Coder>),
}

/// A folder's decoder, `SzAr_DecodeFolder`, as a reader of its unpacked
/// stream; the folder's CRC, when it has one, is checked at its end.
pub(crate) struct FolderDecoder {
    root: Root,
    size: u64,
    pos: u64,
    crc: u32,
    expected_crc: Option<u32>,
    failed: Option<Error>,
}

impl FolderDecoder {
    /// The decoder of folder `fo` of `p`, whose packed streams start at
    /// `start_pos` in the archive.
    pub(crate) fn new(p: &Ar, fo: usize, start_pos: u64) -> Result<Self> {
        let start = p.fo_coders_offsets[fo];
        let data = &p.coders_data[start..p.fo_coders_offsets[fo + 1]];
        let mut sd = Sd::new(data);
        let folder = arc_in::get_next_folder_item(&mut sd)?;
        if !sd.data.is_empty()
            || folder.unpack_stream != u32::from(p.fo_to_main_unpack_size_index[fo])
        {
            return Err(Error::Fail);
        }
        let out_size = p.folder_unpack_size(fo);
        let unpack_sizes = &p.coder_unpack_sizes[p.fo_to_coder_unpack_sizes[fo] as usize..];
        let pack_positions = &p.pack_positions[p.fo_start_pack_stream_index[fo] as usize..];

        check_supported_folder(&folder)?;
        let props = |ci: usize| {
            let c = &folder.coders[ci];
            &data[c.props_offset..c.props_offset + usize::from(c.props_size)]
        };
        let pack = |si: usize| -> (u64, u64) {
            let offset = pack_positions[si];
            (
                start_pos.wrapping_add(offset),
                pack_positions[si + 1] - offset,
            )
        };

        let root = if folder.num_coders == 4 {
            // Coders 0 and 1 make the JUMP and CALL streams, coder 2 the
            // MAIN one, from packed streams 3, 2 and 0; packed stream 1 is
            // the RC stream.
            let mut mains = Vec::with_capacity(3);
            for (ci, si) in [(0usize, 3usize), (1, 2), (2, 0)] {
                let unpack_size = unpack_sizes[ci];
                if ci == 2 && unpack_size > out_size {
                    // Check it.
                    return Err(Error::Param);
                }
                let (pos, in_size) = pack(si);
                mains.push(MainCoder::new(
                    folder.coders[ci].method_id,
                    props(ci),
                    pos,
                    in_size,
                    unpack_size,
                )?);
            }
            let (jump_size, call_size, main_size) =
                (unpack_sizes[0], unpack_sizes[1], unpack_sizes[2]);
            if jump_size & 3 != 0
                || call_size & 3 != 0
                || main_size.wrapping_add(jump_size).wrapping_add(call_size) != out_size
            {
                return Err(Error::Data);
            }
            let mut mains = mains.into_iter();
            let (Some(jump), Some(call), Some(main)) = (mains.next(), mains.next(), mains.next())
            else {
                return Err(Error::Fail);
            };
            let (rc_pos, rc_size) = pack(1);
            Root::Bcj2(Box::new(Bcj2Coder {
                dec: Bcj2Dec::new(),
                coders: [main, call, jump],
                rc: PackReader::new(rc_pos, rc_size),
                bufs: Default::default(),
                starts: [0; bcj2::NUM_STREAMS],
                lens: [0; bcj2::NUM_STREAMS],
                ends: [false; bcj2::NUM_STREAMS],
                out_size,
                out_pos: 0,
            }))
        } else {
            let (pos, in_size) = pack(0);
            let main =
                MainCoder::new(folder.coders[0].method_id, props(0), pos, in_size, out_size)?;
            if folder.num_coders == 2 {
                Root::Filter(
                    Box::new(FilterCoder::new(folder.coders[1].method_id, props(1))?),
                    main,
                )
            } else {
                Root::Main(main)
            }
        };
        Ok(FolderDecoder {
            root,
            size: out_size,
            pos: 0,
            crc: 0,
            expected_crc: p.folder_crcs.check(fo).then(|| p.folder_crcs.vals[fo]),
            failed: None,
        })
    }

    /// The folder's unpacked size.
    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    /// How much of the folder has been read.
    pub(crate) fn position(&self) -> u64 {
        self.pos
    }

    /// Up to `out.len()` bytes of the folder; 0 at its end, once checked.
    pub(crate) fn read<R: Read + Seek>(&mut self, r: &mut R, out: &mut [u8]) -> Result<usize> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        let res = self.read_inner(r, out);
        if let Err(e) = res {
            self.failed = Some(e);
        }
        res
    }

    fn read_inner<R: Read + Seek>(&mut self, r: &mut R, out: &mut [u8]) -> Result<usize> {
        let at_end = self.pos == self.size;
        let probe = &mut [0u8; 1][..];
        // At the end, the coders are asked once more, to check their ends.
        let out = if at_end && !out.is_empty() {
            probe
        } else {
            out
        };
        let n = match &mut self.root {
            Root::Main(main) => main.read(r, out)?,
            Root::Filter(filter, main) => filter.read(main, r, out)?,
            Root::Bcj2(bcj2) => bcj2.read(r, out)?,
        };
        if at_end {
            if n != 0 {
                return Err(Error::Data);
            }
            if let Some(expected) = self.expected_crc.take()
                && self.crc != expected
            {
                return Err(Error::Crc);
            }
            return Ok(0);
        }
        if n == 0 && !out.is_empty() {
            // The coders ended before the folder's size.
            return Err(Error::Data);
        }
        self.crc = hivepack_deflate::crc32(self.crc, &out[..n]);
        self.pos += n as u64;
        Ok(n)
    }
}

/// `SzAr_DecodeFolder`: all of folder `fo` into `out`, which holds its
/// unpacked size, checked.
pub(crate) fn decode_folder<R: Read + Seek>(
    p: &Ar,
    fo: usize,
    in_stream: &mut R,
    start_pos: u64,
    out: &mut [u8],
) -> Result<()> {
    let mut folder = FolderDecoder::new(p, fo, start_pos)?;
    if out.len() as u64 != folder.size() {
        return Err(Error::Fail);
    }
    let mut at = 0;
    while at < out.len() {
        let n = folder.read(in_stream, &mut out[at..])?;
        at += n;
    }
    let mut end = [0u8; 1];
    folder.read(in_stream, &mut end)?;
    Ok(())
}
