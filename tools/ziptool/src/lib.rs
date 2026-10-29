//! What ziptool and tryopen share: archives opened as libzip's programs
//! open them, and their options parsed as `getopt` parses them.

use std::fs::File;
use std::io;

use hivepack_zip::{Archive, Error, ErrorCode, OpenFlags, ReadAt};

/// What an archive is read from: a part of a file (`zip_source_file_create`
/// with a start and a length), or all of it in memory (ziptool_regress's
/// `-m`).
pub enum Src {
    File { file: File, start: u64, len: u64 },
    Memory(Vec<u8>),
}

impl ReadAt for Src {
    fn size(&self) -> io::Result<u64> {
        match self {
            Src::File { len, .. } => Ok(*len),
            Src::Memory(data) => Ok(data.len() as u64),
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Src::File { file, start, len } => {
                let n = (buf.len() as u64).min(len.saturating_sub(offset)) as usize;
                ReadAt::read_at(file, start + offset, &mut buf[..n])
            }
            Src::Memory(data) => data.as_slice().read_at(offset, buf),
        }
    }

    fn accept_empty(&self) -> bool {
        matches!(self, Src::Memory(_))
    }
}

/// The flags of `zip_open` that hivepack-zip, which only reads, leaves to
/// the programs: `ZIP_CREATE`, `ZIP_EXCL` and `ZIP_TRUNCATE`.
#[derive(Clone, Copy, Default)]
pub struct Create {
    pub create: bool,
    pub excl: bool,
    pub truncate: bool,
}

/// Opens `path` as `zip_open` does, or `zip_source_file_create` with
/// `start` and `len` (0: to the end) and then `zip_open_from_source`. Where
/// libzip makes a new archive (`ZIP_CREATE` and no file, or
/// `ZIP_TRUNCATE`), the archive is empty; nothing is ever written.
pub fn zip_open(
    path: &str,
    flags: OpenFlags,
    create: Create,
    start: u64,
    len: u64,
) -> Result<Archive<Src>, Error> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if !create.create {
                return Err(Error::new(ErrorCode::NoEntry, 0));
            }
            return Archive::open(Src::Memory(Vec::new()), flags);
        }
        Err(e) => return Err(Error::new(ErrorCode::Open, e.raw_os_error().unwrap_or(0))),
    };
    if create.excl {
        return Err(Error::new(ErrorCode::Exists, 0));
    }
    if create.truncate {
        return Archive::open(Src::Memory(Vec::new()), flags);
    }
    let size = file
        .metadata()
        .map_err(|e| Error::new(ErrorCode::Read, e.raw_os_error().unwrap_or(0)))?
        .len();
    if start > size || (len > 0 && start + len > size) {
        return Err(Error::new(ErrorCode::Inval, 0));
    }
    let len = if len == 0 { size - start } else { len };
    Archive::open(Src::File { file, start, len }, flags)
}

/// Opens `path` read into memory: ziptool_regress's `read_to_memory`.
pub fn zip_open_in_memory(
    path: &str,
    flags: OpenFlags,
    create: Create,
) -> Result<Archive<Src>, Error> {
    match std::fs::read(path) {
        Ok(data) => Archive::open(Src::Memory(data), flags),
        Err(e) if e.kind() == io::ErrorKind::NotFound && create.create => {
            Archive::open(Src::Memory(Vec::new()), flags)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(Error::new(ErrorCode::NoEntry, 0)),
        Err(e) => Err(Error::new(ErrorCode::Open, e.raw_os_error().unwrap_or(0))),
    }
}

/// The options before the first operand, as `getopt` returns them:
/// grouped (`-cs`), with their argument attached or next (`-l 5`, `-l5`),
/// and `--` ending them.
pub struct Getopt<'a> {
    args: &'a [String],
    /// the index of the first operand, once the options are read
    pub optind: usize,
    pos: usize,
}

impl<'a> Getopt<'a> {
    pub fn new(args: &'a [String]) -> Getopt<'a> {
        Getopt {
            args,
            optind: 1,
            pos: 0,
        }
    }

    /// The next option and its argument, `Err` with the character for one
    /// not in `optstring` (or missing its argument), or `None` at the
    /// first operand.
    pub fn next(&mut self, optstring: &str) -> Option<Result<(char, Option<String>), char>> {
        if self.pos == 0 {
            let arg = self.args.get(self.optind)?;
            if arg == "--" {
                self.optind += 1;
                return None;
            }
            if !arg.starts_with('-') || arg.len() == 1 {
                return None;
            }
            self.pos = 1;
        }
        let arg = &self.args[self.optind];
        let c = arg[self.pos..].chars().next()?;
        self.pos += c.len_utf8();
        let at_end = self.pos >= arg.len();
        let Some(spec) = optstring.find(c).filter(|_| c != ':') else {
            if at_end {
                self.optind += 1;
                self.pos = 0;
            }
            return Some(Err(c));
        };
        if optstring[spec + 1..].starts_with(':') {
            let value = if !at_end {
                Some(arg[self.pos..].to_string())
            } else {
                self.optind += 1;
                self.args.get(self.optind).cloned()
            };
            self.optind += 1;
            self.pos = 0;
            return Some(value.map(|v| (c, Some(v))).ok_or(c));
        }
        if at_end {
            self.optind += 1;
            self.pos = 0;
        }
        Some(Ok((c, None)))
    }
}

/// `strtoull(text, NULL, 10)`: the leading digits, 0 if none, and, after
/// a minus sign, their negation modulo 2^64, as C's.
pub fn strtoull(text: &str) -> u64 {
    let text = text.trim_start();
    let (negative, rest) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    let value = if digits.is_empty() {
        0
    } else {
        digits.parse().unwrap_or(u64::MAX)
    };
    if negative {
        value.wrapping_neg()
    } else {
        value
    }
}
