//! The ASCII armor, age's PEM-like text form: port of `armor/armor.go`,
//! the reading half.
//!
//! ```text
//! -----BEGIN AGE ENCRYPTED FILE-----
//! YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB...
//! -----END AGE ENCRYPTED FILE-----
//! ```
//!
//! Strict base64 with padding, in lines of 64 columns, the last shorter;
//! line ends may be CRLF, and up to 1 KiB of whitespace is allowed before
//! the first line and after the last.

use std::io::{self, BufRead, Read};

use crate::base64;
use crate::error::Error;
use crate::format::{BYTES_PER_LINE, COLUMNS_PER_LINE};

/// `Header`: the first line.
pub const HEADER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";

/// `Footer`: the last line.
pub const FOOTER: &str = "-----END AGE ENCRYPTED FILE-----";

/// `maxWhitespace`.
pub(crate) const MAX_WHITESPACE: usize = 1024;

/// Differs from age, which reads a line whole whatever its length: a line
/// is read up to this many bytes. Longer, it fails as age would fail it,
/// as too long or not the first line, with a shorter message.
const MAX_LINE: usize = 4 * MAX_WHITESPACE;

/// Go's `bytes.TrimSpace`, the start only: Unicode's white space, which
/// Rust's `char::is_whitespace` and Go's `unicode.IsSpace` agree on, in
/// valid UTF-8; an invalid byte is not space.
pub(crate) fn trim_space_start(b: &[u8]) -> &[u8] {
    let mut at = 0;
    for chunk in b.utf8_chunks() {
        for c in chunk.valid().chars() {
            if !c.is_whitespace() {
                return &b[at..];
            }
            at += c.len_utf8();
        }
        if !chunk.invalid().is_empty() {
            return &b[at..];
        }
    }
    &b[at..]
}

/// Whether `bytes.TrimSpace(b)` is empty.
fn is_space(b: &[u8]) -> bool {
    trim_space_start(b).is_empty()
}

/// What stopped the reader, kept to be returned again.
#[derive(Clone, Debug)]
enum Stop {
    End,
    Armor(String),
    Io(io::ErrorKind, String),
}

impl Stop {
    fn to_error(&self) -> io::Error {
        match self {
            Stop::End => io::Error::from(io::ErrorKind::UnexpectedEof),
            Stop::Armor(message) => Error::Armor(message.clone()).into(),
            Stop::Io(kind, message) => io::Error::new(*kind, message.clone()),
        }
    }
}

/// `armoredReader`: the bytes an armored file encodes, read from `r`.
///
/// Errors come as `io::Error`s of kind `InvalidData` that hold an
/// [`Error::Armor`], which `Error::from` takes back out; once one is
/// returned, every later read returns it again.
#[derive(Debug)]
pub struct ArmoredReader<R> {
    r: R,
    started: bool,
    buf: [u8; BYTES_PER_LINE],
    start: usize,
    end: usize,
    err: Option<Stop>,
}

impl<R: BufRead> ArmoredReader<R> {
    /// `NewReader`.
    pub fn new(r: R) -> ArmoredReader<R> {
        ArmoredReader {
            r,
            started: false,
            buf: [0; BYTES_PER_LINE],
            start: 0,
            end: 0,
            err: None,
        }
    }

    /// `getLine`: the next line, without its LF or CRLF; the last may end
    /// without one. At the end, `UnexpectedEof`.
    fn get_line(&mut self) -> Result<Vec<u8>, Stop> {
        let mut line = Vec::new();
        let mut complete = false;
        loop {
            let buf = match self.r.fill_buf() {
                Ok(buf) => buf,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Stop::Io(e.kind(), e.to_string())),
            };
            if buf.is_empty() {
                break;
            }
            let take = match buf.iter().position(|&c| c == b'\n') {
                Some(at) => {
                    complete = true;
                    at + 1
                }
                None => buf.len(),
            };
            let room = MAX_LINE + 2 - line.len();
            if take > room {
                return Err(Stop::Armor("line too long".into()));
            }
            line.extend_from_slice(&buf[..take]);
            self.r.consume(take);
            if complete {
                break;
            }
        }
        if !complete && line.is_empty() {
            return Err(Stop::Armor("unexpected EOF".into()));
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Ok(line)
    }

    /// `drainTrailing`: after the footer, only white space, and no more
    /// than 1 KiB of it.
    fn drain_trailing(&mut self) -> Stop {
        let mut buf = Vec::with_capacity(MAX_WHITESPACE);
        if let Err(e) = (&mut self.r)
            .take(MAX_WHITESPACE as u64)
            .read_to_end(&mut buf)
        {
            return Stop::Io(e.kind(), e.to_string());
        }
        if !is_space(&buf) {
            return Stop::Armor("trailing data after armored file".into());
        }
        if buf.len() == MAX_WHITESPACE {
            return Stop::Armor("too much trailing whitespace".into());
        }
        Stop::End
    }

    fn fail(&mut self, stop: Stop) -> io::Error {
        let error = stop.to_error();
        self.err = Some(stop);
        error
    }

    /// The next line of data into `buf`, and the footer after a short one.
    fn next_line(&mut self) -> Result<(), Stop> {
        let mut removed_whitespace = 0;
        while !self.started {
            let line = self.get_line()?;
            if is_space(&line) {
                removed_whitespace += line.len() + 1;
                if removed_whitespace > MAX_WHITESPACE {
                    return Err(Stop::Armor("too much leading whitespace".into()));
                }
                continue;
            }
            if line != HEADER.as_bytes() {
                return Err(Stop::Armor(format!(
                    "invalid first line: {:?}",
                    String::from_utf8_lossy(&line)
                )));
            }
            self.started = true;
        }
        let line = self.get_line()?;
        if line == FOOTER.as_bytes() {
            return Err(self.drain_trailing());
        }
        if line.is_empty() {
            return Err(Stop::Armor("empty line in armored data".into()));
        }
        if line.len() > COLUMNS_PER_LINE {
            return Err(Stop::Armor("column limit exceeded".into()));
        }
        if line.iter().any(|&c| c == b'\n' || c == b'\r') {
            return Err(Stop::Armor("unexpected newline character".into()));
        }
        let Some(data) = base64::decode(&line, true) else {
            return Err(Stop::Armor("illegal base64 data".into()));
        };
        // At most 64 columns: at most 48 bytes.
        self.buf[..data.len()].copy_from_slice(&data);
        self.start = 0;
        self.end = data.len();
        if data.len() < BYTES_PER_LINE {
            let line = self.get_line()?;
            if line != FOOTER.as_bytes() {
                return Err(Stop::Armor(format!(
                    "invalid closing line: {:?}",
                    String::from_utf8_lossy(&line)
                )));
            }
            self.err = Some(self.drain_trailing());
        }
        Ok(())
    }
}

impl<R: BufRead> Read for ArmoredReader<R> {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if self.start < self.end {
            let n = p.len().min(self.end - self.start);
            p[..n].copy_from_slice(&self.buf[self.start..self.start + n]);
            self.start += n;
            return Ok(n);
        }
        if let Some(stop) = &self.err {
            return match stop {
                Stop::End => Ok(0),
                stop => Err(stop.to_error()),
            };
        }
        match self.next_line() {
            Ok(()) => {}
            Err(Stop::End) => {
                self.err = Some(Stop::End);
                return Ok(0);
            }
            Err(stop) => return Err(self.fail(stop)),
        }
        let n = p.len().min(self.end - self.start);
        p[..n].copy_from_slice(&self.buf[self.start..self.start + n]);
        self.start += n;
        Ok(n)
    }
}
