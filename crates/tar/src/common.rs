//! What the reader and its callers share: port of `common.go`, the reading
//! half, with the formats of `format.go`.

use std::collections::BTreeMap;
use std::fmt;
use std::io;

/// `TypeReg`: a regular file.
pub const TYPE_REG: u8 = b'0';
/// `TypeRegA`: a regular file in old archives; the reader turns it into
/// [`TYPE_REG`], or [`TYPE_DIR`] when the name ends with `/`.
pub const TYPE_REG_A: u8 = 0;
/// `TypeLink`: a hard link.
pub const TYPE_LINK: u8 = b'1';
/// `TypeSymlink`: a symbolic link.
pub const TYPE_SYMLINK: u8 = b'2';
/// `TypeChar`: a character device.
pub const TYPE_CHAR: u8 = b'3';
/// `TypeBlock`: a block device.
pub const TYPE_BLOCK: u8 = b'4';
/// `TypeDir`: a directory.
pub const TYPE_DIR: u8 = b'5';
/// `TypeFifo`: a named pipe.
pub const TYPE_FIFO: u8 = b'6';
/// `TypeCont`: reserved; read as a regular file.
pub const TYPE_CONT: u8 = b'7';
/// `TypeXHeader`: PAX records for the next entry, which the reader merges.
pub const TYPE_X_HEADER: u8 = b'x';
/// `TypeXGlobalHeader`: PAX records for the whole archive, which the
/// reader returns as an entry of their own.
pub const TYPE_X_GLOBAL_HEADER: u8 = b'g';
/// `TypeGNUSparse`: a GNU sparse file in the old format.
pub const TYPE_GNU_SPARSE: u8 = b'S';
/// `TypeGNULongName`: GNU's long name for the next entry, merged.
pub const TYPE_GNU_LONG_NAME: u8 = b'L';
/// `TypeGNULongLink`: GNU's long link target for the next entry, merged.
pub const TYPE_GNU_LONG_LINK: u8 = b'K';

/// `isHeaderOnlyType`: the types whose entries have no data, whatever
/// their size says.
pub(crate) fn is_header_only_type(flag: u8) -> bool {
    matches!(
        flag,
        TYPE_LINK | TYPE_SYMLINK | TYPE_CHAR | TYPE_BLOCK | TYPE_DIR | TYPE_FIFO
    )
}

/// `blockSize`.
pub(crate) const BLOCK_SIZE: usize = 512;

/// `maxSpecialFileSize`: the largest PAX records or GNU long name taken.
pub(crate) const MAX_SPECIAL_FILE_SIZE: usize = 1 << 20;

/// `maxSparseFileEntries`.
pub(crate) const MAX_SPARSE_FILE_ENTRIES: usize = 1 << 20;

/// `blockPadding`: the padding after `offset` bytes, to a block's end.
pub(crate) fn block_padding(offset: i64) -> i64 {
    offset.wrapping_neg() & (BLOCK_SIZE as i64 - 1)
}

/// The formats an entry may be in: Go's `Format`, a set of bits.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Format(u32);

impl Format {
    /// `FormatUnknown`.
    pub const UNKNOWN: Format = Format(0);
    /// `formatV7`: the original Unix format.
    pub const V7: Format = Format(1);
    /// `FormatUSTAR`: POSIX.1-1988.
    pub const USTAR: Format = Format(2);
    /// `FormatPAX`: POSIX.1-2001, USTAR with PAX records.
    pub const PAX: Format = Format(4);
    /// `FormatGNU`.
    pub const GNU: Format = Format(8);
    /// `formatSTAR`: Schily's.
    pub const STAR: Format = Format(16);

    /// `has`: whether any of `f2`'s formats are in this set.
    pub fn has(self, f2: Format) -> bool {
        self.0 & f2.0 != 0
    }

    /// `mayOnlyBe`.
    pub(crate) fn may_only_be(&mut self, f2: Format) {
        self.0 &= f2.0;
    }

    pub(crate) fn union(self, f2: Format) -> Format {
        Format(self.0 | f2.0)
    }

    /// The bits, as Go's `Format` holds them.
    pub fn bits(self) -> u32 {
        self.0
    }
}

/// As Go's `Format.String`: `USTAR`, `(USTAR | PAX)`, `<unknown>`.
impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = [
            (1, "V7"),
            (2, "USTAR"),
            (4, "PAX"),
            (8, "GNU"),
            (16, "STAR"),
        ];
        let ss: Vec<&str> = names
            .iter()
            .filter(|(bit, _)| self.0 & bit != 0)
            .map(|(_, n)| *n)
            .collect();
        match ss.len() {
            0 => f.write_str("<unknown>"),
            1 => f.write_str(ss[0]),
            _ => write!(f, "({})", ss.join(" | ")),
        }
    }
}

impl fmt::Debug for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A time as Go's `time.Unix` makes it: seconds since 1970, and
/// nanoseconds from 0 to 999,999,999.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Time {
    /// Seconds since 1970-01-01T00:00:00Z.
    pub secs: i64,
    /// Nanoseconds past them.
    pub nanos: u32,
}

impl Time {
    /// `time.Unix`: `nsec` outside a second carried into the seconds, with
    /// Go's wrapping arithmetic.
    pub(crate) fn unix(mut sec: i64, mut nsec: i64) -> Time {
        if !(0..1_000_000_000).contains(&nsec) {
            let n = nsec / 1_000_000_000;
            sec = sec.wrapping_add(n);
            nsec -= n * 1_000_000_000;
            if nsec < 0 {
                nsec += 1_000_000_000;
                sec = sec.wrapping_sub(1);
            }
        }
        Time {
            secs: sec,
            nanos: nsec as u32,
        }
    }
}

/// Keys and values of PAX records, and of extended attributes: bytes, as
/// Go's strings hold them.
pub type Records = BTreeMap<Vec<u8>, Vec<u8>>;

/// An entry's header: Go's `Header`. Names are bytes, as tar keeps them;
/// most archives write UTF-8.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// The type, one of the `TYPE_` constants or another byte.
    pub typeflag: u8,
    /// The entry's name, with USTAR's prefix, GNU's long name or PAX's
    /// `path` applied.
    pub name: Vec<u8>,
    /// A link's target.
    pub linkname: Vec<u8>,
    /// The size of the data, as the file will have it (sparse files take
    /// less in the archive).
    pub size: i64,
    /// The mode: permission bits, and in some archives the type's.
    pub mode: i64,
    /// The owner.
    pub uid: i64,
    /// The group.
    pub gid: i64,
    /// The owner's name.
    pub uname: Vec<u8>,
    /// The group's name.
    pub gname: Vec<u8>,
    /// The time of the last change of the data. `None` only for a global
    /// PAX header.
    pub mod_time: Option<Time>,
    /// The time of the last access, if the archive has it (PAX, GNU, STAR).
    pub access_time: Option<Time>,
    /// The time of the last change of the inode, if the archive has it.
    pub change_time: Option<Time>,
    /// A device's major number.
    pub devmajor: i64,
    /// A device's minor number.
    pub devminor: i64,
    /// Extended attributes, from PAX's `SCHILY.xattr.` records (Go's
    /// deprecated `Xattrs`).
    pub xattrs: Records,
    /// All the PAX records that applied to the entry.
    pub pax_records: Records,
    /// The formats the entry may be in.
    pub format: Format,
}

/// `sparseEntry`: a fragment of a sparse file, data or hole.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SparseEntry {
    pub(crate) offset: i64,
    pub(crate) length: i64,
}

impl SparseEntry {
    /// `endOffset`.
    pub(crate) fn end_offset(self) -> i64 {
        self.offset.wrapping_add(self.length)
    }
}

/// `validateSparseEntries`: in order, not overlapping, within `size`.
pub(crate) fn validate_sparse_entries(sp: &[SparseEntry], size: i64) -> bool {
    if size < 0 {
        return false;
    }
    let mut pre = SparseEntry::default();
    for &cur in sp {
        if cur.offset < 0 || cur.length < 0 {
            return false; // Negative values are never okay.
        }
        if cur.offset > i64::MAX - cur.length {
            return false; // Overflow with a large length.
        }
        if cur.end_offset() > size {
            return false; // Past the size.
        }
        if pre.end_offset() > cur.offset {
            return false; // Overlapping, or out of order.
        }
        pre = cur;
    }
    true
}

/// `invertSparseEntries`: the data fragments into the holes between them,
/// the last hole possibly empty, so that there is always one.
pub(crate) fn invert_sparse_entries(src: &[SparseEntry], size: i64) -> Vec<SparseEntry> {
    let mut dst = Vec::with_capacity(src.len() + 1);
    let mut pre = SparseEntry::default();
    for &cur in src {
        if cur.length == 0 {
            continue; // Empty fragments are skipped.
        }
        pre.length = cur.offset - pre.offset;
        if pre.length > 0 {
            dst.push(pre); // Only fragments that are not empty.
        }
        pre.offset = cur.end_offset();
    }
    pre.length = size - pre.offset; // Possibly the only empty fragment.
    dst.push(pre);
    dst
}

/// Why an archive could not be read: Go's errors.
#[derive(Debug)]
pub enum Error {
    /// `ErrHeader`: a header that is not valid.
    Header,
    /// `ErrFieldTooLong`: PAX records or a GNU long name over 1 MiB.
    FieldTooLong,
    /// `errSparseTooLong`: a sparse map over 1 MiB or a million entries.
    SparseTooLong,
    /// `errMissData`: a sparse file whose map needs more data than the
    /// archive has for it.
    MissData,
    /// `errUnrefData`: a sparse file with data its map does not use.
    UnrefData,
    /// `io.ErrUnexpectedEOF`: the archive ends in the middle of an entry.
    UnexpectedEof,
    /// Reading failed.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Header => "archive/tar: invalid tar header",
            Error::FieldTooLong => "archive/tar: header field too long",
            Error::SparseTooLong => "archive/tar: sparse map too long",
            Error::MissData => "archive/tar: sparse file references non-existent data",
            Error::UnrefData => "archive/tar: sparse file contains unreferenced data",
            Error::UnexpectedEof => "unexpected EOF",
            Error::Io(e) => return e.fmt(f),
        })
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl Error {
    /// The same error again: `io::Error` cannot be cloned, so its kind and
    /// message are kept.
    pub(crate) fn again(&self) -> Error {
        match self {
            Error::Header => Error::Header,
            Error::FieldTooLong => Error::FieldTooLong,
            Error::SparseTooLong => Error::SparseTooLong,
            Error::MissData => Error::MissData,
            Error::UnrefData => Error::UnrefData,
            Error::UnexpectedEof => Error::UnexpectedEof,
            Error::Io(e) => Error::Io(io::Error::new(e.kind(), e.to_string())),
        }
    }
}

/// An error that came through `io::Read` comes out as itself.
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        if error.get_ref().is_some_and(|inner| inner.is::<Error>()) {
            if let Some(inner) = error.into_inner()
                && let Ok(error) = inner.downcast::<Error>()
            {
                return *error;
            }
            return Error::Io(io::Error::other("lost error"));
        }
        Error::Io(error)
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> io::Error {
        match error {
            Error::Io(e) => e,
            Error::UnexpectedEof => {
                io::Error::new(io::ErrorKind::UnexpectedEof, Error::UnexpectedEof)
            }
            error => io::Error::new(io::ErrorKind::InvalidData, error),
        }
    }
}
