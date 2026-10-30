//! Why an extraction stopped, and at which entry.

use std::fmt;

use crate::name::NameError;

/// Why an extraction stopped: the entry, by its index in the archive and
/// its name as the archive has it, and the reason.
#[derive(Debug)]
pub struct Error {
    /// The entry's index, if an entry is to blame.
    pub index: Option<u64>,
    /// The entry's name, as the archive has it.
    pub name: Option<Vec<u8>>,
    pub kind: ErrorKind,
}

/// The reasons an extraction stops.
#[derive(Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The name is refused (see [`check_name`](crate::check_name)).
    Name(NameError),
    /// Another entry, `first`, names the same path, ignoring case, or
    /// names a file where this one has a directory, or the other way.
    Duplicate { first: u64 },
    /// A symbolic link, which is not created (see
    /// [`Links`](crate::Links)).
    Link,
    /// A hard link (tar, ISO 9660) whose target is not a file extracted
    /// before it.
    HardLinkTarget,
    /// A device or FIFO (tar, ISO 9660): nothing is created as one.
    Special,
    /// A link whose target is refused, as a name is
    /// ([`NameError::Dot`] for one that climbs out of the destination).
    LinkTarget(NameError),
    /// A link whose target passes through link `other`, which the system
    /// would follow where the target's text does not.
    LinkChain { other: u64 },
    /// The entry's data overlaps that of entry `other`: an archive bomb
    /// that reuses the same compressed data, or a broken archive.
    Overlap { other: u64 },
    /// More entries than [`Limits::max_entries`](crate::Limits::max_entries).
    TooManyEntries,
    /// More data than [`Limits::max_entry_size`](crate::Limits::max_entry_size).
    EntryTooLarge,
    /// More data in all than [`Limits::max_total_size`](crate::Limits::max_total_size).
    TotalTooLarge,
    /// More data for the compressed data than [`Limits::max_ratio`](crate::Limits::max_ratio).
    Ratio,
    /// More or less data than the archive says the entry has.
    SizeMismatch,
    /// Something is already at the entry's path: nothing is overwritten.
    Exists,
    /// A directory on the entry's path is a symbolic link, or not a
    /// directory: nothing is written through it.
    NotADirectory,
    /// Past [`Options::time_limit`](crate::Options::time_limit).
    TimeLimit,
    /// Stopped by [`Options::cancel`](crate::Options::cancel).
    Cancelled,
    /// The mark of origin ([`Options::origin`](crate::Options::origin))
    /// could not be written, or this system cannot carry it.
    Origin(std::io::Error),
    /// The archive could not be read.
    Archive(hivepack_zip::Error),
    /// The tar archive could not be read.
    Tar(hivepack_tar::Error),
    /// The ISO 9660 image could not be read.
    Iso(hivepack_iso::Error),
    /// An entry of the ISO 9660 image that libarchive gives with something
    /// missing ([`hivepack_iso::Warning`]): a directory left out with what
    /// it holds, a file past the image's end or whose data is before its
    /// directory, a name not in UTF-16, a part of a file's data out of
    /// place.
    IsoEntry(hivepack_iso::Warning),
    /// The tar archive or ISO 9660 image read again, to write it, is not
    /// the one checked.
    Changed,
    /// The destination could not be written.
    Io(std::io::Error),
}

impl Error {
    pub(crate) fn new(index: u64, name: &[u8], kind: ErrorKind) -> Error {
        Error {
            index: Some(index),
            name: Some(name.to_vec()),
            kind,
        }
    }

    pub(crate) fn global(kind: ErrorKind) -> Error {
        Error {
            index: None,
            name: None,
            kind,
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Name(e) => write!(f, "name refused: {e}"),
            ErrorKind::Duplicate { first } => write!(f, "same path as entry {first}"),
            ErrorKind::Link => f.write_str("link"),
            ErrorKind::HardLinkTarget => f.write_str("hard link to no file extracted before it"),
            ErrorKind::Special => f.write_str("device or FIFO"),
            ErrorKind::LinkTarget(e) => write!(f, "link target refused: {e}"),
            ErrorKind::LinkChain { other } => write!(f, "link through link {other}"),
            ErrorKind::Overlap { other } => write!(f, "data overlaps entry {other}"),
            ErrorKind::TooManyEntries => f.write_str("too many entries"),
            ErrorKind::EntryTooLarge => f.write_str("entry too large"),
            ErrorKind::TotalTooLarge => f.write_str("too much data in all"),
            ErrorKind::Ratio => f.write_str("compression ratio too high"),
            ErrorKind::SizeMismatch => f.write_str("data not of the size the archive says"),
            ErrorKind::Exists => f.write_str("already exists"),
            ErrorKind::NotADirectory => f.write_str("a directory on the path is a link or a file"),
            ErrorKind::TimeLimit => f.write_str("past the time limit"),
            ErrorKind::Cancelled => f.write_str("cancelled"),
            ErrorKind::Origin(e) => write!(f, "mark of origin not written: {e}"),
            ErrorKind::Archive(e) => write!(f, "archive: {e}"),
            ErrorKind::Tar(e) => write!(f, "archive: {e}"),
            ErrorKind::Iso(e) => write!(f, "image: {e}"),
            ErrorKind::IsoEntry(w) => write!(f, "entry with something missing: {w}"),
            ErrorKind::Changed => f.write_str("the archive changed between its two readings"),
            ErrorKind::Io(e) => write!(f, "{e}"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.index, &self.name) {
            (Some(index), Some(name)) => write!(
                f,
                "entry {index} ({}): {}",
                String::from_utf8_lossy(name),
                self.kind
            ),
            _ => write!(f, "{}", self.kind),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            ErrorKind::Archive(e) => Some(e),
            ErrorKind::Tar(e) => Some(e),
            ErrorKind::Iso(e) => Some(e),
            ErrorKind::Io(e) | ErrorKind::Origin(e) => Some(e),
            _ => None,
        }
    }
}
