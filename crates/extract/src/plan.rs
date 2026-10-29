//! What is to be extracted, and the checks made on all of it before
//! anything is written: the limits that can be checked on what the archive
//! says, the same path named twice, links and special files, and data that
//! overlaps.

use std::collections::HashMap;
use std::ops::Range;
use std::time::SystemTime;

use crate::error::{Error, ErrorKind};
use crate::name::Name;

/// Limits on what an archive may write, against archive bombs. They count
/// the bytes actually written, not what the archive says: the declared
/// sizes are checked first, and the data is cut off where it passes them.
///
/// The defaults are a judgment, to be tuned on real archives: 100,000
/// entries, 4 GiB an entry, 16 GiB in all, and 2,000 bytes for each byte
/// of compressed data, once an entry has passed 1 MiB. Deflate tops out
/// near 1,032 to one, which a file of zeros reaches, so the ratio stops
/// only methods that go further (Deflate64).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Entries in the archive.
    pub max_entries: u64,
    /// Bytes an entry writes.
    pub max_entry_size: u64,
    /// Bytes all entries write.
    pub max_total_size: u64,
    /// Bytes written for each byte of compressed data.
    pub max_ratio: u64,
    /// The bytes an entry writes before its ratio is checked.
    pub ratio_threshold: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_entries: 100_000,
            max_entry_size: 4 << 30,
            max_total_size: 16 << 30,
            max_ratio: 2_000,
            ratio_threshold: 1 << 20,
        }
    }
}

/// How to extract.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct Options {
    pub limits: Limits,
    /// The password encrypted entries are read with.
    pub password: Option<Vec<u8>>,
}

/// Shows the limits, not the password.
impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("limits", &self.limits)
            .field("password", &self.password.as_ref().map(|_| ".."))
            .finish()
    }
}

/// What an entry is, as the archive says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    Dir,
    Link,
    Special,
}

/// An entry to extract.
pub(crate) struct Item {
    pub index: u64,
    pub raw_name: Vec<u8>,
    pub name: Name,
    pub kind: Kind,
    /// what the archive says it decompresses to
    pub size: u64,
    /// its compressed data
    pub compressed: u64,
    /// where its compressed data is in the archive, if it has any
    pub data: Option<Range<u64>>,
    /// Unix permission bits, if the archive has them
    pub mode: Option<u32>,
    pub mtime: Option<SystemTime>,
}

/// A path as the checks see it: case folded, as a case-insensitive file
/// system would.
fn fold(components: &[String]) -> String {
    components.join("/").to_lowercase()
}

/// What a path already is, among the entries checked.
struct Seen {
    spelling: Vec<String>,
    is_dir: bool,
    /// the first entry that names it, or that it is on the way to
    first: u64,
    /// whether an entry names it, not only has it on its way
    named: bool,
}

/// Checks the entries before anything is written: their number, what
/// they say of their sizes, that no two name the same path (ignoring case,
/// and a directory one way and a file another), that none is a link or a
/// special file, and that no two share compressed data.
pub(crate) fn check(items: &[Item], limits: &Limits) -> Result<(), Error> {
    if items.len() as u64 > limits.max_entries {
        return Err(Error::global(ErrorKind::TooManyEntries));
    }
    let mut total: u64 = 0;
    let mut seen: HashMap<String, Seen> = HashMap::new();
    for item in items {
        let error = |kind| Error::new(item.index, &item.raw_name, kind);
        match item.kind {
            Kind::Link => return Err(error(ErrorKind::Link)),
            Kind::Special => return Err(error(ErrorKind::SpecialFile)),
            Kind::File | Kind::Dir => {}
        }
        if item.size > limits.max_entry_size {
            return Err(error(ErrorKind::EntryTooLarge));
        }
        total = total.saturating_add(item.size);
        if total > limits.max_total_size {
            return Err(error(ErrorKind::TotalTooLarge));
        }

        let components = &item.name.components;
        // The directories on the way.
        for end in 1..components.len() {
            let prefix = &components[..end];
            match seen.get(&fold(prefix)) {
                Some(other) if other.spelling != prefix || !other.is_dir => {
                    return Err(error(ErrorKind::Duplicate { first: other.first }));
                }
                Some(_) => {}
                None => {
                    seen.insert(
                        fold(prefix),
                        Seen {
                            spelling: prefix.to_vec(),
                            is_dir: true,
                            first: item.index,
                            named: false,
                        },
                    );
                }
            }
        }
        let is_dir = item.kind == Kind::Dir;
        match seen.get_mut(&fold(components)) {
            // A directory named after files in it.
            Some(other)
                if is_dir && other.is_dir && !other.named && other.spelling == *components =>
            {
                other.named = true;
            }
            Some(other) => {
                return Err(error(ErrorKind::Duplicate { first: other.first }));
            }
            None => {
                seen.insert(
                    fold(components),
                    Seen {
                        spelling: components.clone(),
                        is_dir,
                        first: item.index,
                        named: true,
                    },
                );
            }
        }
    }

    // Data that two entries share: the overlapping entries of Fifield's
    // archive bombs, which reuse one stream for many files.
    let mut ranges: Vec<(&Range<u64>, &Item)> = items
        .iter()
        .filter_map(|item| item.data.as_ref().map(|range| (range, item)))
        .filter(|(range, _)| !range.is_empty())
        .collect();
    ranges.sort_by_key(|(range, _)| (range.start, range.end));
    for pair in ranges.windows(2) {
        let ((before, first), (after, second)) = (pair[0], pair[1]);
        if after.start < before.end {
            return Err(Error::new(
                second.index,
                &second.raw_name,
                ErrorKind::Overlap { other: first.index },
            ));
        }
    }
    Ok(())
}
