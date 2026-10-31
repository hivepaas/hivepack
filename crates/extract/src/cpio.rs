//! Extracting a cpio archive that `hivepack-cpio` reads.
//!
//! A cpio archive is a run of entries, each header before its data, as in
//! tar: it is read twice, once for the headers, the data skipped, and once
//! to write, each header compared with the first reading's. The caller
//! gives a function that opens it again, which for a compressed archive or
//! an RPM package's payload decompresses it again.
//!
//! A file with several names is an entry for each name, and its data comes
//! with any of them: with the last in newc, as GNU cpio and RPM write it,
//! the others empty; with each in odc. libarchive's extraction writes the
//! data of each into the file the names share, which ends with the last
//! data written. Here the file is written once, when the last of its
//! entries with data comes, under its first name; its other names are
//! linked to it then, or as they come after.

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hivepack_cpio::{
    AE_IFBLK, AE_IFCHR, AE_IFDIR, AE_IFIFO, AE_IFLNK, AE_IFMT, AE_IFSOCK, Header, Reader,
};

use crate::destination::Destination;
use crate::error::{Error, ErrorKind};
use crate::name::NameError;
use crate::plan::{Item, Kind, Links, OnRefused, Options, check};
use crate::progress::Run;
use crate::tar::{
    Entry, LinkPlan, bytes_to_write, copy_of, finish_file, name_of, plan_links, read_rest,
};
use crate::zip::{Summary, set_dir_times};

/// An entry's error, by its index and its path.
fn entry_error(index: u64, h: &Header, kind: ErrorKind) -> Error {
    Error::new(index, &h.path, kind)
}

/// Seconds since 1970 as a `SystemTime`.
fn system_time(secs: i64) -> Option<SystemTime> {
    if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
    }
}

/// A file with several names.
#[derive(Debug, Default)]
struct Group {
    /// The entry whose data the file holds: the last with data, if any.
    data: Option<u64>,
    /// Whether the file is written.
    written: bool,
    /// Its other names that came before it was written, by their place in
    /// the items, to link to it once it is.
    waiting: Vec<usize>,
}

/// What the first reading found.
#[derive(Default)]
struct FirstReading {
    entries: Vec<Entry<Header>>,
    items: Vec<Item>,
    /// The errors of the entries refused for a warning, to skip.
    refused: Vec<Error>,
    /// The files with several names, by their first entry's index.
    groups: HashMap<u64, Group>,
    /// The first entry of the file each hard link is a name of.
    first_of: HashMap<u64, u64>,
}

/// The first reading: every header, the data skipped (which reading it
/// through does). An entry that comes with a warning, after bytes that are
/// not a header were passed over, is refused: what was passed over is lost.
fn read_headers<R: Read>(r: R, run: &Run<'_>, options: &Options) -> Result<FirstReading, Error> {
    let mut cpio = Reader::new(r);
    let mut first = FirstReading::default();
    // The entry each path was given by, for the hard links that name it.
    let mut by_path: HashMap<Vec<u8>, u64> = HashMap::new();
    loop {
        let index = first.entries.len() as u64;
        run.check().map_err(Error::global)?;
        let h = match cpio.next() {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) => {
                return Err(Error {
                    index: Some(index),
                    name: None,
                    kind: ErrorKind::Cpio(e),
                });
            }
        };
        // Every entry counts, as in tar.
        if first.entries.len() as u64 >= options.limits.max_entries {
            return Err(Error::global(ErrorKind::TooManyEntries));
        }
        let mut entry = Entry {
            seen: h.clone(),
            item: None,
            target: Vec::new(),
        };
        if let Some(warning) = &h.warning {
            let error = entry_error(index, &h, ErrorKind::CpioEntry(warning.clone()));
            match options.on_refused {
                OnRefused::Stop => return Err(error),
                OnRefused::Skip => first.refused.push(error),
            }
            first.entries.push(entry);
            continue;
        }
        // The file a hard link is a name of, by an earlier entry's path:
        // its own, if it has the path of the file's first name, is not one.
        let target = h.hardlink.as_ref().and_then(|t| by_path.get(t)).copied();
        by_path.insert(h.path.clone(), index);
        // The root directory, ".", is not an entry.
        let Some(name) = name_of(&h.path, options) else {
            first.entries.push(entry);
            continue;
        };
        let kind = if h.hardlink.is_some() {
            Kind::HardLink
        } else {
            match h.mode & AE_IFMT {
                AE_IFDIR => Kind::Dir,
                AE_IFLNK => Kind::Link,
                AE_IFCHR | AE_IFBLK | AE_IFIFO | AE_IFSOCK => Kind::Special,
                _ => Kind::File,
            }
        };
        if let Some(target) = target {
            first.first_of.insert(index, target);
            let target_size = first.entries[target as usize].seen.size;
            let group = first.groups.entry(target).or_insert_with(|| Group {
                data: (target_size > 0).then_some(target),
                ..Group::default()
            });
            if h.size > 0 {
                group.data = Some(index);
            }
        }
        entry.target = match kind {
            Kind::Link => h.symlink.clone().unwrap_or_default(),
            Kind::HardLink => h.hardlink.clone().unwrap_or_default(),
            _ => Vec::new(),
        };
        let size = match kind {
            Kind::File => h.size,
            _ => 0,
        };
        first.items.push(Item {
            index,
            raw_name: h.path.clone(),
            name,
            kind,
            size,
            compressed: size,
            data: None,
            mode: Some(h.mode & 0o7777),
            mtime: system_time(h.mod_time),
        });
        entry.item = Some(first.items.len() - 1);
        first.entries.push(entry);
    }
    read_rest(cpio.into_inner(), run, options)?;
    // A file with several names holds the data of its last entry with
    // data, which its first name is written with.
    for (&target, group) in &first.groups {
        let (Some(data), Some(at)) = (group.data, first.entries[target as usize].item) else {
            continue;
        };
        let size = first.entries[data as usize].seen.size;
        let item = &mut first.items[at];
        if item.kind == Kind::File {
            item.size = size;
            item.compressed = size;
        }
    }
    Ok(first)
}

/// Extracts the cpio archive that `open` gives into `destination`, which is
/// created if it is not there, with `options`: Linux's initramfs images,
/// RPM packages' payloads (`hivepack_open::Opener` takes the package and
/// its compression off), and what `cpio` writes.
///
/// `open` is called twice, and must give the same archive each time, as
/// for [`extract_tar`](crate::extract_tar): the first reading checks every
/// entry before anything is written, the second writes them, each header
/// compared with the first reading's ([`ErrorKind::Changed`] if one
/// differs). Each reading goes on to the end of the stream.
///
/// Besides tar's rules: the root directory, `.`, is not an entry. An entry
/// found after bytes that are not a header were passed over comes with a
/// warning ([`hivepack_cpio::Warning`]), and is refused
/// ([`ErrorKind::CpioEntry`]), or left out with [`OnRefused::Skip`]: what
/// was passed over is lost. A hard link names the first entry of its file,
/// which holds the data of the last of their entries with data, as
/// libarchive's extraction leaves it; the file is written when that data
/// comes, and its names linked to it. An archive cut short, or without
/// `TRAILER!!!`, fails the first reading.
pub fn extract_cpio<R: Read, F: FnMut() -> io::Result<R>>(
    mut open: F,
    destination: &Path,
    options: &Options,
) -> Result<Summary, Error> {
    let run = Run::new(options);
    if let Some(origin) = &options.origin {
        origin
            .check_supported()
            .map_err(|e| Error::global(ErrorKind::Origin(e)))?;
    }

    let first = open().map_err(|e| Error::global(ErrorKind::Io(e)))?;
    let FirstReading {
        entries,
        items,
        refused,
        mut groups,
        first_of,
    } = read_headers(first, &run, options)?;
    let (kept, mut skipped) = check(&items, options)?;
    skipped.splice(0..0, refused);
    skipped.sort_by_key(|e| e.index);
    let plans = plan_links(&entries, &items, &kept, options, &mut skipped)?;
    let kept_indexes: HashSet<u64> = kept
        .iter()
        .filter(|item| {
            !matches!(item.kind, Kind::Link | Kind::HardLink) || plans.contains_key(&item.index)
        })
        .map(|item| item.index)
        .collect();
    let created_later = |item: &Item| matches!(plans.get(&item.index), Some(LinkPlan::Symlink(..)));
    run.start(
        kept_indexes.len() as u64,
        bytes_to_write(&entries, &items, &kept_indexes, &plans, options),
    );

    let destination = Destination::open(destination, options.origin.as_ref())
        .map_err(|e| Error::global(ErrorKind::Io(e)))?;
    let mut summary = Summary {
        skipped,
        ..Summary::default()
    };
    let writer = Writer {
        destination: &destination,
        plans: &plans,
        run: &run,
        options,
    };

    // The second reading.
    let second = open().map_err(|e| Error::global(ErrorKind::Io(e)))?;
    let mut cpio = Reader::new(second);
    for (index, entry) in entries.iter().enumerate() {
        let index = index as u64;
        run.check().map_err(Error::global)?;
        let h = match cpio.next() {
            Ok(Some(h)) => h,
            Ok(None) => return Err(Error::global(ErrorKind::Changed)),
            Err(e) => return Err(Error::global(ErrorKind::Cpio(e))),
        };
        if h != entry.seen {
            return Err(entry_error(index, &h, ErrorKind::Changed));
        }
        // The data of a file with several names, which its first name is
        // written with, whichever of them it comes with.
        if let Some(target) = first_of.get(&index).copied().or(Some(index))
            && let Some(group) = groups.get_mut(&target)
            && group.data == Some(index)
        {
            let first_entry = &entries[target as usize];
            if let Some(at) = first_entry.item
                && items[at].kind == Kind::File
                && kept_indexes.contains(&target)
            {
                writer.file(&mut cpio, &items[at], h.size, &mut summary)?;
                for &waiting in &group.waiting {
                    writer.hard_link(&items[waiting], &mut summary)?;
                }
                group.waiting.clear();
            }
            group.written = true;
        }
        let Some(at) = entry.item else {
            continue;
        };
        let item = &items[at];
        if !kept_indexes.contains(&item.index) || created_later(item) {
            continue;
        }
        let Ok(name) = &item.name else {
            continue;
        };
        let error = |kind| item.error(kind);
        if item.kind == Kind::Dir {
            destination.directory(&name.components).map_err(error)?;
            summary.directories += 1;
            run.entry_done();
            continue;
        }
        match plans.get(&item.index) {
            Some(LinkPlan::Hard(_)) => {
                match first_of
                    .get(&index)
                    .and_then(|target| groups.get_mut(target))
                {
                    Some(group) if !group.written => group.waiting.push(at),
                    _ => writer.hard_link(item, &mut summary)?,
                }
                continue;
            }
            Some(LinkPlan::SymlinkAsFile) => {
                writer.file(
                    &mut &entry.target[..],
                    item,
                    entry.target.len() as u64,
                    &mut summary,
                )?;
                continue;
            }
            _ => {}
        }
        match groups.get(&index) {
            // Written with its data, which comes with a later name.
            Some(group) if group.data.is_some() => {}
            // A file with several names and no data at all.
            Some(_) => {
                writer.file(&mut io::empty(), item, 0, &mut summary)?;
                if let Some(group) = groups.get_mut(&index) {
                    group.written = true;
                }
            }
            None => writer.file(&mut cpio, item, item.size, &mut summary)?,
        }
    }
    // The second reading must end where the first did.
    match cpio.next() {
        Ok(None) => {}
        Ok(Some(h)) => {
            return Err(entry_error(entries.len() as u64, &h, ErrorKind::Changed));
        }
        Err(e) => return Err(Error::global(ErrorKind::Cpio(e))),
    }
    read_rest(cpio.into_inner(), &run, options)?;

    for &item in kept.iter().filter(|item| created_later(item)) {
        let error = |kind| item.error(kind);
        let (Ok(name), Some(LinkPlan::Symlink(target, to_dir))) =
            (&item.name, plans.get(&item.index))
        else {
            continue;
        };
        let (last, parents) = name
            .components
            .split_last()
            .ok_or_else(|| error(ErrorKind::Name(NameError::Empty)))?;
        run.check().map_err(error)?;
        let dir = destination.directory(parents).map_err(error)?;
        Destination::symlink(&dir, last, target, *to_dir).map_err(error)?;
        summary.links += 1;
        run.entry_done();
    }

    set_dir_times(&destination, &kept, &run)?;
    Ok(summary)
}

/// What the second reading writes with.
struct Writer<'a> {
    destination: &'a Destination<'a>,
    plans: &'a HashMap<u64, LinkPlan>,
    run: &'a Run<'a>,
    options: &'a Options,
}

impl Writer<'_> {
    /// Writes `item` as a file of the `size` bytes `r` gives.
    fn file(
        &self,
        r: &mut impl Read,
        item: &Item,
        size: u64,
        summary: &mut Summary,
    ) -> Result<(), Error> {
        let error = |kind| item.error(kind);
        let name = item.name.as_ref().map_err(|e| error(ErrorKind::Name(*e)))?;
        let (last, parents) = name
            .components
            .split_last()
            .ok_or_else(|| error(ErrorKind::Name(NameError::Empty)))?;
        let dir = self.destination.directory(parents).map_err(error)?;
        let file = Destination::create_file(&dir, last, self.options.overwrite).map_err(error)?;
        let remaining = self
            .options
            .limits
            .max_total_size
            .saturating_sub(summary.bytes);
        match write_data(r, item, size, file, remaining, self.run, self.options) {
            Ok(written) => {
                summary.files += 1;
                summary.bytes += written;
                self.run.entry_done();
                Ok(())
            }
            Err(kind) => {
                // A file whose data failed is not left.
                let _ = dir.remove_file(last);
                Err(error(kind))
            }
        }
    }

    /// Makes `item` a hard link to the file its plan names, which is
    /// written: a copy of it, with [`Links::AsFile`].
    fn hard_link(&self, item: &Item, summary: &mut Summary) -> Result<(), Error> {
        let error = |kind| item.error(kind);
        let Some(LinkPlan::Hard(target)) = self.plans.get(&item.index) else {
            return Err(error(ErrorKind::HardLinkTarget));
        };
        let name = item.name.as_ref().map_err(|e| error(ErrorKind::Name(*e)))?;
        let (last, parents) = name
            .components
            .split_last()
            .ok_or_else(|| error(ErrorKind::Name(NameError::Empty)))?;
        let dir = self.destination.directory(parents).map_err(error)?;
        if self.options.links != Links::AsFile {
            let (target_last, target_parents) = target
                .split_last()
                .ok_or_else(|| error(ErrorKind::HardLinkTarget))?;
            let target_dir = self.destination.directory(target_parents).map_err(error)?;
            Destination::hard_link(&target_dir, target_last, &dir, last).map_err(error)?;
            summary.files += 1;
            self.run.entry_done();
            return Ok(());
        }
        let file = Destination::create_file(&dir, last, self.options.overwrite).map_err(error)?;
        let remaining = self
            .options
            .limits
            .max_total_size
            .saturating_sub(summary.bytes);
        match copy_of(
            self.destination,
            target,
            item,
            file,
            remaining,
            self.run,
            self.options,
        ) {
            Ok(written) => {
                summary.files += 1;
                summary.bytes += written;
                self.run.entry_done();
                Ok(())
            }
            Err(kind) => {
                let _ = dir.remove_file(last);
                Err(error(kind))
            }
        }
    }
}

/// Writes the `size` bytes of `r` into `file`, for `item`, at most
/// `remaining` in all, then its time and permissions: the bytes written.
fn write_data(
    r: &mut impl Read,
    item: &Item,
    size: u64,
    file: cap_std::fs::File,
    remaining: u64,
    run: &Run<'_>,
    options: &Options,
) -> Result<u64, ErrorKind> {
    let limits = &options.limits;
    if size > limits.max_entry_size {
        return Err(ErrorKind::EntryTooLarge);
    }
    if size > remaining {
        return Err(ErrorKind::TotalTooLarge);
    }
    let mut file = file.into_std();
    let mut written: u64 = 0;
    let mut buffer = vec![0u8; 64 * 1024];
    while written < size {
        run.check()?;
        let want = buffer.len().min((size - written) as usize);
        let n = match r.read(&mut buffer[..want]) {
            Ok(0) => return Err(ErrorKind::SizeMismatch),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ErrorKind::Cpio(hivepack_cpio::Error::from(e))),
        };
        written += n as u64;
        file.write_all(&buffer[..n]).map_err(ErrorKind::Io)?;
        run.wrote(n as u64);
    }
    finish_file(&file, item, options)?;
    Ok(written)
}
