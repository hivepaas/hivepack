//! Writing an archive with its changes: port of `zip_close.c`, for entries
//! whose data is kept as it is.
//!
//! In torrentzip format ([`ArchiveFlags::WANT_TORRENTZIP`]), the entries
//! are sorted by name, ignoring ASCII case, and written without times,
//! extra fields or comments, and the archive comment is the signature with
//! the CRC-32 of the central directory.

use std::cmp::Ordering;
use std::io::{Seek, Write};

use crate::buffer::Buffer;
use crate::dirent::Dirent;
use crate::error::{Error, ErrorCode, Result};
use crate::file_get_offset::file_get_offset;
use crate::hash::c_string;
use crate::io_util::read;
use crate::open::Archive;
use crate::source::{ReadAt, Source, Whence};
use crate::source_write::Output;
use crate::zip::{ArchiveFlags, Flags, em};
use crate::zipint::{
    BUFSIZE, DATADES_MAGIC, Entry, GPBF_DATA_DESCRIPTOR, MAX_DATA_DESCRIPTOR_LENGTH, changed,
};

/// What [`Archive::close_to`] did: what libzip's `zip_close` does to the
/// archive's file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closed {
    /// Nothing changed, so nothing was written: the archive stays as it is.
    Unchanged,
    /// No entries are left, so nothing was written: libzip removes the
    /// archive, unless it is told to keep it
    /// ([`ArchiveFlags::CREATE_OR_KEEP_FILE_FOR_EMPTY_ARCHIVE`]).
    Removed,
    /// The archive was written, with its changes.
    Written,
}

impl<R: ReadAt> Archive<R> {
    /// Writes the archive with its changes to `out`, from its position:
    /// port of `zip_close`. The entries that are not deleted are written in
    /// order, each with a new local header and its data copied, then the
    /// central directory, with the Zip64 end of central directory record
    /// when the count of entries, the offset or the size of the directory
    /// need it. Nothing is written if nothing changed, or if no entries are
    /// left (see [`Closed`]).
    ///
    /// Differs from libzip:
    /// - The archive is written to `out` in whole, as libzip writes to a
    ///   source that cannot clone the data it keeps
    ///   (`ZIP_SOURCE_BEGIN_WRITE_CLONING`), and offsets in `out` count
    ///   from where it was when given.
    /// - The archive stays open. libzip discards it once written; on
    ///   failure, both leave it as it was then, and `out` has what was
    ///   written up to the error.
    /// - Recompressing, which writing in torrentzip format needs
    ///   ([`ArchiveFlags::WANT_TORRENTZIP`]), fails with
    ///   `ZIP_ER_OPNOTSUPP`, for now.
    pub fn close_to<W: Write + Seek>(&mut self, out: W) -> Result<Closed> {
        let (changed, survivors) = self.changed();

        if survivors == 0
            && !self
                .ch_flags
                .intersects(ArchiveFlags::CREATE_OR_KEEP_FILE_FOR_EMPTY_ARCHIVE)
        {
            // don't create zip files with no entries (ZIP_TRUNCATE, which
            // also removes the file, is not one of the port's flags yet)
            return Ok(if changed {
                Closed::Removed
            } else {
                Closed::Unchanged
            });
        }

        // Always write empty archive if we are told to keep it, otherwise it
        // wouldn't be created if the file doesn't already exist.
        if !changed && survivors > 0 {
            return Ok(Closed::Unchanged);
        }

        if survivors > self.entry.len() as u64 {
            return Err(Error::new(ErrorCode::Internal, 0));
        }

        // create list of files with index into original archive
        let mut filelist = Vec::new();
        for (i, entry) in self.entry.iter().enumerate() {
            if entry.deleted {
                continue;
            }
            if filelist.len() as u64 >= survivors {
                return Err(Error::new(ErrorCode::Internal, 0));
            }
            filelist.push(i);
        }
        if (filelist.len() as u64) < survivors {
            return Err(Error::new(ErrorCode::Internal, 0));
        }

        if self.want_torrentzip() && survivors > 1 {
            let names: Vec<Option<Vec<u8>>> = filelist
                .iter()
                .map(|&i| {
                    self.get_name(i as u64, Flags::NONE)
                        .ok()
                        .map(|name| c_string(name).to_vec())
                })
                .collect();
            let mut order: Vec<usize> = (0..filelist.len()).collect();
            // glibc's qsort sorts these stably.
            order.sort_by(|&a, &b| torrentzip_compare_names(&names[a], &names[b]));
            filelist = order.into_iter().map(|j| filelist[j]).collect();
        }

        let mut out = Output::new(out);
        for &i in &filelist {
            self.write_entry(i, &mut out)?;
        }

        write_cdir(self, &filelist, &mut out)?;
        out.commit_write()?;
        Ok(Closed::Written)
    }

    /// The loop body of `zip_close`: writes entry `i`, its local header and
    /// its data, and keeps where in its dirent of changes.
    fn write_entry<W: Write + Seek>(&mut self, i: usize, out: &mut Output<W>) -> Result<()> {
        let want_torrentzip = self.want_torrentzip();
        let entry = &self.entry[i];
        let new_data = entry.data_changed()
            || entry.changed(changed::COMP_METHOD)
            || entry.changed(changed::ENCRYPTION_METHOD)
            || (want_torrentzip && !self.is_torrentzip());

        // create new local directory entry
        let entry = &mut self.entry[i];
        let data_changed = entry.data_changed();
        match (entry.changes.as_deref_mut(), entry.orig.as_deref()) {
            (None, orig) => entry.changes = Some(Box::new(Dirent::clone_changes(orig))),
            (Some(changes), Some(orig)) => changes.merge(orig, data_changed),
            (Some(_), None) => {}
        }

        self.read_local_ef(i as u64)?;

        if want_torrentzip && let Some(changes) = self.entry[i].changes.as_deref_mut() {
            changes.torrentzip_normalize();
        }

        let Archive { src, entry, .. } = self;
        let Entry { orig, changes, .. } = &mut entry[i];
        let Some(de) = changes.as_deref_mut() else {
            return Err(Error::new(ErrorCode::Internal, 0));
        };

        de.offset = out.tell_write()?;

        if new_data {
            // Differs from libzip, for now: recompressing comes later.
            return Err(Error::new(ErrorCode::OpNotSupp, 0));
        }

        if de.encryption_method != em::TRAD_PKWARE {
            // when copying data, all sizes are known -> no data descriptor
            // needed, except for PKWare encryption, where removing the data
            // descriptor breaks password validation
            de.bitflags &= !GPBF_DATA_DESCRIPTOR;
        }
        de.write(out, Flags::LOCAL, want_torrentzip)?;

        // _zip_file_get_offset
        let Some(orig) = orig.as_deref() else {
            return Err(Error::new(ErrorCode::Internal, 0));
        };
        let mut src = src.view();
        let offset = file_get_offset(&mut src, orig.offset)?;
        src.seek(offset as i64, Whence::Set)?;
        copy_data(&mut src, out, de.comp_size)?;

        if de.bitflags & GPBF_DATA_DESCRIPTOR != 0 {
            write_data_descriptor(out, de, de.needs_zip64(Flags::NONE))?;
        }
        Ok(())
    }

    /// Whether anything changed, and how many entries are not deleted:
    /// port of `_zip_changed`.
    pub(crate) fn changed(&self) -> (bool, u64) {
        let mut changed = self.comment_changed || (self.want_torrentzip() && !self.is_torrentzip());
        let mut survivors = 0;
        for entry in &self.entry {
            if entry.has_changes() {
                changed = true;
            }
            if !entry.deleted {
                survivors += 1;
            }
        }
        (changed, survivors)
    }
}

/// The order of names in a torrentzipped archive, ignoring ASCII case,
/// those that cannot be read first: port of `torrentzip_compare_names`,
/// with `strcasecmp`.
fn torrentzip_compare_names(a: &Option<Vec<u8>>, b: &Option<Vec<u8>>) -> Ordering {
    match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(a), Some(b)) => a
            .iter()
            .map(u8::to_ascii_lowercase)
            .cmp(b.iter().map(u8::to_ascii_lowercase)),
    }
}

/// Copies `len` bytes from `src` to `out`: port of `copy_data`.
fn copy_data<R: ReadAt + ?Sized, W: Write + Seek>(
    src: &mut Source<&R>,
    out: &mut Output<W>,
    len: u64,
) -> Result<()> {
    let mut buf = vec![0; BUFSIZE];
    let mut len = len;
    while len > 0 {
        let n = len.min(BUFSIZE as u64) as usize;
        read(src, &mut buf[..n])?;
        out.write(&buf[..n])?;
        len -= n as u64;
    }
    Ok(())
}

/// Port of `write_cdir`.
fn write_cdir<R: ReadAt, W: Write + Seek>(
    za: &mut Archive<R>,
    filelist: &[usize],
    out: &mut Output<W>,
) -> Result<()> {
    za.cdir_write(filelist, out)?;
    Ok(())
}

/// Writes the data descriptor of `de`, with 64-bit sizes if `is_zip64`:
/// port of `write_data_descriptor`.
fn write_data_descriptor<W: Write + Seek>(
    out: &mut Output<W>,
    de: &Dirent,
    is_zip64: bool,
) -> Result<()> {
    let mut buffer = Buffer::with_size(MAX_DATA_DESCRIPTOR_LENGTH as usize);

    buffer.put(DATADES_MAGIC);
    buffer.put_32(de.crc);
    if is_zip64 {
        buffer.put_64(de.comp_size);
        buffer.put_64(de.uncomp_size);
    } else {
        buffer.put_32(de.comp_size as u32);
        buffer.put_32(de.uncomp_size as u32);
    }

    if !buffer.ok() {
        return Err(Error::new(ErrorCode::Internal, 0));
    }
    let len = buffer.offset() as usize;
    out.write(&buffer.data()[..len])
}
