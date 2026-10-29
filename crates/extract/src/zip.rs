//! Extracting a ZIP archive that `hivepack-zip` opened.

use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use hivepack_zip::{Archive, Flags, ReadAt, opsys, stat};

use crate::destination::Destination;
use crate::error::{Error, ErrorKind};
use crate::name::check_name;
use crate::plan::{Item, Kind, Options, check};

/// What was extracted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Summary {
    pub files: u64,
    pub directories: u64,
    /// Bytes written.
    pub bytes: u64,
}

/// The type bits of a Unix mode.
const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;

/// What the archive says of entry `i`.
fn item<R: ReadAt>(archive: &Archive<R>, i: u64) -> Result<Item, Error> {
    let archive_error = |e| Error {
        index: Some(i),
        name: None,
        kind: ErrorKind::Archive(e),
    };
    // The name as the archive has it, for errors and for the control
    // characters a CP437 name decodes to symbols (0x01 to ☺): an extractor
    // that takes the bytes as they are sees them.
    let raw_name = archive
        .get_name(i, Flags::ENC_RAW)
        .map_err(archive_error)?
        .to_vec();
    let name_error = |e| Error::new(i, &raw_name, ErrorKind::Name(e));
    if raw_name.iter().any(u8::is_ascii_control) {
        return Err(name_error(crate::NameError::Control));
    }
    // The name as it is written: UTF-8, or decoded from CP437.
    let decoded = archive.get_name(i, Flags::NONE).map_err(archive_error)?;
    let name = check_name(decoded).map_err(name_error)?;
    let st = archive
        .stat_index(i, Flags::NONE)
        .map_err(|e| Error::new(i, &raw_name, ErrorKind::Archive(e)))?;
    let (system, attributes) = archive
        .file_get_external_attributes(i, Flags::NONE)
        .map_err(|e| Error::new(i, &raw_name, ErrorKind::Archive(e)))?;

    // Unix keeps the mode in the high half of the external attributes.
    let unix_mode = (system == opsys::UNIX).then_some(attributes >> 16);
    let kind = match unix_mode.map(|mode| mode & S_IFMT) {
        Some(S_IFLNK) => Kind::Link,
        Some(S_IFDIR) => Kind::Dir,
        Some(0 | S_IFREG) | None if name.is_dir => Kind::Dir,
        Some(0 | S_IFREG) | None => Kind::File,
        Some(_) => Kind::Special,
    };
    let data = if st.valid & stat::COMP_SIZE != 0 && st.comp_size > 0 {
        let start = archive
            .file_get_offset(i)
            .map_err(|e| Error::new(i, &raw_name, ErrorKind::Archive(e)))?;
        Some(start..start.saturating_add(st.comp_size))
    } else {
        None
    };
    let mtime = if st.valid & stat::MTIME == 0 {
        None
    } else if st.mtime >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(st.mtime as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(st.mtime.unsigned_abs()))
    };
    Ok(Item {
        index: i,
        raw_name,
        name,
        kind,
        size: if st.valid & stat::SIZE != 0 {
            st.size
        } else {
            0
        },
        compressed: st.comp_size,
        data,
        mode: unix_mode.map(|mode| mode & 0o7777),
        mtime,
    })
}

/// Extracts `archive` into `destination`, which is created if it is not
/// there, with `options`.
///
/// Every entry is checked before anything is written: its name (see
/// [`check_name`]), that no two entries name the same path (ignoring
/// case), that none is a link or a special file, that no two share
/// compressed data, and what the archive says of the sizes against the
/// limits. Then each is written, its data counted against the limits as it
/// comes and checked when it ends (the CRC-32, or WinZip AES's
/// authentication code); a file whose data fails is removed, and the
/// extraction stops there. Nothing is overwritten, and nothing is written
/// through a link.
///
/// Files get the time the archive has, and on Unix its permission bits,
/// masked: no setuid, setgid or sticky bit, no writing by group or others,
/// and reading and writing by the owner. Directories get the system's
/// defaults.
///
/// Open the archive with
/// [`OpenFlags::CHECKCONS`](hivepack_zip::OpenFlags::CHECKCONS), so that
/// local headers that disagree with the central directory are refused.
pub fn extract_zip<R: ReadAt>(
    archive: &Archive<R>,
    destination: &Path,
    options: &Options,
) -> Result<Summary, Error> {
    let limits = &options.limits;
    let n = archive.get_num_entries(Flags::NONE);
    if n > limits.max_entries {
        return Err(Error::global(ErrorKind::TooManyEntries));
    }
    let items = (0..n)
        .map(|i| item(archive, i))
        .collect::<Result<Vec<Item>, Error>>()?;
    check(&items, limits)?;

    let destination =
        Destination::open(destination).map_err(|e| Error::global(ErrorKind::Io(e)))?;
    let mut summary = Summary::default();
    for item in &items {
        let error = |kind| Error::new(item.index, &item.raw_name, kind);
        let components = &item.name.components;
        if item.kind == Kind::Dir {
            destination.directory(components).map_err(error)?;
            summary.directories += 1;
            continue;
        }
        let (last, parents) = components
            .split_last()
            .ok_or_else(|| error(ErrorKind::Name(crate::NameError::Empty)))?;
        let dir = destination.directory(parents).map_err(error)?;
        let file = Destination::create_file(&dir, last).map_err(error)?;
        let remaining = limits.max_total_size.saturating_sub(summary.bytes);
        match write_data(archive, item, file, limits, remaining, options) {
            Ok(written) => {
                summary.files += 1;
                summary.bytes += written;
            }
            Err(kind) => {
                // A file whose data failed is not left.
                let _ = dir.remove_file(last);
                return Err(error(kind));
            }
        }
    }
    Ok(summary)
}

/// Writes the data of `item` into `file`, at most `remaining` bytes in
/// all, then its time and permissions: the bytes written.
fn write_data<R: ReadAt>(
    archive: &Archive<R>,
    item: &Item,
    file: cap_std::fs::File,
    limits: &crate::Limits,
    remaining: u64,
    options: &Options,
) -> Result<u64, ErrorKind> {
    let mut zf = archive
        .fopen_index_encrypted(item.index, Flags::NONE, options.password.as_deref())
        .map_err(ErrorKind::Archive)?;
    let mut file = file.into_std();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut written: u64 = 0;
    loop {
        let n = match zf.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                return Err(match zf.fclose() {
                    Err(error) => ErrorKind::Archive(error),
                    Ok(()) => ErrorKind::Io(e),
                });
            }
        };
        written += n as u64;
        if written > limits.max_entry_size {
            return Err(ErrorKind::EntryTooLarge);
        }
        if written > remaining {
            return Err(ErrorKind::TotalTooLarge);
        }
        if written > item.size {
            return Err(ErrorKind::SizeMismatch);
        }
        if written > limits.ratio_threshold
            && written > item.compressed.saturating_mul(limits.max_ratio)
        {
            return Err(ErrorKind::Ratio);
        }
        file.write_all(&buffer[..n]).map_err(ErrorKind::Io)?;
    }
    zf.fclose().map_err(ErrorKind::Archive)?;
    if written != item.size {
        return Err(ErrorKind::SizeMismatch);
    }

    if let Some(mtime) = item.mtime {
        file.set_times(std::fs::FileTimes::new().set_modified(mtime))
            .map_err(ErrorKind::Io)?;
    }
    #[cfg(unix)]
    if let Some(mode) = item.mode {
        use std::os::unix::fs::PermissionsExt;
        // No setuid, setgid or sticky bit, no writing by group or others,
        // and reading and writing by the owner.
        let mode = (mode & 0o755) | 0o600;
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(ErrorKind::Io)?;
    }
    file.flush().map_err(ErrorKind::Io)?;
    Ok(written)
}
