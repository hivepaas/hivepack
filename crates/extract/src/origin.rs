//! Marks of origin: where a file came from, which the system checks before
//! opening or running it. A downloaded archive has one (Windows' Mark of
//! the Web, a `Zone.Identifier` stream; macOS's `com.apple.quarantine`
//! attribute), and the files extracted from it must have it too, or
//! extracting is a way around the check, as 7-Zip's CVE-2025-0411 was.
//!
//! The mark is written by handle, as everything else here: on Windows the
//! stream is opened from the file's own handle, on macOS the attribute is
//! set on the file's descriptor.

use std::io;
use std::path::Path;

/// A mark of origin, carried from an archive to every file extracted from
/// it (see [`Options::origin`](crate::Options::origin)). [`Origin::of`]
/// reads the one an archive has.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Origin {
    /// Windows' Mark of the Web: what a `Zone.Identifier` stream holds,
    /// such as `[ZoneTransfer]` and `ZoneId=3`. Written on every file
    /// extracted, as it is.
    ZoneIdentifier(Vec<u8>),
    /// macOS's quarantine: what a `com.apple.quarantine` extended
    /// attribute holds. Written on every file extracted and every
    /// directory created, as an app is a directory, as it is.
    Quarantine(Vec<u8>),
}

/// Shows which mark, and how long it is.
impl std::fmt::Debug for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, value) = match self {
            Origin::ZoneIdentifier(value) => ("ZoneIdentifier", value),
            Origin::Quarantine(value) => ("Quarantine", value),
        };
        write!(f, "{kind}({:?})", String::from_utf8_lossy(value))
    }
}

/// The name of macOS's quarantine attribute.
#[cfg(target_os = "macos")]
const QUARANTINE: &str = "com.apple.quarantine";

impl Origin {
    /// The mark the file at `path` has: on Windows its `Zone.Identifier`
    /// stream, on macOS its quarantine attribute; `None` if it has none,
    /// and on other systems, which have no mark.
    pub fn of(path: &Path) -> io::Result<Option<Origin>> {
        read(path)
    }

    /// Whether this system can write the mark: an error, before anything
    /// is written, if not.
    pub(crate) fn check_supported(&self) -> io::Result<()> {
        let supported = match self {
            Origin::ZoneIdentifier(_) => cfg!(windows),
            Origin::Quarantine(_) => cfg!(target_os = "macos"),
        };
        if supported {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "this system cannot carry this mark of origin",
            ))
        }
    }

    /// Writes the mark on `file`, just created: the stream on Windows, the
    /// attribute on macOS. Directories get only macOS's.
    pub(crate) fn write_file(&self, file: &std::fs::File) -> io::Result<()> {
        write(self, file)
    }

    /// Writes the mark on the directory `dir`, just created, where the
    /// system marks directories: macOS.
    pub(crate) fn write_dir(&self, dir: &cap_std::fs::Dir) -> io::Result<()> {
        write_dir(self, dir)
    }
}

#[cfg(windows)]
fn read(path: &Path) -> io::Result<Option<Origin>> {
    // The stream, by the absolute path: `a:Zone.Identifier` alone would be
    // a path on drive A.
    let mut stream = std::path::absolute(path)?.into_os_string();
    stream.push(":Zone.Identifier");
    match std::fs::read(&stream) {
        Ok(value) => Ok(Some(Origin::ZoneIdentifier(value))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(windows)]
fn write(origin: &Origin, file: &std::fs::File) -> io::Result<()> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
    use std::io::Write;
    let Origin::ZoneIdentifier(value) = origin else {
        return Ok(());
    };
    // The stream, opened from the file's own handle (`:Zone.Identifier`
    // relative to it), so that no path is resolved again.
    let base = cap_std::fs::Dir::from_std_file(file.try_clone()?);
    let mut options = cap_std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    options.follow(FollowSymlinks::No);
    let mut stream = base.open_with(":Zone.Identifier", &options)?;
    stream.write_all(value)?;
    stream.flush()
}

#[cfg(target_os = "macos")]
fn read(path: &Path) -> io::Result<Option<Origin>> {
    let file = std::fs::File::open(path)?;
    let mut value = Vec::with_capacity(256);
    loop {
        match rustix::fs::fgetxattr(
            &file,
            QUARANTINE,
            rustix::buffer::spare_capacity(&mut value),
        ) {
            Ok(_) => return Ok(Some(Origin::Quarantine(value))),
            Err(rustix::io::Errno::NOATTR) => return Ok(None),
            // A value longer than the room given: give more.
            Err(rustix::io::Errno::RANGE) if value.capacity() < 1 << 16 => {
                value.reserve(value.capacity() * 2);
            }
            Err(e) => return Err(e.into()),
        }
    }
}

#[cfg(target_os = "macos")]
fn write(origin: &Origin, file: &std::fs::File) -> io::Result<()> {
    let Origin::Quarantine(value) = origin else {
        return Ok(());
    };
    rustix::fs::fsetxattr(file, QUARANTINE, value, rustix::fs::XattrFlags::empty())?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn write_dir(origin: &Origin, dir: &cap_std::fs::Dir) -> io::Result<()> {
    let Origin::Quarantine(value) = origin else {
        return Ok(());
    };
    rustix::fs::fsetxattr(dir, QUARANTINE, value, rustix::fs::XattrFlags::empty())?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn write_dir(_origin: &Origin, _dir: &cap_std::fs::Dir) -> io::Result<()> {
    Ok(())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn read(_path: &Path) -> io::Result<Option<Origin>> {
    Ok(None)
}

#[cfg(not(any(windows, target_os = "macos")))]
fn write(_origin: &Origin, _file: &std::fs::File) -> io::Result<()> {
    Ok(())
}
