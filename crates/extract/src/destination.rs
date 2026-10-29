//! Writing under the destination by handle: each directory is opened from
//! its parent's handle without following a symbolic link, and each file is
//! created new, so nothing is written outside the destination, through a
//! link that is there or that appears while extracting, or over what is
//! there.
//!
//! cap-std does the opening, with `openat2` and `RESOLVE_BENEATH` on
//! Linux, `openat` and `O_NOFOLLOW` a component at a time elsewhere on
//! Unix, and handles relative to a directory's on Windows. It is the one
//! dependency here with `unsafe` code (see the repository's
//! `docs/safety.md`): the standard library's directory handles
//! (`std::fs::Dir`) are not stable yet.

use std::io;
use std::path::Path;

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions};

use crate::error::ErrorKind;

/// The destination, open.
pub(crate) struct Destination {
    root: Dir,
}

impl Destination {
    /// Opens `path`, creating it first if it is not there. The path itself
    /// is the caller's, and is followed as given.
    pub(crate) fn open(path: &Path) -> io::Result<Destination> {
        std::fs::create_dir_all(path)?;
        let root = Dir::open_ambient_dir(path, ambient_authority())?;
        Ok(Destination { root })
    }

    /// The directory at `components`, created where it is not there, each
    /// opened from the one before without following a link.
    pub(crate) fn directory(&self, components: &[String]) -> Result<Dir, ErrorKind> {
        let mut dir = self.root.try_clone().map_err(ErrorKind::Io)?;
        for component in components {
            match dir.create_dir(component) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(ErrorKind::Io(e)),
            }
            dir = match dir.open_dir_nofollow(component) {
                Ok(next) => next,
                Err(e) => {
                    // A link, or a file, where a directory was to be.
                    return Err(match dir.symlink_metadata(component) {
                        Ok(metadata) if !metadata.is_dir() => ErrorKind::NotADirectory,
                        _ => ErrorKind::Io(e),
                    });
                }
            };
        }
        Ok(dir)
    }

    /// Creates the file `name` in `dir`, which must not be there, not even
    /// as a link.
    pub(crate) fn create_file(dir: &Dir, name: &str) -> Result<File, ErrorKind> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        options.follow(FollowSymlinks::No);
        dir.open_with(name, &options).map_err(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => ErrorKind::Exists,
            _ => ErrorKind::Io(e),
        })
    }
}
