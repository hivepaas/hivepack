// hivepack-rar: a port of UnRAR 7.3.2 to Rust. UnRAR's license says:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.
//! Going through an archive's entries: UnRAR's `CmdExtract` (extract.cpp)
//! and the reading and writing of `ComprDataIO` (rdwrfn.cpp), as they are
//! when testing an archive: each entry's data is read, given to a callback
//! and checked against its hash, and nothing is created.
//!
//! So far entries that are stored, not encrypted and whole in this volume:
//! anything else is [`Error::NotYet`].

use std::io;

use crate::archive::Archive;
use crate::error::{Error, ExitCode};
use crate::hash::DataHash;
use crate::headers::{CryptMethod, Format, HEAD_ENDARC, HEAD_FILE, Redirection};
use crate::name::convert_path;
use crate::source::ReadAt;

/// A size at a time. `File::CopyBufferSize`'s is larger, which makes no
/// difference to what comes out.
const COPY_BUFFER_SIZE: usize = 64 << 10;

/// Where an entry's data goes.
pub type Output<'a> = dyn FnMut(&[u8]) -> io::Result<()> + 'a;

/// `CmdExtract`: what lasts from one entry to the next, and what became of
/// the last entry.
#[derive(Clone, Debug)]
pub struct Extract {
    /// The largest dictionary an entry may ask for, stored or not: over it
    /// the extraction stops, as `CheckWinLimit` stops it when nobody allows
    /// more. By default what UnRAR allows, 4 GiB.
    pub win_size_limit: u64,
    /// How many bytes of the last entry were given out: `CurUnpWrite`.
    pub cur_unp_write: u64,
    /// Whether the last entry's data was skipped over, as the data before a
    /// wanted entry of a solid archive is. The data is still given out, as
    /// UnRAR's library gives it out, and has not been checked.
    pub skip_solid: bool,
    /// Whether the last entry's hash was checked and failed.
    pub broken_file: bool,
}

impl Default for Extract {
    fn default() -> Extract {
        Extract {
            win_size_limit: 0x1_0000_0000,
            cur_unp_write: 0,
            skip_solid: false,
            broken_file: false,
        }
    }
}

impl Extract {
    /// Nothing done yet.
    pub fn new() -> Extract {
        Extract::default()
    }

    /// `CmdExtract::ExtractCurrentFile` when testing: what to do with the
    /// header [`Archive::read_header`] just read, whose result is
    /// `header_size`. Whether to go on with the next header.
    ///
    /// A file's data goes to `out`, in pieces; a directory, a link or
    /// anything else has none. A hash that fails sets the exit code to
    /// [`ExitCode::Crc`] and the reading goes on, as UnRAR's does.
    ///
    /// # Errors
    ///
    /// [`Error::NotYet`] for an entry that cannot be read yet, the position
    /// left at its header's end: [`Archive::seek_to_next`] goes on past it.
    /// [`Error::Io`] when the archive cannot be read or `out` fails.
    pub fn current_file<R: ReadAt>(
        &mut self,
        arc: &mut Archive<R>,
        header_size: usize,
        out: &mut Output<'_>,
    ) -> Result<bool, Error> {
        self.cur_unp_write = 0;
        self.skip_solid = false;
        self.broken_file = false;
        if header_size == 0 {
            return Ok(false);
        }
        let header_type = arc.cur_header_type;
        if header_type != HEAD_FILE {
            if header_type == HEAD_ENDARC {
                // MergeArchive cannot open a next volume, for now: volumes
                // are step 3. It says so, and ExtractCurrentFile warns.
                if arc.end_arc_head.next_volume {
                    arc.set_error_code(ExitCode::Open);
                    arc.set_error_code(ExitCode::Warning);
                }
                return Ok(false);
            }
            arc.seek_to_next();
            return Ok(true);
        }

        let head = &arc.file_head;
        if head.method != 0 {
            return Err(Error::NotYet("compressed data"));
        }
        if head.encrypted {
            return Err(Error::NotYet("encrypted data"));
        }
        if head.split_before || head.split_after {
            return Err(Error::NotYet("data split across volumes"));
        }

        let named = !convert_path(&head.file_name).is_empty();
        let (redir_type, dir) = (head.redir_type, head.dir);

        // `Arc.Seek(Arc.NextBlockPos-Arc.FileHead.PackSize,SEEK_SET)`: the end
        // of the header, as the next position is the header's end plus the
        // pack size, or reading the header would have failed. So this always
        // moves forward from the header's start.
        arc.seek((arc.next_block_pos - arc.file_head.pack_size) as u64);

        // `CheckUnpVer`: a kind of encryption UnRAR does not know stops even a
        // stored entry, whether or not the entry says it is encrypted.
        if arc.file_head.crypt_method == CryptMethod::Unknown {
            arc.set_error_code(ExitCode::Fatal);
            arc.seek_to_next();
            return Ok(!arc.solid);
        }

        // Also excludes names of nothing, like "/" or "../".
        let mut extr_file = named;
        let link_entry = redir_type != Redirection::None;
        if !link_entry || redir_type == Redirection::FileCopy {
            if dir {
                // No seek: what follows a directory's header is read as the
                // next header, whatever its pack size says.
                return Ok(true);
            }
            if extr_file && !self.check_win_limit(arc) {
                return Ok(false);
            }
        }
        if !extr_file && arc.solid {
            self.skip_solid = true;
            extr_file = true;
            if !self.check_win_limit(arc) {
                return Ok(false);
            }
        }
        if !extr_file {
            // Not solid here: solid has just set it.
            arc.seek_to_next();
            return Ok(true);
        }

        let mut hash = DataHash::new(arc.file_head.file_hash.kind);
        let mut show_checksum = true;
        if link_entry {
            // Nothing to read for any of them when testing. A kind nobody
            // knows has no checksum to speak of, and RAR 4's links keep
            // their target as data, checked only when extracting.
            if redir_type == Redirection::Unknown || arc.format == Format::Rar15 {
                show_checksum = false;
            }
        } else {
            self.unstore_file(arc, &mut hash, out)?;
        }
        arc.seek_to_next();

        if !self.skip_solid && show_checksum && !hash.matches(&arc.file_head.file_hash) {
            self.broken_file = true;
            arc.set_error_code(ExitCode::Crc);
        }
        Ok(true)
    }

    /// `CmdExtract::CheckWinLimit`, where nobody allows more.
    fn check_win_limit<R: ReadAt>(&self, arc: &mut Archive<R>) -> bool {
        // `Cmd->WinSize`, the default of the -md switch, is smaller.
        if arc.file_head.win_size <= self.win_size_limit {
            return true;
        }
        arc.set_error_code(ExitCode::Fatal);
        arc.seek_to_next();
        false
    }

    /// `CmdExtract::UnstoreFile` with `ComprDataIO::UnpRead` and `UnpWrite`:
    /// up to the pack size is read, and up to the unpacked size written.
    fn unstore_file<R: ReadAt>(
        &mut self,
        arc: &mut Archive<R>,
        hash: &mut DataHash,
        out: &mut Output<'_>,
    ) -> Result<(), Error> {
        // Neither is negative: the header's reading sees to that.
        let mut packed_left = arc.file_head.pack_size as u64;
        let mut dest_left = arc.file_head.unp_size as u64;
        let mut buffer = vec![0u8; packed_left.min(COPY_BUFFER_SIZE as u64) as usize];
        while packed_left > 0 {
            let to_read = packed_left.min(buffer.len() as u64) as usize;
            let read = arc.cursor().read(&mut buffer[..to_read])?;
            if read == 0 {
                break;
            }
            packed_left -= read as u64;
            let write = (read as u64).min(dest_left) as usize;
            if write > 0 {
                out(&buffer[..write])?;
                self.cur_unp_write += write as u64;
                dest_left -= write as u64;
                if !self.skip_solid {
                    hash.update(&buffer[..write]);
                }
            }
        }
        Ok(())
    }
}
