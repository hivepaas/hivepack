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
//! So far entries whole in this volume: anything else is [`Error::NotYet`].

use std::io;

use crate::archive::Archive;
use crate::crypt::{CryptData, set_crypt_keys};
use crate::error::{Error, ExitCode};
use crate::hash::DataHash;
use crate::headers::{CryptMethod, Format, HEAD_ENDARC, HEAD_FILE, Redirection};
use crate::name::convert_path;
use crate::source::ReadAt;
use crate::unpack::{UnpIo, Unpack};

/// A size at a time. `File::CopyBufferSize`'s is larger, which makes no
/// difference to what comes out.
const COPY_BUFFER_SIZE: usize = 64 << 10;

/// `VER_UNPACK`.
const VER_UNPACK: u32 = 29;
/// `VER_UNPACK7`.
const VER_UNPACK7: u32 = 70;

/// `ComprDataIO`, for an entry that is whole in this volume.
struct DataIo<'a, 'o, R: ReadAt> {
    arc: &'a mut Archive<R>,
    packed_left: u64,
    hash: &'a mut DataHash,
    out: &'a mut Output<'o>,
    skip_unp_crc: bool,
    cur_unp_write: &'a mut u64,
    decrypt: Option<CryptData>,
}

impl<R: ReadAt> UnpIo for DataIo<'_, '_, R> {
    fn unp_read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        // Whole blocks: what reads here always asks for more than one.
        let count = if self.decrypt.is_some() {
            buf.len() & !15
        } else {
            buf.len()
        };
        let to_read = (count as u64).min(self.packed_left) as usize;
        if to_read == 0 {
            return Ok(0);
        }
        let read = self.arc.cursor().read(&mut buf[..to_read])?;
        self.packed_left -= read as u64;
        if let Some(decrypt) = &mut self.decrypt {
            decrypt.decrypt_block(buf, read);
        }
        Ok(read)
    }

    fn unp_write(&mut self, data: &[u8]) -> Result<(), Error> {
        (self.out)(data)?;
        *self.cur_unp_write += data.len() as u64;
        if !self.skip_unp_crc {
            self.hash.update(data);
        }
        Ok(())
    }
}

/// Where an entry's data goes.
pub type Output<'a> = dyn FnMut(&[u8]) -> io::Result<()> + 'a;

/// `CmdExtract`: what lasts from one entry to the next, and what became of
/// the last entry.
#[derive(Debug)]
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
    /// Whether the last entry was encrypted and there was no password: the
    /// going through stops there, as `ERAR_MISSING_PASSWORD` stops it.
    pub missing_password: bool,
    /// Whether RAR 5's check says the password is not the last entry's: its
    /// data is not read, unless a solid stream needs it to go on.
    pub bad_password: bool,
    /// `Unp`: made when first needed, and it lasts for a solid archive's sake.
    unp: Option<Box<Unpack>>,
    /// `FileCount`: the entries gone through that were to be read.
    file_count: u32,
}

impl Default for Extract {
    fn default() -> Extract {
        Extract {
            win_size_limit: 0x1_0000_0000,
            cur_unp_write: 0,
            skip_solid: false,
            broken_file: false,
            missing_password: false,
            bad_password: false,
            unp: None,
            file_count: 0,
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
    /// [`Error::NoMemory`] when a dictionary cannot be had: it stops
    /// everything, as `bad_alloc` does in UnRAR.
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
        self.missing_password = false;
        self.bad_password = false;
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

        // `CheckUnpVer`: stored data does not care about the version. A kind
        // of encryption UnRAR does not know stops even a stored entry, whether
        // or not the entry says it is encrypted.
        let unp_ver = arc.file_head.unp_ver;
        let wrong_ver = arc.file_head.method != 0
            && if arc.format == Format::Rar50 {
                unp_ver > VER_UNPACK7
            } else {
                !(13..=VER_UNPACK).contains(&unp_ver)
            };
        if wrong_ver || arc.file_head.crypt_method == CryptMethod::Unknown {
            arc.set_error_code(ExitCode::Fatal);
            arc.seek_to_next();
            return Ok(!arc.solid);
        }

        // Also excludes names of nothing, like "/" or "../".
        let mut extr_file = named;

        let mut decrypt = None;
        let mut hash_key = None;
        if arc.file_head.encrypted {
            if !arc.password.is_set() {
                self.missing_password = true;
                return Ok(false);
            }
            let keys = set_crypt_keys(
                arc.file_head.crypt_method,
                &arc.password,
                &mut arc.kdf_cache,
                arc.file_head.salt_set.then_some(&arc.file_head.salt[..]),
                &arc.file_head.init_v,
                arc.file_head.lg2_count,
            );
            if let Some((crypt, checks)) = keys {
                // A damaged header cannot be relied on for the check value.
                if arc.file_head.use_psw_check
                    && !arc.broken_header
                    && arc.file_head.psw_check != checks.psw_check
                {
                    self.bad_password = true;
                    arc.set_error_code(ExitCode::BadPassword);
                    extr_file = false;
                }
                decrypt = Some(crypt);
                hash_key = Some(checks.hash_key);
            }
        }

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

        self.file_count = self.file_count.wrapping_add(1);

        let mut hash = DataHash::new(arc.file_head.file_hash.kind);
        let mut show_checksum = true;
        if link_entry {
            // Nothing to read for any of them when testing. A kind nobody
            // knows has no checksum to speak of, and RAR 4's links keep
            // their target as data, checked only when extracting.
            if redir_type == Redirection::Unknown || arc.format == Format::Rar15 {
                show_checksum = false;
            }
        } else if arc.file_head.method == 0 {
            let packed_left = arc.file_head.pack_size as u64;
            let dest_left = arc.file_head.unp_size as u64;
            let mut io = DataIo {
                arc: &mut *arc,
                packed_left,
                hash: &mut hash,
                out,
                skip_unp_crc: self.skip_solid,
                cur_unp_write: &mut self.cur_unp_write,
                decrypt,
            };
            unstore_file(&mut io, dest_left)?;
        } else {
            let unp = self.unp.get_or_insert_with(|| Box::new(Unpack::new()));
            unp.init(arc.file_head.win_size, arc.file_head.solid)?;
            unp.set_dest_size(arc.file_head.unp_size);
            // RAR 1.3 to 1.5 archives do not set a solid flag per file.
            let (method, solid) = if arc.format != Format::Rar50 && arc.file_head.unp_ver <= 15 {
                (15, self.file_count > 1 && arc.solid)
            } else {
                (arc.file_head.unp_ver, arc.file_head.solid)
            };
            let packed_left = arc.file_head.pack_size as u64;
            let mut io = DataIo {
                arc: &mut *arc,
                packed_left,
                hash: &mut hash,
                out,
                skip_unp_crc: self.skip_solid,
                cur_unp_write: &mut self.cur_unp_write,
                decrypt,
            };
            unp.do_unpack(method, solid, &mut io)?;
        }
        arc.seek_to_next();

        let key = hash_key.filter(|_| arc.file_head.use_hash_key);
        let valid = match &key {
            Some(key) => hash.matches_keyed(&arc.file_head.file_hash, key),
            None => hash.matches(&arc.file_head.file_hash),
        };
        if !self.skip_solid && show_checksum && !valid {
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
}

/// `CmdExtract::UnstoreFile`: up to the pack size is read, and up to the
/// unpacked size written. Neither is negative: the header's reading sees to it.
fn unstore_file<R: ReadAt>(io: &mut DataIo<'_, '_, R>, mut dest_left: u64) -> Result<(), Error> {
    let mut buffer = vec![0u8; COPY_BUFFER_SIZE];
    loop {
        let read = io.unp_read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        let write = (read as u64).min(dest_left) as usize;
        if write > 0 {
            io.unp_write(&buffer[..write])?;
            dest_left -= write as u64;
        }
    }
}
