//! The sources that read an entry's data: port of `zip_source_zip_new.c`,
//! for an entry of the archive as read.

use crate::error::{Detail, Error, ErrorCode, Result};
use crate::open::Archive;
use crate::source::ReadAt;
use crate::source_compress::Decompress;
use crate::source_crc::Crc;
use crate::source_stack::{Layer, Stack};
use crate::source_window::{Lower, UpperWindow, Window};
use crate::zip::{Flags, OpenFlags, Stat, cm, em, stat};

impl<R: ReadAt> Archive<R> {
    /// The stack of sources that reads entry `srcidx` from byte `start`,
    /// `len` bytes of it (or to its end if `len` is -1): decompressed unless
    /// `flags` has [`Flags::COMPRESSED`], with its CRC checked when all of
    /// it is read. Port of `zip_source_zip_file_create`.
    ///
    /// Differs from libzip: decryption comes later, so an encrypted entry
    /// is refused with `ZIP_ER_NOPASSWD` without a password and
    /// `ZIP_ER_ENCRNOTSUPP` with one.
    pub(crate) fn source_zip_file_create(
        &self,
        srcidx: u64,
        flags: Flags,
        start: u64,
        len: i64,
        password: Option<&[u8]>,
    ) -> Result<Stack<'_, R>> {
        if srcidx >= self.entry.len() as u64 || len < -1 {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        let mut flags = flags;
        if flags.intersects(Flags::ENCRYPTED) {
            flags = flags | Flags::COMPRESSED;
        }

        let stat_flags = flags | Flags::UNCHANGED;
        let st: Stat<'static> = match self.stat_index(srcidx, stat_flags) {
            Ok(st) => Stat { name: None, ..st },
            Err(_) => return Err(Error::new(ErrorCode::Internal, 0)),
        };

        if (start > 0 || len >= 0) && flags.intersects(Flags::COMPRESSED) {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        // Check for overflow of end.
        if len > 0 && start > 0 && start.checked_add(len as u64).is_none() {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        let have_size = st.valid & stat::SIZE != 0;
        if have_size {
            // Check that start and end are within the size of the file.
            if start > st.size || (len > 0 && start + len as u64 > st.size) {
                return Err(Error::new(ErrorCode::Inval, 0));
            }
        }

        let data_len: i64 = if len == -1 {
            if have_size {
                if st.size - start > i64::MAX as u64 {
                    return Err(Error::new(ErrorCode::Inval, 0));
                }
                (st.size - start) as i64
            } else {
                -1
            }
        } else {
            len
        };
        let partial_data = if have_size {
            (data_len as u64) < st.size
        } else {
            true
        };

        let encrypted = st.valid & stat::ENCRYPTION_METHOD != 0 && st.encryption_method != em::NONE;
        let needs_decrypt = !flags.intersects(Flags::ENCRYPTED) && encrypted;
        let compressed = st.valid & stat::COMP_METHOD != 0 && st.comp_method != cm::STORE;
        let needs_decompress = !flags.intersects(Flags::COMPRESSED) && compressed;
        // when reading the whole file, check for CRC errors
        let needs_crc = (!flags.intersects(Flags::COMPRESSED) || !compressed)
            && !partial_data
            && st.valid & stat::CRC != 0;

        if needs_decrypt && password.is_none() {
            return Err(Error::new(ErrorCode::NoPasswd, 0));
        }

        let de = self.get_dirent(srcidx, flags)?;

        let have_comp_size = st.valid & stat::COMP_SIZE != 0;
        let empty_data = if needs_decrypt || needs_decompress {
            have_comp_size && st.comp_size == 0
        } else {
            have_size && st.size == 0
        };
        // An entry with no data is read from an empty buffer, as if its data
        // had been changed.
        let lower = if empty_data {
            Lower::Empty
        } else {
            Lower::Archive(self.src.view())
        };
        let changed_data = empty_data;

        let window = if partial_data && !needs_decrypt && !needs_decompress {
            if start + data_len as u64 > st.comp_size {
                return Err(Error::incons_at(Detail::StoredSizeMismatch, srcidx));
            }
            let mut st2 = Stat {
                comp_method: cm::STORE,
                valid: stat::COMP_METHOD,
                ..Stat::default()
            };
            if data_len >= 0 {
                st2.size = data_len as u64;
                st2.comp_size = data_len as u64;
                st2.valid |= stat::SIZE | stat::COMP_SIZE;
            }
            if st.valid & stat::MTIME != 0 {
                st2.mtime = st.mtime;
                st2.valid |= stat::MTIME;
            }
            let source_archive = (!changed_data).then_some(de.offset);
            Window::new(&lower, start, data_len, &st2, stat::NAME, source_archive)?
        } else if !changed_data {
            // this branch is executed only for archive sources; we know that
            // stat data come from the archive too, so it's safe to assume
            // that st has a comp_size specified
            if st.comp_size > i64::MAX as u64 {
                return Err(Error::new(ErrorCode::Inval, 0));
            }
            Window::new(
                &lower,
                0,
                st.comp_size as i64,
                &st,
                stat::NAME,
                Some(de.offset),
            )?
        } else {
            // reading from a zero-sized source buffer created above
            Window::new(&lower, 0, data_len, &st, stat::NAME, None)?
        };

        if needs_decrypt {
            return Err(Error::new(ErrorCode::EncrNotSupp, 0));
        }

        let decompress = if needs_decompress {
            let check_consistency = self.open_flags.intersects(OpenFlags::CHECKCONS);
            Some(Layer::new(Decompress::new(
                st.comp_method,
                check_consistency,
            )?))
        } else {
            None
        };

        let crc = needs_crc.then(|| Layer::new(Crc::new(true)));

        let mut stack = Stack {
            lower,
            window: Layer::new(window),
            decompress,
            crc,
            partial: None,
            index: srcidx,
        };

        // The part of the data asked for, a window on top of the
        // decompressed data.
        if partial_data && (needs_decrypt || needs_decompress) {
            let upper = UpperWindow::new(stack.size_below_partial(), start, data_len)?;
            stack.partial = Some(Layer::new(upper));
        }

        Ok(stack)
    }
}
