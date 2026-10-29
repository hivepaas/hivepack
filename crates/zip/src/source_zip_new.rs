//! The sources that read an entry's data: port of `zip_source_zip_new.c`,
//! for the whole of an entry of the archive as read.

use crate::error::{Error, ErrorCode, Result};
use crate::open::Archive;
use crate::source::ReadAt;
use crate::source_compress::Decompress;
use crate::source_crc::Crc;
use crate::source_stack::{Layer, Stack};
use crate::source_window::{Lower, Window};
use crate::zip::{Flags, OpenFlags, Stat, cm, em, stat};

impl<R: ReadAt> Archive<R> {
    /// The stack of sources that reads all of entry `srcidx`: decompressed
    /// unless `flags` has [`Flags::COMPRESSED`], with its CRC checked when
    /// it is. Port of `zip_source_zip_file_create`, with `start` 0 and
    /// `len` -1.
    ///
    /// Differs from libzip: decryption comes later, so an encrypted entry
    /// is refused with `ZIP_ER_NOPASSWD` without a password and
    /// `ZIP_ER_ENCRNOTSUPP` with one.
    pub(crate) fn source_zip_file_create(
        &self,
        srcidx: u64,
        flags: Flags,
        password: Option<&[u8]>,
    ) -> Result<Stack<'_, R>> {
        if srcidx >= self.entry.len() as u64 {
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

        let have_size = st.valid & stat::SIZE != 0;
        let data_len: i64 = if have_size {
            if st.size > i64::MAX as u64 {
                return Err(Error::new(ErrorCode::Inval, 0));
            }
            st.size as i64
        } else {
            -1
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

        // A buffer source for an entry with no data, read as if its data
        // had been changed; else the archive. A whole entry is never
        // partial data.
        let (lower, window) = if empty_data {
            let lower = Lower::Empty;
            let window = Window::new(&lower, 0, data_len, &st, stat::NAME, None)?;
            (lower, window)
        } else {
            if st.comp_size > i64::MAX as u64 {
                return Err(Error::new(ErrorCode::Inval, 0));
            }
            let lower = Lower::Archive(self.src.view());
            let window = Window::new(
                &lower,
                0,
                st.comp_size as i64,
                &st,
                stat::NAME,
                Some(de.offset),
            )?;
            (lower, window)
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

        Ok(Stack {
            lower,
            window: Layer::new(window),
            decompress,
            crc,
            index: srcidx,
        })
    }
}
