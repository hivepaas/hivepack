//! Port of `zip_stat_index.c`.

use crate::dirent::d2u_time;
use crate::error::Result;
use crate::open::Archive;
use crate::source::ReadAt;
use crate::zip::{Flags, Stat, stat};

impl<R: ReadAt> Archive<R> {
    /// What the central directory says about entry `index`: port of
    /// `zip_stat_index`. The CRC is not valid for WinZip AES entries of
    /// version 2 (AE-2). The time is taken as UTC (see
    /// [`Archive::file_get_dos_time`] for the time as stored).
    pub fn stat_index(&self, index: u64, flags: Flags) -> Result<Stat<'_>> {
        let de = self.get_dirent(index, flags)?;
        let name = self.get_name(index, flags)?;

        let mut st = Stat {
            crc: de.crc,
            size: de.uncomp_size,
            mtime: d2u_time(de.last_mod),
            comp_size: de.comp_size,
            comp_method: de.comp_method as u16,
            encryption_method: de.encryption_method,
            valid: (if de.crc_valid { stat::CRC } else { 0 })
                | stat::SIZE
                | stat::MTIME
                | stat::COMP_SIZE
                | stat::COMP_METHOD
                | stat::ENCRYPTION_METHOD,
            ..Stat::default()
        };

        st.index = index;
        st.name = Some(name);
        st.valid |= stat::INDEX | stat::NAME;
        Ok(st)
    }

    /// The modification time of entry `index` as stored, in MS-DOS format:
    /// `(time, date)`.
    pub fn file_get_dos_time(&self, index: u64, flags: Flags) -> Result<(u16, u16)> {
        let de = self.get_dirent(index, flags)?;
        Ok((de.last_mod.time, de.last_mod.date))
    }
}
