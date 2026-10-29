//! Reading extra fields: port of `zip_extra_field_api.c`, the reading half.

use crate::error::{Error, ErrorCode, Result};
use crate::extra_field::ExtraField;
use crate::open::Archive;
use crate::source::ReadAt;
use crate::zip::Flags;
use crate::zipint::{EF_BOTH, EF_CENTRAL};

impl<R: ReadAt> Archive<R> {
    /// Extra field number `ef_idx` of entry `idx`, counted through those of
    /// the central directory, then those of the local header, as `flags`
    /// ask ([`Flags::CENTRAL`], [`Flags::LOCAL`] or both): its header id and
    /// data. Port of `zip_file_extra_field_get`. The fields libzip reads
    /// itself (Zip64, the Info-ZIP UTF-8 name and comment, WinZip AES) are
    /// not among them.
    pub fn file_extra_field_get(
        &self,
        idx: u64,
        ef_idx: u16,
        flags: Flags,
    ) -> Result<(u16, &[u8])> {
        self.file_extra_field_get_impl(idx, ef_idx, None, flags)
    }

    /// Extra field number `ef_idx` among those of entry `idx` with header id
    /// `ef_id`: port of `zip_file_extra_field_get_by_id`.
    pub fn file_extra_field_get_by_id(
        &self,
        idx: u64,
        ef_id: u16,
        ef_idx: u16,
        flags: Flags,
    ) -> Result<&[u8]> {
        self.file_extra_field_get_impl(idx, ef_idx, Some(ef_id), flags)
            .map(|(_, data)| data)
    }

    /// The number of extra fields of entry `idx`: port of
    /// `zip_file_extra_fields_count`.
    pub fn file_extra_fields_count(&self, idx: u64, flags: Flags) -> Result<i16> {
        self.count_impl(idx, -1, flags)
    }

    /// The number of extra fields of entry `idx` with header id `ef_id`:
    /// port of `zip_file_extra_fields_count_by_id`.
    pub fn file_extra_fields_count_by_id(&self, idx: u64, ef_id: u16, flags: Flags) -> Result<i16> {
        self.count_impl(idx, i32::from(ef_id), flags)
    }

    fn count_impl(&self, idx: u64, id: i32, flags: Flags) -> Result<i16> {
        if !flags.intersects(EF_BOTH) {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        self.get_dirent(idx, flags)?;
        if flags.intersects(Flags::LOCAL) {
            self.read_local_ef(idx)?;
        }
        Ok(self.get_dirent(idx, flags)?.extra_fields.count(id, flags))
    }

    /// Port of `_zip_file_extra_field_get`. The field is found first, then
    /// borrowed, as the local header may have to be read in between.
    fn file_extra_field_get_impl(
        &self,
        idx: u64,
        mut ef_idx: u16,
        ef_id: Option<u16>,
        flags: Flags,
    ) -> Result<(u16, &[u8])> {
        if !flags.intersects(EF_BOTH) {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        let de = self.get_dirent(idx, flags)?;

        let mut found = None;
        if flags.intersects(EF_CENTRAL) {
            found = get_one(&de.extra_fields.central, &mut ef_idx, ef_id).map(|at| (false, at));
        }
        if found.is_none() && flags.intersects(Flags::LOCAL) {
            self.read_local_ef(idx)?;
            let de = self.get_dirent(idx, flags)?;
            found = get_one(
                de.extra_fields.local.get().map_or(&[][..], Vec::as_slice),
                &mut ef_idx,
                ef_id,
            )
            .map(|at| (true, at));
        }

        let Some((local, at)) = found else {
            return Err(Error::new(ErrorCode::NoEntry, 0));
        };
        let de = self.get_dirent(idx, flags)?;
        let fields = if local {
            de.extra_fields.local.get().map_or(&[][..], Vec::as_slice)
        } else {
            &de.extra_fields.central
        };
        let ef = &fields[at];
        Ok((ef.id, &ef.data))
    }
}

/// The position of field number `*idx` with header id `id` (any, if
/// `None`), counting down `*idx` past the others: port of
/// `_zip_file_extra_field_get_one`.
fn get_one(ef: &[ExtraField], idx: &mut u16, id: Option<u16>) -> Option<usize> {
    for (at, ef) in ef.iter().enumerate() {
        if id.is_none_or(|id| ef.id == id) {
            if *idx == 0 {
                return Some(at);
            }
            *idx -= 1;
        }
    }
    None
}
