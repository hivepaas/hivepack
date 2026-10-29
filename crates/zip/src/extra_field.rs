//! Extra fields: port of `zip_extra_field.c`.

use std::io::{Seek, Write};
use std::sync::OnceLock;

use crate::buffer::Buffer;
use crate::error::{Detail, Error, ErrorCode, Result};
use crate::io_util::read_data;
use crate::open::Archive;
use crate::source::{ReadAt, Whence};
use crate::source_write::Output;
use crate::zip::Flags;
use crate::zipint::{EF_CENTRAL, EF_LOCAL, ef_is_internal};

/// `zip_extra_field_t`: one field, its header id and data. A list of them
/// is a `Vec`, in the order of the header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExtraField {
    /// header id
    pub id: u16,
    pub data: Vec<u8>,
}

/// `zip_extra_fields_t`: the fields of the local header, once read (set
/// when libzip sets `local_extra_fields_read`), and those of the central
/// directory. Differs from libzip: the local fields are kept in a
/// `OnceLock`, so that they can be read through `&Archive`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ExtraFields {
    pub local: OnceLock<Vec<ExtraField>>,
    pub central: Vec<ExtraField>,
}

/// The data of field number `id_idx` with header id `id`: port of
/// `_zip_ef_get_by_id`, with `_zip_ef_find`.
pub(crate) fn ef_get_by_id(ef: &[ExtraField], id: u16, id_idx: u16) -> Option<&[u8]> {
    ef.iter()
        .filter(|ef| ef.id == id)
        .nth(usize::from(id_idx))
        .map(|ef| ef.data.as_slice())
}

/// The fields of `data`, `len` bytes of a header: port of `_zip_ef_parse`.
/// Up to three zero bytes after the last field are padding, which Android's
/// `zipalign` writes; anything else is an error.
pub(crate) fn ef_parse(data: &[u8]) -> Result<Vec<ExtraField>> {
    let mut buffer = Buffer::new(data);
    let mut fields = Vec::new();

    while buffer.ok() && buffer.left() >= 4 {
        let fid = buffer.get_16();
        let flen = buffer.get_16();
        let Some(ef_data) = buffer.get(u64::from(flen)) else {
            return Err(Error::incons(Detail::InvalidEfLength));
        };
        fields.push(ExtraField {
            id: fid,
            data: ef_data.to_vec(),
        });
    }

    if !buffer.eof() {
        // Android APK files align stored file data with padding in extra
        // fields; ignore.
        let glen = buffer.left();
        let garbage = buffer.get(glen);
        if glen >= 4 || garbage.is_none_or(|g| g.iter().any(|&b| b != 0)) {
            return Err(Error::incons(Detail::EfTrailingGarbage));
        }
    }

    Ok(fields)
}

/// The fields without those libzip interprets itself (Zip64, the UTF-8
/// name and comment, WinZip AES): port of `_zip_ef_remove_internal`.
pub(crate) fn ef_remove_internal(ef: &mut Vec<ExtraField>) {
    ef.retain(|ef| !ef_is_internal(ef.id));
}

/// The size of the fields `ef` in a header, or `None` past 65,535 bytes:
/// port of `_zip_ef_size`.
pub(crate) fn ef_size(ef: &[ExtraField]) -> Option<u16> {
    let mut size: u32 = 0;
    for ef in ef {
        size += 4 + ef.data.len() as u32;
        if size > 0xffff {
            return None;
        }
    }
    Some(size as u16)
}

/// Writes the fields `ef`: port of `_zip_ef_write`.
pub(crate) fn ef_write<W: Write + Seek>(out: &mut Output<W>, ef: &[ExtraField]) -> Result<()> {
    for ef in ef {
        let mut buffer = Buffer::with_size(4);
        buffer.put_16(ef.id);
        buffer.put_16(ef.data.len() as u16);
        if !buffer.ok() {
            return Err(Error::new(ErrorCode::Internal, 0));
        }
        out.write(buffer.data())?;
        if !ef.data.is_empty() {
            out.write(&ef.data)?;
        }
    }
    Ok(())
}

/// How many fields with header id `id` (any, if negative) there are: port
/// of `_zip_ef_count`.
fn ef_count(ef: &[ExtraField], id: i32) -> i16 {
    ef.iter()
        .filter(|ef| id < 0 || i32::from(ef.id) == id)
        .count() as i16
}

impl ExtraFields {
    /// The data of field number `extra_field_index` with header id
    /// `extra_field_id`, looked for in the local header first, then in the
    /// central directory, as `flags` allow: port of
    /// `_zip_extra_fields_get_by_id`.
    pub(crate) fn get_by_id(
        &self,
        extra_field_id: u16,
        extra_field_index: u16,
        flags: Flags,
    ) -> Result<&[u8]> {
        if flags.intersects(EF_LOCAL)
            && let Some(data) = ef_get_by_id(
                self.local.get().map_or(&[][..], Vec::as_slice),
                extra_field_id,
                extra_field_index,
            )
        {
            return Ok(data);
        }
        if flags.intersects(EF_CENTRAL)
            && let Some(data) = ef_get_by_id(&self.central, extra_field_id, extra_field_index)
        {
            return Ok(data);
        }
        Err(Error::new(ErrorCode::NoEntry, 0))
    }

    /// `_zip_extra_fields_count`.
    pub(crate) fn count(&self, id: i32, flags: Flags) -> i16 {
        let mut n = 0;
        if flags.intersects(EF_LOCAL) {
            n += ef_count(self.local.get().map_or(&[][..], Vec::as_slice), id);
        }
        if flags.intersects(EF_CENTRAL) {
            n += ef_count(&self.central, id);
        }
        n
    }
}

impl<R: ReadAt> Archive<R> {
    /// Reads the local header's extra fields of entry `idx`, if they were
    /// not read yet: port of `_zip_read_local_ef`, through a view of the
    /// source of its own.
    pub(crate) fn read_local_ef(&self, idx: u64) -> Result<()> {
        if idx >= self.entry.len() as u64 {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        let Some(orig) = self.entry[idx as usize].orig.as_deref() else {
            return Ok(());
        };
        if orig.extra_fields.local.get().is_some() {
            return Ok(());
        }

        if orig.offset + 26 > i64::MAX as u64 {
            return Err(Error::new(ErrorCode::Seek, EFBIG));
        }
        let mut src = self.src.view();
        src.seek((orig.offset + 26) as i64, Whence::Set)?;
        let mut buffer = Buffer::from_source(&mut src, 4)?;
        let fname_len = buffer.get_16();
        let ef_len = buffer.get_16();
        if !buffer.eof() {
            return Err(Error::new(ErrorCode::Internal, 0));
        }

        let mut ef = Vec::new();
        if ef_len > 0 {
            // libzip reports ZIP_ER_SEEK with errno, which a seek past the
            // end of the source leaves at 0, as it fails before any system
            // call.
            if src.seek(i64::from(fname_len), Whence::Cur).is_err() {
                return Err(Error::new(ErrorCode::Seek, 0));
            }
            let ef_raw = read_data(None, &mut src, usize::from(ef_len))?;
            ef = ef_parse(&ef_raw)?;
            ef_remove_internal(&mut ef);
        }

        // Another reader may have set them first, to the same fields.
        let changes = self.entry[idx as usize].changes.as_deref();
        if let Some(changes) = changes
            && changes.extra_fields.local.get().is_none()
        {
            let _ = changes.extra_fields.local.set(ef.clone());
        }
        let _ = orig.extra_fields.local.set(ef);
        Ok(())
    }
}

/// `EFBIG`, which libzip gives with `ZIP_ER_SEEK` for an offset past
/// `ZIP_INT64_MAX`.
pub(crate) const EFBIG: i32 = 27;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fields_and_padding() {
        let fields = ef_parse(&[1, 0, 2, 0, 0xaa, 0xbb, 0x75, 0x70, 0, 0, 0, 0]).unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(ef_get_by_id(&fields, 1, 0), Some(&[0xaa, 0xbb][..]));
        assert_eq!(ef_get_by_id(&fields, 0x7075, 0), Some(&[][..]));
        assert_eq!(ef_get_by_id(&fields, 1, 1), None);
        assert!(ef_parse(&[1, 0, 2, 0, 0xaa, 0, 0]).is_ok());
        let error = ef_parse(&[1, 0, 9, 0, 0]).unwrap_err();
        assert_eq!(error.detail(), Some((Detail::InvalidEfLength, Some(0))));
        let error = ef_parse(&[1, 0, 0, 0, 0, 1]).unwrap_err();
        assert_eq!(error.detail(), Some((Detail::EfTrailingGarbage, Some(0))));
    }
}
