//! Central and local headers: port of `zip_dirent.c`, the reading half.
//!
//! `read` keeps libzip's error out-parameter: on some failures (a data
//! descriptor that cannot be reached), libzip returns without setting the
//! error, so what the caller reports is what the error held before, and the
//! port reports the same.

use crate::buffer::Buffer;
use crate::error::{Detail, Error, ErrorCode};
use crate::extra_field::{EFBIG, ExtraFields, ef_parse, ef_remove_internal};
use crate::io_util::{read_data, read_string};
use crate::source::{ReadAt, Source, Whence};
use crate::string::{ZipString, string_crc32, string_equal};
use crate::zip::{Flags, em, opsys};
use crate::zipint::{
    CDENTRYSIZE, CENTRAL_MAGIC, CM_WINZIP_AES, DATADES_MAGIC, EF_BOTH, EF_CENTRAL, EF_LOCAL,
    EF_UTF_8_COMMENT, EF_UTF_8_NAME, EF_WINZIP_AES, EF_ZIP64, EXT_ATTRIB_DEFAULT, Encoding,
    GPBF_DATA_DESCRIPTOR, GPBF_ENCODING_UTF_8, GPBF_ENCRYPTED, GPBF_STRONG_ENCRYPTION, LENTRYSIZE,
    LOCAL_MAGIC, MAGIC_LEN, MAX_DATA_DESCRIPTOR_LENGTH,
};

/// `zip_dostime_t`: a time as MS-DOS keeps it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DosTime {
    pub time: u16,
    pub date: u16,
}

/// `ZIP_CM_DEFAULT`: better of deflate or store.
pub(crate) const CM_DEFAULT: i32 = -1;

/// `zip_dirent_t`: a central directory entry or local header, as read.
/// The editor will add the fields libzip uses for changes.
#[derive(Clone, Debug)]
pub(crate) struct Dirent {
    /// whether we already read in local header extra fields
    pub local_extra_fields_read: bool,
    /// if CRC is valid (sometimes not for encrypted archives)
    pub crc_valid: bool,
    /// (c) version of creator
    pub version_madeby: u16,
    /// (cl) version needed to extract
    pub version_needed: u16,
    /// (cl) general purpose bit flag
    pub bitflags: u16,
    /// (cl) compression method used (uint16 and ZIP_CM_DEFAULT (-1))
    pub comp_method: i32,
    /// (cl) time of last modification
    pub last_mod: DosTime,
    /// (cl) CRC-32 of uncompressed data
    pub crc: u32,
    /// (cl) size of compressed data
    pub comp_size: u64,
    /// (cl) size of uncompressed data
    pub uncomp_size: u64,
    /// (cl) file name
    pub filename: Option<ZipString>,
    /// (cl) extra fields, parsed
    pub extra_fields: ExtraFields,
    /// (c) file comment
    pub comment: Option<ZipString>,
    /// (c) disk number start
    pub disk_number: u32,
    /// (c) internal file attributes
    pub int_attrib: u16,
    /// (c) external file attributes
    pub ext_attrib: u32,
    /// (c) offset of local header
    pub offset: u64,
    /// encryption method, computed from other fields
    pub encryption_method: u16,
}

impl Default for Dirent {
    /// Port of `_zip_dirent_init`.
    fn default() -> Dirent {
        Dirent {
            local_extra_fields_read: false,
            crc_valid: true,
            version_madeby: 63 | (u16::from(opsys::DEFAULT) << 8),
            version_needed: 10, // 1.0
            bitflags: 0,
            comp_method: CM_DEFAULT,
            last_mod: DosTime::default(),
            crc: 0,
            comp_size: 0,
            uncomp_size: 0,
            filename: None,
            extra_fields: ExtraFields::default(),
            comment: None,
            disk_number: 0,
            int_attrib: 0,
            ext_attrib: EXT_ATTRIB_DEFAULT,
            offset: 0,
            encryption_method: em::NONE,
        }
    }
}

impl Dirent {
    /// Reads a central directory entry, or with `local` a local header,
    /// from `buffer` if there is one, else from `src` at its position.
    /// Returns the entry and the bytes it took, or `None` with `error` set
    /// (or, where libzip leaves it, as it was). Port of `_zip_dirent_read`.
    // The fields are read in the order of the header, as in libzip.
    #[allow(clippy::field_reassign_with_default)]
    pub(crate) fn read<R: ReadAt + ?Sized>(
        src: &mut Source<R>,
        mut buffer: Option<&mut Buffer<'_>>,
        local: bool,
        is_zip64: bool,
        central_compressed_size: u64,
        check_consistency: bool,
        error: &mut Error,
    ) -> Option<(Dirent, u64)> {
        let size = if local { LENTRYSIZE } else { CDENTRYSIZE };

        let mut own;
        let fixed: &mut Buffer<'_> = match buffer.as_deref_mut() {
            Some(buffer) => {
                if buffer.left() < size {
                    *error = Error::new(ErrorCode::NoZip, 0);
                    return None;
                }
                buffer
            }
            None => match Buffer::from_source(src, size) {
                Ok(b) => {
                    own = b;
                    &mut own
                }
                Err(e) => {
                    *error = e;
                    return None;
                }
            },
        };

        let magic: &[u8; 4] = if local { LOCAL_MAGIC } else { CENTRAL_MAGIC };
        if fixed.get(4) != Some(&magic[..]) {
            *error = Error::new(ErrorCode::NoZip, 0);
            return None;
        }

        // convert buffercontents to zip_dirent
        let mut zde = Dirent::default();
        zde.version_madeby = if local { 0 } else { fixed.get_16() };
        zde.version_needed = fixed.get_16();
        zde.bitflags = fixed.get_16();
        zde.comp_method = i32::from(fixed.get_16());

        zde.last_mod.time = fixed.get_16();
        zde.last_mod.date = fixed.get_16();

        zde.crc = fixed.get_32();
        zde.comp_size = u64::from(fixed.get_32());
        zde.uncomp_size = u64::from(fixed.get_32());

        let filename_len = fixed.get_16();
        let ef_len = fixed.get_16();

        let comment_len;
        if local {
            comment_len = 0;
            zde.disk_number = 0;
            zde.int_attrib = 0;
            zde.ext_attrib = 0;
            zde.offset = 0;
        } else {
            comment_len = fixed.get_16();
            zde.disk_number = u32::from(fixed.get_16());
            zde.int_attrib = fixed.get_16();
            zde.ext_attrib = fixed.get_32();
            zde.offset = u64::from(fixed.get_32());
        }

        if !fixed.ok() {
            *error = Error::new(ErrorCode::Internal, 0);
            return None;
        }

        zde.encryption_method = if zde.bitflags & GPBF_ENCRYPTED != 0 {
            if zde.bitflags & GPBF_STRONG_ENCRYPTION != 0 {
                em::UNKNOWN
            } else {
                em::TRAD_PKWARE
            }
        } else {
            em::NONE
        };

        let variable_size = u64::from(filename_len) + u64::from(ef_len) + u64::from(comment_len);

        let mut own_variable;
        let variable: &mut Buffer<'_> = match buffer {
            Some(buffer) => {
                if buffer.left() < variable_size {
                    *error = Error::incons(Detail::VariableSizeOverflow);
                    return None;
                }
                buffer
            }
            None => match Buffer::from_source(src, variable_size) {
                Ok(b) => {
                    own_variable = b;
                    &mut own_variable
                }
                Err(e) => {
                    *error = e;
                    return None;
                }
            },
        };

        if filename_len > 0 {
            match read_string(Some(&mut *variable), src, filename_len) {
                Ok(name) => zde.filename = name,
                Err(e) => {
                    *error = if e.code() == ErrorCode::Eof {
                        Error::incons(Detail::VariableSizeOverflow)
                    } else {
                        e
                    };
                    return None;
                }
            }
            if zde.bitflags & GPBF_ENCODING_UTF_8 != 0
                && let Some(name) = zde.filename.as_mut()
                && name.guess_encoding(Encoding::Utf8Known) == Encoding::Error
            {
                *error = Error::incons(Detail::InvalidUtf8InFilename);
                return None;
            }
        }

        if ef_len > 0 {
            let ef = match read_data(Some(&mut *variable), src, usize::from(ef_len)) {
                Ok(ef) => ef,
                Err(e) => {
                    *error = e;
                    return None;
                }
            };
            match ef_parse(&ef) {
                Ok(fields) if local => zde.extra_fields.local = fields,
                Ok(fields) => zde.extra_fields.central = fields,
                Err(e) => {
                    *error = e;
                    return None;
                }
            }
            if local {
                zde.local_extra_fields_read = true;
            }
        }

        if comment_len > 0 {
            match read_string(Some(&mut *variable), src, comment_len) {
                Ok(comment) => zde.comment = comment,
                Err(e) => {
                    *error = e;
                    return None;
                }
            }
            if zde.bitflags & GPBF_ENCODING_UTF_8 != 0
                && let Some(comment) = zde.comment.as_mut()
                && comment.guess_encoding(Encoding::Utf8Known) == Encoding::Error
            {
                *error = Error::incons(Detail::InvalidUtf8InComment);
                return None;
            }
        }

        let filename = zde.filename.take();
        let had_filename = filename.is_some();
        match process_ef_utf_8(&zde, EF_UTF_8_NAME, filename, check_consistency) {
            Some(name) => zde.filename = name,
            None if had_filename => {
                *error = Error::incons(Detail::Utf8FilenameMismatch);
                return None;
            }
            None => {}
        }

        // Check for a NUL byte in the final name; the Info-ZIP Unicode Path
        // extra field can replace zde->filename above, so this must run
        // after that.
        if check_consistency
            && zde
                .filename
                .as_ref()
                .is_some_and(|name| name.raw().contains(&0))
        {
            *error = Error::incons(Detail::NulInFilename);
            return None;
        }

        if !local {
            let comment = zde.comment.take();
            let had_comment = comment.is_some();
            match process_ef_utf_8(&zde, EF_UTF_8_COMMENT, comment, check_consistency) {
                Some(comment) => zde.comment = comment,
                None if had_comment => {
                    *error = Error::incons(Detail::Utf8CommentMismatch);
                    return None;
                }
                None => {}
            }
        }

        // Zip64

        if zde.uncomp_size == u64::from(u32::MAX)
            || zde.comp_size == u64::from(u32::MAX)
            || zde.offset == u64::from(u32::MAX)
        {
            let flags = if local { EF_LOCAL } else { EF_CENTRAL };
            match zde.extra_fields.get_by_id(EF_ZIP64, 0, flags) {
                Ok(ef) => {
                    let ef = ef.to_vec();
                    if let Err(e) = process_ef_zip64(&mut zde, &ef, local) {
                        *error = e;
                        return None;
                    }
                }
                Err(e) => {
                    *error = e;
                    if is_zip64 {
                        *error = Error::incons(Detail::MissingZip64Ef);
                        return None;
                    }
                }
            }
        }

        if !variable.ok() {
            *error = Error::new(ErrorCode::Internal, 0);
            return None;
        }

        if local && zde.bitflags & GPBF_DATA_DESCRIPTOR != 0 {
            // libzip returns here without setting the error when the seek
            // fails; so does the port.
            if src
                .seek(central_compressed_size as i64, Whence::Cur)
                .is_err()
            {
                return None;
            }
            let mut dd = match Buffer::from_source(src, MAX_DATA_DESCRIPTOR_LENGTH) {
                Ok(dd) => dd,
                Err(e) => {
                    *error = e;
                    return None;
                }
            };
            if dd.peek(MAGIC_LEN) == Some(&DATADES_MAGIC[..]) {
                dd.skip(MAGIC_LEN);
            }
            let df_crc = dd.get_32();
            let df_comp_size = if is_zip64 {
                dd.get_64()
            } else {
                u64::from(dd.get_32())
            };
            let df_uncomp_size = if is_zip64 {
                dd.get_64()
            } else {
                u64::from(dd.get_32())
            };

            if !dd.ok() {
                *error = Error::new(ErrorCode::Internal, 0);
                return None;
            }

            // According to the appnote, it should be 0, but some
            // implementations write the actual value.
            if (zde.crc != 0 && zde.crc != df_crc)
                || (zde.comp_size != 0 && zde.comp_size != df_comp_size)
                || (zde.uncomp_size != 0 && zde.uncomp_size != df_uncomp_size)
            {
                *error = Error::incons(Detail::DataDescriptorMismatch);
                return None;
            }
            zde.crc = df_crc;
            zde.comp_size = df_comp_size;
            zde.uncomp_size = df_uncomp_size;
        }

        // zip_source_seek / zip_source_tell don't support values >
        // ZIP_INT64_MAX
        if zde.offset > i64::MAX as u64 {
            *error = Error::new(ErrorCode::Seek, EFBIG);
            return None;
        }

        if let Err(e) = process_winzip_aes(&mut zde) {
            *error = e;
            return None;
        }

        let efp = if local {
            &mut zde.extra_fields.local
        } else {
            &mut zde.extra_fields.central
        };
        ef_remove_internal(efp);

        Some((zde, size + variable_size))
    }
}

/// Takes the sizes, offset and disk number the header leaves to the Zip64
/// extra field `ef`: port of `zip_dirent_process_ef_zip64`.
fn process_ef_zip64(zde: &mut Dirent, ef: &[u8], local: bool) -> Result<(), Error> {
    let mut ef_buffer = Buffer::new(ef);
    let got_len = ef.len();

    if zde.uncomp_size == u64::from(u32::MAX) {
        zde.uncomp_size = ef_buffer.get_64();
    } else if local {
        // From appnote.txt: This entry in the Local header MUST include
        // BOTH original and compressed file size fields.
        ef_buffer.skip(8); // error is caught by _zip_buffer_eof() call
    }
    if zde.comp_size == u64::from(u32::MAX) {
        zde.comp_size = ef_buffer.get_64();
    } else if local {
        ef_buffer.skip(8); // error is caught by _zip_buffer_eof() call
    }
    if !local {
        if zde.offset == u64::from(u32::MAX) {
            zde.offset = ef_buffer.get_64();
        }
        if zde.disk_number == u32::from(u16::MAX) {
            zde.disk_number = ef_buffer.get_32();
        }
    }

    if !ef_buffer.eof() {
        // accept additional fields if values match
        let mut ok = true;
        match got_len {
            28 | 24 => {
                if got_len == 28 {
                    ef_buffer.set_offset(24);
                    if zde.disk_number != ef_buffer.get_32() {
                        ok = false;
                    }
                }
                ef_buffer.set_offset(0);
                if zde.uncomp_size != ef_buffer.get_64()
                    || zde.comp_size != ef_buffer.get_64()
                    || zde.offset != ef_buffer.get_64()
                {
                    ok = false;
                }
            }
            _ => ok = false,
        }
        if !ok {
            return Err(Error::incons(Detail::InvalidZip64Ef));
        }
    }
    Ok(())
}

/// The name or comment from the Info-ZIP Unicode Path or Comment extra
/// field `id`, if it has one whose CRC is that of `str`; `str` otherwise.
/// `None` where libzip returns `NULL`: with `check_consistency`, a field
/// in ASCII that differs from `str`, and when `str` is absent and nothing
/// replaces it. Port of `_zip_dirent_process_ef_utf_8`.
fn process_ef_utf_8(
    de: &Dirent,
    id: u16,
    str: Option<ZipString>,
    check_consistency: bool,
) -> Option<Option<ZipString>> {
    let Ok(ef) = de.extra_fields.get_by_id(id, 0, EF_BOTH) else {
        return keep(str);
    };
    if ef.len() < 5 || ef[0] != 1 {
        return keep(str);
    }

    let mut buffer = Buffer::new(ef);
    buffer.get_8();
    let ef_crc = buffer.get_32();

    if string_crc32(str.as_ref()) == ef_crc {
        let len = buffer.left();
        let raw = buffer.get(len).unwrap_or(&[]);
        if let Ok(Some(ef_str)) = ZipString::new(raw, Flags::ENC_UTF_8) {
            if check_consistency && !string_equal(str.as_ref(), Some(&ef_str)) && ef_str.is_ascii()
            {
                return None;
            }
            return Some(Some(ef_str));
        }
    }

    keep(str)
}

/// `return str;` of `_zip_dirent_process_ef_utf_8`, which is `NULL` when
/// `str` is.
fn keep(str: Option<ZipString>) -> Option<Option<ZipString>> {
    str.map(Some)
}

/// The encryption method and real compression method of a WinZip AES
/// entry, from its extra field: port of `_zip_dirent_process_winzip_aes`.
fn process_winzip_aes(de: &mut Dirent) -> Result<(), Error> {
    if de.comp_method != i32::from(CM_WINZIP_AES) {
        return Ok(());
    }

    let Ok(ef) = de.extra_fields.get_by_id(EF_WINZIP_AES, 0, EF_BOTH) else {
        return Err(Error::incons(Detail::InvalidWinzipaesEf));
    };
    if ef.len() < 7 {
        return Err(Error::incons(Detail::InvalidWinzipaesEf));
    }
    let ef_len = ef.len();
    let mut buffer = Buffer::new(ef);

    // version
    let crc_valid = match buffer.get_16() {
        1 => true,
        2 => false,
        _ => return Err(Error::new(ErrorCode::EncrNotSupp, 0)),
    };

    // vendor
    if buffer.get(2) != Some(b"AE") {
        return Err(Error::new(ErrorCode::EncrNotSupp, 0));
    }

    // mode
    let enc_method = match buffer.get_8() {
        1 => em::AES_128,
        2 => em::AES_192,
        3 => em::AES_256,
        _ => return Err(Error::new(ErrorCode::EncrNotSupp, 0)),
    };

    if ef_len != 7 {
        return Err(Error::incons(Detail::InvalidWinzipaesEf));
    }

    let comp_method = buffer.get_16();
    de.crc_valid = crc_valid;
    de.encryption_method = enc_method;
    de.comp_method = i32::from(comp_method);
    Ok(())
}

/// The length of the header at `src`'s position, read from its length
/// fields: port of `_zip_dirent_size`.
pub(crate) fn dirent_size<R: ReadAt + ?Sized>(
    src: &mut Source<R>,
    local: bool,
) -> Result<u32, Error> {
    let mut size = if local { LENTRYSIZE } else { CDENTRYSIZE } as u32;

    // Central header has fixed fields after size pointers.
    let want = if local { LENTRYSIZE } else { 34 };
    let mut buffer = Buffer::from_source(src, want)?;
    if buffer.left() != want {
        return Err(Error::incons(Detail::CdirEntryInvalid));
    }

    let magic: &[u8; 4] = if local { LOCAL_MAGIC } else { CENTRAL_MAGIC };
    if buffer.peek(4) != Some(&magic[..]) {
        return Err(Error::incons(Detail::CdirEntryInvalid));
    }

    // Skip to size pointers.
    buffer.skip(if local { 26 } else { 28 });

    for _ in 0..if local { 2 } else { 3 } {
        size += u32::from(buffer.get_16());
    }

    Ok(size)
}

/// Seconds since 1970 of a DOS time, taken as UTC: port of `_zip_d2u_time`.
///
/// Differs from libzip, which calls `mktime` and so takes the time in the
/// machine's time zone: the two agree where it is UTC. Out-of-range fields
/// carry over into the next as `mktime` carries them (month 0 is December
/// of the year before).
pub(crate) fn d2u_time(dtime: DosTime) -> i64 {
    let year = i64::from((dtime.date >> 9) & 127) + 1980;
    let mon = i64::from((dtime.date >> 5) & 15) - 1;
    let mday = i64::from(dtime.date & 31);

    let hour = i64::from((dtime.time >> 11) & 31);
    let min = i64::from((dtime.time >> 5) & 63);
    let sec = i64::from((dtime.time << 1) & 62);

    let year = year + mon.div_euclid(12);
    let mon = mon.rem_euclid(12);
    let days = days_from_civil(year, mon + 1, 1) + mday - 1;
    days * 86400 + hour * 3600 + min * 60 + sec
}

/// Days since 1970-01-01 of a date in the proleptic Gregorian calendar
/// (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The stored sizes of a stored entry, which must differ by the length of
/// its encryption header: port of `zip_dirent_check_consistency`.
pub(crate) fn check_consistency(dirent: &Dirent) -> Option<Detail> {
    if dirent.comp_method == 0 {
        let header_size = match dirent.encryption_method {
            em::NONE => 0,
            em::TRAD_PKWARE => 12,
            em::AES_128 => 20,
            em::AES_192 => 24,
            em::AES_256 => 28,
            _ => return None,
        };
        match dirent.uncomp_size.checked_add(header_size) {
            Some(size) if size == dirent.comp_size => {}
            _ => return Some(Detail::StoredSizeMismatch),
        }
    }
    None
}

impl<R: ReadAt> crate::open::Archive<R> {
    /// The entry `idx` as read: port of `_zip_get_dirent`.
    pub(crate) fn get_dirent(&self, idx: u64, _flags: Flags) -> Result<&Dirent, Error> {
        match self
            .entry
            .get(usize::try_from(idx).unwrap_or(usize::MAX))
            .and_then(|e| e.orig.as_deref())
        {
            Some(orig) => Ok(orig),
            None => Err(Error::new(ErrorCode::Inval, 0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_dos_times_as_mktime_in_utc() {
        // 2026-10-29 12:34:56
        let t = DosTime {
            date: ((2026 - 1980) << 9) | (10 << 5) | 29,
            time: (12 << 11) | (34 << 5) | 28,
        };
        assert_eq!(d2u_time(t), 1_793_277_296);
        // 1980-00-00 00:00:00 is 1979-11-30.
        assert_eq!(d2u_time(DosTime::default()), 312_768_000);
    }
}
