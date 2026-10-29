//! Opens the input as a ZIP archive with hivepack-zip, makes the edits its
//! first bytes choose (the count, then a kind and an index for each), and
//! writes it with `close_to`, or `close_to_cloning` if the first byte's top
//! bit is set. The archive `close_to` writes must open, with the entries
//! that are not deleted, in order, as edited: their names, comments,
//! attributes, times, sizes and data. A panic is a bug.
//! `crates/zip/tests/oracle.rs` compares the edits and what is written
//! with libzip through the oracle.

#![no_main]

use std::io::{Cursor, Read};

use hivepack_zip::{
    Archive, ArchiveFlags, Closed, EXTRA_FIELD_ALL, EXTRA_FIELD_NEW, Flags, OpenFlags, ReadAt, stat,
};
use libfuzzer_sys::fuzz_target;

/// The raw data of entry `i`, as stored.
fn raw_data<R: ReadAt>(za: &Archive<R>, i: u64) -> Option<Vec<u8>> {
    let mut zf = za.fopen_index(i, Flags::ENCRYPTED).ok()?;
    let mut data = Vec::new();
    zf.read_to_end(&mut data).ok()?;
    Some(data)
}

/// That `written` has the entries of `za` that are not deleted, as they are
/// now.
fn check_written<R: ReadAt>(za: &Archive<R>, written: &[u8]) {
    let kept: Vec<u64> = (0..za.get_num_entries(Flags::NONE))
        .filter(|&i| za.get_name(i, Flags::NONE).is_ok())
        .collect();
    // Something that looks like an end of central directory record, or a
    // Zip64 one or its locator, in a name, a comment, an extra field or the
    // data may be taken for the real one: libzip does not check that what
    // it writes reads back.
    let count = |signature: &[u8]| written.windows(4).filter(|&w| w == signature).count();
    let (eocd64, locator) = (count(b"PK\x06\x06"), count(b"PK\x06\x07"));
    if count(b"PK\x05\x06") > 1 || eocd64 > 1 || locator != eocd64 {
        return;
    }
    let new = match Archive::open(written, OpenFlags(0)) {
        Ok(new) => new,
        Err(e) => panic!("the written archive does not open: {e} ({:?})", e.detail()),
    };
    assert_eq!(new.get_num_entries(Flags::NONE), kept.len() as u64);
    for (j, &i) in kept.iter().enumerate() {
        let j = j as u64;
        assert_eq!(
            new.get_name(j, Flags::ENC_RAW).ok(),
            za.get_name(i, Flags::ENC_RAW).ok()
        );
        assert_eq!(
            new.file_get_comment(j, Flags::ENC_RAW).ok(),
            za.file_get_comment(i, Flags::ENC_RAW).ok()
        );
        assert_eq!(
            new.file_get_external_attributes(j, Flags::NONE).ok(),
            za.file_get_external_attributes(i, Flags::NONE).ok()
        );
        assert_eq!(
            new.file_get_dos_time(j, Flags::NONE).ok(),
            za.file_get_dos_time(i, Flags::NONE).ok()
        );
        let (Ok(a), Ok(b)) = (
            new.stat_index(j, Flags::NONE),
            za.stat_index(i, Flags::NONE),
        ) else {
            panic!("stat of entry {i}");
        };
        assert_eq!(
            (a.size, a.comp_size, a.comp_method, a.encryption_method),
            (b.size, b.comp_size, b.comp_method, b.encryption_method)
        );
        if a.valid & b.valid & stat::CRC != 0 {
            assert_eq!(a.crc, b.crc);
        }
        // A WinZip AES entry of AE-2, without a CRC, is written as AE-1 if
        // it has 20 bytes or more, and its CRC is then checked on reading,
        // on the encrypted data.
        if a.valid & stat::CRC == b.valid & stat::CRC
            && let Some(data) = raw_data(za, i)
        {
            assert_eq!(raw_data(&new, j), Some(data), "entry {i}");
        }
    }
    // As in libzip, a comment removed is still given until the archive is
    // written.
    let comment = new.get_archive_comment(Flags::ENC_RAW);
    assert!(comment.is_empty() || comment == za.get_archive_comment(Flags::ENC_RAW));
}

fuzz_target!(|data: &[u8]| {
    let Some((&count_byte, rest)) = data.split_first() else {
        return;
    };
    let count = usize::from(count_byte % 8);
    if rest.len() < 2 * count {
        return;
    }
    let (ops, zip) = rest.split_at(2 * count);
    let Ok(mut za) = Archive::open(zip, OpenFlags(0)) else {
        return;
    };
    let n = za.get_num_entries(Flags::NONE);
    for op in ops.chunks(2) {
        let (kind, arg) = (op[0], op[1]);
        let i = u64::from(arg) % (n + 1);
        // ZIP_FL_LOCAL, ZIP_FL_CENTRAL or both, or neither.
        let ef_flags = Flags(u32::from(kind & 0x30) << 4);
        let _ = match kind % 12 {
            0 => za.delete(i),
            1 => za.file_rename(
                i,
                &[b'r', arg, b'/'][..1 + usize::from(arg % 3)],
                Flags::NONE,
            ),
            2 => za.file_set_comment(i, op, Flags(u32::from(kind & 0x80) << 4)),
            3 => za.set_archive_comment(&op[..usize::from(arg % 3)]),
            4 => za.file_set_dostime(
                i,
                u16::from(arg) << 8,
                0x21 | u16::from(kind) << 9,
                Flags::NONE,
            ),
            5 => za.file_set_mtime(i, i64::from(arg) << (kind % 64), Flags::NONE),
            6 => za.file_set_external_attributes(i, Flags::NONE, arg % 20, u32::from(kind) << 16),
            7 => za.unchange(i),
            8 => {
                za.unchange_all();
                Ok(())
            }
            9 => za.set_archive_flag(
                ArchiveFlags::CREATE_OR_KEEP_FILE_FOR_EMPTY_ARCHIVE,
                kind & 0x80 != 0,
            ),
            10 => za.file_extra_field_set(
                i,
                0xcafe,
                if kind & 0x40 != 0 { EXTRA_FIELD_NEW } else { 0 },
                &op[..usize::from(arg % 3)],
                ef_flags,
            ),
            _ => za.file_extra_field_delete(
                i,
                if kind & 0x40 != 0 {
                    EXTRA_FIELD_ALL
                } else {
                    u16::from(arg % 3)
                },
                ef_flags,
            ),
        };
    }
    let mut out = Cursor::new(Vec::new());
    if count_byte & 0x80 != 0 {
        // Cloning what is kept: an entry before the first one that changed
        // is cut there if its data reaches past it, as in libzip, so only
        // that it does not panic.
        let _ = za.close_to_cloning(&mut out, |offset| offset % 2 == 0);
    } else if matches!(za.close_to(&mut out), Ok(Closed::Written)) {
        check_written(&za, out.get_ref());
    }
});
