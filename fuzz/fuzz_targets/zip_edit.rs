//! Opens the input as a ZIP archive with hivepack-zip, makes the edits its
//! first bytes choose (the count, then a kind and an index for each), and
//! writes it with `close_to`. The archive written must open, with the
//! entries that are not deleted, in order, as edited: their names,
//! comments, attributes, times, sizes and data. A panic is a bug.
//! `crates/zip/tests/oracle.rs` compares the edits and what is written
//! with libzip through the oracle.

#![no_main]

use std::io::{Cursor, Read};

use hivepack_zip::{Archive, ArchiveFlags, Closed, Detail, Flags, OpenFlags, ReadAt, stat};
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
        // libzip writes a size of 0xffffffff, or a disk number of 0xffff, in
        // the header without the Zip64 extra field that should then have
        // it, and refuses that as invalid; so does the port.
        Err(e) if matches!(e.detail(), Some((Detail::InvalidZip64Ef, _))) => return,
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
    let Some((&count, rest)) = data.split_first() else {
        return;
    };
    let count = usize::from(count % 8);
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
        let _ = match kind % 10 {
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
            _ => za.set_archive_flag(
                ArchiveFlags::CREATE_OR_KEEP_FILE_FOR_EMPTY_ARCHIVE,
                kind & 0x80 != 0,
            ),
        };
    }
    let mut out = Cursor::new(Vec::new());
    if matches!(za.close_to(&mut out), Ok(Closed::Written)) {
        check_written(&za, out.get_ref());
    }
});
