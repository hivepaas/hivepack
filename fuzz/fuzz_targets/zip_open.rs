//! Opens the input as a ZIP archive with hivepack-zip, leniently and with
//! `ZIP_CHECKCONS`, and asks everything the reading API answers about each
//! entry. A panic is a bug. libzip is not built here:
//! `crates/zip/tests/oracle.rs` compares the answers with it through the
//! oracle.

#![no_main]

use hivepack_zip::{Archive, ArchiveFlags, Flags, OpenFlags};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for flags in [OpenFlags(0), OpenFlags::CHECKCONS] {
        let Ok(mut za) = Archive::open(data, flags) else { continue };
        let _ = za.get_archive_flag(ArchiveFlags::IS_TORRENTZIP, Flags::NONE);
        let _ = za.get_archive_comment(Flags::NONE);
        let _ = za.get_archive_comment(Flags::ENC_STRICT);
        for i in 0..za.get_num_entries(Flags::NONE) {
            for flags in [Flags::NONE, Flags::ENC_RAW, Flags::ENC_STRICT] {
                let _ = za.get_name(i, flags);
                let _ = za.file_get_comment(i, flags);
            }
            let _ = za.stat_index(i, Flags::NONE);
            let _ = za.file_get_external_attributes(i, Flags::NONE);
            for flags in [Flags::CENTRAL, Flags::LOCAL, Flags::CENTRAL | Flags::LOCAL] {
                let count = za.file_extra_fields_count(i, flags).unwrap_or(0);
                for j in 0..count.max(0) as u16 + 1 {
                    let _ = za.file_extra_field_get(i, j, flags);
                }
            }
            let _ = za.file_get_offset(i);
            if let Ok(name) = za.get_name(i, Flags::NONE) {
                let name = name.to_vec();
                for flags in [Flags::NONE, Flags::NOCASE, Flags::NODIR, Flags::ENC_RAW, Flags::ENC_STRICT, Flags::ENC_CP437] {
                    let _ = za.name_locate(&name, flags);
                }
            }
        }
    }
});
