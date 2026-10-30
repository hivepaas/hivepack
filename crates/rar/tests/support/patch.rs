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

//! Copies of existing archives with something changed, for the comparison
//! with UnRAR and for fuzzing. Nothing here compresses: what goes in as packed
//! data is whatever the caller has, usually a fuzzer's bytes, so that damage
//! reaches what a damaged header's CRC would stop, and what no archive at hand
//! does (RAR 7's algorithm, long distances, every filter).
//!
//! A module of `tests/support` and of the `rar_unpack` target.

/// libarchive 3.8.10's `rar5_stored.rar`, BSD-2-Clause: its main header, its
/// file header without the fields that change, and its end header.
const MAIN: &[u8] =
    b"Rar!\x1a\x07\x01\x00\x33\x92\xb5\xe5\x0a\x01\x05\x06\x00\x05\x01\x01\x80\x80\x00";
const ATTRIBUTES: &[u8] = b"\xa4\x83\x02";
const NAME: &[u8] = b"helloworld.txt";
const FILE_EXTRA: &[u8] = b"\x0a\x03\x13\x7e\x0e\xab\x5b\x56\xe9\x0e\x1a";
const END: &[u8] = b"\x1d\x77\x56\x51\x03\x05\x04\x00";

/// libarchive 3.8.10's `rar.rar`, BSD-2-Clause: its signature and main header,
/// the name and attributes of its first file, and its end header.
const MAIN15: &[u8] = b"Rar!\x1a\x07\x00\xcf\x90\x73\x00\x00\x0d\x00\x00\x00\x00\x00\x00\x00";
const NAME15: &[u8] = b"test.txt";
const ATTRIBUTES15: &[u8] = b"\xa4\x81\x00\x00";
const END15: &[u8] = b"\xc4\x3d\x7b\x00\x40\x07\x00";

fn crc32(data: &[u8]) -> u32 {
    hivepack_deflate::crc32(0, data)
}

fn put_vint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// `rar5_stored.rar`'s file header with these fields changed.
fn put_file(out: &mut Vec<u8>, comp_info: u64, unp_size: u64, packed: &[u8]) {
    let mut body = vec![2, 3];
    put_vint(&mut body, FILE_EXTRA.len() as u64);
    put_vint(&mut body, packed.len() as u64);
    // Its flags: only the time, no CRC, so that no hash is checked.
    body.push(0);
    put_vint(&mut body, unp_size);
    body.extend_from_slice(ATTRIBUTES);
    put_vint(&mut body, comp_info);
    body.push(1);
    put_vint(&mut body, NAME.len() as u64);
    body.extend_from_slice(NAME);
    body.extend_from_slice(FILE_EXTRA);
    let mut header = Vec::new();
    put_vint(&mut header, body.len() as u64);
    header.extend_from_slice(&body);
    out.extend_from_slice(&crc32(&header).to_le_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(packed);
}

/// `rar.rar`'s first file header with these fields changed.
fn put_file15(out: &mut Vec<u8>, dictionary: u16, solid: bool, unp_size: u32, packed: &[u8]) {
    put_file15_as(out, 29, dictionary, solid, unp_size, packed);
}

/// The same, with this version of the algorithm.
fn put_file15_as(
    out: &mut Vec<u8>,
    unp_ver: u8,
    dictionary: u16,
    solid: bool,
    unp_size: u32,
    packed: &[u8],
) {
    let flags = 0x8000 | dictionary << 5 | u16::from(solid) << 4;
    let size = 32 + NAME15.len() as u16;
    let mut body = vec![0x74];
    body.extend_from_slice(&flags.to_le_bytes());
    body.extend_from_slice(&size.to_le_bytes());
    body.extend_from_slice(&(packed.len() as u32).to_le_bytes());
    body.extend_from_slice(&unp_size.to_le_bytes());
    body.push(3);
    // No file CRC to speak of, and its time.
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(b"\xb7\x76\xda\x3e");
    // The algorithm, and a method that is not stored.
    body.extend_from_slice(&[unp_ver, 0x33]);
    body.extend_from_slice(&(NAME15.len() as u16).to_le_bytes());
    body.extend_from_slice(ATTRIBUTES15);
    body.extend_from_slice(NAME15);
    out.extend_from_slice(&(crc32(&body) as u16).to_le_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(packed);
}

/// A copy of `rar5_stored.rar`, or `rar.rar`, whose data is `input` from its
/// fourth byte, as compressed data. The first byte says the algorithm, for
/// RAR 5 (bit 0), the dictionary (bits 1 and 2, the smallest being below the
/// 256 KiB that UnRAR uses at least), whether a second entry goes on as solid
/// (bit 3), whether it is `rar.rar` (bit 4), whether only 4 KiB are to come out
/// (bit 5), whether the second entry asks for a larger dictionary (bit 6) and
/// whether for a smaller one (bit 7), and the next two where the second entry's
/// data starts.
pub fn with_packed_data(input: &[u8]) -> Vec<u8> {
    let options = input.first().copied().unwrap_or(0);
    let split = match input {
        [_, a, b, ..] => usize::from(*a) | usize::from(*b) << 8,
        _ => 0,
    };
    let packed = input.get(3..).unwrap_or(&[]);
    let (first, second) = packed.split_at(split.min(packed.len()));

    if options & 16 != 0 {
        let dictionary = u16::from(options >> 1 & 3);
        let more = u16::from(options >> 6 & 1) * 3;
        let dictionary_first = dictionary + u16::from(options >> 7) * 3;
        let unp_size = if options & 32 != 0 { 4096 } else { u32::MAX };
        let mut out = MAIN15.to_vec();
        if options & 8 != 0 {
            put_file15(&mut out, dictionary_first, false, unp_size, first);
            put_file15(&mut out, dictionary + more, true, unp_size, second);
        } else {
            put_file15(&mut out, dictionary, false, unp_size, packed);
        }
        out.extend_from_slice(END15);
        return out;
    }

    let version = u64::from(options & 1);
    let dictionary = u64::from(options >> 1 & 3);
    let method = 3;
    let comp_info = version | method << 7 | dictionary << 10;
    let more = u64::from(options >> 6 & 1) * 3;
    let dictionary_first = u64::from(options >> 7) * 3;
    // By default more than can come out, as no size is what stops it here.
    let unp_size = if options & 32 != 0 { 4096 } else { 1 << 40 };

    let mut out = MAIN.to_vec();
    if options & 8 != 0 {
        put_file(
            &mut out,
            comp_info + (dictionary_first << 10),
            unp_size,
            first,
        );
        put_file(
            &mut out,
            (comp_info + (more << 10)) | 1 << 6,
            unp_size,
            second,
        );
    } else {
        put_file(&mut out, comp_info, unp_size, packed);
    }
    out.extend_from_slice(END);
    out
}

/// A copy of `rar.rar` with `input` from its fifth byte as data compressed by
/// RAR 1.5 or 2.x, with entries going on from each other as only these can. The
/// first byte says the algorithm (bits 0 and 1), the dictionary (bits 2 and 3),
/// whether a second entry follows (bit 4), whether the archive is solid (bit 5),
/// whether only 4 KiB are to come out (bit 6) and whether the second entry says
/// it is solid (bit 7), and the next two where the second entry's data starts.
/// The fourth says what the second entry's algorithm is (bits 0 and 1, the same
/// first) and how much larger its dictionary (bits 2 and 3).
pub fn with_old_packed_data(input: &[u8]) -> Vec<u8> {
    const ALGORITHMS: [u8; 4] = [15, 20, 26, 13];
    const SECOND: [u8; 4] = [0, 15, 20, 29];
    let options = input.first().copied().unwrap_or(0);
    let split = match input {
        [_, a, b, ..] => usize::from(*a) | usize::from(*b) << 8,
        _ => 0,
    };
    let more = input.get(3).copied().unwrap_or(0);
    let packed = input.get(4..).unwrap_or(&[]);
    let (first, second) = packed.split_at(split.min(packed.len()));

    let algorithm = ALGORITHMS[usize::from(options & 3)];
    let dictionary = u16::from(options >> 2 & 3);
    let unp_size = if options & 64 != 0 { 4096 } else { u32::MAX };

    // `MAIN15` with the archive's solid flag.
    let mut main = vec![0x73];
    main.extend_from_slice(&(u16::from(options & 32 != 0) << 3).to_le_bytes());
    main.extend_from_slice(&MAIN15[12..20]);
    let mut out = MAIN15[..7].to_vec();
    out.extend_from_slice(&(crc32(&main) as u16).to_le_bytes());
    out.extend_from_slice(&main);

    if options & 16 != 0 {
        put_file15_as(&mut out, algorithm, dictionary, false, unp_size, first);
        let chosen = SECOND[usize::from(more & 3)];
        let later = if chosen == 0 { algorithm } else { chosen };
        let dictionary = dictionary + u16::from(more >> 2 & 3);
        put_file15_as(
            &mut out,
            later,
            dictionary,
            options & 128 != 0,
            unp_size,
            second,
        );
    } else {
        put_file15_as(&mut out, algorithm, dictionary, false, unp_size, packed);
    }
    out.extend_from_slice(END15);
    out
}

fn get_vint(data: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in 0..10 {
        let byte = *data.get(*at)?;
        *at += 1;
        value |= u64::from(byte & 0x7f) << (shift * 7);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// Makes the CRCs of the headers right again, as far as they can be followed,
/// so that damage to a header gets past reading it.
pub fn fix_header_crcs(data: &mut [u8]) {
    if data.starts_with(b"Rar!\x1a\x07\x01\x00") {
        fix_rar5(data);
    } else if data.starts_with(b"Rar!\x1a\x07\x00") {
        fix_rar15(data);
    }
}

fn fix_rar5(data: &mut [u8]) {
    let mut at = 8;
    while at + 7 <= data.len() {
        let start = at + 4;
        let mut cursor = start;
        let Some(size) = get_vint(data, &mut cursor) else {
            return;
        };
        let Some(end) = usize::try_from(size)
            .ok()
            .and_then(|s| cursor.checked_add(s))
            .filter(|&end| end <= data.len())
        else {
            return;
        };
        let crc = crc32(&data[start..end]);
        data[at..at + 4].copy_from_slice(&crc.to_le_bytes());

        let Some(_kind) = get_vint(data, &mut cursor) else {
            return;
        };
        let Some(flags) = get_vint(data, &mut cursor) else {
            return;
        };
        if flags & 1 != 0 && get_vint(data, &mut cursor).is_none() {
            return;
        }
        let mut pack_size = 0;
        if flags & 2 != 0 {
            let Some(size) = get_vint(data, &mut cursor) else {
                return;
            };
            pack_size = size;
        }
        let Some(next) = usize::try_from(pack_size)
            .ok()
            .and_then(|s| end.checked_add(s))
        else {
            return;
        };
        at = next;
    }
}

fn fix_rar15(data: &mut [u8]) {
    let mut at = 7;
    while at + 7 <= data.len() {
        let flags = u16::from_le_bytes([data[at + 3], data[at + 4]]);
        let size = usize::from(u16::from_le_bytes([data[at + 5], data[at + 6]]));
        if size < 7 || at + size > data.len() {
            return;
        }
        let crc = crc32(&data[at + 2..at + size]) as u16;
        data[at..at + 2].copy_from_slice(&crc.to_le_bytes());
        let mut add = 0;
        if flags & 0x8000 != 0 && at + 11 <= data.len() {
            add = u32::from_le_bytes([data[at + 7], data[at + 8], data[at + 9], data[at + 10]]);
        }
        at = at.saturating_add(size).saturating_add(add as usize);
    }
}
