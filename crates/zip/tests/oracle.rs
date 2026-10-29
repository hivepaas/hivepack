//! Comparison with libzip 1.12.1 through `tools/zip-oracle`: opening
//! archives, and everything the central directory and local headers say
//! about their entries.
//!
//! The oracle is a small C program built with libzip's sources by
//! `scripts/testdata.py`. It answers requests such as `open 4 b 504b0506...`
//! (open with `ZIP_CHECKCONS` from a buffer) by calling libzip, one line per
//! request: the error, or the entries' names, stat, attributes, comments,
//! extra fields, data offsets and name lookups. [`answer`] answers the same
//! requests with the port, so the two can be compared as text.
//!
//! - With the oracle built, libzip's own test archives (`regress/`) and
//!   generated ones are compared with libzip directly. The generated ones
//!   come from [`archive`], which writes every kind of header field libzip
//!   reads, right and wrong, and some are then damaged.
//! - Everywhere, `testdata/oracle/zip-open.txt` replays answers libzip gave
//!   earlier. `cargo test -p hivepack-zip --test oracle
//!   record_open_answers -- --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use hivepack_deflate::{
    Deflate, Flush as DeflateFlush, InBuffer, OutBuffer, Status as DeflateStatus, crc32,
};
use hivepack_zip::{Archive, ArchiveFlags, Error, Flags, OpenFlags, ReadAt};
use support::{Oracle, Rng, damage, hex, recorded_form, repository, unhex};

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/zip-open.txt")
}

fn recorded_read_path() -> PathBuf {
    repository().join("testdata/oracle/zip-read.txt")
}

fn error_text(e: Error) -> String {
    format!("e{}/{}", e.code().number(), e.system())
}

/// A name as C sees it: up to its first NUL byte.
fn c_string(name: &[u8]) -> &[u8] {
    &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())]
}

/// The oracle's description of an open archive, or of the error.
fn describe<R: ReadAt>(result: hivepack_zip::Result<Archive<R>>) -> String {
    let mut za = match result {
        Ok(za) => za,
        Err(e) => return error_text(e),
    };
    let n = za.get_num_entries(Flags::NONE);
    let mut text = format!(
        "ok {n} {} {} {}",
        u8::from(za.get_archive_flag(ArchiveFlags::IS_TORRENTZIP, Flags::NONE)),
        hex(za.get_archive_comment(Flags::NONE)),
        hex(za.get_archive_comment(Flags::ENC_RAW))
    );
    for i in 0..n {
        let name = |za: &Archive<R>, flags| match za.get_name(i, flags) {
            Ok(name) => hex(c_string(name)),
            Err(e) => error_text(e),
        };
        let _ = write!(
            text,
            " |{} {} {} ",
            name(&za, Flags::NONE),
            name(&za, Flags::ENC_RAW),
            name(&za, Flags::ENC_STRICT)
        );
        match za.stat_index(i, Flags::NONE) {
            Ok(st) => {
                let _ = write!(
                    text,
                    "{}/{}/{}/{}/{}/{}/{}",
                    st.valid,
                    st.size,
                    st.comp_size,
                    st.mtime,
                    st.crc,
                    st.comp_method,
                    st.encryption_method
                );
            }
            Err(e) => text.push_str(&error_text(e)),
        }
        match za.file_get_external_attributes(i, Flags::NONE) {
            Ok((opsys, attributes)) => {
                let _ = write!(text, " {opsys}/{attributes}");
            }
            Err(e) => text.push_str(&format!(" {}", error_text(e))),
        }
        for flags in [Flags::NONE, Flags::ENC_RAW] {
            match za.file_get_comment(i, flags) {
                Ok(comment) => text.push_str(&format!(" {}", hex(comment))),
                Err(e) => text.push_str(&format!(" {}", error_text(e))),
            }
        }
        for (tag, flags) in [("c", Flags::CENTRAL), ("l", Flags::LOCAL)] {
            text.push_str(&format!(" {tag}"));
            match za.file_extra_fields_count(i, flags) {
                Ok(count) => {
                    text.push_str(&format!("{count}:"));
                    for j in 0..count {
                        if j > 0 {
                            text.push(',');
                        }
                        match za.file_extra_field_get(i, j as u16, flags) {
                            Ok((id, data)) => text.push_str(&format!("{id}={}", hex(data))),
                            Err(e) => text.push_str(&error_text(e)),
                        }
                    }
                }
                Err(e) => text.push_str(&error_text(e)),
            }
        }
        match za.file_get_offset(i) {
            Ok(offset) => text.push_str(&format!(" o{offset}")),
            Err(e) => text.push_str(&format!(" o{}", error_text(e))),
        }
        text.push_str(" n");
        match za.get_name(i, Flags::NONE) {
            Ok(name) => {
                let name = c_string(name).to_vec();
                let last = match name.iter().rposition(|&b| b == b'/') {
                    Some(p) => name[p + 1..].to_vec(),
                    None => name.clone(),
                };
                let raw = c_string(za.get_name(i, Flags::ENC_RAW).unwrap()).to_vec();
                let lookups = [
                    (&name, Flags::NONE),
                    (&name, Flags::NOCASE),
                    (&last, Flags::NODIR),
                    (&raw, Flags::ENC_RAW),
                ];
                let found: Vec<String> = lookups
                    .iter()
                    .map(|(fname, flags)| match za.name_locate(fname, *flags) {
                        Ok(index) => index.to_string(),
                        Err(e) => error_text(e),
                    })
                    .collect();
                text.push_str(&found.join(","));
            }
            Err(_) => text.push('-'),
        }
    }
    text
}

fn fnv(mut hash: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// The oracle's answer to a `read` request: every entry read in pieces of
/// `chunks`, up to `limit` bytes, then closed.
fn read_entries<R: ReadAt>(
    result: hivepack_zip::Result<Archive<R>>,
    fflags: u32,
    chunks: &str,
    limit: i64,
) -> String {
    let za = match result {
        Ok(za) => za,
        Err(e) => return error_text(e),
    };
    let chunks: Vec<i64> = chunks.split(',').map(|c| c.parse().unwrap()).collect();
    let n = za.get_num_entries(Flags::NONE);
    let mut text = format!("ok {n}");
    let mut buffer = vec![0u8; 1 << 20];
    for i in 0..n {
        text.push_str(" |");
        let mut zf = match za.fopen_index(i, Flags(fflags)) {
            Ok(zf) => zf,
            Err(e) => {
                text.push_str(&error_text(e));
                continue;
            }
        };
        let (mut data_hash, mut returns_hash) = (0xcbf2_9ce4_8422_2325, 0xcbf2_9ce4_8422_2325);
        let (mut total, mut reads, mut next) = (0i64, 0, 0);
        let mut end = "eof".to_string();
        loop {
            let mut want = chunks[next];
            next = (next + 1) % chunks.len();
            if limit >= 0 && want > limit - total {
                want = limit - total;
            }
            if limit >= 0 && want == 0 {
                end = "limit".into();
                break;
            }
            reads += 1;
            match zf.fread(&mut buffer[..want as usize]) {
                Err(e) => {
                    returns_hash = fnv(returns_hash, b"-1,");
                    end = error_text(e);
                    break;
                }
                Ok(got) => {
                    returns_hash = fnv(returns_hash, format!("{got},").as_bytes());
                    if got == 0 {
                        break;
                    }
                    data_hash = fnv(data_hash, &buffer[..got]);
                    total += got as i64;
                }
            }
        }
        let close = match zf.fclose() {
            Ok(()) => 0,
            Err(e) => e.code().number(),
        };
        let _ = write!(
            text,
            "{total}/{data_hash:016x}/{reads}/{returns_hash:016x}/{end}/{close}"
        );
    }
    text
}

/// The port's answer to a request, in the oracle's format.
fn respond<R: ReadAt>(words: &[&str], result: hivepack_zip::Result<Archive<R>>) -> String {
    match words[0] {
        "open" => describe(result),
        _ => read_entries(
            result,
            words[3].parse().unwrap(),
            words[4],
            words[5].parse().unwrap(),
        ),
    }
}

/// The port's answer to an `open` or `read` request, in the oracle's
/// format.
fn answer(request: &str) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    let (flags, kind, data) = match words[..] {
        ["open", flags, kind, data] => (flags, kind, data),
        ["read", flags, kind, _, _, _, data] => (flags, kind, data),
        _ => panic!("{request:.100}"),
    };
    let flags = OpenFlags(flags.parse().unwrap());
    let data = unhex(data);
    if kind == "f" {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "hivepack-zip-{}-{}.zip",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, &data).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let text = respond(&words, Archive::open(file, flags));
        let _ = std::fs::remove_file(&path);
        text
    } else {
        respond(&words, Archive::open(data.as_slice(), flags))
    }
}

/// One entry of a generated archive, as written in each header.
#[derive(Clone)]
struct Spec {
    name: Vec<u8>,
    local_name: Vec<u8>,
    gpbf: u16,
    local_gpbf: u16,
    method: u16,
    local_method: u16,
    time: u16,
    date: u16,
    local_time: u16,
    crc: u32,
    local_crc: u32,
    /// The size fields as written, 0xffffffff where the Zip64 field has it.
    csize: u32,
    usize: u32,
    local_csize: u32,
    local_usize: u32,
    data: Vec<u8>,
    central_extra: Vec<u8>,
    local_extra: Vec<u8>,
    comment: Vec<u8>,
    made_by: u16,
    needed: u16,
    local_needed: u16,
    int_attr: u16,
    ext_attr: u32,
    disk: u16,
    /// The offset field, `None` for the real one.
    offset: Option<u32>,
    /// The data descriptor after the data.
    descriptor: Vec<u8>,
}

fn put16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn field(out: &mut Vec<u8>, id: u16, data: &[u8]) {
    put16(out, id);
    put16(out, data.len() as u16);
    out.extend_from_slice(data);
}

/// A name or comment of some kind.
fn text(rng: &mut Rng, len: usize) -> Vec<u8> {
    let pieces: [&[u8]; 12] = [
        b"a",
        b"Readme",
        b".txt",
        b"/",
        b"dir/",
        b"\xc3\xa9",
        "日本".as_bytes(),
        "😀".as_bytes(),
        b"\x81\xe9",
        b"\x01",
        b" ",
        b"Z9",
    ];
    let mut out = Vec::new();
    while out.len() < len {
        match rng.below(12) {
            0 => out.push(rng.next() as u8),
            _ => out.extend_from_slice(rng.pick(&pieces)),
        }
    }
    out
}

fn name(rng: &mut Rng, earlier: &[Spec]) -> Vec<u8> {
    match rng.below(20) {
        0 => Vec::new(),
        1 => b"a\0b".to_vec(),
        2 | 3 if !earlier.is_empty() => earlier[rng.below(earlier.len() as u64) as usize]
            .name
            .clone(),
        4 if !earlier.is_empty() => earlier[rng.below(earlier.len() as u64) as usize]
            .name
            .to_ascii_uppercase(),
        5 => text(rng, 3).iter().map(|&b| b & 0x7f).collect(),
        6..=11 => {
            let parts = [
                &b"docs"[..],
                b"src",
                b"main.rs",
                b"README",
                b"x/y/z.txt",
                b"empty/",
            ];
            let mut name = rng.pick(&parts).to_vec();
            name.extend_from_slice(rng.below(1000).to_string().as_bytes());
            name
        }
        _ => {
            let len = 1 + rng.below(12) as usize;
            text(rng, len)
        }
    }
}

/// The Info-ZIP Unicode Path or Comment extra field for `of`.
fn unicode_field(rng: &mut Rng, id: u16, of: &[u8]) -> Vec<u8> {
    let mut data = vec![if rng.below(8) == 0 { 2 } else { 1 }];
    let crc = if rng.below(4) == 0 {
        rng.next() as u32
    } else {
        crc32(0, of)
    };
    put32(&mut data, crc);
    match rng.below(4) {
        0 => data.extend_from_slice(of),
        1 => data.extend_from_slice(&text(rng, 4).iter().map(|&b| b & 0x7f).collect::<Vec<_>>()),
        2 => data.extend_from_slice("ünïcödé".as_bytes()),
        _ => {
            let len = rng.below(6) as usize;
            data.extend_from_slice(&text(rng, len));
        }
    }
    if rng.below(10) == 0 {
        data.truncate(rng.below(6) as usize);
    }
    let mut out = Vec::new();
    field(&mut out, id, &data);
    out
}

/// Fields of no meaning to libzip.
fn other_fields(rng: &mut Rng) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..rng.below(3) {
        let id = rng.pick(&[0x5455u16, 0x7875, 0x000a, 0xcafe, 0x0002, 0x9901]);
        let len = rng.below(12) as usize;
        let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        field(&mut out, id, &data);
    }
    out
}

/// The uncompressed data of an entry: text, runs or random bytes.
fn plain(rng: &mut Rng) -> Vec<u8> {
    let len = rng.pick(&[0usize, 1, 5, 12, 40, 300, 3000, 20_000]);
    match rng.below(3) {
        0 => (0..len).map(|_| rng.next() as u8).collect(),
        1 => text(rng, len),
        _ => {
            let byte = rng.next() as u8;
            vec![byte; len]
        }
    }
}

/// `plain` as a raw deflate stream, from the port's compressor, which
/// writes zlib's streams.
fn deflated(rng: &mut Rng, plain: &[u8]) -> Vec<u8> {
    let level = rng.below(10) as i32;
    let mut stream = Deflate::new(level, -15, 8, 0).unwrap();
    let mut out = vec![0; stream.bound(plain.len() as u64) as usize];
    let mut output = OutBuffer::new(&mut out);
    let ret = stream.deflate(&mut output, &mut InBuffer::new(plain), DeflateFlush::Finish);
    assert_eq!(ret, Ok(DeflateStatus::StreamEnd));
    let written = output.pos;
    out.truncate(written);
    out
}

fn spec(rng: &mut Rng, earlier: &[Spec]) -> Spec {
    let name = name(rng, earlier);
    let method = rng.pick(&[0u16, 0, 0, 8, 8, 8, 9, 12, 99, 14, 93]);
    let plain = plain(rng);
    let data = match method {
        0 => plain.clone(),
        8 => {
            let mut data = deflated(rng, &plain);
            match rng.below(12) {
                // Cut short, garbage after it, or a byte changed.
                0 => data.truncate(rng.below(data.len() as u64 + 1) as usize),
                1 => data.extend((0..1 + rng.below(4)).map(|_| rng.next() as u8)),
                2 if !data.is_empty() => {
                    let at = rng.below(data.len() as u64) as usize;
                    data[at] ^= 1 << rng.below(8);
                }
                _ => {}
            }
            data
        }
        _ => (0..plain.len().min(40)).map(|_| rng.next() as u8).collect(),
    };
    let data_len = data.len();
    let mut gpbf = 0u16;
    if rng.below(3) == 0 {
        gpbf |= 0x0800;
    }
    if rng.below(6) == 0 {
        gpbf |= 0x0008;
    }
    if rng.below(8) == 0 {
        gpbf |= 0x0001;
        if rng.below(4) == 0 {
            gpbf |= 0x0040;
        }
    }
    let encrypted_header = if gpbf & 1 != 0 { 12 } else { 0 };
    let usize = match rng.below(10) {
        0 => rng.next() as u32 % 100,
        1 => plain.len() as u32 + 1,
        _ if method == 0 => (data_len as u32).saturating_sub(encrypted_header),
        _ => plain.len() as u32,
    };
    let crc = if rng.below(8) == 0 {
        rng.next() as u32
    } else {
        crc32(0, &plain)
    };
    let time = rng.next() as u16;
    let date = rng.next() as u16;
    let mut central_extra = Vec::new();
    let mut local_extra = Vec::new();
    if rng.below(4) == 0 {
        central_extra.extend(unicode_field(rng, 0x7075, &name));
    }
    if rng.below(8) == 0 {
        local_extra.extend(unicode_field(rng, 0x7075, &name));
    }
    let comment = match rng.below(6) {
        0 => text(rng, 5),
        1 => b"note".to_vec(),
        _ => Vec::new(),
    };
    if rng.below(8) == 0 {
        central_extra.extend(unicode_field(rng, 0x6375, &comment));
    }
    if method == 99 || rng.below(20) == 0 {
        let mut aes = Vec::new();
        put16(&mut aes, rng.pick(&[1, 2, 2, 3]));
        aes.extend_from_slice(rng.pick(&[&b"AE"[..], b"AE", b"XY"]));
        aes.push(rng.pick(&[1, 2, 3, 3, 4]));
        put16(&mut aes, rng.pick(&[0, 8, 8]));
        if rng.below(10) == 0 {
            aes.push(0);
        }
        let mut f = Vec::new();
        field(&mut f, 0x9901, &aes);
        central_extra.extend_from_slice(&f);
        if rng.below(2) == 0 {
            local_extra.extend_from_slice(&f);
        }
    }
    central_extra.extend(other_fields(rng));
    local_extra.extend(other_fields(rng));
    for extra in [&mut central_extra, &mut local_extra] {
        match rng.below(20) {
            0 => extra.extend(std::iter::repeat_n(0, 1 + rng.below(3) as usize)),
            1 => extra.push(rng.next() as u8),
            2 => extra.extend_from_slice(&[0x01, 0x02, 0x40, 0x00]),
            _ => {}
        }
    }
    let needed = rng.pick(&[10u16, 20, 20, 45, 63]);
    let descriptor_sizes = gpbf & 0x0008 != 0;
    let mut s = Spec {
        local_name: name.clone(),
        name,
        gpbf,
        local_gpbf: gpbf,
        method,
        local_method: method,
        time,
        date,
        local_time: time,
        crc,
        local_crc: if descriptor_sizes && rng.below(2) == 0 {
            0
        } else {
            crc
        },
        csize: data_len as u32,
        usize,
        local_csize: if descriptor_sizes && rng.below(2) == 0 {
            0
        } else {
            data_len as u32
        },
        local_usize: if descriptor_sizes && rng.below(2) == 0 {
            0
        } else {
            usize
        },
        data,
        central_extra,
        local_extra,
        comment,
        made_by: rng.pick(&[0x031e, 0x0014, 0x0a3f, 0x1314]),
        needed,
        local_needed: needed,
        int_attr: rng.pick(&[0, 1]),
        ext_attr: rng.next() as u32,
        disk: 0,
        offset: None,
        descriptor: Vec::new(),
    };
    // The local header disagrees now and then.
    match rng.below(25) {
        0 => s.local_name = b"other".to_vec(),
        1 => s.local_time ^= 1,
        2 => s.local_needed += 1,
        3 => s.local_method ^= 8,
        4 => s.local_crc ^= 1,
        5 => s.local_gpbf ^= 0x0008,
        6 => s.disk = rng.pick(&[1, 0xffff]),
        7 => s.offset = Some(rng.next() as u32 % 200),
        _ => {}
    }
    if s.local_gpbf & 0x0008 != 0 && rng.below(6) != 0 {
        let mut dd = Vec::new();
        if rng.below(2) == 0 {
            dd.extend_from_slice(b"PK\x07\x08");
        }
        put32(&mut dd, s.crc);
        put32(&mut dd, s.csize);
        put32(&mut dd, s.usize);
        if rng.below(8) == 0 {
            let last = dd.len() - 1;
            dd[last] ^= 1;
        }
        s.descriptor = dd;
    }
    s
}

/// Moves sizes and the offset into Zip64 extra fields, as Zip64 writers
/// do, sometimes not quite right.
fn zip64_fields(rng: &mut Rng, s: &mut Spec, offset: u64) {
    let mut central = Vec::new();
    let mut local = Vec::new();
    let (usize, csize) = (u64::from(s.usize), u64::from(s.csize));
    let all = rng.below(3) == 0;
    if all || rng.below(2) == 0 {
        put64(&mut central, usize);
        s.usize = u32::MAX;
    }
    if all || rng.below(2) == 0 {
        put64(&mut central, csize);
        s.csize = u32::MAX;
    }
    if all || rng.below(2) == 0 {
        put64(&mut central, offset);
        s.offset = Some(u32::MAX);
    }
    if rng.below(4) == 0 {
        put32(&mut central, 0);
        s.disk = 0xffff;
    }
    match rng.below(12) {
        0 => central.truncate(central.len().saturating_sub(4)),
        1 => central.extend_from_slice(&[0; 8]),
        2 => {
            central.clear();
            put64(&mut central, usize);
            put64(&mut central, csize);
            put64(&mut central, offset);
            if rng.below(2) == 0 {
                put32(&mut central, 0);
            }
        }
        _ => {}
    }
    if rng.below(6) != 0 {
        let mut f = Vec::new();
        field(&mut f, 0x0001, &central);
        s.central_extra.splice(0..0, f);
    }
    if rng.below(2) == 0 {
        put64(&mut local, usize);
        put64(&mut local, csize);
        s.local_usize = u32::MAX;
        s.local_csize = u32::MAX;
        let mut f = Vec::new();
        field(&mut f, 0x0001, &local);
        s.local_extra.splice(0..0, f);
    }
}

fn write_local(out: &mut Vec<u8>, s: &Spec) {
    out.extend_from_slice(b"PK\x03\x04");
    put16(out, s.local_needed);
    put16(out, s.local_gpbf);
    put16(out, s.local_method);
    put16(out, s.local_time);
    put16(out, s.date);
    put32(out, s.local_crc);
    put32(out, s.local_csize);
    put32(out, s.local_usize);
    put16(out, s.local_name.len() as u16);
    put16(out, s.local_extra.len() as u16);
    out.extend_from_slice(&s.local_name);
    out.extend_from_slice(&s.local_extra);
    out.extend_from_slice(&s.data);
    out.extend_from_slice(&s.descriptor);
}

fn write_central(out: &mut Vec<u8>, s: &Spec, offset: u32) {
    out.extend_from_slice(b"PK\x01\x02");
    put16(out, s.made_by);
    put16(out, s.needed);
    put16(out, s.gpbf);
    put16(out, s.method);
    put16(out, s.time);
    put16(out, s.date);
    put32(out, s.crc);
    put32(out, s.csize);
    put32(out, s.usize);
    put16(out, s.name.len() as u16);
    put16(out, s.central_extra.len() as u16);
    put16(out, s.comment.len() as u16);
    put16(out, s.disk);
    put16(out, s.int_attr);
    put32(out, s.ext_attr);
    put32(out, s.offset.unwrap_or(offset));
    out.extend_from_slice(&s.name);
    out.extend_from_slice(&s.central_extra);
    out.extend_from_slice(&s.comment);
}

/// A generated archive.
fn archive(rng: &mut Rng) -> Vec<u8> {
    let mut out = Vec::new();
    let prefix = rng.below(10) == 0;
    if prefix {
        out.extend((0..1 + rng.below(60)).map(|_| rng.next() as u8));
    }
    let count = match rng.below(10) {
        0 => 0,
        1 => 10 + rng.below(30),
        _ => 1 + rng.below(5),
    } as usize;
    let zip64 = rng.below(6) == 0;
    let mut specs: Vec<Spec> = Vec::new();
    let mut offsets = Vec::new();
    for _ in 0..count {
        let mut s = spec(rng, &specs);
        let offset = out.len() as u64;
        if zip64 && rng.below(2) == 0 {
            zip64_fields(rng, &mut s, offset);
        }
        // A self-extractor that does not count its prefix.
        let written = if prefix && rng.below(2) == 0 {
            offset.saturating_sub(10)
        } else {
            offset
        };
        write_local(&mut out, &s);
        offsets.push(written as u32);
        specs.push(s);
    }
    let cd_offset = out.len() as u64;
    let mut central = Vec::new();
    for (s, &offset) in specs.iter().zip(&offsets) {
        write_central(&mut central, s, offset);
    }
    out.extend_from_slice(&central);
    let cd_size = central.len() as u64;

    let mut entries = count as u64;
    let mut size = cd_size;
    let mut offset = cd_offset;
    match rng.below(20) {
        0 => entries += 1,
        1 => entries = entries.saturating_sub(1),
        2 => size += 1,
        3 => offset = offset.saturating_sub(1),
        4 => offset += 3,
        _ => {}
    }
    let mut disks = [0u16, 0];
    if rng.below(25) == 0 {
        disks[rng.below(2) as usize] = rng.pick(&[1, 2, 0xffff]);
    }
    let mut this_disk_entries = entries;
    if rng.below(30) == 0 {
        this_disk_entries ^= 1;
    }

    if zip64 {
        let eocd64 = out.len() as u64;
        out.extend_from_slice(b"PK\x06\x06");
        put64(&mut out, if rng.below(15) == 0 { 40 } else { 44 });
        put16(&mut out, 45);
        put16(&mut out, 45);
        put32(&mut out, u32::from(disks[0]));
        put32(&mut out, u32::from(disks[1]));
        put64(&mut out, this_disk_entries);
        put64(
            &mut out,
            if rng.below(20) == 0 {
                entries * 100
            } else {
                entries
            },
        );
        put64(&mut out, size);
        put64(&mut out, offset);
        if rng.below(15) == 0 {
            out.extend_from_slice(&[0; 4]);
        }
        out.extend_from_slice(b"PK\x06\x07");
        put32(&mut out, u32::from(disks[1]));
        put64(
            &mut out,
            if rng.below(15) == 0 {
                eocd64 + 1
            } else {
                eocd64
            },
        );
        put32(&mut out, if rng.below(20) == 0 { 2 } else { 1 });
    }

    let comment = match rng.below(12) {
        0 => {
            let crc = if rng.below(3) == 0 {
                rng.next() as u32
            } else {
                crc32(0, &central)
            };
            let mut c = b"TORRENTZIPPED-".to_vec();
            let digits = format!("{crc:08X}");
            c.extend_from_slice(
                if rng.below(6) == 0 {
                    digits.to_lowercase()
                } else {
                    digits
                }
                .as_bytes(),
            );
            c
        }
        1 => b"has PK\x05\x06 in it".to_vec(),
        2..=4 => text(rng, 8),
        _ => Vec::new(),
    };
    let mut eocd_entries = |n: u64| {
        if zip64 && rng.below(2) == 0 {
            0xffff
        } else {
            n as u16
        }
    };
    out.extend_from_slice(b"PK\x05\x06");
    put16(&mut out, disks[0]);
    put16(&mut out, disks[1]);
    put16(&mut out, eocd_entries(this_disk_entries));
    put16(&mut out, eocd_entries(entries));
    put32(
        &mut out,
        if zip64 && rng.below(2) == 0 {
            u32::MAX
        } else {
            size as u32
        },
    );
    put32(
        &mut out,
        if zip64 && rng.below(2) == 0 {
            u32::MAX
        } else {
            offset as u32
        },
    );
    let comment_len = match rng.below(15) {
        0 => comment.len() as u16 + 3,
        1 => (comment.len() as u16).saturating_sub(1),
        _ => comment.len() as u16,
    };
    put16(&mut out, comment_len);
    out.extend_from_slice(&comment);
    if rng.below(15) == 0 {
        out.extend((0..1 + rng.below(30)).map(|_| rng.next() as u8));
    }
    out
}

/// `count` open requests on generated archives, some damaged.
fn requests(rng: &mut Rng, count: usize) -> Vec<String> {
    (0..count)
        .map(|_| {
            let mut zip = archive(rng);
            if rng.below(4) == 0 {
                zip = damage(rng, &zip);
            }
            let flags = rng.pick(&[0, 4]);
            let kind = if rng.below(10) == 0 { "f" } else { "b" };
            format!("open {flags} {kind} {}", hex(&zip))
        })
        .collect()
}

/// `count` read requests on generated archives, some damaged: in pieces of
/// every size, with each flag that changes what is read, sometimes stopping
/// early.
fn read_requests(rng: &mut Rng, count: usize) -> Vec<String> {
    (0..count)
        .map(|_| {
            let mut zip = archive(rng);
            if rng.below(6) == 0 {
                zip = damage(rng, &zip);
            }
            format!("read {} {}", read_parameters(rng), hex(&zip))
        })
        .collect()
}

/// The flags, source, file flags, pieces and limit of a read request.
fn read_parameters(rng: &mut Rng) -> String {
    let flags = rng.pick(&[0, 4]);
    let kind = if rng.below(10) == 0 { "f" } else { "b" };
    // 0, ZIP_FL_COMPRESSED, ZIP_FL_ENCRYPTED, ZIP_FL_UNCHANGED
    let fflags = rng.pick(&[0, 0, 0, 4, 32, 8]);
    let chunks = rng.pick(&["8192", "1", "7,100", "65536", "3,5000,1", "20000"]);
    let limit = match rng.below(5) {
        0 => rng.below(100) as i64,
        1 => rng.pick(&[5, 12, 40, 300, 3000, 20_000]),
        _ => -1,
    };
    format!("{flags} {kind} {fflags} {chunks} {limit}")
}

/// libzip's test archives, where the libzip sources are fetched.
fn regress_archives() -> Vec<(String, Vec<u8>)> {
    let cache = std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository().join("target/testdata"));
    let regress = cache.join("libzip-1.12.1-source/libzip-1.12.1/regress");
    let mut files = Vec::new();
    for folder in [regress.clone(), regress.join("data")] {
        let Ok(dir) = std::fs::read_dir(&folder) else {
            continue;
        };
        for entry in dir {
            let path = entry.unwrap().path();
            if path.is_file() {
                files.push((
                    path.file_name().unwrap().to_string_lossy().into_owned(),
                    std::fs::read(&path).unwrap(),
                ));
            }
        }
    }
    files.sort();
    files
}

#[test]
fn regress_archives_match_libzip() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let files = regress_archives();
    assert!(
        files.len() > 150,
        "libzip's regress files are missing: {}",
        files.len()
    );
    for (name, data) in &files {
        // The large ones take the oracle's line too long for no gain.
        if data.len() > 1 << 20 {
            continue;
        }
        for flags in [0, 4] {
            for kind in ["b", "f"] {
                let request = format!("open {flags} {kind} {}", hex(data));
                let want = oracle.ask(&request);
                assert_eq!(
                    answer(&request),
                    want,
                    "{name} with flags {flags}, source {kind}"
                );
            }
        }
    }
}

#[test]
fn regress_archives_read_like_libzip() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x2400_0001);
    for (name, data) in &regress_archives() {
        if data.len() > 1 << 20 {
            continue;
        }
        for parameters in [
            "0 b 0 8192 -1",
            "4 b 0 8192 -1",
            "0 f 4 100 -1",
            "0 b 0 1 -1",
        ]
        .map(String::from)
        .into_iter()
        .chain([read_parameters(&mut rng)])
        {
            let request = format!("read {parameters} {}", hex(data));
            let want = oracle.ask(&request);
            assert_eq!(answer(&request), want, "{name}: read {parameters}");
        }
    }
}

#[test]
fn generated_archives_read_like_libzip() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x2400_0002);
    for request in read_requests(&mut rng, 800) {
        let want = oracle.ask(&request);
        assert_eq!(answer(&request), want, "{request:.400}");
    }
}

#[test]
fn generated_archives_match_libzip() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x2100_0001);
    for request in requests(&mut rng, 1500) {
        let want = oracle.ask(&request);
        assert_eq!(answer(&request), want, "{request:.400}");
    }
}

/// Replays the answers recorded in `path`.
fn replay(path: &PathBuf, at_least: usize) {
    let text = std::fs::read_to_string(path).expect("the recorded answers");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(recorded_form(&answer(request)), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked > at_least, "only {checked} recorded answers");
}

/// Writes libzip's answers to `requests` into `path`, but for the long
/// ones (past `max_len`), and, with `errors_kept` n, only every nth archive
/// libzip refuses or finds empty.
fn record(
    path: &PathBuf,
    what: &str,
    test: &str,
    requests: Vec<String>,
    max_len: usize,
    errors_kept: usize,
) {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut text = format!(
        "# {what} from libzip 1.12.1 (tools/zip-oracle), replayed by crates/zip/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack-zip --test oracle {test} -- --ignored\n"
    );
    let mut refused = 0;
    for request in requests {
        if request.len() > max_len {
            continue;
        }
        let reply = oracle.ask(&request);
        if !reply.contains(" |") {
            refused += 1;
            if refused % errors_kept != 0 {
                continue;
            }
        }
        let _ = writeln!(text, "{request}\t{}", recorded_form(&reply));
    }
    std::fs::write(path, text).expect("written");
}

#[test]
fn port_reads_as_recorded() {
    replay(&recorded_read_path(), 300);
}

#[test]
#[ignore = "rewrites testdata/oracle/zip-read.txt from the oracle"]
fn record_read_answers() {
    let mut rng = Rng(0x2400_0003);
    record(
        &recorded_read_path(),
        "Reads",
        "record_read_answers",
        read_requests(&mut rng, 2500),
        5_000,
        5,
    );
}

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/zip-open.txt");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(recorded_form(&answer(request)), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked > 500, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/zip-open.txt from the oracle"]
fn record_open_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng(0x2100_0002);
    let mut text = String::from(
        "# Answers from libzip 1.12.1 (tools/zip-oracle), replayed by crates/zip/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack-zip --test oracle record_open_answers -- --ignored\n",
    );
    for request in requests(&mut rng, 800) {
        if request.len() > 3_000 {
            continue;
        }
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{}", recorded_form(&reply));
    }
    std::fs::write(recorded_path(), text).expect("written");
}

/// A sanity check of the harness: libzip's test for an archive with bytes
/// after the end of central directory record (`open_cons_extrabytes.test`).
#[test]
fn refuses_extra_bytes_with_checkcons() {
    let mut zip = Vec::new();
    zip.extend_from_slice(b"PK\x05\x06");
    zip.extend_from_slice(&[0; 18]);
    zip.extend_from_slice(b"junk");
    assert_eq!(answer(&format!("open 4 b {}", hex(&zip))), "e21/2");
    assert_eq!(answer(&format!("open 0 b {}", hex(&zip))), "ok 0 0 - -");
}
