//! What the SDK's decoder answers `SZ_ERROR_UNSUPPORTED` to and 7-Zip's
//! program reads: the methods and graphs of coders of `dec.rs`'s `Graph`,
//! compared from the outside with `7zz`, where `scripts/testdata.py` built it.
//! Archives 7-Zip makes must read back as their files, and a damaged one that
//! `7zz t` calls good must read here too. The other way around is allowed: the
//! headers are read as the SDK reads them, and 7-Zip's parser refuses more.
//!
//! - `SEVENZ_METHODS_SEED=<n>` makes other archives, and
//!   `SEVENZ_METHODS_COUNT=<n>` more damaged ones of each.
//! - Archives put together by hand, for what `7zz` does not write, are read
//!   everywhere: Zstandard, which 7-Zip's program does not take in 7z, a
//!   filter alone, and what is left over after a coder's stream.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::io::{Cursor, Read};
use std::path::Path;
use std::process::{Command, Stdio};

use hivepack_7z::Archive;
use support::{Rng, damaged, input, make_archive, scratch, seven_zip, write_files};

const OPTIONS: &[&str] = &[
    "-m0=Deflate",
    "-m0=Deflate -mhc=off",
    "-m0=Deflate:a=0",
    "-m0=Deflate64",
    "-m0=Deflate64 -ms=off",
    "-m0=BZip2",
    "-m0=BZip2:d=100k -mhc=off",
    "-m0=BZip2:d=900k:mt=4",
    "-m0=Swap2 -m1=LZMA",
    "-m0=Swap4 -m1=Deflate",
    "-m0=Swap4",
    "-m0=BCJ",
    "-m0=Delta:2 -m1=Deflate",
    "-m0=BCJ -m1=BZip2",
    "-m0=ARM64 -m1=Deflate64",
    "-m0=BCJ -m1=Delta:1 -m2=LZMA",
    "-m0=Delta:4 -m1=Swap2 -m2=BCJ -m3=LZMA2 -mhc=off",
    "-m0=BCJ2 -m1=Deflate -m2=BZip2 -m3=LZMA -mb0s0:1 -mb0s1:2 -mb0s2:3",
    "-m0=BCJ2 -m1=LZMA2 -m2=Deflate64 -m3=Deflate -mb0s0:1 -mb0s1:2 -mb0s2:3 -mhc=off",
];

/// Whether `7zz t` finds all of the archive right.
fn tool_says_good(tool: &Path, dir: &Path, archive: &[u8]) -> bool {
    let path = dir.join("asked.7z");
    std::fs::write(&path, archive).expect("the archive written");
    Command::new(tool)
        .args(["t", "-bd", "-bso0", "-bse0", "-bsp0", "-p-"])
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("7zz starts")
        .success()
}

/// Each file's name and data, read one after another, or the first error.
fn read_all(archive: &[u8]) -> Result<Vec<(String, Vec<u8>)>, hivepack_7z::Error> {
    let mut a = Archive::open(Cursor::new(archive))?;
    let mut files = a.files();
    let mut out = Vec::new();
    while let Some(entry) = files.next()? {
        let mut data = Vec::new();
        files
            .read_to_end(&mut data)
            .map_err(|_| hivepack_7z::Error::Data)?;
        out.push((entry.name, data));
    }
    Ok(out)
}

#[test]
fn reads_what_seven_zip_makes() {
    let Some(tool) = seven_zip() else {
        return;
    };
    let dir = scratch("methods");
    let env = |name: &str| std::env::var(name).ok().and_then(|s| s.parse::<u64>().ok());
    let mut rng = Rng(env("SEVENZ_METHODS_SEED").unwrap_or(0x5eed_7a11));
    let count = env("SEVENZ_METHODS_COUNT").unwrap_or(12);
    let mut tallies = [[0; 2]; 2];
    for options in OPTIONS {
        let files = 1 + rng.below(6) as usize;
        write_files(&mut rng, &dir, files, 200_000);
        let archive = make_archive(&tool, &dir, "files", options);
        let read = read_all(&archive).unwrap_or_else(|e| panic!("{options}: {e}"));
        assert!(!read.is_empty());
        for (name, data) in &read {
            let path = dir.join(name);
            if path.is_file() {
                assert_eq!(
                    data,
                    &std::fs::read(&path).expect("the file"),
                    "{options}: {name}"
                );
            }
        }
        let mut a = Archive::open(Cursor::new(&archive)).expect("it opens");
        for (i, (_, data)) in read.iter().enumerate() {
            assert_eq!(&a.extract(i).expect("it extracts"), data, "{options}");
        }
        for round in 0..count {
            let bad = damaged(&mut rng, &archive);
            let good = tool_says_good(&tool, &dir, &bad);
            let read = read_all(&bad);
            if good {
                assert!(
                    read.is_ok(),
                    "{options}, round {round}: 7zz reads it: {read:?}"
                );
            }
            tallies[usize::from(good)][usize::from(read.is_ok())] += 1;
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    let [[neither, only_port], [_, both]] = tallies;
    eprintln!("{both} good for both, {neither} for neither, {only_port} for the port alone");
}

/// A coder of a hand-made folder: its ID, properties and input streams.
struct Coder<'a> {
    id: &'a [u8],
    props: &'a [u8],
    streams: u8,
    unpack_size: u64,
}

fn number(out: &mut Vec<u8>, n: u64) {
    if n < 0x80 {
        out.push(n as u8);
    } else {
        out.push(0xFF);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// An archive of one file in one folder, whose header is not compressed.
/// `pack` holds the packed streams, `bonds` the (input, coder) pairs and
/// `pack_streams` which input streams they feed.
fn hand_made(
    pack: &[&[u8]],
    coders: &[Coder<'_>],
    bonds: &[(u64, u64)],
    pack_streams: &[u64],
    data_crc: u32,
) -> Vec<u8> {
    let mut h = vec![0x01, 0x04, 0x06];
    number(&mut h, 0);
    number(&mut h, pack.len() as u64);
    h.push(0x09);
    for p in pack {
        number(&mut h, p.len() as u64);
    }
    h.extend_from_slice(&[0x00, 0x07, 0x0B, 0x01, 0x00]);
    number(&mut h, coders.len() as u64);
    for c in coders {
        let complex = c.streams != 1;
        let flags = c.id.len() as u8
            | if complex { 0x10 } else { 0 }
            | if c.props.is_empty() { 0 } else { 0x20 };
        h.push(flags);
        h.extend_from_slice(c.id);
        if complex {
            number(&mut h, u64::from(c.streams));
            number(&mut h, 1);
        }
        if !c.props.is_empty() {
            number(&mut h, c.props.len() as u64);
            h.extend_from_slice(c.props);
        }
    }
    for (input, coder) in bonds {
        number(&mut h, *input);
        number(&mut h, *coder);
    }
    if pack_streams.len() > 1 {
        for s in pack_streams {
            number(&mut h, *s);
        }
    }
    h.push(0x0C);
    for c in coders {
        number(&mut h, c.unpack_size);
    }
    h.extend_from_slice(&[0x0A, 0x01]);
    h.extend_from_slice(&data_crc.to_le_bytes());
    h.extend_from_slice(&[0x00, 0x00, 0x05]);
    number(&mut h, 1);
    let name: Vec<u8> = "file"
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    h.push(0x11);
    number(&mut h, 1 + name.len() as u64);
    h.push(0);
    h.extend_from_slice(&name);
    h.extend_from_slice(&[0x00, 0x00]);

    let packed: Vec<u8> = pack.concat();
    let mut tail = Vec::new();
    tail.extend_from_slice(&(packed.len() as u64).to_le_bytes());
    tail.extend_from_slice(&(h.len() as u64).to_le_bytes());
    tail.extend_from_slice(&hivepack_deflate::crc32(0, &h).to_le_bytes());
    let mut out = vec![b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, 0, 4];
    out.extend_from_slice(&hivepack_deflate::crc32(0, &tail).to_le_bytes());
    out.extend_from_slice(&tail);
    out.extend_from_slice(&packed);
    out.extend_from_slice(&h);
    out
}

/// What `7zz t` says about `archive`, where it is built.
fn ask_tool(archive: &[u8], what: &str) -> Option<bool> {
    let tool = seven_zip()?;
    let dir = scratch(&format!("hand-{}", what.replace(' ', "-")));
    let good = tool_says_good(&tool, &dir, archive);
    let _ = std::fs::remove_dir_all(&dir);
    Some(good)
}

/// The archive reads as `data`.
fn check_reads(archive: &[u8], data: &[u8], what: &str) {
    let read = read_all(archive).unwrap_or_else(|e| panic!("{what}: {e}"));
    assert_eq!(read.len(), 1, "{what}");
    assert_eq!(read[0].1, data, "{what}");
    let mut a = Archive::open(Cursor::new(archive)).expect("it opens");
    assert_eq!(a.extract(0).expect("it extracts"), data, "{what}");
}

/// The archive fails, by the end of its data.
fn check_fails(archive: &[u8], what: &str) {
    assert!(read_all(archive).is_err(), "{what}: it reads");
    let mut a = Archive::open(Cursor::new(archive)).expect("it opens");
    assert!(a.extract(0).is_err(), "{what}: it extracts");
}

/// `data` in a raw Deflate stream.
fn deflated(data: &[u8]) -> Vec<u8> {
    let mut z = hivepack_deflate::Deflate::new(6, -15, 8, hivepack_deflate::Z_DEFAULT_STRATEGY)
        .expect("a compressor");
    let mut out = vec![0; data.len() + 1000];
    let mut o = hivepack_deflate::OutBuffer::new(&mut out);
    let mut i = hivepack_deflate::InBuffer::new(data);
    z.deflate(&mut o, &mut i, hivepack_deflate::Flush::Finish)
        .expect("it compresses");
    let n = o.pos;
    out.truncate(n);
    out
}

#[test]
fn zstandard_frames() {
    let mut rng = Rng(0x5eed_7a12);
    let data = input(&mut rng, 300_000);
    let crc = hivepack_deflate::crc32(0, &data);
    let bound = hivepack_zstd::compress_bound(data.len()).expect("a bound") + 100;
    let mut packed = vec![0; bound];
    let n = hivepack_zstd::compress(&mut packed, &data, 3).expect("it compresses");
    packed.truncate(n);
    let coder = |unpack_size| Coder {
        id: &[0x04, 0xF7, 0x11, 0x01],
        props: &[0, 0, 0],
        streams: 1,
        unpack_size,
    };
    let size = data.len() as u64;
    check_reads(
        &hand_made(&[&packed], &[coder(size)], &[], &[0], crc),
        &data,
        "zstd",
    );
    // Two frames.
    let half = data.len() / 2;
    let mut two = vec![0; bound];
    let n = hivepack_zstd::compress(&mut two, &data[..half], 1).expect("it compresses");
    let m = hivepack_zstd::compress(&mut two[n..], &data[half..], 1).expect("it compresses");
    two.truncate(n + m);
    check_reads(
        &hand_made(&[&two], &[coder(size)], &[], &[0], crc),
        &data,
        "zstd two frames",
    );
    // Something after the frames, and output that stops before they do.
    let mut more = packed.clone();
    more.push(0);
    check_fails(
        &hand_made(&[&more], &[coder(size)], &[], &[0], crc),
        "zstd with more after",
    );
    let short = hivepack_deflate::crc32(0, &data[..1000]);
    check_fails(
        &hand_made(&[&packed], &[coder(1000)], &[], &[0], short),
        "zstd cut short",
    );
}

#[test]
fn a_filter_alone() {
    let mut rng = Rng(0x5eed_7a13);
    let data = input(&mut rng, 100_000);
    // Delta with a distance of 1: each byte's difference from the last.
    let mut packed = data.clone();
    for i in (1..packed.len()).rev() {
        packed[i] = packed[i].wrapping_sub(packed[i - 1]);
    }
    let crc = hivepack_deflate::crc32(0, &data);
    let coder = Coder {
        id: &[0x03],
        props: &[0],
        streams: 1,
        unpack_size: data.len() as u64,
    };
    let archive = hand_made(&[&packed], &[coder], &[], &[0], crc);
    check_reads(&archive, &data, "delta alone");
    assert_ne!(ask_tool(&archive, "delta alone"), Some(false));
}

/// A stream with more input than it reads, or more output than the header
/// says, is an error here as in `7zz t`, though the data may be right.
#[test]
fn what_is_left_over_is_an_error() {
    let mut rng = Rng(0x5eed_7a14);
    let data = input(&mut rng, 100_000);
    let crc = hivepack_deflate::crc32(0, &data);
    let half_crc = hivepack_deflate::crc32(0, &data[..50_000]);
    let packed = deflated(&data);
    let coder = |id, unpack_size| Coder {
        id,
        props: &[],
        streams: 1,
        unpack_size,
    };
    let deflate = &[0x04, 0x01, 0x08][..];
    let size = data.len() as u64;

    let good = hand_made(&[&packed], &[coder(deflate, size)], &[], &[0], crc);
    check_reads(&good, &data, "deflate");
    assert_ne!(ask_tool(&good, "deflate"), Some(false));

    let mut more = packed.clone();
    more.extend_from_slice(b"more");
    let cases = [
        (
            "input left over",
            hand_made(&[&more], &[coder(deflate, size)], &[], &[0], crc),
        ),
        (
            "output left over",
            hand_made(&[&packed], &[coder(deflate, 50_000)], &[], &[0], half_crc),
        ),
        (
            "copy left over",
            hand_made(&[&data], &[coder(&[0x00], 50_000)], &[], &[0], half_crc),
        ),
    ];
    for (what, archive) in &cases {
        check_fails(archive, what);
        assert_ne!(ask_tool(archive, what), Some(true), "{what}");
    }
}

#[test]
fn loops_of_coders_are_refused() {
    // Coder 1 reads coder 2 and coder 2 coder 1; coder 0 reads a packed stream
    // and is the folder's output.
    let coder = |unpack_size| Coder {
        id: &[0x00],
        props: &[],
        streams: 1,
        unpack_size,
    };
    let archive = hand_made(
        &[&[0; 4]],
        &[coder(4), coder(4), coder(4)],
        &[(1, 2), (2, 1)],
        &[0],
        0,
    );
    if let Ok(mut a) = Archive::open(Cursor::new(&archive)) {
        assert!(a.extract(0).is_err());
    }
}
