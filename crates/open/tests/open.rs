//! Opening files through their layers, made by the reference libraries:
//! each compressor alone, stacked, with several streams one after the
//! other, cut short or followed by other data, past the limits, and read a
//! byte at a time; then a tar archive under them extracted through the
//! opener.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::io::{self, Cursor, Read};

use hivepack_open::{Container, DecodeError, Error, Layer, Limits, Opener};
use support::{Scratch, bzip2, gzip, lz4, lz4_legacy, lzip, lzma, sample_tar, xz, xz_preset, zstd};

/// A reference library's compressor.
type Compress = fn(&[u8]) -> Vec<u8>;

/// What `file` opens to: its layers, container and data.
fn open_named(file: &[u8], name: Option<&str>) -> Result<(Vec<Layer>, Container, Vec<u8>), Error> {
    let mut opener = Opener::new(|| Ok(Cursor::new(file.to_vec())));
    if let Some(name) = name {
        opener = opener.name(name);
    }
    let mut opened = opener.open()?;
    let mut data = Vec::new();
    opened.read_to_end(&mut data)?;
    Ok((opened.layers().to_vec(), opened.container(), data))
}

fn open(file: &[u8]) -> Result<(Vec<Layer>, Container, Vec<u8>), Error> {
    open_named(file, None)
}

/// The layer a read failed in.
fn failed_layer(result: Result<(Vec<Layer>, Container, Vec<u8>), Error>) -> Layer {
    match result {
        Err(Error::Io(e)) => {
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
            e.get_ref()
                .and_then(|inner| inner.downcast_ref::<DecodeError>())
                .unwrap_or_else(|| panic!("not a DecodeError: {e}"))
                .layer
        }
        other => panic!("not a decoding error: {other:?}"),
    }
}

#[test]
fn each_layer_comes_off() {
    let tar = sample_tar();
    let cases: [(Layer, Compress); 7] = [
        (Layer::Zstd, zstd),
        (Layer::Xz, xz),
        (Layer::Lzip, lzip),
        (Layer::Lz4, lz4),
        (Layer::Lz4, lz4_legacy),
        (Layer::Gzip, gzip),
        (Layer::Bzip2, bzip2),
    ];
    for (layer, compress) in cases {
        let (layers, container, data) = open(&compress(&tar)).unwrap();
        assert_eq!(layers, [layer]);
        assert_eq!(container, Container::Tar, "{layer:?}");
        assert!(data == tar, "{layer:?}");
    }
    // The tar archive as it is.
    assert_eq!(open(&tar).unwrap(), (vec![], Container::Tar, tar));
}

#[test]
fn lzma_is_told_by_its_name() {
    let tar = sample_tar();
    let file = lzma(&tar);
    let (layers, container, data) = open_named(&file, Some("backup.tar.LZMA")).unwrap();
    assert_eq!((layers, container), (vec![Layer::Lzma], Container::Tar));
    assert!(data == tar);
    // Without its name, it is data.
    assert_eq!(
        open(&file).unwrap(),
        (vec![], Container::Data, file.clone())
    );
    // Under another layer, the name is the one without its extension.
    let (layers, _, data) = open_named(&gzip(&file), Some("backup.tar.lzma.gz")).unwrap();
    assert_eq!(layers, [Layer::Gzip, Layer::Lzma]);
    assert!(data == tar);
}

#[test]
fn layers_stack() {
    let tar = sample_tar();
    let file = gzip(&bzip2(&xz(&zstd(&tar))));
    let (layers, container, data) = open(&file).unwrap();
    assert_eq!(layers, [Layer::Gzip, Layer::Bzip2, Layer::Xz, Layer::Zstd]);
    assert_eq!(container, Container::Tar);
    assert!(data == tar);
    let (layers, _, data) = open(&lz4(&gzip(&lz4_legacy(&tar)))).unwrap();
    assert_eq!(layers, [Layer::Lz4, Layer::Gzip, Layer::Lz4]);
    assert!(data == tar);
}

#[test]
fn other_contents() {
    // One file, compressed.
    let text = b"Just some notes, not an archive.\n".repeat(50);
    assert_eq!(
        open(&zstd(&text)).unwrap(),
        (vec![Layer::Zstd], Container::Data, text.clone())
    );
    // A ZIP archive, compressed: the caller takes it out to a file.
    let mut zip = b"PK\x03\x04".to_vec();
    zip.extend([0; 100]);
    assert_eq!(
        open(&xz(&zip)).unwrap(),
        (vec![Layer::Xz], Container::Zip, zip.clone())
    );
    // Nothing at all.
    assert_eq!(open(b"").unwrap(), (vec![], Container::Data, vec![]));
    assert_eq!(
        open(&gzip(b"")).unwrap(),
        (vec![Layer::Gzip], Container::Data, vec![])
    );
}

/// An ISO 9660 image, as libarchive's tests have it (xz-compressed in
/// `testdata/libarchive-iso`): ISO 9660 in a layer, read in order.
#[test]
fn an_iso_image_under_layers_reads() {
    let path =
        support::repository().join("testdata/libarchive-iso/test_read_format_iso_joliet.iso.xz");
    let file = std::fs::read(path).unwrap();
    let (layers, container, image) = open(&file).unwrap();
    assert_eq!((layers, container), (vec![Layer::Xz], Container::Iso));
    for compressed in [gzip(&image), zstd(&image)] {
        let (_, container, data) = open(&compressed).unwrap();
        assert_eq!((container, data.len()), (Container::Iso, image.len()));
    }
    assert_eq!(open(&image).unwrap().1, Container::Iso);
    // What hivepack-iso reads through the layer is what it reads of the
    // image itself.
    let entries = |r: Box<dyn Read + Send + '_>| {
        let mut iso = hivepack_iso::Reader::new(r);
        let mut out = Vec::new();
        while let Some(h) = iso.next().unwrap() {
            let mut data = Vec::new();
            iso.read_to_end(&mut data).unwrap();
            out.push((h, data));
        }
        out
    };
    let mut opener = Opener::new(|| Ok(Cursor::new(file.clone())));
    let through_layer = entries(Box::new(opener.open().unwrap()));
    assert_eq!(through_layer, entries(Box::new(Cursor::new(image))));
    let names: Vec<_> = through_layer
        .iter()
        .filter_map(|(h, _)| h.path.clone())
        .collect();
    assert!(
        names.contains(&b"long-joliet-file-name.textfile".to_vec()),
        "{names:?}"
    );
}

/// Data looked into for an ISO 9660 image, cut short in what is looked
/// at: it opens, and the error comes after the data before it, as without
/// the look.
#[test]
fn data_cut_short_where_an_iso_image_is_looked_for() {
    // Random bytes, which do not compress: half the stream is half of them.
    let mut x = 0x9e37_79b9u32;
    let text: Vec<u8> = (0..20_000)
        .map(|_| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (x >> 24) as u8
        })
        .collect();
    let file = gzip(&text);
    let cut = &file[..file.len() / 2];
    let mut opener = Opener::new(|| Ok(Cursor::new(cut.to_vec())));
    let mut opened = opener.open().unwrap();
    assert_eq!(opened.container(), Container::Data);
    let mut data = Vec::new();
    let error = opened.read_to_end(&mut data).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
    assert!(
        data.len() > 1570 && text.starts_with(&data),
        "{}",
        data.len()
    );
}

#[test]
fn streams_one_after_another() {
    let tar = sample_tar();
    let (a, b) = tar.split_at(30_000);
    // zstd frames, a skippable one between them.
    let mut file = zstd(a);
    file.extend([0x5E, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 1, 2, 3]);
    file.extend(zstd(b));
    assert_eq!(
        open(&file).unwrap(),
        (vec![Layer::Zstd], Container::Tar, tar.clone())
    );
    // A file that starts with a skippable frame.
    let mut file = vec![0x50, 0x2A, 0x4D, 0x18, 0, 0, 0, 0];
    file.extend(zstd(&tar));
    assert_eq!(
        open(&file).unwrap(),
        (vec![Layer::Zstd], Container::Tar, tar.clone())
    );
    // gzip members and bzip2 streams, zeros after them as tar's blocking
    // leaves them.
    for (layer, compress) in [(Layer::Gzip, gzip as Compress), (Layer::Bzip2, bzip2)] {
        let mut file = compress(a);
        file.extend(compress(b));
        file.extend([0; 3000]);
        assert_eq!(
            open(&file).unwrap(),
            (vec![layer], Container::Tar, tar.clone()),
            "{layer:?}"
        );
    }
    // LZ4 frames, a skippable one first and between them: the frame after
    // it tells LZ4 from zstd.
    let mut file = vec![0x50, 0x2A, 0x4D, 0x18, 2, 0, 0, 0, 7, 7];
    file.extend(lz4(a));
    file.extend([0x5A, 0x2A, 0x4D, 0x18, 0, 0, 0, 0]);
    file.extend(lz4(b));
    assert_eq!(
        open(&file).unwrap(),
        (vec![Layer::Lz4], Container::Tar, tar.clone())
    );
    // xz streams, Stream Padding between and after them.
    let mut file = xz(a);
    file.extend([0; 8]);
    file.extend(xz(b));
    file.extend([0; 4]);
    assert_eq!(
        open(&file).unwrap(),
        (vec![Layer::Xz], Container::Tar, tar.clone())
    );
    // lzip members, and what follows them, which lzip and xz ignore.
    let mut file = lzip(a);
    file.extend(lzip(b));
    assert_eq!(
        open(&file).unwrap(),
        (vec![Layer::Lzip], Container::Tar, tar.clone())
    );
    file.extend(b"\0\0\0\0appended after the last member");
    assert_eq!(
        open(&file).unwrap(),
        (vec![Layer::Lzip], Container::Tar, tar.clone())
    );
    // It is read to its end: a layer around it is checked to its end.
    let mut outer = gzip(&file);
    outer.truncate(outer.len() - 4);
    assert_eq!(failed_layer(open(&outer)), Layer::Gzip);
}

#[test]
fn other_data_after_the_streams_fails() {
    let tar = sample_tar();
    let cases: [(Layer, Compress); 5] = [
        (Layer::Zstd, zstd),
        (Layer::Xz, xz),
        (Layer::Lz4, lz4),
        (Layer::Gzip, gzip),
        (Layer::Bzip2, bzip2),
    ];
    for (layer, compress) in cases {
        let mut file = compress(&tar);
        file.extend(b"\0\0\0\0junk after the end");
        assert_eq!(failed_layer(open(&file)), layer);
    }
}

#[test]
fn a_stream_cut_short_fails() {
    let tar = sample_tar();
    let cases: [(Layer, Compress); 8] = [
        (Layer::Zstd, zstd),
        (Layer::Xz, xz),
        (Layer::Lzip, lzip),
        (Layer::Lz4, lz4),
        (Layer::Lz4, lz4_legacy),
        (Layer::Gzip, gzip),
        (Layer::Bzip2, bzip2),
        (Layer::Lzma, lzma),
    ];
    for (layer, compress) in cases {
        let file = compress(&tar);
        for cut in [1, 4, file.len() / 2] {
            let result = open_named(&file[..file.len() - cut], Some("x.lzma"));
            assert_eq!(failed_layer(result), layer, "{layer:?} without {cut} bytes");
        }
    }
    // Under another layer, the inner one fails.
    let inner = zstd(&tar);
    assert_eq!(
        failed_layer(open(&gzip(&inner[..inner.len() - 3]))),
        Layer::Zstd
    );
    // The outer one's error comes through LZ4's reader as it is.
    let outer = gzip(&lz4(&tar));
    assert_eq!(failed_layer(open(&outer[..outer.len() - 3])), Layer::Gzip);
}

#[test]
fn damaged_data_fails() {
    let tar = sample_tar();
    let mut file = bzip2(&tar);
    let middle = file.len() / 2;
    file[middle] ^= 0x55;
    assert_eq!(failed_layer(open(&file)), Layer::Bzip2);
    let mut file = gzip(&tar);
    let end = file.len() - 6;
    file[end] ^= 1;
    assert_eq!(failed_layer(open(&file)), Layer::Gzip);
}

/// The data and how reading ended, in pieces of `size`.
fn read_in(file: &[u8], name: &str, size: usize) -> (Vec<u8>, String) {
    let mut opener = Opener::new(|| Ok(Cursor::new(file))).name(name);
    let mut opened = match opener.open() {
        Ok(opened) => opened,
        Err(e) => return (Vec::new(), e.to_string()),
    };
    let mut data = Vec::new();
    let mut buf = vec![0; size];
    loop {
        match opened.read(&mut buf) {
            Ok(0) => return (data, "end".into()),
            Ok(n) => data.extend_from_slice(&buf[..n]),
            Err(e) => return (data, e.to_string()),
        }
    }
}

#[test]
fn what_comes_before_an_error_is_given_out() {
    // The bytes a decoder produced in the call that failed are read before
    // its error, so that what is read does not depend on the size of the
    // reads (the fuzz target found it with a .lzma file).
    let tar = sample_tar();
    let cases: [(Layer, Compress); 6] = [
        (Layer::Xz, xz),
        (Layer::Lzip, lzip),
        (Layer::Lzma, lzma),
        (Layer::Lz4, lz4),
        (Layer::Gzip, gzip),
        (Layer::Bzip2, bzip2),
    ];
    for (layer, compress) in cases {
        let mut file = compress(&tar);
        let at = file.len() * 2 / 3;
        file[at] ^= 0x10;
        let small = read_in(&file, "x.lzma", 1);
        assert_ne!(small.1, "end", "{layer:?}");
        assert!(!small.0.is_empty(), "{layer:?}");
        assert_eq!(read_in(&file, "x.lzma", 64 << 10), small, "{layer:?}");
        assert_eq!(read_in(&file, "x.lzma", 1000), small, "{layer:?}");
    }
}

#[test]
fn small_reads() {
    let tar = sample_tar();
    let file = xz(&gzip(&bzip2(&tar)));
    let mut opener = Opener::new(|| Ok(Cursor::new(&file[..])));
    let mut opened = opener.open().unwrap();
    let mut data = Vec::new();
    let mut byte = [0u8; 1];
    while opened.read(&mut byte).unwrap() == 1 {
        data.push(byte[0]);
    }
    assert!(data == tar);
    // A read into nothing reads nothing.
    assert_eq!(opened.read(&mut []).unwrap(), 0);
}

/// A reader that gives a byte at a time, and is interrupted between.
struct Trickle<'a>(&'a [u8], bool);

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.1 = !self.1;
        if self.1 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let Some((&first, rest)) = self.0.split_first() else {
            return Ok(0);
        };
        if buf.is_empty() {
            return Ok(0);
        }
        buf[0] = first;
        self.0 = rest;
        Ok(1)
    }
}

#[test]
fn input_a_byte_at_a_time() {
    let tar = sample_tar();
    for file in [
        zstd(&tar),
        xz(&tar),
        gzip(&bzip2(&tar)),
        lzip(&tar),
        lz4(&tar),
        lz4_legacy(&tar),
    ] {
        let mut opener = Opener::new(|| Ok(Trickle(&file, false)));
        let mut opened = opener.open().unwrap();
        let mut data = Vec::new();
        opened.read_to_end(&mut data).unwrap();
        assert!(data == tar);
    }
}

#[test]
fn layers_are_limited() {
    let tar = sample_tar();
    let mut file = tar.clone();
    for _ in 0..9 {
        file = gzip(&file);
    }
    assert!(matches!(open(&file), Err(Error::TooManyLayers(8))));
    let mut limits = Limits::default();
    limits.max_layers = 9;
    let mut opener = Opener::new(|| Ok(Cursor::new(&file[..]))).limits(limits);
    let mut data = Vec::new();
    opener.open().unwrap().read_to_end(&mut data).unwrap();
    assert!(data == tar);
}

#[test]
fn decoders_memory_is_limited() {
    let tar = sample_tar();
    // A 128 MiB window is allowed, and a larger one is not: libzstd's own
    // limit.
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), 1).unwrap();
    encoder.window_log(28).unwrap();
    io::copy(&mut &tar[..], &mut encoder).unwrap();
    let file = encoder.finish().unwrap();
    assert_eq!(failed_layer(open(&file)), Layer::Zstd);
    let mut limits = Limits::default();
    limits.zstd_window_log_max = 28;
    let mut opener = Opener::new(|| Ok(Cursor::new(&file[..]))).limits(limits);
    let mut data = Vec::new();
    opener.open().unwrap().read_to_end(&mut data).unwrap();
    assert!(data == tar);
    // xz -9's 64 MiB dictionary, past a limit of 16 MiB.
    let file = xz_preset(&tar, 9);
    let mut limits = Limits::default();
    limits.xz_memlimit = 16 << 20;
    let mut opener = Opener::new(|| Ok(Cursor::new(&file[..]))).limits(limits);
    // Its first bytes are needed to tell what is under it.
    let result = opener
        .open()
        .map(|o| (o.layers().to_vec(), o.container(), vec![]));
    assert_eq!(failed_layer(result), Layer::Xz);
    assert!(open(&file).is_ok());
}

#[test]
fn an_error_stays() {
    let tar = sample_tar();
    // The first frame tells what is under it; the second is cut short.
    let (a, b) = tar.split_at(10_240);
    let mut file = zstd(a);
    let second = zstd(b);
    file.extend(&second[..second.len() / 2]);
    let mut opener = Opener::new(|| Ok(Cursor::new(&file[..])));
    let mut opened = opener.open().unwrap();
    let mut data = Vec::new();
    let first = opened.read_to_end(&mut data).unwrap_err().to_string();
    let again = opened.read(&mut [0; 100]).unwrap_err().to_string();
    assert_eq!(first, again);
}

#[test]
fn a_file_that_changed_fails() {
    let tar = sample_tar();
    let files = [zstd(&tar), gzip(&tar)];
    let mut next = 0;
    let mut opener = Opener::new(|| {
        next += 1;
        Ok(Cursor::new(files[(next - 1).min(1)].clone()))
    });
    opener.open().unwrap();
    assert!(matches!(opener.open(), Err(Error::Changed)));
}

#[test]
fn opening_fails_as_the_file_does() {
    let mut opener =
        Opener::new(|| -> io::Result<Cursor<Vec<u8>>> { Err(io::ErrorKind::NotFound.into()) });
    match opener.open() {
        Err(Error::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_tar_archive_under_layers_extracts() {
    let tar = sample_tar();
    let file = xz(&zstd(&tar));
    let scratch = Scratch::new();
    let path = scratch.path().join("backup.tar.zst.xz");
    std::fs::write(&path, &file).unwrap();
    let mut opener = Opener::new(|| std::fs::File::open(&path)).name("backup.tar.zst.xz");
    assert_eq!(opener.open().unwrap().container(), Container::Tar);
    let out = scratch.path().join("out");
    let summary = hivepack_extract::extract_tar(
        || Ok(opener.open()?),
        &out,
        &hivepack_extract::Options::default(),
    )
    .unwrap();
    assert_eq!(summary.files, 2);
    assert_eq!(
        std::fs::read(out.join("docs/notes.txt")).unwrap(),
        b"Hello from inside the layers.\n"
    );
    assert_eq!(
        std::fs::read(out.join("docs/data.bin")).unwrap().len(),
        100_000
    );
}

/// libarchive's Rock Ridge and Joliet image, xz-compressed in
/// `testdata`, extracted through its layer.
#[test]
fn an_iso_image_under_layers_extracts() {
    let path = support::repository()
        .join("testdata/libarchive-iso/test_read_format_iso_joliet_rockridge.iso.xz");
    let mut opener = Opener::new(|| std::fs::File::open(&path)).name("disc.iso.xz");
    assert_eq!(opener.open().unwrap().container(), Container::Iso);
    let scratch = Scratch::new();
    let out = scratch.path().join("out");
    let mut options = hivepack_extract::Options::default();
    options.links = hivepack_extract::Links::AsFile;
    let summary = hivepack_extract::extract_iso(|| Ok(opener.open()?), &out, &options).unwrap();
    assert_eq!((summary.files, summary.directories), (3, 1));
    // The hard link's file and its copy hold the same data, and the
    // symbolic link its target.
    let file = std::fs::read(out.join("long-joliet-file-name.textfile")).unwrap();
    assert_eq!(std::fs::read(out.join("hardlink")).unwrap(), file);
    assert_eq!(
        std::fs::read(out.join("symlink")).unwrap(),
        b"long-joliet-file-name.textfile"
    );
}

#[test]
fn a_damaged_stream_stops_before_anything_is_written() {
    // gzip's stored blocks hold the data as it is: only the CRC-32 at the
    // end tells a byte changed, after the tar archive's end, which
    // extract_tar reads before it writes.
    let tar = sample_tar();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::none());
    io::Write::write_all(&mut encoder, &tar).unwrap();
    let mut file = encoder.finish().unwrap();
    let at = file
        .windows(5)
        .position(|w| w == b"Hello")
        .expect("the data as it is");
    file[at] = b'J';
    let scratch = Scratch::new();
    let out = scratch.path().join("out");
    let mut opener = Opener::new(|| Ok(Cursor::new(&file[..])));
    let e = hivepack_extract::extract_tar(
        || Ok(opener.open()?),
        &out,
        &hivepack_extract::Options::default(),
    )
    .unwrap_err();
    match e.kind {
        hivepack_extract::ErrorKind::Io(e) => {
            let inner = e.get_ref().unwrap().downcast_ref::<DecodeError>().unwrap();
            assert_eq!(inner.layer, Layer::Gzip);
            assert_eq!(inner.message, "incorrect data check");
        }
        other => panic!("{other:?}"),
    }
    assert!(!out.exists());
}
