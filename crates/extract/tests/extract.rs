//! Extracting archives made to attack extractors: names that climb out of
//! the destination, the same path twice, links in the archive and on disk,
//! files already there, archive bombs past the limits or sharing their
//! data, and data that fails its check. Each must stop with its reason,
//! and leave nothing outside the destination.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use hivepack_extract::{ErrorKind, Limits, NameError, Options, Summary, extract_zip};
use hivepack_zip::{Archive, BufferSource, Flags, OpenFlags, cm, em, opsys};

/// The time the test entries have, an even number of seconds as MS-DOS
/// times are.
const MTIME: i64 = 1_600_000_000;

/// An entry of a test archive.
enum Entry<'a> {
    File(&'a [u8], &'a [u8]),
    /// A file with Unix mode bits, type included.
    Mode(&'a [u8], &'a [u8], u32),
    Dir(&'a [u8]),
    Stored(&'a [u8], &'a [u8]),
}

/// An archive of `entries`, written by hivepack-zip.
fn zip(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut za = Archive::open(&[][..], OpenFlags(0)).unwrap();
    for entry in entries {
        match *entry {
            Entry::File(name, data) => {
                za.file_add(name, BufferSource::with_mtime(data, MTIME), Flags::NONE)
                    .unwrap();
            }
            Entry::Mode(name, data, mode) => {
                let i = za
                    .file_add(name, BufferSource::with_mtime(data, MTIME), Flags::NONE)
                    .unwrap();
                za.file_set_external_attributes(i, Flags::NONE, opsys::UNIX, mode << 16)
                    .unwrap();
            }
            Entry::Dir(name) => {
                za.dir_add(name, Flags::NONE).unwrap();
            }
            Entry::Stored(name, data) => {
                let i = za
                    .file_add(name, BufferSource::with_mtime(data, MTIME), Flags::NONE)
                    .unwrap();
                za.set_file_compression(i, i32::from(cm::STORE), 0).unwrap();
            }
        }
    }
    let mut out = Cursor::new(Vec::new());
    za.close_to(&mut out).unwrap();
    out.into_inner()
}

/// A fresh folder for a test, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "hivepack-extract-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Scratch(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// The destination inside it, not created yet.
    fn out(&self) -> PathBuf {
        self.0.join("out")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn extract(data: &[u8], out: &Path, options: &Options) -> Result<Summary, hivepack_extract::Error> {
    let archive = Archive::open(data, OpenFlags::CHECKCONS).unwrap();
    extract_zip(&archive, out, options)
}

/// The paths under `dir`, sorted, with `/` after directories.
fn listing(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            let relative = path
                .strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if path.symlink_metadata().unwrap().is_dir() {
                found.push(format!("{relative}/"));
                stack.push(path);
            } else {
                found.push(relative);
            }
        }
    }
    found.sort();
    found
}

#[test]
fn extracts_files_and_directories() {
    let scratch = Scratch::new();
    let data = zip(&[
        Entry::File(b"a.txt", b"hello"),
        Entry::Dir(b"dir/"),
        Entry::File(b"dir/b.txt", b"world"),
        Entry::Stored("dir/sub/naïve.bin".as_bytes(), &[0, 1, 2, 3]),
        Entry::File(b"empty", b""),
    ]);
    let summary = extract(&data, &scratch.out(), &Options::default()).unwrap();
    assert_eq!(
        (summary.files, summary.directories, summary.bytes),
        (4, 1, 14)
    );
    assert_eq!(
        listing(&scratch.out()),
        [
            "a.txt",
            "dir/",
            "dir/b.txt",
            "dir/sub/",
            "dir/sub/naïve.bin",
            "empty"
        ]
    );
    assert_eq!(
        std::fs::read(scratch.out().join("a.txt")).unwrap(),
        b"hello"
    );
    assert_eq!(
        std::fs::read(scratch.out().join("dir/sub/naïve.bin")).unwrap(),
        [0, 1, 2, 3]
    );
    let modified = std::fs::metadata(scratch.out().join("dir/b.txt"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(
        modified
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        MTIME as u64
    );
}

#[cfg(unix)]
#[test]
fn unix_permissions_are_masked() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new();
    let data = zip(&[
        Entry::Mode(b"setuid", b"x", 0o104_777),
        Entry::Mode(b"private", b"x", 0o100_600),
        Entry::Mode(b"read-only", b"x", 0o100_444),
        Entry::Mode(b"script", b"x", 0o100_775),
    ]);
    extract(&data, &scratch.out(), &Options::default()).unwrap();
    for (name, mode) in [
        ("setuid", 0o755),
        ("private", 0o600),
        ("read-only", 0o644),
        ("script", 0o755),
    ] {
        let metadata = std::fs::metadata(scratch.out().join(name)).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, mode, "{name}");
    }
}

#[test]
fn refused_names_write_nothing() {
    let cases: &[(&[u8], NameError)] = &[
        (b"../evil", NameError::Dot),
        (b"a/../../evil", NameError::Dot),
        (b"/tmp/evil", NameError::Absolute),
        (b"a\\..\\evil", NameError::Backslash),
        (b"C:evil", NameError::Colon),
        (b"a.txt:hidden", NameError::Colon),
        (b"CON", NameError::Device),
        (b"dir/nul.txt", NameError::Device),
        (b"evil./x", NameError::TrailingSpaceOrDot),
        (b"a//b", NameError::Empty),
        (b"a\x01b", NameError::Control),
    ];
    for &(name, reason) in cases {
        let scratch = Scratch::new();
        let data = zip(&[Entry::File(b"good.txt", b"ok"), Entry::File(name, b"evil")]);
        let shown = String::from_utf8_lossy(name);
        let Err(error) = extract(&data, &scratch.out(), &Options::default()) else {
            panic!("{shown:?} extracted: {:?}", listing(&scratch.out()));
        };
        assert!(
            matches!(error.kind, ErrorKind::Name(r) if r == reason),
            "{shown}: {error}"
        );
        assert_eq!(error.index, Some(1), "{shown}");
        assert_eq!(error.name.as_deref(), Some(name), "{shown}");
        // Checked before anything is written, the destination too.
        assert!(listing(scratch.path()).is_empty(), "{shown}");
    }
}

#[test]
fn the_same_path_twice_is_refused() {
    let cases: &[&[Entry<'_>]] = &[
        &[Entry::File(b"A.txt", b"1"), Entry::File(b"a.txt", b"2")],
        &[Entry::File(b"dir/x", b"1"), Entry::File(b"DIR/y", b"2")],
        &[Entry::File(b"a", b"1"), Entry::File(b"a/b", b"2")],
        &[Entry::File(b"a/b", b"1"), Entry::File(b"a", b"2")],
        &[Entry::Dir(b"d/"), Entry::File(b"D", b"2")],
        &[
            Entry::File("É".as_bytes(), b"1"),
            Entry::File("é".as_bytes(), b"2"),
        ],
    ];
    for entries in cases {
        let scratch = Scratch::new();
        let error = extract(&zip(entries), &scratch.out(), &Options::default()).unwrap_err();
        assert!(
            matches!(error.kind, ErrorKind::Duplicate { first: 0 }),
            "{error}"
        );
        assert!(listing(&scratch.out()).is_empty());
    }
    // A directory entry after the files in it is fine.
    let scratch = Scratch::new();
    let data = zip(&[Entry::File(b"d/x", b"1"), Entry::Dir(b"d/")]);
    extract(&data, &scratch.out(), &Options::default()).unwrap();
    assert_eq!(listing(&scratch.out()), ["d/", "d/x"]);
}

#[test]
fn links_and_special_files_are_not_created() {
    for (mode, kind) in [
        (0o120_777, "link"),
        (0o010_644, "fifo"),
        (0o020_644, "device"),
    ] {
        let scratch = Scratch::new();
        let data = zip(&[Entry::Mode(b"x", b"/etc/passwd", mode)]);
        let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
        match kind {
            "link" => assert!(matches!(error.kind, ErrorKind::Link), "{error}"),
            _ => assert!(matches!(error.kind, ErrorKind::SpecialFile), "{error}"),
        }
        assert!(listing(&scratch.out()).is_empty());
    }
}

/// A link already in the destination is not followed, as a directory on
/// the way or as the file itself.
#[cfg(unix)]
#[test]
fn links_in_the_destination_are_not_followed() {
    let scratch = Scratch::new();
    let outside = scratch.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("victim"), b"untouched").unwrap();
    std::fs::create_dir(scratch.out()).unwrap();
    std::os::unix::fs::symlink(&outside, scratch.out().join("link")).unwrap();
    std::os::unix::fs::symlink(outside.join("victim"), scratch.out().join("victim")).unwrap();

    let data = zip(&[Entry::File(b"link/evil", b"evil")]);
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::NotADirectory), "{error}");

    let data = zip(&[Entry::File(b"victim", b"evil")]);
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Exists), "{error}");

    assert_eq!(listing(&outside), ["victim"]);
    assert_eq!(std::fs::read(outside.join("victim")).unwrap(), b"untouched");
}

#[test]
fn nothing_is_overwritten() {
    let scratch = Scratch::new();
    std::fs::create_dir_all(scratch.out().join("dir")).unwrap();
    std::fs::write(scratch.out().join("dir/a.txt"), b"mine").unwrap();
    let data = zip(&[Entry::File(b"dir/a.txt", b"theirs")]);
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Exists), "{error}");
    assert_eq!(
        std::fs::read(scratch.out().join("dir/a.txt")).unwrap(),
        b"mine"
    );
    // A file where a directory is to be.
    let data = zip(&[Entry::File(b"dir/a.txt/b", b"theirs")]);
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::NotADirectory), "{error}");
}

fn limits(change: impl FnOnce(&mut Limits)) -> Options {
    let mut options = Options::default();
    change(&mut options.limits);
    options
}

#[test]
fn limits_stop_archive_bombs() {
    let three = zip(&[
        Entry::File(b"a", &[1; 10]),
        Entry::File(b"b", &[2; 10]),
        Entry::File(b"c", &[3; 10]),
    ]);
    type Expected = fn(&ErrorKind) -> bool;
    let cases: Vec<(Options, Expected)> = vec![
        (limits(|l| l.max_entries = 2), |k| {
            matches!(k, ErrorKind::TooManyEntries)
        }),
        (limits(|l| l.max_entry_size = 9), |k| {
            matches!(k, ErrorKind::EntryTooLarge)
        }),
        (limits(|l| l.max_total_size = 25), |k| {
            matches!(k, ErrorKind::TotalTooLarge)
        }),
    ];
    for (options, expected) in cases {
        let scratch = Scratch::new();
        let error = extract(&three, &scratch.out(), &options).unwrap_err();
        assert!(expected(&error.kind), "{error}");
        // What the archive says is checked before anything is written.
        assert!(listing(&scratch.out()).is_empty(), "{error}");
    }

    // Two MiB of zeros, deflated to about two KiB.
    let zeros = vec![0u8; 2 << 20];
    let data = zip(&[Entry::File(b"ok", b"fine"), Entry::File(b"bomb", &zeros)]);
    let scratch = Scratch::new();
    let options = limits(|l| l.max_ratio = 100);
    let error = extract(&data, &scratch.out(), &options).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Ratio), "{error}");
    // The file cut off is removed; the one before stays.
    assert_eq!(listing(&scratch.out()), ["ok"]);
    let scratch = Scratch::new();
    extract(&data, &scratch.out(), &Options::default()).unwrap();
}

/// The central directory entry at `index`, and where it starts.
fn central_entries(data: &[u8]) -> Vec<(usize, usize)> {
    let eocd = data.len() - 22;
    assert_eq!(&data[eocd..eocd + 4], b"PK\x05\x06");
    let count = u16::from_le_bytes([data[eocd + 10], data[eocd + 11]]) as usize;
    let mut at = u32::from_le_bytes(data[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    let mut entries = Vec::new();
    for _ in 0..count {
        let len = |o: usize| u16::from_le_bytes([data[at + o], data[at + o + 1]]) as usize;
        let size = 46 + len(28) + len(30) + len(32);
        entries.push((at, size));
        at += size;
    }
    entries
}

/// Two central directory entries for the same data, as Fifield's
/// overlapping bombs have: refused before anything is written.
#[test]
fn entries_that_share_data_are_refused() {
    let data = zip(&[Entry::File(b"a", &[7; 1000])]);
    let (start, size) = central_entries(&data)[0];
    let mut copy = data[start..start + size].to_vec();
    // The same entry, named "b".
    let name = 46;
    copy[name] = b'b';
    let eocd = data.len() - 22;
    let mut bomb = data[..eocd].to_vec();
    bomb.extend_from_slice(&copy);
    let mut end = data[eocd..].to_vec();
    for o in [8, 10] {
        end[o] = 2;
    }
    let cd_size = u32::from_le_bytes(end[12..16].try_into().unwrap()) + size as u32;
    end[12..16].copy_from_slice(&cd_size.to_le_bytes());
    bomb.extend_from_slice(&end);

    let scratch = Scratch::new();
    // Not with ZIP_CHECKCONS, which refuses the local header named "a" for
    // the entry "b" already.
    let archive = Archive::open(bomb.as_slice(), OpenFlags(0)).unwrap();
    let error = extract_zip(&archive, &scratch.out(), &Options::default()).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::Overlap { other: 0 }),
        "{error}"
    );
    assert_eq!(error.index, Some(1));
    assert!(listing(&scratch.out()).is_empty());
}

/// Patches the uncompressed size of the entry at `index`, in its local
/// header and in the central directory.
fn patch_size(data: &mut [u8], index: usize, size: u32) {
    let (central, _) = central_entries(data)[index];
    data[central + 24..central + 28].copy_from_slice(&size.to_le_bytes());
    let local = u32::from_le_bytes(data[central + 42..central + 46].try_into().unwrap()) as usize;
    data[local + 22..local + 26].copy_from_slice(&size.to_le_bytes());
}

#[test]
fn data_that_fails_is_removed() {
    // A byte of stored data changed: its CRC-32 fails.
    let mut data = zip(&[
        Entry::File(b"first", b"fine"),
        Entry::Stored(b"second", b"0123456789"),
    ]);
    let at = data.windows(10).position(|w| w == b"0123456789").unwrap();
    data[at + 4] ^= 1;
    let scratch = Scratch::new();
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(
        matches!(&error.kind, ErrorKind::Archive(e) if e.code() == hivepack_zip::ErrorCode::Crc),
        "{error}"
    );
    assert_eq!(listing(&scratch.out()), ["first"]);

    // More data than the archive says: cut off where it passes the size.
    let mut data = zip(&[Entry::File(b"big", &[5; 100_000])]);
    patch_size(&mut data, 0, 1000);
    let scratch = Scratch::new();
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::SizeMismatch), "{error}");
    assert!(listing(&scratch.out()).is_empty());
}

#[test]
fn encrypted_entries_need_their_password() {
    let mut za = Archive::open(&[][..], OpenFlags(0)).unwrap();
    za.set_random_source(Some(std::sync::Arc::new(|buffer: &mut [u8]| {
        buffer.fill(7);
        Ok(())
    })));
    for (name, method) in [
        (&b"aes"[..], em::AES_256),
        (&b"zipcrypto"[..], em::TRAD_PKWARE),
    ] {
        let i = za
            .file_add(
                name,
                BufferSource::with_mtime(&b"secret"[..], MTIME),
                Flags::NONE,
            )
            .unwrap();
        za.file_set_encryption(i, method, Some(b"password"))
            .unwrap();
    }
    let mut out = Cursor::new(Vec::new());
    za.close_to(&mut out).unwrap();
    let data = out.into_inner();

    let scratch = Scratch::new();
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(
        matches!(&error.kind, ErrorKind::Archive(e) if e.code() == hivepack_zip::ErrorCode::NoPasswd),
        "{error}"
    );
    assert!(listing(&scratch.out()).is_empty());

    let scratch = Scratch::new();
    let mut options = Options::default();
    options.password = Some(b"password".to_vec());
    extract(&data, &scratch.out(), &options).unwrap();
    assert_eq!(std::fs::read(scratch.out().join("aes")).unwrap(), b"secret");
    assert_eq!(
        std::fs::read(scratch.out().join("zipcrypto")).unwrap(),
        b"secret"
    );
}
