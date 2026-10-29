//! Extracting archives made to attack extractors: names that climb out of
//! the destination, the same path twice, links in the archive and on disk,
//! files already there, archive bombs past the limits or sharing their
//! data, and data that fails its check. Each must stop with its reason,
//! and leave nothing outside the destination.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use hivepack_extract::{
    ErrorKind, Limits, Links, NameError, Names, OnRefused, Options, Summary, extract_zip,
};
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
    /// A directory with the test time.
    DirAt(&'a [u8]),
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
            Entry::DirAt(name) => {
                let i = za.dir_add(name, Flags::NONE).unwrap();
                za.file_set_mtime(i, MTIME, Flags::NONE).unwrap();
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
fn links_are_not_created() {
    let scratch = Scratch::new();
    let data = zip(&[Entry::Mode(b"x", b"/etc/passwd", 0o120_777)]);
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Link), "{error}");
    assert!(listing(&scratch.out()).is_empty());
}

/// A FIFO or a device in a ZIP archive is a mode with data, as Info-ZIP's
/// zip writes what it reads from a pipe: written as a file.
#[test]
fn special_files_are_written_as_files() {
    for mode in [0o010_644, 0o020_644, 0o060_644, 0o140_644] {
        let scratch = Scratch::new();
        let data = zip(&[Entry::Mode(b"-", b"from a pipe", mode)]);
        extract(&data, &scratch.out(), &Options::default()).unwrap();
        let path = scratch.out().join("-");
        assert!(
            std::fs::symlink_metadata(&path).unwrap().is_file(),
            "{mode:o}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"from a pipe");
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
    // A directory where a file is to be, which Windows reports as access
    // denied.
    let data = zip(&[Entry::File(b"dir", b"theirs")]);
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Exists), "{error}");
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

fn options(change: impl FnOnce(&mut Options)) -> Options {
    let mut options = Options::default();
    change(&mut options);
    options
}

/// Links whose target stays inside are created, last; the others are
/// refused, here skipped.
#[cfg(unix)]
#[test]
fn links_inside_the_destination_are_created() {
    let scratch = Scratch::new();
    let data = zip(&[
        Entry::Dir(b"lib/"),
        Entry::Mode(b"lib/libfoo.so", b"libfoo.so.1", 0o120_777),
        Entry::File(b"lib/libfoo.so.1", b"elf"),
        Entry::Mode(b"up", b"lib/../lib/libfoo.so.1", 0o120_777),
        Entry::Mode(b"to-dir", b"lib", 0o120_777),
        Entry::Mode(b"escape", b"../outside", 0o120_777),
        Entry::Mode(b"absolute", b"/etc/passwd", 0o120_777),
        Entry::Mode(b"through", b"to-dir/libfoo.so.1", 0o120_777),
    ]);
    let options = options(|o| {
        o.links = Links::Inside;
        o.on_refused = OnRefused::Skip;
    });
    let summary = extract(&data, &scratch.out(), &options).unwrap();
    assert_eq!((summary.files, summary.links), (1, 3));
    let reasons: Vec<_> = summary
        .skipped
        .iter()
        .map(|e| (e.index, format!("{:?}", e.kind)))
        .collect();
    assert_eq!(
        reasons,
        [
            (Some(5), "LinkTarget(Dot)".to_string()),
            (Some(6), "LinkTarget(Absolute)".to_string()),
            (Some(7), "LinkChain { other: 4 }".to_string()),
        ]
    );
    let out = scratch.out();
    assert_eq!(
        std::fs::read_link(out.join("lib/libfoo.so")).unwrap(),
        Path::new("libfoo.so.1")
    );
    assert_eq!(std::fs::read(out.join("up")).unwrap(), b"elf");
    assert_eq!(
        std::fs::read(out.join("to-dir/libfoo.so.1")).unwrap(),
        b"elf"
    );
    assert_eq!(listing(scratch.path()).len(), listing(&out).len() + 1);

    // Stopping, the default: before anything is written.
    let scratch = Scratch::new();
    let options = self::options(|o| o.links = Links::Inside);
    let error = extract(&data, &scratch.out(), &options).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::LinkTarget(NameError::Dot)),
        "{error}"
    );
    assert!(listing(scratch.path()).is_empty());
}

#[test]
fn links_can_be_written_as_files() {
    let scratch = Scratch::new();
    let data = zip(&[Entry::Mode(b"link", b"../../etc/passwd", 0o120_777)]);
    let options = options(|o| o.links = Links::AsFile);
    extract(&data, &scratch.out(), &options).unwrap();
    assert_eq!(
        std::fs::read(scratch.out().join("link")).unwrap(),
        b"../../etc/passwd"
    );
    assert!(
        !std::fs::symlink_metadata(scratch.out().join("link"))
            .unwrap()
            .is_symlink()
    );
}

#[test]
fn names_can_be_cleaned_up() {
    let scratch = Scratch::new();
    let data = zip(&[
        Entry::File(b"/etc/passwd", b"1"),
        Entry::File(b"../../up", b"2"),
        Entry::File(b"C:\\win\\..\\x.txt", b"3"),
        Entry::File(b"a/./b//c", b"4"),
    ]);
    let options = options(|o| {
        o.names = Names::Sanitize;
        o.backslash_separator = true;
    });
    extract(&data, &scratch.out(), &options).unwrap();
    assert_eq!(
        listing(&scratch.out()),
        [
            "a/",
            "a/b/",
            "a/b/c",
            "etc/",
            "etc/passwd",
            "up",
            "win/",
            "win/x.txt"
        ]
    );

    // A backslash for a separator, nothing cleaned up.
    let scratch = Scratch::new();
    let data = zip(&[Entry::File(b"dir\\file.txt", b"x")]);
    let options = self::options(|o| o.backslash_separator = true);
    extract(&data, &scratch.out(), &options).unwrap();
    assert_eq!(listing(&scratch.out()), ["dir/", "dir/file.txt"]);
}

#[test]
fn refused_entries_can_be_skipped() {
    let scratch = Scratch::new();
    let data = zip(&[
        Entry::File(b"good.txt", b"ok"),
        Entry::File(b"../evil", b"x"),
        Entry::File(b"CON", b"x"),
        Entry::File(b"GOOD.txt", b"x"),
        Entry::Mode(b"link", b"good.txt", 0o120_777),
        Entry::File(b"also-good", b"ok"),
    ]);
    let options = options(|o| o.on_refused = OnRefused::Skip);
    let summary = extract(&data, &scratch.out(), &options).unwrap();
    assert_eq!(listing(&scratch.out()), ["also-good", "good.txt"]);
    let skipped: Vec<_> = summary.skipped.iter().map(|e| e.index.unwrap()).collect();
    assert_eq!(skipped, [1, 2, 3, 4]);
    assert!(matches!(
        summary.skipped[2].kind,
        ErrorKind::Duplicate { first: 0 }
    ));

    // The limits still stop it.
    let scratch = Scratch::new();
    let options = self::options(|o| {
        o.on_refused = OnRefused::Skip;
        o.limits.max_entries = 3;
    });
    let error = extract(&data, &scratch.out(), &options).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::TooManyEntries), "{error}");
}

#[test]
fn files_can_be_overwritten() {
    let scratch = Scratch::new();
    std::fs::create_dir_all(scratch.out().join("dir/sub")).unwrap();
    std::fs::write(scratch.out().join("a.txt"), b"mine, and longer").unwrap();
    let options = options(|o| o.overwrite = true);
    extract(
        &zip(&[Entry::File(b"a.txt", b"theirs")]),
        &scratch.out(),
        &options,
    )
    .unwrap();
    assert_eq!(
        std::fs::read(scratch.out().join("a.txt")).unwrap(),
        b"theirs"
    );
    // Not a directory.
    let error = extract(
        &zip(&[Entry::File(b"dir/sub", b"x")]),
        &scratch.out(),
        &options,
    )
    .unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Exists), "{error}");
}

/// Not a link, even with `overwrite`: the file it points to is untouched.
#[cfg(unix)]
#[test]
fn links_are_not_overwritten() {
    let scratch = Scratch::new();
    std::fs::create_dir(scratch.out()).unwrap();
    let victim = scratch.path().join("victim");
    std::fs::write(&victim, b"untouched").unwrap();
    std::os::unix::fs::symlink(&victim, scratch.out().join("a.txt")).unwrap();
    let options = options(|o| o.overwrite = true);
    let error = extract(
        &zip(&[Entry::File(b"a.txt", b"theirs")]),
        &scratch.out(),
        &options,
    )
    .unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Exists), "{error}");
    assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
}

#[cfg(unix)]
#[test]
fn permissions_can_be_kept_or_left_to_the_system() {
    use hivepack_extract::Permissions;
    use std::os::unix::fs::PermissionsExt;
    let data = zip(&[Entry::Mode(b"x", b"x", 0o106_775)]);
    let mode = |permissions| {
        let scratch = Scratch::new();
        let options = options(|o| o.permissions = permissions);
        extract(&data, &scratch.out(), &options).unwrap();
        std::fs::metadata(scratch.out().join("x"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    };
    assert_eq!(mode(Permissions::Masked), 0o755);
    assert_eq!(mode(Permissions::Preserve), 0o775);
    // The system's: no setuid or setgid bit either way.
    assert_eq!(mode(Permissions::Ignore) & 0o7000, 0);
}

#[test]
fn directories_get_their_time() {
    let scratch = Scratch::new();
    let data = zip(&[
        Entry::DirAt(b"dir/"),
        Entry::File(b"dir/inner/file", b"x"),
        Entry::DirAt(b"dir/inner/"),
    ]);
    extract(&data, &scratch.out(), &Options::default()).unwrap();
    for dir in ["dir", "dir/inner"] {
        let modified = std::fs::metadata(scratch.out().join(dir))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(
            modified
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            MTIME as u64,
            "{dir}"
        );
    }
}

/// The archives of libzip's tests, where the libzip sources are fetched.
fn regress_archives() -> Vec<(String, Vec<u8>)> {
    let cache = std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/testdata"));
    let regress = cache.join("libzip-1.12.1-source/libzip-1.12.1/regress");
    let mut files = Vec::new();
    for folder in [regress.clone(), regress.join("data")] {
        let Ok(dir) = std::fs::read_dir(&folder) else {
            continue;
        };
        for entry in dir {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_file() && !name.ends_with(".test") {
                files.push((name, std::fs::read(&path).unwrap()));
            }
        }
    }
    files.sort();
    files
}

/// Every archive of libzip's tests that opens extracts, or stops with its
/// reason, and writes nothing outside the destination: a test of the rules
/// on archives made by others, and a measure of what they refuse.
#[test]
fn libzip_archives_extract_or_stop_cleanly() {
    let archives = regress_archives();
    if archives.is_empty() {
        let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
        assert!(
            !required.split(',').any(|g| g == "all" || g == "generated"),
            "libzip's archives are missing: run `python3 scripts/testdata.py fetch --group generated`"
        );
        eprintln!("skipping: libzip's archives are not fetched");
        return;
    }
    let mut outcomes = std::collections::BTreeMap::<String, Vec<String>>::new();
    let mut opened = 0;
    for (name, data) in &archives {
        let Ok(archive) = Archive::open(data.as_slice(), OpenFlags::CHECKCONS) else {
            continue;
        };
        opened += 1;
        let scratch = Scratch::new();
        std::fs::write(scratch.path().join("sentinel"), b"untouched").unwrap();
        let mut options = Options::default();
        options.password = Some(b"foofoofoo".to_vec());
        let outcome = match extract_zip(&archive, &scratch.out(), &options) {
            Ok(summary) => {
                let files = listing(&scratch.out())
                    .iter()
                    .filter(|path| !path.ends_with('/'))
                    .count();
                assert_eq!(files as u64, summary.files, "{name}");
                "extracted".to_string()
            }
            Err(error) => {
                let kind = format!("{:?}", error.kind);
                kind.split(['(', ' ', '{'])
                    .next()
                    .unwrap_or_default()
                    .to_string()
            }
        };
        let mut around = listing(scratch.path());
        around.retain(|path| !path.starts_with("out/") && path != "out/");
        assert_eq!(around, ["sentinel"], "{name}");
        outcomes.entry(outcome).or_default().push(name.clone());
    }
    eprintln!("{opened} of {} archives open", archives.len());
    for (outcome, names) in &outcomes {
        eprintln!("{outcome}: {} ({})", names.len(), names.join(" "));
    }
    assert!(opened > 100, "only {opened} archives open");
}
