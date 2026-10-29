# Extracting safely

`hivepack-extract` writes an archive's entries to disk, and is safe by default: nothing is written outside the destination, through a link, over what is there, or past limits set against archive bombs. It starts with ZIP archives that `hivepack-zip` opened; tar and RAR will use the same checks and the same writing.

Extractors no longer break on memory, which safe Rust settles, but on logic, and memory-safe code gets that wrong as often as C: writing through a link (the `zip` crate's CVE-2025-29787, adm-zip's CVE-2026-76845), keeping setuid bits or chmod through a link (RUSTSEC-2026-0367 and 0369), links that point outside (RUSTSEC-2026-0368), alternate data streams on Windows (WinRAR's CVE-2025-8088, exploited), and Python's tarfile filter, which took five CVEs in June 2025 for checking strings and `realpath`. The rules below answer those, and come from the research behind this repository's ZIP plan.

> **Status:** names, the same path twice, links, overlapping data, the limits, writing by handle, integrity, masked permissions and times, the options that relax them, a time limit, cancelling and progress, names compared as file systems compare them, and marks of origin: done, for ZIP, checked on libzip's test archives, Fifield's bombs and Unicode's own tests, and fuzzed. Next: tar and RAR (see [What comes next](#what-comes-next)).

## Refuse, do not repair

Other extractors clean names up: Python drops `..` and drive letters, UnZip drops `../`. Two of them clean the same name differently (`foo/../bar` becomes `foo/bar` in one and `bar` in another), and that difference is itself an attack (ZipDiff, USENIX Security 2025). `hivepack-extract` refuses instead, with the same rules on every system, so that an archive extracts the same everywhere or not at all.

A name is refused (`check_name`, `NameError`) when it:

| Has | Because |
|---|---|
| nothing, or an empty component (`a//b`) | |
| bytes that are not UTF-8, once decoded from CP437 for a name without the UTF-8 flag | |
| a control character (U+0001 to U+001F, DEL) or NUL, in the decoded name or the raw bytes | libzip decodes CP437 0x01 as ☺; an extractor that takes the bytes as they are sees a control character |
| a backslash | Windows takes it for a separator |
| a leading `/` | absolute |
| a colon | a drive (`C:`), or an NTFS alternate data stream (`a.txt:hidden`) |
| `<`, `>`, `"`, `\|`, `?` or `*` | Windows does not allow them in names, so an archive that has them extracts on Linux and fails half way on Windows |
| a component `.` or `..` | climbs out |
| a Windows device name, with or without extension, in any case: `CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9`, `LPT0`–`LPT9`, `COM¹`–`COM³`, `LPT¹`–`LPT³`, `CONIN$`, `CONOUT$` | names a device in every directory |
| a component ending in a space or a dot | Windows drops them, so `a.` and `a` are one file |
| a component longer than 255 bytes | file systems refuse it |

Two entries may not name the same path either: compared as a case-insensitive file system, and macOS, compare them, which stops a file and a directory of one name (WinRAR's CVE-2023-38831), a path written through another's case, and one name written two ways. A directory entry may follow the files in it.

Names are compared by their key, Unicode's canonical caseless match with simple case folding: NFD(fold(NFD(name))), the canonical decomposition of the case folding of the canonical decomposition. So `é` as one character (U+00E9) and as `e` and a combining accent (U+0065 U+0301), which macOS takes for one name and Linux for two, are one name here; and so are the Kelvin sign and `K`, one by canonical decomposition as macOS takes them, and `σ` and `ς`, one by case folding as NTFS takes them. Compatibility forms stay apart (the ligature `ﬁ` is not `fi`), as no file system takes them for one, and so does `ß` and `ss`, which full case folding would join but NTFS keeps apart. Without the check, a second name written another way stops the extraction at its write, as `Exists` on macOS, after the first is written; with it, the archive extracts the same everywhere or not at all.

The tables are this crate's own, in safe Rust, for one Unicode version on every system (`UNICODE_VERSION`, 18.0.0), rather than the standard library's, whose version moves with Rust, or `unicode-normalization`, which has `unsafe` code. `scripts/unicode.py` makes them from the Unicode Character Database (`UnicodeData.txt` and `CaseFolding.txt`, the `unicode-18.0.0` test data set); the tests check them against the same files for every character, run Unicode's own `NormalizationTest.txt` (20,171 lines, and every character it does not list decomposing to itself), and check that a key is its own key. Raising the version is changing it in the script and the manifest, and running the script.

## Links and special files

Symbolic links (from the Unix mode of the external attributes) are refused, unless the options say otherwise.

A device, FIFO or socket in a ZIP archive is only a mode with data: Info-ZIP's `zip` records the mode of what it reads, a pipe for standard input (the entry `-` of libzip's `streamed.zip` and `zip64.zip`). Such an entry is written as a file with its data; nothing is ever created as what the mode says.

## Writing by handle

Checking a path and then writing to it lets a link put in between be followed. Every write goes through handles instead: the destination is opened once, each directory under it is opened from its parent's handle without following a link, and each file is created new (`O_CREAT|O_EXCL`, `O_NOFOLLOW`; `CREATE_NEW` on Windows). So a link already in the destination, or one put there while extracting, is not followed: a directory on the way that is a link stops the extraction (`NotADirectory`), and so does a file that is there (`Exists`). Nothing is overwritten.

The standard library cannot do this yet: its directory handles (`std::fs::Dir`) are not stable. cap-std does it, with `openat2` and `RESOLVE_BENEATH` on Linux 5.6 and later, `openat` with `O_NOFOLLOW` a component at a time elsewhere on Unix, and handles relative to a directory's on Windows; it is a dependency with `unsafe` code, in this crate only (see [safety.md](safety.md#dependencies-with-unsafe-code)), and `std::fs::Dir` replaces it once stable.

The destination itself is the caller's: it is created if it is not there, and its path is followed as given.

## Limits

An archive's sizes are what it says, and archive bombs say what gets them past a check: adm-zip believed them three times in 2026 alone. `Limits` count what is actually written:

| Limit | Default | |
|---|---|---|
| `max_entries` | 100,000 | counted before anything is read |
| `max_entry_size` | 4 GiB | |
| `max_total_size` | 16 GiB | |
| `max_ratio` | 2,000 | bytes written for each compressed byte, once an entry has written `ratio_threshold` (1 MiB). Deflate tops out near 1,032 to one, which a file of zeros reaches, so this stops only methods that go further, such as Deflate64 |

The sizes the archive declares are checked against the limits before anything is written, then the data is counted as it comes, and an entry stops as soon as it passes a limit or the size it declared (`SizeMismatch`). Nothing is allocated from a declared size.

Entries whose compressed data overlap are refused before anything is written. That is how David Fifield's bombs work, 42 kB to 5.5 GB or 46 MB to 4.5 PB with Zip64: many entries, one stream. The data ranges are sorted and each compared with the one before, which catches the "quoted" form too, whose entries each hold the next one's header.

The defaults are a judgment, to be tuned on real archives; each can be raised.

## Integrity, permissions and times

Every entry's data is checked at its end, its CRC-32, or for WinZip AES its authentication code, by `hivepack-zip`; a file whose data fails is removed, as is one cut off at a limit, and the extraction stops. Encrypted entries are read with `Options::password`.

On Unix, a file gets the permission bits its entry has, masked as Python's `data` filter masks them: no setuid, setgid or sticky bit, nothing writable by group or others, and readable and writable by its owner. Owners, ACLs and extended attributes are not restored. Directories get the system's default permissions. Files and directories get the time their entry has, the directories once nothing more is written in them, the deepest first, without following a link.

## Marks of origin

A downloaded archive carries a mark of where it came from, which the system checks before a file is opened or run: Windows' Mark of the Web, a `Zone.Identifier` stream with the zone (`ZoneId=3` for the internet) and the address, and macOS's quarantine, the `com.apple.quarantine` attribute that Gatekeeper reads. A file extracted without it escapes the check: 7-Zip's CVE-2025-0411, exploited, was nested archives losing it.

`Origin::of` reads the mark an archive's file has, and `Options::origin` carries it, as it is, to every file written: on Windows the stream is opened from the file's own handle (`:Zone.Identifier` relative to it, so no path is resolved again, and a file named `a` is not taken for drive A); on macOS the attribute is set on the file's descriptor, and on every directory created too, as Gatekeeper checks an app, which is a directory. The mark is written before the file's time, which writing a stream changes. A mark that cannot be written stops the extraction (`ErrorKind::Origin`), and so does one this system cannot carry, before anything is written: an extraction that drops the mark would hide where its files came from. It is not the default only because the archive's path is the caller's: `extract_zip` reads an `Archive`, not a file.

Linux and the other systems have no mark (`Origin::of` gives `None`). macOS's attribute takes `rustix`, a dependency with `unsafe` code, already there for `cap-std`, since the standard library has no extended attributes (see [safety.md](safety.md#dependencies-with-unsafe-code)).

## Time, cancelling and progress

The limits bound what an archive writes, not how long it takes: a disk that is slow, or many small entries, take their time within them. `Options::time_limit` (none by default) stops an extraction once past it, from when it starts (`ErrorKind::TimeLimit`), and `Cancel`, a token whose clones share one flag, stops it from another thread (`ErrorKind::Cancelled`). Both are checked between entries and before each read of data, which gives at most 64 KiB; a read of compressed data that gives nothing, such as empty Deflate blocks, runs to the end of that entry's data, which the archive's size bounds. A file cut off is removed, as one whose data fails; what was written before stays.

`Options::progress` is told the entries and bytes to write once the entries are checked, as the archive says them (the data is checked against them, so what is written does not pass them), then the entries and bytes written after each piece of data and each entry. It is called on the extracting thread, and should hand on what it is told, not wait. Calling `Cancel::cancel` from it stops the extraction.

The research behind this plan found neither in any Rust ZIP crate, so the design is this crate's own: a token and a function, rather than an asynchronous interface, as the writing blocks anyway.

## Options

Each rule that is not about writing outside the destination can be relaxed, by name (`Options`):

| Option | Default | Otherwise |
|---|---|---|
| `links` | `Links::Refuse` | `AsFile`: a file holding the target, as extractors on Windows write links. `Inside`: links whose target is relative and stays inside the destination by its text (`..` allowed, as long as it does not climb out), and does not pass through another link of the archive, which the system would follow where the text does not; read and checked before anything is written, and created after every other entry, so nothing is written through them. On Windows, creating a link takes a privilege that most accounts lack |
| `names` | `Names::Strict` | `Sanitize`: first drops what Python's `zipfile` drops, a leading `/`, a drive (`C:`, a letter and a colon, as Windows reads it) and `.`, `..` and empty components, then refuses what is still refused |
| `backslash_separator` | `false` | `\` taken for a separator, as PowerShell 5.1's `Compress-Archive` writes it |
| `on_refused` | `OnRefused::Stop` | `Skip`: an entry refused for its name, as a link or as the same path as another is left out, listed in `Summary::skipped` with its reason, and the rest extracted. The limits and overlapping data still stop the extraction: they are about the archive, not one entry |
| `overwrite` | `false` | Files that are there are replaced, if they are files: opened without following a link and emptied. A link or a directory there still stops it |
| `permissions` | `Permissions::Masked` | `Preserve`: the entry's bits but setuid, setgid and sticky. `Ignore`: the system's |
| `limits` | see [Limits](#limits) | each raised or lowered |
| `password` | none | the password encrypted entries are read with |
| `origin` | none | the archive's mark of origin (`Origin::of`), carried to every file (see [Marks of origin](#marks-of-origin)) |
| `time_limit` | none | how long the extraction may take (see [Time, cancelling and progress](#time-cancelling-and-progress)) |
| `cancel` | none | a `Cancel` token that stops it |
| `progress` | none | a function told how far it is |

## Errors

An extraction stops at the first entry refused (unless `on_refused` is `Skip`), with its index, its name as the archive has it, and the reason (`Error`, `ErrorKind`). What is checked before writing (names, the same path, links, overlaps, declared sizes) stops it before anything is written, the destination included.

## How it is shown

`crates/extract/tests/extract.rs` extracts archives made to attack extractors, written by `hivepack-zip` and changed by hand where it would not write them: names that climb, are absolute, carry backslashes, drives, streams, device names or control characters (as CP437 too); the same path in two cases, as a file and a directory; links; FIFOs and devices, written as files; links already in the destination, to a directory and to a file outside it (Unix); files already there; the limits; two entries sharing one stream, as Fifield's bombs do; data whose CRC-32 fails, and more data than the header says; and encrypted entries, with and without the password. Each must stop with its reason, leave nothing outside the destination, and nothing at all when the checks before writing stop it. Each option has its test: links inside, climbing out, absolute and through another link; links as files; names cleaned up and backslashes; entries skipped; files overwritten but not links; permissions kept or left; directory times; a time limit of zero and one too far to count; cancelling before and in the middle of a file, which is removed; and progress, its totals told first, never going back, in pieces of 64 KiB at most. The name rules have unit tests of their own, and random bytes are checked without panicking.

The same test extracts every archive of libzip's `regress/` that opens with `ZIP_CHECKCONS` (112 of 180), beside a file that must stay as it was. 80 extract; 29 stop on their data, as they were made to (wrong passwords, CRC errors, garbage after a stream, and bzip2, LZMA, XZ and Zstandard, which the port does not read yet); 3 stop on their names (an empty one, and two whose CP437 names have control characters). It was this run that found the FIFOs of `streamed.zip`, which were refused before they were written as files.

Fifield's three published bombs (the `fifield-zipbombs` set) stop before anything is written, whether opened with `ZIP_CHECKCONS` or not: libzip's consistency check passes them, as their local headers agree with the central directory. With the default limits, `zbsm.zip` (250 entries, 42 kB to 5.5 GB) stops on its shared data, as its 5.5 GB pass the limits; without the overlap check it writes them all, which is how the test was checked. `zblg.zip` (10 MB to 281 TB) stops on the sizes it declares, and `zbxl.zip` (190,023 entries, 46 MB to 4.5 PB) on its number of entries. With those limits lifted, each stops on its shared data, once the entries refused are skipped: the names of the two big ones, every name of digits and capital letters of one character, then of two, then of three, include `AUX`, `CON`, `NUL` and `PRN`, which are refused on every system. The test sets a ratio of ten to one throughout, checked only while writing, so that a bomb let through stops within its first entry rather than fill the disk.

ZipDiff's archives (the `zipdiff-constructions` set: 5,927 archives that ZIP parsers read differently, made once by ZipDiff's own program) each extract or stop with their reason, opened with `ZIP_CHECKCONS` and without, and the test holds the count of each outcome for each type, so that a change shows. `hivepack-zip` reads every one as libzip does (see [zip.md](zip.md)), so what is extracted is what libzip reads. With `ZIP_CHECKCONS`, most of those whose headers disagree do not open (4,248 of `a2`'s 4,609 size combinations, every several-ends archive of `c2`, the moved central directory of `c4`). The name rules refuse every one of `b3`'s twenty forms of `a/b` (`/a/b`, `a//b`, `a\b`, `./a/b`, `../a/b`, `.../a/b`, `c/../a/b`...), whichever comes first, and the same path stops `b1` (one name twice, without the check) and `b4` (`test.txt` and `test.TXT`). The data that overlaps stops one of `c1`'s. It was this run that found the characters Windows does not allow (`a<b`, `a*b` and the others of `b2`), which were extracted on Linux and would have failed on Windows; they are refused now.

The `extract` fuzz target (see [fuzz/README.md](../fuzz/README.md)) extracts its input with options its first byte picks, cancelling it after some progress if that byte says so, and checks that nothing is written beside the destination, that every link created stays inside it by its text, that the summary counts what is there, and, however the extraction ends, that the files left hold exactly the bytes of the entries written in full, so that none is left cut off. 11 million inputs over four minutes found nothing before the first commit, and 9.6 million with cancelling; with the removal of a failed file taken out, it fails on the seed corpus, before mutating anything.

## What comes next

- **tar and RAR**, through the same checks and writing.
- **Corpora**: the archives behind recent CVEs.
