# Extracting safely

`hivepack-extract` writes an archive's entries to disk, and is safe by default: nothing is written outside the destination, through a link, over what is there, or past limits set against archive bombs. It starts with ZIP archives that `hivepack-zip` opened; tar and RAR will use the same checks and the same writing.

Extractors no longer break on memory, which safe Rust settles, but on logic, and memory-safe code gets that wrong as often as C: writing through a link (the `zip` crate's CVE-2025-29787, adm-zip's CVE-2026-76845), keeping setuid bits or chmod through a link (RUSTSEC-2026-0367 and 0369), links that point outside (RUSTSEC-2026-0368), alternate data streams on Windows (WinRAR's CVE-2025-8088, exploited), and Python's tarfile filter, which took five CVEs in June 2025 for checking strings and `realpath`. The rules below answer those, and come from the research behind this repository's ZIP plan.

> **Status:** names, the same path twice, links and special files, overlapping data, the limits, writing by handle, integrity, masked permissions and times: done, for ZIP. Next: the options to relax them, marks of origin, tar and RAR (see [What comes next](#what-comes-next)).

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
| a component `.` or `..` | climbs out |
| a Windows device name, with or without extension, in any case: `CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9`, `LPT0`–`LPT9`, `COM¹`–`COM³`, `LPT¹`–`LPT³`, `CONIN$`, `CONOUT$` | names a device in every directory |
| a component ending in a space or a dot | Windows drops them, so `a.` and `a` are one file |
| a component longer than 255 bytes | file systems refuse it |

Two entries may not name the same path either: compared with case folded (`str::to_lowercase`), as a case-insensitive file system sees them, which stops a file and a directory of one name (WinRAR's CVE-2023-38831) and a path written through another's case. A directory entry may follow the files in it. Unicode normalization (`é` as one code point or two, which macOS takes for one name) comes next.

## Links and special files

Symbolic links, and devices, FIFOs and sockets (from the Unix mode of the external attributes), are refused, not created.

## Writing by handle

Checking a path and then writing to it lets a link put in between be followed. Every write goes through handles instead: the destination is opened once, each directory under it is opened from its parent's handle without following a link, and each file is created new (`O_CREAT|O_EXCL`, `O_NOFOLLOW`; `CREATE_NEW` on Windows). So a link already in the destination, or one put there while extracting, is not followed: a directory on the way that is a link stops the extraction (`NotADirectory`), and so does a file that is there (`Exists`). Nothing is overwritten.

The standard library cannot do this yet: its directory handles (`std::fs::Dir`) are not stable. cap-std does it, with `openat2` and `RESOLVE_BENEATH` on Linux 5.6 and later, `openat` with `O_NOFOLLOW` a component at a time elsewhere on Unix, and handles relative to a directory's on Windows; it is the one dependency with `unsafe` code in the libraries (see [safety.md](safety.md#dependencies-with-unsafe-code)), and `std::fs::Dir` replaces it once stable.

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

On Unix, a file gets the permission bits its entry has, masked as Python's `data` filter masks them: no setuid, setgid or sticky bit, nothing writable by group or others, and readable and writable by its owner. Owners, ACLs and extended attributes are not restored. Directories get the system's defaults. Files get the time the entry has.

## Errors

An extraction stops at the first entry refused, with its index, its name as the archive has it, and the reason (`Error`, `ErrorKind`). What is checked before writing (names, the same path, links, overlaps, declared sizes) stops it before anything is written, the destination included.

## How it is shown

`crates/extract/tests/extract.rs` extracts archives made to attack extractors, written by `hivepack-zip` and changed by hand where it would not write them: names that climb, are absolute, carry backslashes, drives, streams, device names or control characters (as CP437 too); the same path in two cases, as a file and a directory; links, FIFOs and devices; links already in the destination, to a directory and to a file outside it (Unix); files already there; the limits; two entries sharing one stream, as Fifield's bombs do; data whose CRC-32 fails, and more data than the header says; and encrypted entries, with and without the password. Each must stop with its reason, leave nothing outside the destination, and nothing at all when the checks before writing stop it. The name rules have unit tests of their own, and random bytes are checked without panicking.

## What comes next

- **Options to relax the rules**, each named: names cleaned up as Python does, `\` taken as a separator (PowerShell 5.1's `Compress-Archive` writes it), links kept when they point inside the destination (created last) or written as files, permissions kept, entries refused skipped rather than stopping, and a time budget.
- **Unicode normalization** of names before they are compared, which needs Unicode's tables.
- **Marks of origin**: the archive's `Zone.Identifier` on Windows and `com.apple.quarantine` on macOS, carried to every file written, a failure to write one being a failure to extract. The macOS one takes a system call the standard library does not wrap.
- **Directory times**, set once their contents are written.
- **tar and RAR**, through the same checks and writing.
- **Corpora**: ZipDiff's archives, Fifield's bombs and the archives behind recent CVEs, and fuzzing.
