# Porting libzip

`hivepack-zip` will read and write ZIP archives. Its container logic is a port of [libzip](https://libzip.org) to safe Rust; its compression and encryption come from hivepack's own crates, each ported from or checked against an official library. What libzip does not do, such as split archives, legacy file name encodings and extracting to disk, is written for hivepack and checked against other implementations.

> **Status:** step 2 has started. `hivepack-zip` opens archives and reads their central directory and local headers as libzip does, compared with libzip on its own test archives and on generated ones (see [Progress](#progress)). Reading the entries' data is next.

## Why libzip

ZIP has a specification, PKWARE's [APPNOTE.TXT](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) (6.3.10), but no official library: PKWARE sells only a closed SDK. Implementations disagree with each other; a 2025 study had 50 parsers read the same archives and found 1221 of 1225 pairs disagreeing on at least one ([ZipDiff, USENIX Security 2025](https://www.usenix.org/system/files/usenixsecurity25-you.pdf)). So the port follows the implementation that comes closest to a reference:

- **libzip** is under BSD-3-Clause, maintained (1.12.1, October 2026), and its stated goal is "Do not create corrupt files, even in case of errors". It has a strict mode that compares every local header with the central directory (`ZIP_CHECKCONS`), 199 regression tests with their archives, and runs on OSS-Fuzz.
- **minizip-ng** (Zlib) reads and writes split archives, but converts legacy file names through `iconv` or the Windows API, and checks paths as strings before it opens them.
- **libarchive** (BSD-2) and Go's `archive/zip` (BSD-3) reject multi-disk archives too, and are less strict.
- **Info-ZIP** has not been released since 2009, and its licence is not one `deny.toml` allows. **7-Zip** is under the LGPL.

None of these is copied from except libzip, but all of them are used as oracles: programs whose answers the tests compare with.

## The version

The port follows libzip **1.12.1** (tag `v1.12.1`, commit `8e037534ccd62f444abbe4ce265443ee74bbfeb3`). As with libzstd, it follows releases, not `main`.

## What following libzip means

The rules are those of [porting.md](porting.md):

- **The same layout.** Each file in `lib/` that is ported maps to a module: `lib/zip_open.c` becomes `crates/zip/src/open.rs`, `lib/zip_dirent.c` becomes `crates/zip/src/dirent.rs`.
- **The same names**, in snake case, without the `zip_` and `_zip_` prefixes: `_zip_find_central_dir` becomes `find_central_dir`. Every ported function's doc comment names its C original and file.
- **The same errors.** libzip's `ZIP_ER_*` codes and its `ZIP_ER_DETAIL_*` details (which say what is inconsistent, and in which entry) become one error type, so a test can check that both reject a file for the same reason.
- **Differences are marked** with a comment starting `Differs from libzip:`.

Unlike libzstd, libzip's value is in its rules, not its algorithms: which end of central directory record it accepts, what it checks and when, what it writes. Those are ported faithfully. Its C interface, built on layers of `zip_source` callbacks, is not; the Rust API reads by position (`ReaderAt`) and writes to `Write + Seek`.

## The map

libzip 1.12.1's `lib/` is about 22,000 lines of C. Roughly half of it is ported.

| libzip | Lines | What happens to it |
|---|---|---|
| `zip_open.c` | 1,039 | Ported: finding the end of central directory (backwards through the last 64 KiB), the Zip64 records, reading the central directory, Info-ZIP's entry count modulo 65,536, `ZIP_CHECKCONS` and the local header comparison, torrentzip detection |
| `zip_dirent.c` | 1,421 | Ported: reading and writing central and local headers, the Zip64, Unicode path/comment and WinZip AES extra fields, DOS times, attributes and `version made by`, the consistency checks |
| `zip_extra_field.c`, `zip_extra_field_api.c` | 896 | Ported |
| `zip_close.c` | 812 | Ported: writing an archive (local header, data, header rewritten once sizes are known, data descriptor, central directory), raw copies of unchanged entries, torrentzip order. Not the cloning of unchanged data (`begin_write_cloning`), which needs reflinks |
| `zip_utf-8.c` | 294 | Ported, then extended: libzip tells ASCII, UTF-8 and CP437 apart; hivepack adds the legacy code pages (see below) |
| `zip_string.c`, `zip_buffer.c`, `zip_io_util.c`, `zip_error*.c` | ~800 | Ported as small helpers; `zip_buffer` becomes a cursor over a slice |
| `zip_winzip_aes.c`, `zip_pkware.c`, `zip_source_winzip_aes_*.c`, `zip_source_pkware_*.c` | ~1,370 | Ported: the encryption framing (salt, password check, authentication code; ZipCrypto's header). The primitives come from `hivepack-crypto` |
| `zip_source_crc.c`, `zip_source_compress.c`, `zip_source_window.c`, `zip_source_zip_new.c`, `zip_algorithm_*.c` | ~2,500 | Their rules are ported (when the CRC and sizes are checked, the parameters given to each codec) into Rust readers and writers. The layering is not |
| `zip_hash.c`, `siphash.c` | 533 | Replaced by `std::collections::HashMap`, which already hashes with SipHash-1-3 and random keys, as libzip 1.12 does to stop hash flooding. Duplicate names are reported as libzip reports them |
| The rest of `zip_source_*.c`, `zip_fdopen.c`, `zip_memdup.c`, `zip_realloc.c`, `compat.h` | ~4,900 | Not ported: C plumbing |
| `zip_crypto_*.c`, `zip_random_*.c` | ~1,600 | Not ported: OpenSSL, GnuTLS, mbed TLS, CommonCrypto and Windows backends, replaced by `hivepack-crypto` |
| The editing API (`zip_add.c`, `zip_delete.c`, `zip_rename.c`, `zip_set_*.c`, `zip_unchange*.c`, …) | ~2,000 | Ported as an editor over `zip_close`'s model: an entry's original header plus its changes, written out as a new archive |

## What libzip does not do

These are hivepack's own, and each one has its own oracles.

| Missing from libzip | Where it shows | hivepack | Checked against |
|---|---|---|---|
| Split archives (`.z01`, `.z02`, …, `.zip`) | `check_eocd` and `_zip_read_eocd64` fail with `ZIP_ER_MULTIDISK` | A volume set that reads the segments as one byte space, and a writer that splits. A single segment on its own still fails with `ZIP_ER_MULTIDISK` | minizip-ng, Commons Compress, 7-Zip, Info-ZIP `zip -s` |
| `.zip.001` volumes | Not a ZIP feature: 7-Zip splits the bytes | The same volume set, joined end to end | 7-Zip |
| Legacy code pages | `zip_utf-8.c` knows only CP437 | Tables for CP932, CP936, CP949, CP950, CP866, CP1258 and others, chosen by the caller or guessed | 7-Zip `-mcp`, `unzip -O`, libarchive `hdrcharset`, Python `metadata_encoding` |
| Deflate64 and PPMd | Not among libzip's methods | Deflate64: `hivepack-deflate`'s `InflateBack9`, ported from zlib's `contrib/infback9` (done); PPMd later | .NET and Commons Compress test data, 7-Zip |
| Writing to a stream | `add_data` seeks back to rewrite the local header, and forces Zip64 when the size is unknown | A streaming writer with data descriptors | Every oracle reads what it writes |
| Reading a stream | Needs a seekable source | An opt-in streaming reader that checks what it read against the central directory at the end | libarchive's streaming reader |
| Parallel work | One thread | Entries decompressed in parallel through `ReaderAt`; compressed in parallel and written in order | The single-threaded output, byte for byte |
| Extracting to disk | None: libzip is an archive library | `hivepack-extract`, shared with tar and RAR, safe by default | ZipDiff samples, David Fifield's zip bombs, the archives behind recent CVEs in other extractors |

## Strict by default

libzip compares local headers with the central directory only with `ZIP_CHECKCONS`. Without it, `_zip_file_get_offset` reads a local header only for its length, so an archive whose local and central headers disagree opens, and different tools extract different files from it, which is how parser differentials are exploited. hivepack reads with `ZIP_CHECKCONS`'s checks on by default; libzip's default behaviour is the lenient option.

Two further checks are additions, marked `Differs from libzip:`: entries whose data overlap are refused (the non-recursive zip bomb), and the central directory is read under a limit on entries and memory. libzip keeps every entry in one array, sized from the end of central directory record once the record has been checked against the file's length; the port keeps the array.

## How it is shown

- **Reading.** Every archive in libzip's `regress/` is opened by the port and by libzip, with and without `ZIP_CHECKCONS`, from a buffer and from a file. Both must accept or refuse it, with the same error code and detail. The comparison goes through `tools/zip-oracle`, a small C program built from libzip 1.12.1's sources, as `tools/zstd-oracle` is built from libzstd's. For an archive that opens, the oracle answers what the reading API says about every entry: its name raw, guessed and strict, `zip_stat_index`, the external attributes, the comment, the extra fields of the central directory and of the local header, where its data starts, and `zip_name_locate` of its name with each flag. `crates/zip/tests/oracle.rs` also generates archives: names in ASCII, UTF-8, CP437, with NUL bytes, repeated, and with Info-ZIP Unicode fields whose CRC is right or wrong; Zip64 fields and records, right and wrong; WinZip AES fields; data descriptors; padding and garbage after extra fields; local headers that disagree with the central directory; torrentzip comments; prefixes, trailing bytes, wrong counts and disks; and some of them damaged. 1,500 are compared on each run, and 40,000 were before the first commit: every detail libzip reports when opening came up but two, `ZIP_ER_DETAIL_CDIR_LENGTH_INVALID` and `ZIP_ER_DETAIL_EOCD64_WRONG_MAGIC`, which the checks before them leave almost no way to reach. `testdata/oracle/zip-open.txt` replays 742 earlier answers where the oracle is not built (Windows, and the emulated i686 and s390x jobs). libzip's build writes `config.h`, `zipconf.h` and its error strings with CMake; `scripts/testdata.py` builds the oracle with the C compiler alone, from `tools/zip-oracle/config.h` and `zipconf.h` and the strings generated as CMake would.
- **libzip's own tests.** The 199 `.test` files in `regress/` are scripts for libzip's test programs (`ziptool`, `tryopen` and a few others), run by nihtest. The port gets a `tools/ziptool` that takes the same commands, so the tests run unchanged. Most of them open, read or build archives; the others delete, rename, undo changes or change sizes in place, which the editor above covers.
- **Writing.** For the same input, the port writes the same archive as libzip, byte for byte. libzip compresses with zlib's raw deflate (`windowBits` −15) at level 9 and `memLevel` 9 unless told otherwise (`zip_algorithm_deflate.c`), so this needs `hivepack-deflate` to give zlib's output at those settings. Torrentzip output is compared too.
- **Fuzzing.** A fuzzer compares the port with the libzip oracle under AddressSanitizer, seeded with libzip's OSS-Fuzz corpus. For now `fuzz/fuzz_targets/zip_open.rs` opens its input and asks the reading API everything, which must not panic, seeded with the archives of `zip-open.txt`.
- **Beyond libzip.** Info-ZIP `unzip`, 7-Zip, bsdtar, Python and Go read everything the port writes; ZipDiff's ambiguous archives are read, and where the oracles disagree, the manifest records which one hivepack follows.

## Progress

| libzip | Port | Status |
|---|---|---|
| `zip_error.c`, `zip_error_strerror.c`, `zip_err_str.c` (generated) | `error.rs` | done |
| `zip_buffer.c`, `zip_io_util.c`, `zip_string.c` | `buffer.rs`, `io_util.rs`, `string.rs` | reading done; writing with step 3 |
| `zip_utf-8.c` | `utf_8.rs` | done |
| `zip_extra_field.c`, `zip_extra_field_api.c` | `extra_field.rs`, `extra_field_api.rs` | reading done |
| `zip_dirent.c` | `dirent.rs` | reading done |
| `zip_open.c`, `zip_new.c` | `open.rs` | done for reading; `ZIP_CREATE`, `ZIP_EXCL` and `ZIP_TRUNCATE` with step 3 |
| `zip_hash.c` | `hash.rs` | its rules, on `HashMap` |
| `zip_name_locate.c`, `zip_get_name.c`, `zip_stat_index.c`, `zip_stat_init.c`, `zip_file_get_comment.c`, `zip_file_get_external_attributes.c`, `zip_get_archive_comment.c`, `zip_get_archive_flag.c`, `zip_get_num_entries.c` | modules of the same names, `zip.rs` | done |
| `zip_file_get_offset.c` | `file_get_offset.rs` | `_zip_file_get_offset`; `_zip_file_get_end` next |
| The reading rules of `zip_source_seek.c`, `zip_source_read.c`, `zip_source_tell.c`, `zip_source_accept_empty.c`, and the file and buffer sources | `source.rs` | done |
| Reading data: `zip_fopen*.c`, `zip_fread.c`, `zip_source_zip_new.c`, `zip_source_window.c`, `zip_source_crc.c`, `zip_source_compress.c`, `zip_algorithm_deflate.c` | | next, with Deflate64 and `tools/ziptool` |

Where the port differs from libzip, a `Differs from libzip:` comment says so. The differences so far:

- An archive is read through `ReadAt`, reads at a position, in place of a stack of `zip_source_t` callbacks; `Source` keeps the position and the rules of libzip's file and buffer sources (a seek outside the source fails with `ZIP_ER_INVAL`, reads stop at the length it had when opened, a failed read fails all later ones, and an empty buffer is an empty archive but an empty file is not one).
- Names are returned whole: libzip returns C strings, which end at a NUL byte in a name (`ZIP_CHECKCONS` refuses such names). Lookups compare names as libzip does, up to their first NUL.
- Times are taken as UTC, where libzip calls `mktime` in the machine's time zone; the oracle runs with `TZ=UTC`. `Archive::file_get_dos_time` gives the time as stored.
- The system error of an error is described by the standard library, whose text is `strerror`'s on Unix.

## The order of work

1. **CRC-32 and inflate.** The decompressor and checksums of `hivepack-deflate`, ported from zlib 1.3.2 (`crc32.c`; `inflate.c`, `inftrees.c`, `inffast.c`). Nothing compressed can be read before them. Done: see [deflate.md](deflate.md).
2. **Reading.** Errors, buffers, extra fields, headers, file names, `open.rs`; stored and deflated entries; `tools/zip-oracle`, and `tools/ziptool`'s reading commands. Deflate64 entries, whose decoder is done: see [deflate.md](deflate.md).
3. **Writing.** Writing headers, `close.rs`, the editor; the compressor of `hivepack-deflate` (`deflate.c`, `trees.c`), with output identical to zlib's: done, see [deflate.md](deflate.md).
4. **Encryption.** ZipCrypto and WinZip AES, on `hivepack-crypto`.
5. **Beyond libzip.** Legacy code pages, split archives, streaming, parallel work. `hivepack-extract` is built alongside step 2, so that nothing reads archives to disk without it.
6. **More methods.** bzip2, LZMA, XZ and PPMd, as their crates arrive; zstd once `hivepack-zstd` compresses.

## Questions to settle first

- **Random numbers.** WinZip AES needs a random salt for each entry. libzip asks the operating system (`zip_random_*.c`). Unless Rust's standard library has a stable API for it by then, that takes the `getrandom` crate, which uses `unsafe` and libc. Either the caller supplies the salts, or the dependency rules in [safety.md](safety.md) allow it.
- **Unsafe code inside dependencies.** The rules in [safety.md](safety.md) bind hivepack's own crates; nothing says yet whether a library may depend on a crate that uses `unsafe`. Extracting without races needs `openat2`, `openat` with `O_NOFOLLOW`, or `NtCreateFile` relative to a directory handle, and the Rust crates that offer them (rustix, cap-std) use `unsafe` inside.
- **Strictness.** Whether `ZIP_CHECKCONS` by default refuses too many real archives (it refuses, for example, an archive comment whose length is wrong) is measured on the test corpora before it is fixed.

## Licences

The port is derived from libzip, which is under BSD-3-Clause (Copyright (C) Dieter Baron and Thomas Klausner). That is why `hivepack-zip` is under BSD-3-Clause, with libzip's notice in its `LICENSE`, as `hivepack-zstd` keeps Meta's. `hivepack-deflate`, which `hivepack-zip` takes CRC-32 from too, is derived from zlib and is under the zlib license, which asks that altered versions be marked as such. The rest of hivepack stays MIT.

APPNOTE.TXT may not be redistributed (its section 1.4.2), so the repository links to it and does not include it. The test archives from libzip, libarchive, Go, Commons Compress and .NET keep their own licences, listed in [testdata/README.md](../testdata/README.md).
