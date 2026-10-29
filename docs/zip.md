# Porting libzip

`hivepack-zip` will read and write ZIP archives. Its container logic is a port of [libzip](https://libzip.org) to safe Rust; its compression and encryption come from hivepack's own crates, each ported from or checked against an official library. What libzip does not do, such as split archives, legacy file name encodings and extracting to disk, is written for hivepack and checked against other implementations.

> **Status:** step 2 is under way. `hivepack-zip` opens archives, reads their central directory and local headers, and reads stored, deflated and Deflate64 entries as libzip does (libzip reads no Deflate64), compared with libzip on its own test archives and on generated ones (see [Progress](#progress)). It edits archives and writes them as libzip does, byte for byte, but for new data, which is next; 100 of libzip's own tests pass through `tools/ziptool`.

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
| Deflate64 and PPMd | Not among libzip's methods | Deflate64: read with `hivepack-deflate`'s `Inflate9`, which decodes as zlib's `contrib/infback9` (done); PPMd later | .NET and Commons Compress test data, 7-Zip |
| Writing to a stream | `add_data` seeks back to rewrite the local header, and forces Zip64 when the size is unknown | A streaming writer with data descriptors | Every oracle reads what it writes |
| Reading a stream | Needs a seekable source | An opt-in streaming reader that checks what it read against the central directory at the end | libarchive's streaming reader |
| Parallel work | One thread | Entries decompressed in parallel through `ReaderAt`; compressed in parallel and written in order | The single-threaded output, byte for byte |
| Extracting to disk | None: libzip is an archive library | `hivepack-extract`, shared with tar and RAR, safe by default | ZipDiff samples, David Fifield's zip bombs, the archives behind recent CVEs in other extractors |

## Strict by default

libzip compares local headers with the central directory only with `ZIP_CHECKCONS`. Without it, `_zip_file_get_offset` reads a local header only for its length, so an archive whose local and central headers disagree opens, and different tools extract different files from it, which is how parser differentials are exploited. hivepack reads with `ZIP_CHECKCONS`'s checks on by default; libzip's default behaviour is the lenient option.

Two further checks are additions, marked `Differs from libzip:`: entries whose data overlap are refused (the non-recursive zip bomb), and the central directory is read under a limit on entries and memory. libzip keeps every entry in one array, sized from the end of central directory record once the record has been checked against the file's length; the port keeps the array.

## How it is shown

- **Reading.** Every archive in libzip's `regress/` is opened by the port and by libzip, with and without `ZIP_CHECKCONS`, from a buffer and from a file. Both must accept or refuse it, with the same error code and detail. The comparison goes through `tools/zip-oracle`, a small C program built from libzip 1.12.1's sources, as `tools/zstd-oracle` is built from libzstd's. For an archive that opens, the oracle answers what the reading API says about every entry: its name raw, guessed and strict, `zip_stat_index`, the external attributes, the comment, the extra fields of the central directory and of the local header, where its data starts, and `zip_name_locate` of its name with each flag. `crates/zip/tests/oracle.rs` also generates archives: names in ASCII, UTF-8, CP437, with NUL bytes, repeated, and with Info-ZIP Unicode fields whose CRC is right or wrong; Zip64 fields and records, right and wrong; WinZip AES fields; data descriptors; padding and garbage after extra fields; local headers that disagree with the central directory; torrentzip comments; prefixes, trailing bytes, wrong counts and disks; and some of them damaged. 1,500 are compared on each run, and 40,000 were before the first commit: every detail libzip reports when opening came up but two, `ZIP_ER_DETAIL_CDIR_LENGTH_INVALID` and `ZIP_ER_DETAIL_EOCD64_WRONG_MAGIC`, which the checks before them leave almost no way to reach. `testdata/oracle/zip-open.txt` replays 742 earlier answers where the oracle is not built (Windows, and the emulated i686 and s390x jobs).

  Reading entries is compared the same way, through the oracle's `read` requests: every entry opened with `zip_fopen_index` (decompressed, or raw with `ZIP_FL_COMPRESSED` or `ZIP_FL_ENCRYPTED`), read with `zip_fread` in pieces of one byte to 64 KiB, to its end or to a limit, then closed. The port must return the same from every read, the same data, the same error at the end and the same from `zip_fclose`. The generated entries hold deflate streams from `hivepack-deflate`'s compressor, some cut short, followed by garbage or with a byte changed, and CRCs and sizes right or wrong; what came up includes CRC errors when the end is read and when an entry read to its last byte is closed, wrong lengths, zlib data errors, garbage after a stream with `ZIP_CHECKCONS`, compressed sizes past the end of the file, and local headers that cannot be read. 10,000 requests agreed before the first commit, every regress archive is read four ways on each run, and `testdata/oracle/zip-read.txt` replays 560 answers. libzip's build writes `config.h`, `zipconf.h` and its error strings with CMake; `scripts/testdata.py` builds the oracle with the C compiler alone, from `tools/zip-oracle/config.h` and `zipconf.h` and the strings generated as CMake would.
- **libzip's own tests.** The 199 `.test` files in `regress/` are scripts for libzip's test programs (`ziptool`, `tryopen` and a few others), run by nihtest. `tools/ziptool` has the port's `ziptool`, with the commands libzip's tests add to it (`ziptool_regress`), `tryopen` and `zipcmp`, with libzip's output word for word, and `tools/ziptool/tests/regress.rs` runs the scripts as nihtest does: the test's files copied into a fresh folder, the program run there, its exit status, output and errors compared, and the files checked afterwards, an archive written as one with the same name with `zipcmp -pv` as libzip's `nihtest.conf` has it (which compares the entries, their sizes, CRCs, methods, comments and extra fields of both headers, in any order), anything else byte for byte, and no other file may be left. 100 of them run and pass now. The others wait for what they need: 48 add data, compress or encrypt, 2 more recompress to torrentzip, 31 need encryption, bzip2, LZMA or Zstandard, 10 run other test programs, and 8 need a setup the runner does not do yet.
- **Editing.** The oracle's `edit` requests open an archive from a file, make a list of edits (delete, rename, set an entry's or the archive's comment, its time in MS-DOS or Unix form, its external attributes, undo one entry's changes or all of them, set an archive flag), answer each edit's result and what the API then says of every entry, and write the archive with `zip_close`. The port must answer the same and write the same bytes, or nothing where libzip leaves the file as it was or removes it. The generated archives are mostly ones that open, so that the edits are made; the edits take names and comments from the archive or make them up, in each encoding flag, with indices in range and not, and times before 1980, after 2107 and past what `localtime_r` takes. 3,000 requests are compared on each run, every regress archive is edited four ways, an archive of 65,539 entries is written with and without the Zip64 end of central directory records, and `testdata/oracle/zip-edit.txt` replays 693 answers. The edits include setting and deleting extra fields in either header or both, and the archives are opened with each of `ZIP_CREATE`, `ZIP_EXCL`, `ZIP_TRUNCATE` and `ZIP_RDONLY`. The oracle's `editb` requests do the same on a buffer source in fragments of 1 byte to 4 KiB, or one, which clones the start of the archive where it can (`Archive::close_to_cloning`): 2,000 are compared on each run, of which about half clone. Each archive the port writes is opened again and must have the entries that are left, in order, with their names, comments, attributes, times, sizes and data, unless bytes in it look like end records (see below).
- **Writing.** For the same input, the port writes the same archive as libzip, byte for byte. libzip compresses with zlib's raw deflate (`windowBits` −15) at level 9 and `memLevel` 9 unless told otherwise (`zip_algorithm_deflate.c`), so this needs `hivepack-deflate` to give zlib's output at those settings. Torrentzip output is compared too.
- **Fuzzing.** A fuzzer compares the port with the libzip oracle under AddressSanitizer, seeded with libzip's OSS-Fuzz corpus. For now `fuzz/fuzz_targets/zip_open.rs` opens its input and asks the reading API everything, which must not panic, seeded with the archives of `zip-open.txt`, and `fuzz/fuzz_targets/zip_edit.rs` makes the edits its first bytes pick and writes the archive, which must open again with the entries as edited.
- **Beyond libzip.** Info-ZIP `unzip`, 7-Zip, bsdtar, Python and Go read everything the port writes; ZipDiff's ambiguous archives are read, and where the oracles disagree, the manifest records which one hivepack follows.

## Progress

| libzip | Port | Status |
|---|---|---|
| `zip_error.c`, `zip_error_strerror.c`, `zip_err_str.c` (generated) | `error.rs` | done |
| `zip_buffer.c`, `zip_io_util.c`, `zip_string.c` | `buffer.rs`, `io_util.rs`, `string.rs`, `source_write.rs` (`_zip_write`) | done |
| `zip_utf-8.c` | `utf_8.rs` | done |
| `zip_extra_field.c`, `zip_extra_field_api.c` | `extra_field.rs`, `extra_field_api.rs` | done |
| `zip_dirent.c` | `dirent.rs` | done but `_zip_dirent_apply_attributes`, which comes with new data |
| `zip_open.c`, `zip_new.c` | `open.rs` | done |
| `zip_hash.c` | `hash.rs` | its rules, on `HashMap` |
| `zip_name_locate.c`, `zip_get_name.c`, `zip_stat_index.c`, `zip_stat_init.c`, `zip_file_get_comment.c`, `zip_file_get_external_attributes.c`, `zip_get_archive_comment.c`, `zip_get_archive_flag.c`, `zip_get_num_entries.c` | modules of the same names, `zip.rs` | done |
| `zip_file_get_offset.c` | `file_get_offset.rs` | done |
| The reading rules of `zip_source_seek.c`, `zip_source_read.c`, `zip_source_tell.c`, `zip_source_accept_empty.c`, and the file and buffer sources | `source.rs` | done |
| `zip_fopen.c`, `zip_fopen_index.c`, `zip_fopen_index_encrypted.c`, `zip_fread.c`, `zip_fclose.c` | modules of the same names | done, without decryption |
| `zip_source_zip_new.c`, `zip_source_window.c`, `zip_source_crc.c` | modules of the same names | the reading of a whole entry |
| `zip_source_compress.c`, `zip_algorithm_deflate.c` | `source_compress.rs`, `algorithm_deflate.rs` | decompressing deflate |
| The rules of `zip_source_read.c`, `zip_source_open.c`, `zip_source_close.c`, `zip_source_at_eof.c`, `zip_source_stat.c`, `zip_source_layered.c` for those layers | `source_stack.rs` | done |
| Deflate64 (libzip has none) | `algorithm_deflate.rs`, with `Inflate9` | done: `tests/deflate64.rs` reads streams with long and far matches back to their data, checks the CRC and length, and refuses garbage after the stream with `ZIP_CHECKCONS` |
| `zip_source_zip_file_create` with a start and a length | `source_zip_new.rs`, `source_window.rs` (`UpperWindow`) | done: `Archive::fopen_index_range`, compared through the oracle's `range` requests |
| `src/ziptool.c`, `regress/programs/ziptool_regress.c` and `tryopen.c`, but for adding data, compression and encryption; `src/zipcmp.c` and `diff_output.c` for archives | `tools/ziptool` | done: 100 of libzip's tests pass |
| `zip_delete.c`, `zip_file_rename.c`, `zip_set_name.c`, `zip_file_set_comment.c`, `zip_set_archive_comment.c`, `zip_file_set_mtime.c`, `zip_file_set_external_attributes.c`, `zip_set_archive_flag.c`, `zip_unchange.c`, `zip_unchange_all.c`, `zip_unchange_archive.c`, `zip_unchange_data.c` | modules of the same names, `zipint.rs` | done |
| `zip_close.c` | `close.rs` | done for entries whose data is kept, written in whole (`Archive::close_to`) or with what is kept cloned (`Archive::close_to_cloning`), and torrentzip's order; new data (`add_data`) and recompression later |
| The writing commands of `zip_source_write.c`, `zip_source_tell_write.c`, `zip_source_commit_write.c` | `source_write.rs` | on a `Write` and `Seek` |
| Adding data, compression levels, the tests that write | | step 3, next |

Where the port differs from libzip, a `Differs from libzip:` comment says so. The differences so far:

- An archive is read through `ReadAt`, reads at a position, in place of a stack of `zip_source_t` callbacks; `Source` keeps the position and the rules of libzip's file and buffer sources (a seek outside the source fails with `ZIP_ER_INVAL`, reads stop at the length it had when opened, a failed read fails all later ones, and an empty buffer is an empty archive but an empty file is not one).
- Names are returned whole: libzip returns C strings, which end at a NUL byte in a name (`ZIP_CHECKCONS` refuses such names). Lookups compare names as libzip does, up to their first NUL.
- Times are taken as UTC, where libzip calls `mktime` in the machine's time zone; the oracle runs with `TZ=UTC`. `Archive::file_get_dos_time` gives the time as stored.
- The system error of an error is described by the standard library, whose text is `strerror`'s on Unix.
- `zip_source_zip_file_create` sets `ZIP_ER_COMPNOTSUPP` on the archive's error, not on the error it is given, which stays `ZIP_ER_OK`; `Archive::fopen_index_range` returns `ZIP_ER_COMPNOTSUPP`. The port's `ziptool` prints libzip's "No error" there.
- An entry is read through a struct of layers (a window on the archive, then decompression, then the CRC check), each with the state libzip keeps in its `zip_source_t`, in place of a chain of callbacks. Each open entry reads through a view of the archive's source with its own position, so several can be read at once from `&Archive`; a failed read fails only that entry's later reads.
- An archive is written by `Archive::close_to` to a `Write` and `Seek` of the caller's, from scratch, as libzip writes to a source that cannot clone the data it keeps; `Closed` says whether it wrote, or whether libzip would have left the file as it was or removed it. `Archive::close_to_cloning` writes as libzip does to a source that can clone, which keeps the start of the archive as it is: it asks the caller whether that length can be cloned, as libzip asks the source, and copies it from the archive's source. The archive stays open afterwards, where libzip discards it once written. On failure, both leave the archive as it was then.
- An archive can be cloned, with its changes, when its source can, which `ziptool` uses to open an entry with `fopen` while the archive is changed afterwards, as libzip's open entries read what they were opened on.
- A size or offset of exactly 0xffffffff, which the header has as 0xffffffff, has its value in the Zip64 extra field too, and so has a disk number the header has as 0xffff when the field is written: libzip adds a value only when it is larger than 0xffffffff, and never the disk number, so it then refuses the archive it wrote, with `ZIP_ER_INCONS` and `ZIP_ER_DETAIL_INVALID_ZIP64_EF`. The comparison with the oracle expects a different archive there, if the rest of the answer agrees and libzip's archive does not read back; `zip64_edge_values_read_back` writes such entries and checks that the port's does, and that libzip's does not.
- `zip_file_set_mtime` takes the time as UTC, as `_zip_u2d_time` does with `localtime_r` where the time zone is UTC, and fails as `localtime_r` does for a year past what an `int` holds, with the platform's `EOVERFLOW` (75 on Linux, 84 on macOS and the BSDs); the recorded answers, from Linux, are replayed with 75 for it.
- A comment longer than 65,535 bytes is refused with `ZIP_ER_INVAL`, where libzip's `zip_uint16_t` length cuts it. `zip_unchange_all` and `zip_unchange_archive`, which cannot fail, return nothing.
- The oracle clears `errno` before each request, and in edit requests before each edit, each entry's answers and `zip_close`: libzip gives it, stale, with `ZIP_ER_SEEK` when a local header's extra fields cannot be reached, where the port gives 0.
- Decryption comes with step 4: an encrypted entry fails with `ZIP_ER_NOPASSWD`, as in libzip without a password. Of the compression methods, deflate is read, as the oracle's libzip is built without bzip2, LZMA and Zstandard, and Deflate64, which libzip does not read: where libzip refuses such an entry with `ZIP_ER_COMPNOTSUPP` (once the password and sizes are checked, before the local header is read), the port reads it. The comparison with the oracle expects libzip's refusal there, and `tests/deflate64.rs` checks the data.

libzip's ways that the port keeps, though they surprise:

- Comments, names and data are written as they are, so bytes in them that look like an end of central directory record, or a Zip64 one and its locator, can be taken for the real one when the archive is read again.
- An archive comment removed with `zip_set_archive_comment` is still given by `zip_get_archive_comment` until the archive is written without it.
- An AES entry of AE-2 is written as AE-1, with its CRC, when it has 20 bytes or more.

## The order of work

1. **CRC-32 and inflate.** The decompressor and checksums of `hivepack-deflate`, ported from zlib 1.3.2 (`crc32.c`; `inflate.c`, `inftrees.c`, `inffast.c`). Nothing compressed can be read before them. Done: see [deflate.md](deflate.md).
2. **Reading.** Errors, buffers, extra fields, headers, file names, `open.rs`; stored and deflated entries; `tools/zip-oracle`, and `tools/ziptool`'s reading commands. Deflate64 entries, with `Inflate9` (see [deflate.md](deflate.md)): done.
3. **Writing.** Writing headers, `close.rs`, the editor; the compressor of `hivepack-deflate` (`deflate.c`, `trees.c`), with output identical to zlib's: done, see [deflate.md](deflate.md). Editing and writing archives whose data is kept, `ziptool`'s commands for it and the tests that use them: done. Adding data next.
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
