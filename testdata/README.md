# Test data

[manifest.json](manifest.json) lists every set of test files: where it came from, its license, and what it holds.

- **Committed sets** are in this folder. Each source keeps its license file next to its data.
- **Fetched sets** are downloaded by `scripts/testdata.py`, checked against the SHA-256 in the manifest, and unpacked into `target/testdata/<set>`. Setting `HIVEPACK_TESTDATA` puts them somewhere else.
- **Generated sets** are made in the same place by zstd's own `decodecorpus` tool, or are the oracle programs in `tools/`. The script builds them from the zstd 1.5.7, zlib 1.3.2, bzip2 1.0.8, XZ Utils 5.8.4, libzip 1.12.1 and nettle 3.10.2 releases with the system C compiler (and zstd's Makefile for `decodecorpus`), and `tools/age-oracle` and `tools/tar-oracle` with Go, which downloads the modules their `go.sum` pins.

```sh
python3 scripts/testdata.py fetch                  # the core sets: a 16 MB download
python3 scripts/testdata.py fetch --group all      # everything: 129 MB to download, 734 MB unpacked
python3 scripts/testdata.py list                   # every set, and where it lives
```

Tests skip a set that has not been fetched and print a note. CI sets `HIVEPACK_TESTDATA_REQUIRED` (for example to `core,generated`), and then a missing set fails the test instead.

## What a set holds

Each set has a `kind`:

| Kind | Meaning |
|---|---|
| `frames` | Every `.zst` file decodes. `originals: beside` means `x.zst` decodes to `x` whenever that file exists, and `zeros` lists frames that decode to runs of zero bytes. |
| `bad-frames` | Every `.zst` file fails to decode. |
| `inputs` | Every file is data to compress. |
| `dictionaries` | Every file is a dictionary, with inputs to compress using it. |
| `dict-frames` | `.dict` files are dictionaries, and each frame decodes with the one its header names. |
| `fuzz` | Inputs that fuzzers found or used. No outcome is expected; they are for comparing against libzstd and for checking that nothing panics. |
| `archives` | Archives for hivepack-extract's tests, kept as they were published and never unpacked; what each must do is in the test that reads it. |

`expect` marks files whose outcome differs from their kind, with the reason. The outcome is always libzstd 1.5.7's, even where the source of the file expected another one. `crates/zstd/tests/testdata.rs` checks every expectation against libzstd 1.5.7.

## Sources

| Set | From | License | Where |
|---|---|---|---|
| `zstd-golden-*` | zstd v1.5.7 `tests/`: golden frames, frames that must fail, inputs and dictionaries | BSD-3-Clause | committed, `zstd/` |
| `zstd/regression/results.csv` | zstd v1.5.7 `tests/regression`: compressed sizes for each dataset, configuration and API | BSD-3-Clause | committed, `zstd/` |
| `klauspost-good`, `klauspost-bad` | klauspost/compress (Go) `zstd/testdata` `good.zip` and `bad.zip`, unpacked; the Go error messages are left out | BSD-3-Clause | committed, `klauspost/` |
| `aircompressor-*` | airlift/aircompressor (Java) zstd test files | Apache-2.0 | committed, `aircompressor/` |
| `ruzstd-*` | ruzstd's window-size frames, dictionary tests and fuzzer findings | MIT | committed, `ruzstd/` |
| `zstd-regression-data` | the data zstd's regression tests use (silesia.tar and github.tar samples) | BSD-3-Clause | fetched, `core` |
| `klauspost-*` (others) | klauspost/compress: decodecorpus frames, zero runs, a dictionary set, encoder crash inputs, regression inputs | BSD-3-Clause | fetched, `core` |
| `decodecorpus`, `decodecorpus-dict` | 300 frames (seed 1), and 100 frames with a dictionary (seed 2), each with its original | BSD-3-Clause | generated |
| `zstd-fuzz-*` | zstd's fuzzing corpora for its decoding targets | BSD-3-Clause | fetched, `fuzz` |
| `silesia` | the Silesia corpus, for benchmarks | none stated | fetched, `bench` |
| `zstd-oracle` | `tools/zstd-oracle`, built with the zstd 1.5.7 sources: libzstd's internal functions, for comparing the port with them | MIT and BSD-3-Clause | generated |
| `zlib-1.3.2-source` | the zlib 1.3.2 release, to build the next set from | Zlib | fetched, `generated` |
| `zlib-oracle` | `tools/zlib-oracle`, built with the zlib 1.3.2 sources: zlib's inflate and deflate, for comparing hivepack-deflate with them | MIT and Zlib | generated |
| `bzip2-1.0.8-source` | the bzip2 1.0.8 release, to build the next set from, with its samples (`sample1.ref` to `sample3.bz2`); its tarball is signed by bzip2's maintainer, Mark Wielaard | bzip2-1.0.6 | fetched, `generated` |
| `bzip2-oracle` | `tools/bzip2-oracle`, built with the bzip2 1.0.8 sources: libbzip2's API, for comparing hivepack-bzip2 with it | MIT and bzip2-1.0.6 | generated |
| `xz-5.8.4-source` | the XZ Utils 5.8.4 release, to build the next set from, with its test files (`tests/files`); its tarball is signed by XZ Utils' maintainer, Lasse Collin | 0BSD | fetched, `generated` |
| `xz-oracle` | `tools/xz-oracle`, built with the liblzma sources of XZ Utils 5.8.4: liblzma's API, for comparing hivepack-xz with it | MIT and 0BSD | generated |
| `nettle-3.10.2-source` | the nettle 3.10.2 release, to build the next set from; its tarball is signed by nettle's author, Niels Möller | LGPL-3.0-or-later or GPL-2.0-or-later | fetched, `generated` |
| `nettle-oracle` | `tools/nettle-oracle`, built with nettle 3.10.2's AES, SHA-1, HMAC and PBKDF2 sources: for comparing hivepack-crypto with them | MIT, and nettle's licenses | generated |
| `tar-oracle` | `tools/tar-oracle`, built with Go 1.27.2's archive/tar, the release its `go.mod` names: for comparing hivepack-tar with it | MIT, and BSD-3-Clause (Go) | generated |
| `age-oracle` | `tools/age-oracle`, built with Go, age v1.3.2 (`filippo.io/age`) and `golang.org/x/crypto` v0.55.0, the release age requires, as its `go.sum` pins: for comparing hivepack-crypto and hivepack-age with what age runs | MIT, and BSD-3-Clause (age, `x/crypto`) | generated |
| `libzip-1.12.1-source` | the libzip 1.12.1 release, to build the next set from, and its `regress/` archives | BSD-3-Clause | fetched, `generated` |
| `go-tar` | Go 1.27.2's test archives for archive/tar (`src/archive/tar/testdata`), with Go's LICENSE | BSD-3-Clause | committed, `go-tar/` |
| `cctv-age` | C2SP's CCTV test vectors for age (`c2sp.org/CCTV/age` at commit 4448f2097b2d, the module age v1.3.2 tests with), from Go's module proxy: 147 files, each with the outcome it must have and the SHA-256 of its plaintext | 0BSD, CC0-1.0 or Unlicense | fetched, `core` |
| `zipdiff-constructions` | ZipDiff (USENIX Security 2025): the 5,927 archives its `construction` program writes, which ZIP parsers read differently, made once and packed into `constructions.zip`; how, and what each folder holds, is in `zipdiff/README.md` | Apache-2.0 | committed, `zipdiff/` |
| `fifield-zipbombs` | David Fifield's zip bombs from "A better zip bomb" (WOOT 2019): `zbsm.zip` (42 kB to 5.5 GB), `zblg.zip` (10 MB to 281 TB) and `zbxl.zip` (46 MB to 4.5 PB, Zip64), whose entries share one stream | public domain | fetched, `core` |
| `unicode-18.0.0` | the Unicode Character Database 18.0.0: `UnicodeData.txt` and `CaseFolding.txt`, which `scripts/unicode.py` makes hivepack-extract's tables from, and `NormalizationTest.txt`, which its tests check them with | Unicode-3.0 | fetched, `core` |
| `zip-oracle` | `tools/zip-oracle`, built with the libzip 1.12.1, zlib 1.3.2, nettle 3.10.2 and bzip2 1.0.8 sources, and its crypto backend for GnuTLS on nettle: libzip's API, for comparing hivepack-zip with it | MIT, BSD-3-Clause, Zlib, nettle's licenses, and bzip2-1.0.6 | generated |

zstd's `tests/gzip` is GPLv3, and nothing is taken from it.

`oracle/common.txt` holds answers the oracle gave (requests, then libzstd's answer or its FNV-1a hash when long). The port's tests replay them where the oracle cannot be built; `cargo test -p hivepack-zstd record_oracle_answers -- --ignored` rewrites the file. `oracle/compress.txt` does the same for the encoder's requests, and `cargo test -p hivepack-zstd record_compress_answers -- --ignored` rewrites it. `oracle/inflate.txt` and `oracle/deflate.txt` hold zlib's answers for hivepack-deflate's decoder and encoder, and `cargo test -p hivepack-deflate --test oracle record_oracle_answers -- --ignored` (or `record_deflate_answers`) rewrites them. `oracle/inflate9.txt` holds the answers of zlib's `contrib/infback9` for the Deflate64 decoder, and `cargo test -p hivepack-deflate --test deflate64 record_inflate9_answers -- --ignored` rewrites it. `oracle/zip-open.txt`, `oracle/zip-read.txt`, `oracle/zip-range.txt`, `oracle/zip-edit.txt`, `oracle/zip-decrypt.txt` and `oracle/zip-encrypt.txt` hold libzip's answers for hivepack-zip's archives, opened, read, read in part, edited and written to a file or a buffer, encrypted by libzip and read with passwords, and encrypted and changed, and `cargo test -p hivepack-zip --test oracle record_open_answers -- --ignored` (or `record_read_answers`, `record_range_answers`, `record_edit_answers`, `record_decrypt_answers`, `record_encrypt_answers`) rewrites them. `oracle/bzip2.txt` holds libbzip2's answers for hivepack-bzip2's compressor and decompressor, and `cargo test -p hivepack-bzip2 --test oracle record_oracle_answers -- --ignored` rewrites it. `oracle/xz.txt` holds liblzma's answers for hivepack-xz's decoders, and `cargo test -p hivepack-xz --test oracle record_oracle_answers -- --ignored` rewrites it. `oracle/crypto.txt` holds nettle's answers for hivepack-crypto, and `cargo test -p hivepack-crypto --test oracle record_oracle_answers -- --ignored` rewrites it. `oracle/crypto-go.txt` holds Go's answers for the primitives age uses, and `cargo test -p hivepack-crypto --test go_oracle record_oracle_answers -- --ignored` rewrites it. `oracle/tar.txt` holds the answers of Go's archive/tar for hivepack-tar: Go's test archives and their damaged copies by name, small archives in full; `cargo test -p hivepack-tar --test oracle record_oracle_answers -- --ignored` rewrites it. `oracle/age.txt` holds age's outcomes for small files it encrypted, damaged or not, and `cargo test -p hivepack-age --test oracle record_oracle_answers -- --ignored` rewrites it. `oracle/open.txt` holds files age encrypted for hivepack-open: compressed tar archives and data, and age inside age; `cargo test -p hivepack-open --test age record_oracle_answers -- --ignored` rewrites it.
