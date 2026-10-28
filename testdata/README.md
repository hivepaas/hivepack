# Test data

[manifest.json](manifest.json) lists every set of test files: where it came from, its license, and what it holds.

- **Committed sets** are in this folder. Each source keeps its license file next to its data.
- **Fetched sets** are downloaded by `scripts/testdata.py`, checked against the SHA-256 in the manifest, and unpacked into `target/testdata/<set>`. Setting `HIVEPACK_TESTDATA` puts them somewhere else.
- **Generated sets** are made in the same place by zstd's own `decodecorpus` tool, or are the oracle programs in `tools/`. The script builds them from the zstd 1.5.7 and zlib 1.3.2 releases with the system C compiler (and zstd's Makefile for `decodecorpus`).

```sh
python3 scripts/testdata.py fetch                  # the core sets: a 16 MB download
python3 scripts/testdata.py fetch --group all      # everything: 126 MB to download, 720 MB unpacked
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

zstd's `tests/gzip` is GPLv3, and nothing is taken from it.

`oracle/common.txt` holds answers the oracle gave (requests, then libzstd's answer or its FNV-1a hash when long). The port's tests replay them where the oracle cannot be built; `cargo test -p hivepack-zstd record_oracle_answers -- --ignored` rewrites the file. `oracle/compress.txt` does the same for the encoder's requests, and `cargo test -p hivepack-zstd record_compress_answers -- --ignored` rewrites it. `oracle/inflate.txt` holds zlib's answers for hivepack-deflate, and `cargo test -p hivepack-deflate --test oracle record_oracle_answers -- --ignored` rewrites it.
