# Porting libzstd

`hivepack-zstd` is a port of the official Zstandard library, [libzstd](https://github.com/facebook/zstd), to safe Rust. The goal is the same output as libzstd, at the same speed.

## The version

The port follows libzstd **1.5.7** (tag `v1.5.7`, commit `f8745da6ff1ad1e7bab384bd1f9d742439278e99`), the latest release as of October 2026. libzstd's `dev` branch has moved on since then; the port follows releases, not `dev`.

`hivepack_zstd::UPSTREAM_VERSION` names the release. A test checks that the reference library used by the tests is that same release.

## What following the official code means

- **The same layout.** Each file in `lib/` maps to a module in the same place: for example, `lib/common/fse_decompress.c` becomes `crates/zstd/src/common/fse_decompress.rs`.
- **The same names.** Functions keep their C names in snake case, without the prefix that only exists because C has no modules. For example, `ZSTD_decodeLiteralsBlock` becomes `decode_literals_block`. Every ported function's doc comment names its C original and file.
- **The same algorithms, constants and tables.** The compression level table (`clevels.h`) is copied as it is, and so are the parameter choices and how blocks are split. That is what makes the output identical.
- **Differences are marked.** Where the Rust code has to work differently, for example to avoid `unsafe`, a comment starting with `Differs from libzstd:` explains what changed and why.

## How it is shown

The reference is libzstd 1.5.7 itself, built by the `zstd` crate (0.14.3, with zstd-sys 2.1.2+zstd.1.5.7). It is a development dependency only. The tests in `crates/zstd/tests/testdata.rs` check that it is exactly that release: it compresses zstd's regression data to the sizes zstd's own harness records in `tests/regression/results.csv`.

- **Compression:** the port's output is identical, byte for byte, to libzstd's for the same input and parameters. That holds at every level and strategy, with and without a dictionary, and when compressing on several threads (libzstd's output then does not depend on the thread count).
- **Decompression:** the port gives the same output. On a bad input it fails with the same error code.
- **The checks:** tests against the data in [testdata](../testdata/README.md), streaming with chunk boundaries chosen at random, and fuzzers that compare against libzstd.

## The speed target

At least 0.95× libzstd's speed, for compression at each level and for decompression.

- **Machines:** x86-64 (Linux and Windows) and arm64 (macOS and Linux).
- **How:** with `tools/zstd-bench`, which runs the implementations in turn on the same inputs.
- **Inputs:** the Silesia corpus, zstd's regression data, and small JSON files with a dictionary.

libzstd's x86-64 Huffman decoding loop is written in assembly. zstd-sys includes it on x86-64 outside Windows, as the official build does. On Windows and on other processors, libzstd runs the C loop instead, and the benchmark's column header shows "no asm".

## Progress

| libzstd | Port | Status | Checked against libzstd by |
|---|---|---|---|
| `zstd_errors.h`, `common/error_private.{h,c}` | `common/error_private.rs` | done | the error codes in every comparison |
| `common/mem.h` (reads), `common/bits.h` | `common/mem.rs`, `common/bits.rs` | done | the functions that use them |
| `common/bitstream.h` (reading) | `common/bitstream.rs` | done | `bits`: random streams read in random steps |
| `common/entropy_common.c` | `common/entropy_common.rs` | done | `ncount` and `readstats`: tables made by libzstd's encoder, the same tables damaged, random bytes, and zstd's fuzzing corpora |
| `common/fse.h` (decoding), `common/fse_decompress.c` | `common/fse.rs`, `common/fse_decompress.rs` | done | `fsedtable` and `fsedecompress` |
| `common/xxhash.h` (XXH64) | `common/xxhash.rs` | done | `xxh64`, and streamed against one call |
| `common/zstd_internal.h` (format constants) | `common/zstd_internal.rs` | done | used by the decoder |
| `decompress/huf_decompress.c` (tables) | `decompress/huf_decompress.rs` | done | `hufx1` and `hufx2`: every cell of the table |
| `decompress/huf_decompress.c` (decoding loops) and the rest of `lib/decompress` | | next | |
| `lib/compress`, `lib/dictBuilder` | | later | |

The comparisons go through `tools/zstd-oracle`, a small C program built with libzstd 1.5.7's sources that answers requests by calling the internal C function. `crates/zstd/src/oracle.rs` asks the port the same requests and compares the answers as text: thousands per run where the oracle is built (Linux and macOS in CI). `testdata/oracle/common.txt` replays 2,000 earlier answers everywhere else, including Windows, 32-bit and big-endian machines.

## The order of work

1. **Common pieces:**
   - error codes;
   - little-endian reads and bit operations;
   - the bitstream reader;
   - `entropy_common` (`FSE_readNCount`, `HUF_readStats`);
   - FSE and Huffman decoding tables;
   - XXH64.

   Each one is compared with libzstd directly, for example: the same normalized counts must build the same table.
2. **The decoder:** frames, blocks, literals, sequences, dictionaries and streaming. It is done when it passes all the test data and the fuzzers.
3. **Decoder speed:** measured against the target. Any unsafe exception would be proposed here, as [safety.md](safety.md) describes.
4. **The encoder at levels 1 to 3** (`fast` and `dfast`), including entropy coding and streaming. Its output must be identical to libzstd's.
5. **The rest:**
   - the `greedy`, `lazy`, `lazy2` and `btlazy2` strategies, and the optimal parser (`btopt`, `btultra`, `btultra2`);
   - long-distance matching;
   - block splitting;
   - multi-threaded compression;
   - the dictionary builder.

## Not ported, for now

- `lib/legacy`: the formats from before zstd 0.8, v0.1 to v0.7. The tests' reference is built without them too.
- `lib/deprecated`: the old `ZBUFF` streaming API.
- `programs/`, the zstd command line. hivepack will have its own.
- Parts that exist only because the library is in C:
  - custom allocators (`ZSTD_customMem`);
  - static contexts (`ZSTD_initStatic*`);
  - libzstd's own thread pool (the port uses Rust threads);
  - `ZSTD_trace`.

## Following new releases

When libzstd releases a new version:

1. Diff `lib/` between the two tags and port each change.
2. Update `UPSTREAM_VERSION`, the `zstd` crate that provides the reference, and `testdata/zstd/regression/results.csv`.
3. Run everything again.

## Licenses

The port is derived from libzstd, which is under BSD-3-Clause (or GPLv2, at the user's choice). That is why `hivepack-zstd` is under BSD-3-Clause and its [LICENSE](../crates/zstd/LICENSE) keeps Meta's copyright notice. The rest of hivepack is MIT.

- `lib/dictBuilder/divsufsort.c` is under MIT (Yuta Mori). When it is ported, its notice goes with it.
- Nothing is taken from zstd's `tests/gzip`, which is GPLv3.
