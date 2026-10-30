# Porting liblzma

`hivepack-xz` is a port of liblzma, the library of [XZ Utils](https://tukaani.org/xz/), to safe Rust. It decodes `.xz`, `.lzma` and `.lz` files and raw LZMA1 and LZMA2 streams; tar files will use it for `.tar.xz`, and ZIP archives for their methods 14 (LZMA) and 95 (XZ). The goal is the one [porting.md](porting.md) sets for zstd: the same results as liblzma, at the same speed.

The decoders come first. The encoders, the delta and BCJ filters, and the multithreaded decoder and encoder come in later steps (see [Not ported, for now](#not-ported-for-now)).

## The version

The port follows XZ Utils **5.8.4** (9 September 2026), the current release as of October 2026: `xz-5.8.4.tar.gz` from its GitHub releases, SHA-256 `0014c7886930454fe8bd4228665b51af55eeae560ea135c9c4cd33f55b2591d9`, whose signature by Lasse Collin (key `3690C240CE51B4670D30AD1C38EE757D69184620`) was checked, and whose `src/liblzma` and `tests/files` are those of the git tag `v5.8.4`. `hivepack_xz::UPSTREAM_VERSION` names it, `hivepack_xz::version_number()` gives what `lzma_version_number()` gives, `50080042`, and `version_string()` gives `"5.8.4"`.

## What following the official code means

The rules of [porting.md](porting.md):

- **The same layout.** Each file of liblzma becomes a module named after it: `common/stream_decoder.c` becomes `crates/xz/src/stream_decoder.rs`, `lzma/lzma_decoder.c` becomes `lzma_decoder.rs`, `lz/lz_decoder.c` becomes `lz_decoder.rs`. The headers' constants and inline functions are beside the code that uses them (`lzma_common.rs`, `range_decoder.rs`), and `common.c`'s `lzma_code()` and the coders' common parts are in `common.rs`.
- **The same names**, in snake case, with the C name in every doc comment. An `lzma_stream` and its decoder are one type, `Stream`, made by the function that initialises it: `lzma_stream_decoder()` becomes `Stream::stream_decoder`, `lzma_auto_decoder()` becomes `Stream::auto_decoder`, `lzma_code()` becomes `Stream::code`.
- **The same algorithms and constants.** The CRC tables are computed while compiling, as liblzma's `crc32_tablegen.c` and `crc64_tablegen.c` compute the tables it keeps as source, and a test checks them against their definitions and check values.
- **The same results.** A call returns liblzma's code, as `Result<Status, Error>` with the same numbers (`Status::number`, `Error::number`), and reads and writes what liblzma reads and writes. The memory usage and limits are liblzma's numbers too.
- **Differences are marked** with a comment starting `Differs from liblzma`.

liblzma's coders are a chain of `lzma_next_coder` structures, each with function pointers to its code, end, check and memory functions; the port's are boxes of a trait, `NextCoder`, whose methods have liblzma's defaults (none for the check, `LZMA_PROG_ERROR` for the memory functions). `lzma_code()`'s rules are kept as they are: the actions a decoder accepts, the input that must not change after `LZMA_FINISH`, `LZMA_BUF_ERROR` on the second call that can do nothing, and `LZMA_PROG_ERROR` from then on after an error. The stream holds the totals; the caller's input and output come with each call, as an `InBuffer` and an `OutBuffer`, a slice and a position, as in `hivepack-deflate`, `hivepack-zstd` and `hivepack-bzip2`.

The LZMA decoder keeps liblzma's two modes. The resumable one, which liblzma writes as a `switch` whose `case` labels sit inside the code of a symbol so that it can stop wherever the input or the output runs out and start there again, is a `match` on the same sequence values. The fast one, the Non-resumable mode, decodes whole symbols while there are 20 bytes of input at least and room in the dictionary, with liblzma's unrolled bittrees and its branchless bit decoding: on x86-64 liblzma has this in inline assembly, elsewhere in C (`rc_c_bit`); the port has the C. The probabilities are one array in the order of `lzma_lzma1_decoder`'s fields, so that a bittree is an index into it, as liblzma's `probs` is a pointer.

The other differences:

- **The dictionary's buffer grows as it is written.** liblzma allocates the dictionary, up to 4 GiB, when the decoder starts, and leaves it as allocated; the port reserves the same memory then (failing to is `LZMA_MEM_ERROR`, as a `NULL` from `lzma_alloc()` is), and zeroes it up to where each call may write. liblzma reads only what it wrote, so nothing differs.
- **The Index hash** is liblzma's: SHA-256 of each Block's two sizes. liblzma hashes them as they are in memory, the port in little-endian order, on the Blocks' side and the Records' alike, so the comparison is the same.
- **The memory usage** counts liblzma's structures by their sizes on 64-bit machines (`sizeof(lzma_lzma1_decoder)`, 28,352 bytes, and the others), on every machine: the numbers are liblzma's on x86-64 and arm64, and the port's own structures are not those.
- **What C needs and Rust does not:** custom allocators, `lzma_end()` (dropping the stream), and the checks of null pointers and reserved members. A buffer whose `pos` is past its end fails with `LZMA_PROG_ERROR`.
- **A stream is `Send`**, so that it can be moved to another thread, as an `lzma_stream` can: `NextCoder` asks it of every coder.
- **CRC32 and CRC64** are computed slice-by-eight from their tables, as liblzma's generic code does; liblzma's CLMUL, ARM64 and LoongArch versions give the same values.

### What liblzma does, kept

- **A known size with an end marker, split.** liblzma decodes `.lzma` files that have their size in the header and an end of payload marker after the data, which some encoders write (XZ Utils' `good-known_size-with_eopm.lzma`). When the input given to a call ends inside that marker, the next call refuses it with `LZMA_DATA_ERROR`: whether the marker may come is a local variable of `lzma_decode()`, set when the size is reached, and forgotten when the call returns in the middle of the marker. `xz -dc` 5.8.3 fails so on valid files whose marker crosses its 8 KiB reads ("Compressed data is corrupt"), and decodes them when read whole. The port gives the same results, call by call, so as not to differ from liblzma; the decoder of LZMA1 with LZMA1EXT and a known size is affected too.
- **The check before the Stream Header.** `lzma_get_check()` on an `.xz` decoder that has not read its Stream Header returns `stream_flags.check`, which liblzma has not set yet: whatever its allocation held. The port returns `LZMA_CHECK_NONE`, and the oracle (below) allocates with `calloc` to give the same.

## How it is shown

The reference is liblzma 5.8.4 itself, through `tools/xz-oracle`, a small C program built from the release tarball by `scripts/testdata.py`, with the decoders and encoders of LZMA1 and LZMA2, the `.lz` decoder, and the three checks; and, for the fuzzer and the benchmark, built from the sources bundled in `liblzma-sys` 0.4.9 (its `static` feature, so that a system liblzma, which may be another version, is never used) and called through the `liblzma` crate.

- **`tests/oracle.rs`** compares every call: a request is a decoder and a list of steps, calls with some input and output space and an action, memory limits set, and queries of the memory usage, the limit and the check; the port must answer each as liblzma does, with the result and the bytes read and written, then the totals and a hash of the output. The streams come from liblzma's encoders: `.xz` at presets 0 to 9 and extreme, with no check, CRC32, CRC64 and SHA-256; `.lzma`, with the size in its header or not, right or wrong; raw LZMA1 and LZMA2, decoded with the encoder's dictionary, a smaller one, or none, and now and then a preset dictionary; and `.lz` members, version 0 and 1, made from raw LZMA1. Some are damaged, cut short, concatenated with Stream Padding, valid or not, or followed by more, and some `.xz` Streams have a check ID the build does not support. XZ Utils' own test files, `tests/files`, are decoded too, by every decoder they suit. Each is decoded in random pieces, with the flags of the decoders, low memory limits that are reached and then raised, actions the decoders refuse, and calls after the end. 1,031 requests are compared with liblzma where the oracle is built (Linux and macOS in CI), with every return code but `LZMA_MEM_ERROR`; `testdata/oracle/xz.txt` replays 930 earlier answers everywhere else, including Windows, 32-bit and big-endian machines. Before the first commit, the same comparison ran with 450 seeds, about 550,000 requests, with overflow checks and debug assertions on: no difference and no panic.
- **`tests/files.rs`** decodes XZ Utils' test files as its `tests/test_files.sh` does with `xz -dc`: every `good-` file decodes, every `bad-` and `unsupported-` file fails, and each gives the same results decoded at once and a byte at a time (but for the end marker above). The files with delta and BCJ filters fail with `LZMA_OPTIONS_ERROR` until those filters are ported.
- **A unit test** checks the CRC tables against their polynomials, and CRC32, CRC64 and SHA-256 against their check values.
- **`fuzz/fuzz_targets/xz.rs`** decodes the fuzzer's input with each decoder, its flags, memory limit and options from the input, in pieces, against liblzma through the `liblzma` crate: every call must give the same result, bytes read and written, and output (see [fuzz/README.md](../fuzz/README.md)).

## The speed target

At least 0.95× liblzma's speed, as for zstd, zlib and bzip2, measured with `tools/xz-bench` on the Silesia corpus (`python3 scripts/testdata.py fetch --group bench` fetches it):

```sh
cargo run --release -p xz-bench -- [--presets 0,6,9] [--check none|crc32|crc64|sha256] target/testdata/silesia
```

Each run decodes a whole `.xz` Stream that liblzma wrote, in one call, on a new decoder, with room for all the output.

### Where it stands

AMD Ryzen 9 9950X (x86-64, Linux), October 2026, the 12 Silesia files at presets 0, 6 and 9 with CRC64, best of three rounds taken in turn. liblzma is built as `liblzma-sys` builds it, which on x86-64 with GCC or Clang decodes its range coder's bittrees, matched literals, reverse bittrees and direct bits in inline assembly (`LZMA_RANGE_DECODER_CONFIG` 0x1F0); on other machines, arm64 among them, liblzma has C there. Both are measured, the C one by building `liblzma-sys` with `CFLAGS=-DLZMA_RANGE_DECODER_CONFIG=0`:

| | Mean | Range | At 0.95× or more |
|---|---|---|---|
| Against liblzma with its x86-64 assembly | 0.81× | 0.74–0.89× | 0 of 36 |
| Against liblzma's C | 1.18× | 1.06–1.34× | 36 of 36 |

So the port is at liblzma's speed where liblzma is C, and below it on x86-64, where it is assembly: **the target is not met there yet.** As first ported, with the resumable mode only, as liblzma has with `HAVE_SMALL`, the port was at 0.60–0.82×; the Non-resumable mode brought it to the numbers above. Bounds checks cost about 5% (measured with them removed, which the crate's rules forbid); loading both probabilities a bittree's next bit may need before the bit is known, as the assembly does, gained nothing in Rust. Closing the rest of the gap is the next work on the decoder. arm64 is not measured yet.

## Progress

| liblzma | Port | Status | Checked against liblzma by |
|---|---|---|---|
| `common/common.c`: `lzma_code()`, `lzma_get_check()`, `lzma_memusage()`, `lzma_memlimit_*()`, `lzma_get_progress()` | `common.rs`, `lib.rs` | done | the results and totals of every call; the check and the memory functions between calls (`lzma_get_progress()`, which gives the totals for these decoders, is not compared) |
| `check/`: CRC32, CRC64, SHA-256 | `check.rs` | done | the polynomials and check values; every Block's check |
| `rangecoder/range_decoder.h` | `range_decoder.rs`, `lzma_decoder.rs` | done | every LZMA stream, in both modes |
| `lz/lz_decoder.c` | `lz_decoder.rs` | done | every stream, with and without preset dictionaries |
| `lzma/lzma_decoder.c` | `lzma_decoder.rs` | done | raw LZMA1 and LZMA1EXT, `.lzma` and `.lz`, valid and damaged, in pieces |
| `lzma/lzma2_decoder.c` | `lzma2_decoder.rs` | done | raw LZMA2 and every `.xz` Stream |
| `common/vli_decoder.c`, `vli_size.c` | `vli.rs` | done | every Block Header and Index |
| `common/stream_flags_decoder.c`, `stream_flags_common.c` | `stream_flags.rs` | done | every Stream Header and Footer |
| `common/filter_*.c`: the decoder's parts | `filter.rs` | done | every Block Header; the raw decoder's options and memory usage |
| `common/block_header_decoder.c`, `block_decoder.c`, `block_util.c` | `block.rs` | done | every Block, its padding and check |
| `common/index_hash.c` | `index_hash.rs` | done | every Index, valid and damaged |
| `common/stream_decoder.c` | `stream_decoder.rs` | done | every `.xz` file, with every flag |
| `common/alone_decoder.c` | `alone_decoder.rs` | done | every `.lzma` file |
| `common/lzip_decoder.c` | `lzip_decoder.rs` | done | every `.lz` file |
| `common/auto_decoder.c` | `auto_decoder.rs` | done | all three formats |

## Not ported, for now

- The encoders: `lzma_easy_encoder()`, `lzma_stream_encoder()`, `lzma_alone_encoder()`, `lzma_raw_encoder()`, LZMA1 and LZMA2 with their match finders, and the presets. Next.
- The filters other than LZMA1 and LZMA2: delta, and the BCJ filters (x86, PowerPC, IA-64, ARM, ARM-Thumb, ARM64, SPARC, RISC-V). A Block that uses one fails with `LZMA_OPTIONS_ERROR`, as in a liblzma built without it.
- The multithreaded decoder and encoder (`stream_decoder_mt.c`, `stream_encoder_mt.c`).
- The single-call functions (`lzma_stream_buffer_decode()` and the others), `lzma_index` and its decoder, `lzma_file_info_decoder()`, the MicroLZMA decoder, `lzma_block_buffer_decode()`, and the filter string functions.
- The programs: `xz`, `xzdec`, `lzmainfo`, and the scripts.

## Following new releases

When XZ Utils releases a new version:

1. Diff the two tags' `src/liblzma` and port each change.
2. Update `UPSTREAM_VERSION`, `version_number()`, the release in `testdata/manifest.json`, and the `liblzma-sys` version that bundles it.
3. Run everything again.

## Licenses

The port is derived from liblzma, which is under the BSD Zero Clause License (0BSD). `hivepack-xz` is under the same license, and its [LICENSE](../crates/xz/LICENSE) keeps the notice and says that the C has been translated, with the changes marked.
