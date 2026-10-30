# Porting liblz4

`hivepack-lz4` is a port of the official LZ4 library, [liblz4](https://github.com/lz4/lz4), to safe Rust: `.lz4` files, `.tar.lz4` once tar comes, and any other format that holds LZ4 blocks or frames. ZIP has no method for LZ4 (APPNOTE lists none, and libzip has none), so `hivepack-zip` does not use it. The goal is the one [porting.md](porting.md) sets for zstd: the same results as liblz4, at the same speed.

This first part ports decompression. Compression (`LZ4_compress_fast`, `lz4hc.c`'s levels and the frame compressor) comes next.

## The version

The port follows lz4 **1.10.0** (22 July 2024, tag `v1.10.0`, commit `ebb370ca83af193212df4dcbadcc5d87bc0de2f0`), still the latest release as of October 2026: `lz4-1.10.0.tar.gz` from the release's page, SHA-256 `537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b`, the checksum the release gives beside it (lz4's releases are not signed). Its `lib/` is the same, file for file, as the `liblz4/lib` that `lz4-sys` 1.11.1 bundles. `hivepack_lz4::UPSTREAM_VERSION` names it, and `block::version_number()` and `block::version_string()` give what `LZ4_versionNumber()` and `LZ4_versionString()` give, 11000 and `"1.10.0"`.

Only `lib/` is ported: it is under the BSD 2-Clause license, and the rest of lz4 (the `lz4` program, its tests and tools) under the GPL. `hivepack-lz4` is under the BSD 2-Clause license too, with liblz4's and xxHash's notices ([LICENSE](../crates/lz4/LICENSE)).

## What following the official code means

The rules of [porting.md](porting.md):

- **The same layout.** Each file of `lib/` becomes a module of the same name: `lz4.c` becomes `crates/lz4/src/lz4.rs`, `lz4frame.c` `lz4frame.rs`, and the 32-bit half of `xxhash.c` (xxHash 0.6.5, which liblz4 ships) `xxhash.rs`. The public items are in two modules after liblz4's two headers: `hivepack_lz4::block` (`lz4.h`) and `hivepack_lz4::frame` (`lz4frame.h`).
- **The same names**, in snake case, with the C name in every doc comment: `LZ4_decompress_safe_partial` becomes `block::decompress_safe_partial`, `LZ4F_decompress` `DecompressionContext::decompress`.
- **The same results.** A block function returns liblz4's result: the size decoded, or a `DecodeError` whose `number()` is liblz4's negative result, `-(position) - 1`, the position in the block where the decoder found the error. A frame call returns liblz4's hint, or its error code, as `frame::Error` with the same numbers and the names `LZ4F_getErrorName()` gives (`"ERROR_frameType_unknown"`).
- **The same writes.** liblz4 decodes with wild copies, 8, 16 or 32 bytes at a time, writing past the end of a literal run or a match where the block's rules leave room. The port makes the same copies, so the output holds the same bytes as liblz4's, past what was decoded too, and a malformed block (an offset of 0, which liblz4 does not refuse) decodes to the same bytes.
- **Differences are marked** with a comment starting `Differs from liblz4`.

### The differences

- **Buffers, not pointers.** Where liblz4 takes a pointer to the output and finds the dictionary by comparing pointers (`dictStart + dictSize == dest`), the port takes slices: `block::decompress_safe_using_dict` has the dictionary apart from the output, and `block::decompress_safe_with_prefix` has it before the output, in the same buffer. The decoder is `LZ4_decompress_generic` with indices into that buffer, its prefix and its dictionary. The checks for pointers that wrap around the address space are left out, as indices cannot.
- **The fast loop is always on.** liblz4 decodes most of a block in its fast loop (`LZ4_FAST_DEC_LOOP`) on x86, x86-64 and arm64 (with GCC, or Apple's compilers), and in its safe loop alone elsewhere. The two write different bytes past what they decode; the port is liblz4 with the fast loop, on every machine.
- **`StreamDecode` keeps its own history.** liblz4's `LZ4_decompress_safe_continue` remembers where the last block was decoded, and decodes the next as a continuation if it is right after it, or with the last blocks as a separate dictionary if not. The port keeps a copy of the last 64 KB and decodes each block after it, as liblz4 does when the blocks are decoded one after another in one buffer. The output is the same either way; a malformed block can fail at another position, or not fail, as it can between liblz4's own two ways (a match that ends in the block's last 5 bytes is refused when it starts in a separate dictionary, and not always when it starts in the output: liblz4's shortcut copies it unchecked).
- **The frame context's history.** `LZ4F_dctx` points at the history its next block refers to, which is in the caller's output, in its own buffer, or in the dictionary the caller gave. The port's context knows which of those it is (`DictAt`), and keeps a copy of the dictionary of `decompress_using_dict`, which liblz4 asks the caller to keep. At the end of each call, it moves the history into its own buffer, as liblz4 does unless the caller promises that the output stays where it is (`stableDst`), which the port does not take.
- **Errors are kept.** After an error, liblz4 says the frame context is in an undefined state; the port's returns the same error until `reset`. The comparisons stop at the first error.
- **Not ported:** the `LZ4_decompress_fast` functions, deprecated in liblz4 as unsafe on malformed input; in-place decompression (the input and output in one buffer); `LZ4_decoderRingBufferSize`; custom allocators (`LZ4F_CustomMem`); and `lz4file.c`, whose reader works on a `FILE*`, reads one frame only, and fails on a file of less than 19 bytes.

### `.lz4` files

`hivepack_lz4::Decoder` reads what `lz4 -d` reads, as an `std::io::Read`: frames one after another, skippable frames skipped, and the legacy format (`lz4 -l`, which the Linux kernel's images use: blocks of 8 MB, the last ended by the end of the input or by a magic number). `lz4 -d` itself, `programs/lz4io.c`, is under the GPL; `Decoder` is the port's own, from the frame format's description (`doc/lz4_Frame_format.md`) and what `lz4 -d` 1.10.0 does with each case:

- An empty input is an empty stream; data that is not a frame, at the start or after the frames, is an error (`lz4 -d` says "Stream followed by undecodable data" for the latter, and fails); so is a frame or magic number cut short, or damaged data.
- Unlike `lz4 -d` 1.10.0, a legacy frame may follow a frame of the frame format, as the description says (`lz4 -d` reads its magic number as a frame header and fails with `ERROR_frameType_unknown`), and a skippable frame cut short at the end of the input is an error (`lz4 -d` seeks past the end of its file).

## How it is shown

The reference is liblz4 1.10.0 itself, reached two ways: built from the sources bundled in `lz4-sys` 1.11.1 and called through the `lz4` crate 1.28.1, both development dependencies only; and `tools/lz4-oracle`, a small C program built from the release tarball by `scripts/testdata.py`, as `tools/bzip2-oracle` is for libbzip2.

- **`tests/oracle.rs`** compares what the `lz4` crate cannot reach, call by call. Block requests decode with every function (`LZ4_decompress_safe`, `_partial`, `_usingDict` with the dictionary apart or right before the output, and their partial forms) into an output filled with a pattern; the port must return the same result, the error position included, and leave the same bytes in all of the output. The blocks are liblz4's, at every level from acceleration 70 to HC 12, some damaged or cut short; the second and later blocks of liblz4's linked frames, with the 64 KB before them as their dictionary (all of it, 65,535 bytes, or less); and blocks made up by the test, valid or not, with every literal and match length, offsets from 0 to 65,535 and past the history, and the end-of-block rules kept or broken. Stream requests decode blocks one after another with `LZ4_decompress_safe_continue`, with and without a dictionary. Frame requests decode liblz4's frames, of every block size, block mode, checksum and level, and frames the test puts together (linked blocks with their dictionary, every header flag and field, reserved bits, wrong versions and sizes, wrong content sizes, skippable frames in front), damaged, cut short or followed by more, in random pieces of input and output, some of the same output size for every call (to flush a block over several calls); the port must answer each `LZ4F_decompress` and `LZ4F_getFrameInfo` call as liblz4 does, with the hint or error, the bytes read and written, and the frame info, then a hash of all the output. XXH32 is compared in one call and streamed. 1,206 requests are compared with liblz4 where the oracle is built (Linux and macOS in CI), and `testdata/oracle/lz4.txt` replays 568 earlier answers everywhere else, including Windows, 32-bit and big-endian machines.
- **`tests/lz4.rs`** compares with liblz4 through the `lz4` crate on every machine CI tests: blocks liblz4 compressed at every level, up to 2 MB, decoded whole and partially, and damaged ones, which both must decode the same or refuse; frames liblz4 compressed with every setting, up to 6 MB, decoded in pieces of every size, and damaged ones.
- **`tests/decoder.rs`** reads `.lz4` streams with `Decoder`: liblz4's frames one after another, skippable frames between them, legacy frames of 8 MB blocks (made from liblz4's blocks), and what ends a stream (nothing, data that is not LZ4, trailing data, frames cut short anywhere). Files written by the `lz4` program 1.10.0 (`-l`, `-9 --content-size -BD -B4`, `-1 --no-frame-crc -BX`, and those concatenated) were read the same as `lz4 -d` reads them before the first commit.
- **A unit test** checks XXH32 against xxHash's own values.
- **`fuzz/fuzz_targets/lz4.rs`** decodes its input as a block with both, comparing the result and every byte of the output; reads it as a frame through the `lz4` crate's `Decoder` and the same loop over the port's context, comparing every read; and decodes it in the ways the `lz4` crate cannot reach, and with `Decoder`, for panics (see [fuzz/README.md](../fuzz/README.md)). Before the first commit it ran for 20 minutes on 8 cores (31 million inputs), seeded with the recorded requests, with overflow checks and debug assertions on, and for 7 minutes on 4 cores (12 million) after the speed work: no difference and no panic.

Running the comparisons found what is behind two of the differences above: liblz4's two ways of decoding a block after a dictionary give different results on malformed blocks (the fuzzer), and liblz4's frame context points before the output when a block flushed from its buffer over several calls ends a call, and then copies nothing (`tests/lz4.rs`; the port does the same without the pointer).

## The speed target

At least 0.95× liblz4's speed, as for zstd and zlib, measured with `tools/lz4-bench` on the Silesia corpus (`python3 scripts/testdata.py fetch --group bench` fetches it):

```sh
cargo run --release -p lz4-bench -- [--levels 1,9] [--frame] target/testdata/silesia
```

Blocks are decoded in one call each, with room for all the output. With `--frame`, frames of 4 MB linked blocks with a content checksum (`lz4`'s defaults) are read by each library's reader. The tool times lz4_flex too, the other LZ4 in Rust, with its safe code (its default) or, built with `--no-default-features`, its unsafe code.

### Where it stands

Below the target. AMD Ryzen 9 9950X (x86-64, Linux), October 2026, the 12 Silesia files compressed by liblz4 at levels 1 and 9, decoded as blocks in one call each, best of five rounds taken in turn, on one pinned core of a machine that other jobs kept busy (so the absolute speeds are low and some files noisy; the ratios are what to read):

| | Mean | Range | At 0.95× or more |
|---|---|---|---|
| hivepack-lz4 | 0.77× liblz4 | 0.65–0.87× | 0 of 24 |
| lz4_flex 0.14.0, its safe code (its default) | 0.79× | 0.64–0.97× | 1 of 24 |

lz4_flex with its unsafe code was at 0.68–0.98× on five of the files (`dickens`, `mozilla`, `nci`, `reymont`, `x-ray`), where the port was at 0.73–0.85×.

As first ported, the port was at 0.65–0.86×. Most of the gap is bounds checks in the fast loop: with the reads and writes of its main copies unchecked, in a scratch copy, it went to about 0.9×. The port now decodes the most common sequence (a token, up to 14 literals and an offset in the next 18 bytes, and a match of up to 18 bytes) through windows of the input and output of a known size, where the compiler sees the copies are in bounds, and makes wild copies whose source ends before their destination in one copy; text files gained most (`dickens` from 0.64× to 0.77–0.79×). Decoding the rest the same way, and a feature with unchecked copies as `hivepack-zstd`'s `unsafe-fast` (which needs HivePaaS's approval, see [unsafe.md](unsafe.md)), are next. arm64 is not measured yet.

## Progress

| liblz4 | Port | Status | Checked against liblz4 by |
|---|---|---|---|
| `lz4.c`: decoding | `lz4.rs` | done | `tests/oracle.rs`, every function, result, error position and byte written; `tests/lz4.rs` |
| `lz4.c`: `LZ4_streamDecode_t` | `lz4.rs`, `StreamDecode` | done | `tests/oracle.rs`, blocks one after another, with and without a dictionary |
| `xxhash.c`: XXH32 | `xxhash.rs` | done | xxHash's values; `tests/oracle.rs`, in one call and streamed |
| `lz4frame.c`: decoding | `lz4frame.rs` | done | `tests/oracle.rs`, call by call; `tests/lz4.rs` |
| `lz4.c`: encoding | | next | |
| `lz4hc.c` | | next | |
| `lz4frame.c`: encoding | | next | |
| `lz4file.c` | `decoder.rs`, `Decoder`, the port's own | done | `tests/decoder.rs`, and the `lz4` program's files |

## Following new releases

When lz4 releases a new version:

1. Diff the two tags' `lib/` and port each change.
2. Update `UPSTREAM_VERSION`, the release in `testdata/manifest.json`, and the `lz4-sys` version that bundles it.
3. Run everything again.
