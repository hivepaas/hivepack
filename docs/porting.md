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

The reference is libzstd 1.5.7 itself, built by the `zstd` crate (0.14.3, with zstd-sys 2.1.2+zstd.1.5.7). It is a development dependency only. The tests in `crates/zstd/tests/testdata.rs` check that it is exactly that release: it compresses zstd's regression data to the sizes zstd's own harness records in `tests/regression/results.csv`. The tests build it without its x86-64 assembly loop for Huffman decoding (the `no_asm` feature), as the oracle below is built: the port follows the C loop, and on damaged input the assembly need not stop where it does.

- **Compression:** the port's output is identical, byte for byte, to libzstd's for the same input and parameters. That holds at every level and strategy, with and without a dictionary, and when compressing on several threads (libzstd's output then does not depend on the thread count).
- **Decompression:** the port gives the same output. On a bad input it fails with the same error code.
- **The checks:** tests against the data in [testdata](../testdata/README.md), streaming with chunk boundaries chosen at random, and fuzzers that compare against libzstd.

## The speed target

At least 0.95× libzstd's speed, for compression at each level and for decompression.

- **Machines:** x86-64 (Linux and Windows) and arm64 (macOS and Linux).
- **How:** with `tools/zstd-bench`, which runs the implementations in turn on the same inputs.
- **Inputs:** the Silesia corpus, zstd's regression data, and small JSON files with a dictionary.

libzstd's x86-64 Huffman decoding loop is written in assembly. zstd-sys includes it on x86-64 outside Windows, as the official build does. On Windows and on other processors, libzstd runs the C loop instead, and the benchmark's column header shows "no asm". Run the benchmark on its own (`cargo run --release -p zstd-bench`): built together with the tests, it gets their reference, which leaves the assembly out.

### Where decompression stands

On an Apple M1 Pro (October 2026), the Silesia corpus compressed by libzstd 1.5.7 at levels 1, 3, 9 and 19, best of three rounds taken in turn:

| | Mean | Range |
|---|---|---|
| In one call (`ZSTD_decompressDCtx`) | 0.92× libzstd | 0.87–0.99× |
| Streaming, in pieces of `ZSTD_DStreamInSize` and `ZSTD_DStreamOutSize` | 0.91× | 0.87–0.98× |

It was 0.35–0.55× before the speed work. What made the difference, the largest first:

- **Copies in pieces, as libzstd's.** The port used to copy each literal run and match with an exact-length `memmove`: a library call each, for a few bytes. It now copies in libzstd's pieces of 8, 16 and 32 bytes, which on its own doubled the speed.
- **One sequence loop per literal buffer.** The main loop is compiled once for literals in the output, once for another buffer, so its copies do not ask which buffer each time.
- **One load per table cell.** A sequence table cell is a packed `u64`, and a Huffman cell a packed `u16` or `u32`, read at once, where the compiler had read each field separately.
- **Huffman symbols gathered.** The 4-stream X1 loop gathers each stream's five symbols in a register and writes them at once: one bounds check instead of five. On inputs whose literals dominate, such as `sao`, that is 9%.
- **32-byte pieces for matches 32 bytes back or more**, the same bytes with half the bounds checks.
- **Indices that cannot overflow.** Masking an index to `isize::MAX`, which changes no valid index, lets the compiler drop one of the two comparisons of each bounds check.

Tried, and not worth it: prefetching each match as libzstd does on arm64 (the numbers are in [safety.md](safety.md)), and copying long matches with `copy_within` or in 64-byte pieces. x86-64 is not measured yet.

What is left is bounds checks: libzstd's fast-path condition keeps the sequence loop's copies in bounds, but the compiler cannot see it. The `unsafe-fast` feature, off by default, makes those copies without them (see [unsafe.md](unsafe.md)):

| With `unsafe-fast` | Mean | Range | At 0.95× or more |
|---|---|---|---|
| In one call | 0.95× | 0.92–0.98× | 29 of 48 (safe: 7) |
| Streaming | 0.96× | 0.87–1.00× | 41 of 48 (safe: 2) |

How much it gains depends on how the compiler lays out the loop, which is fragile: a version of the same copies that returned an error from the loop when its buffers did not fit was slower than the safe code, by up to 10%, through spilled registers alone. Measure again after changing the loop.

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
| `decompress/huf_decompress.c` (decoding) | `decompress/huf_decompress.rs` | done | `hufdec`: streams made by libzstd's encoder, decoded with each table and loop (the fast loop and the fallback, which check input differently), at the right size and wrong ones, and damaged |
| `decompress/zstd_decompress_internal.h` | `decompress/zstd_decompress_internal.rs` | done | |
| `decompress/zstd_decompress_block.c` | `decompress/zstd_decompress_block.rs` | done | `blocks`: blocks from libzstd's block compressor at several levels and block sizes, decoded one after the other into outputs of various sizes (so the literals sit in the extra buffer, the input, the output, or split), stored blocks in between, and damaged blocks. Test-only counters check that every literal placement and sequence loop is reached; the prefetching loop, which libzstd uses after loading a dictionary or past 16 MiB of history, is forced on every block libzstd decodes |
| `decompress/zstd_ddict.c` | `decompress/zstd_ddict.rs` | done | the frame tests below, with every dictionary as a `ZSTD_DDict` too |
| `decompress/zstd_decompress.c` (frames, one call) | `decompress/zstd_decompress.rs` | done | `tests/decompress.rs`: every test file decoded with `ZSTD_decompressDCtx` (`_usingDict`, `_usingDDict` where the set has a dictionary), and the frame information functions (`ZSTD_getFrameContentSize`, `ZSTD_findDecompressedSize`, `ZSTD_findFrameCompressedSize`, `ZSTD_decompressBound`, `ZSTD_getDictID_fromFrame`). `tests/dctx.rs`: contexts used for several calls in a row, with random parameters, dictionaries loaded, referenced, used as a prefix or several at once, on frames from libzstd's compressor, some damaged. `frames` in the oracle: the block size limit (`ZSTD_d_maxBlockSize`), which libzstd's public API cannot reach from Rust |
| `decompress/zstd_decompress.c` (streaming) | `decompress/zstd_decompress.rs` | done | `tests/stream.rs`: every test file streamed through `ZSTD_decompressStream` and the port in the same pieces (all at once, block by block, random sizes from one byte up, one byte at a time, and with a stable output buffer), comparing each call's result, how far it reads and writes, and its output; frames up to 40 times longer than their window, so that the decoder's buffer wraps around, with dictionaries, skippable frames and damage; parameters and dictionaries refused in the middle of a frame. `tests/dctx.rs`: streaming mixed with one-call decompression on the same contexts, with dictionaries and DDict sets. `stream` in the oracle: the block size limit, and calls that go on after an error, which the `zstd` crate refuses |
| `common/bitstream.h` (writing) | `common/bitstream.rs` | done | `bitc`: bits added and flushed in random steps, into outputs of every size up to and past the one they need |
| `common/fse.h` (encoding) | `common/fse.rs` | done | `fsecompress`, and the costs in `fsectable` (`FSE_bitCost`, `FSE_getMaxNbBits`) |
| `compress/hist.c` | `compress/hist.rs` | done | `hist`: every counting function, below and above the size where libzstd counts in four tables, with the largest symbol given right, too small and too large |
| `compress/fse_compress.c` | `compress/fse_compress.rs` | done | `fseoptlog`, `fsenorm` (including distributions made to need libzstd's second method), `fsencount` (in buffers of every size, and damaged distributions), `fsectable` and `fsectablerle` (every word of the table), `fsecompress` (in outputs around the size where libzstd stops checking) |
| `compress/huf_compress.c` | `compress/huf_compress.rs` | done | `hufctable` (every element, and the description), `hufoptlog`, `hufreadctable` (descriptions from libzstd, damaged, and random), `hufcompress`: one or four streams, in runs of blocks from the same source, each given the table the block before left, as the block compressor gives it; previous tables to check, to trust, or none; every flag; and outputs that are plenty, tight or too small |
| the rest of `lib/compress`, `lib/dictBuilder` | | later | |

The comparisons go through `tools/zstd-oracle`, a small C program built with libzstd 1.5.7's sources that answers requests by calling the internal C function. `crates/zstd/src/oracle.rs` asks the port the same requests and compares the answers as text: thousands per run where the oracle is built (Linux and macOS in CI). `testdata/oracle/common.txt` replays about 2,400 earlier answers everywhere else, including Windows, 32-bit and big-endian machines. The encoder's requests are in `crates/zstd/src/oracle_compress.rs`, and `testdata/oracle/compress.txt` replays about 1,900 of their answers. For tables, the oracle answers every cell, with the ones a function leaves alone still holding the filler they started with, so the port must write exactly the cells libzstd writes: libzstd keeps tables from block to block and reads old cells back.

The frame tests call libzstd through the `zstd` crate. On 32-bit and big-endian machines, libzstd itself behaves differently from the port on some inputs: it accepts windows up to 2^30 only on 32-bit machines, checks damaged Huffman input with its older loop, and places dictionary IDs differently in its set. There the tests compare only the files libzstd decodes, and `tests/dctx.rs` does not run.

For 4-stream Huffman input, libzstd uses a fast loop when it can and an older loop otherwise, and the two check corrupted input differently. libzstd skips the fast loop on processors without BMI2 and on big-endian or 32-bit machines; the port always tries it, as libzstd does on the 64-bit little-endian machines it mostly runs on. The oracle sets `HUF_flags_bmi2` the way the decoder does, so it takes the same path.

libzstd decodes in place when the input sits at the end of the output buffer. The port takes the output and the input as separate slices, which cannot overlap, so that case does not arise.

Two places in libzstd 1.5.7's handling of several dictionaries at once (`ZSTD_d_refMultipleDDicts`) read or write memory they should not. The port does what libzstd means to do, and the tests stay away from both:

- **A use-after-free.** When a frame names a dictionary in the set, `ZSTD_DCtx_selectFrameDDict` calls `ZSTD_clearDict`, which frees a dictionary loaded with `ZSTD_DCtx_loadDictionary` (or a prefix) while that frame and the rest of the call still decode with it. AddressSanitizer reports it. It is still there in libzstd's development branch in October 2026. The port keeps the dictionary alive, so the result is what libzstd gives when the freed memory happens to be intact.
- **Reads and writes one slot past the set's table**, when a search starts in its last slot. libzstd's development branch fixes it (commit c6f91a4), and the port takes that fix: the search wraps around to the first slot.

Otherwise the set behaves as libzstd's does, including a quirk: a search stops at the first DDict of ID 0 (raw content), which libzstd takes for an empty slot, and returns it whatever ID was asked for. Which DDict comes back depends on where each one sits in the table, so the port uses the same table, hash and growth rule. The ID is hashed as little-endian bytes; libzstd hashes it in the machine's byte order, so on big-endian machines its slots differ.

Where libzstd copies with `ZSTD_wildcopy` and the copies built on it, in pieces of 8, 16 or 32 bytes that may write up to 32 bytes past the end of a copy, the port copies in the same pieces. Its buffers then hold what libzstd's hold, those extra bytes included. The copies stay within the margins libzstd keeps for them (`WILDCOPY_OVERLENGTH`) in every buffer; in the port a mistake there would be a bounds-check panic, not a read out of bounds. The extra bytes can differ in one way: when libzstd copies them from memory it never wrote, such as its literals buffer before the first block, which the port starts as zeros. They land where later writes go, on literals already read, or past the output, so they do not show, with one exception. When streaming, libzstd's own buffer is a ring: past the end of a block may be the oldest output, still in the buffer though out of the window. A damaged frame whose offsets reach back further than its window can read those bytes. Valid frames never reach that far, and libzstd does not check offsets against the window either.

For the encoder's entropy coding:

- **The tables' layout.** An `FSE_CTable` is an array of `U32` words read through `U16` and struct views, and libzstd reads old tables back through the same views. The port keeps the array and its layout, with the `U16` as the halves of each word, low half first, as on the little-endian machines libzstd runs on.
- **64-bit results.** libzstd's registers are `size_t`. The bytes written are the same with 32-bit ones, but whether a stream fits its output is decided 8 bytes before the end, the size of the register. The port decides as libzstd does on 64-bit machines.
- **Workspaces.** libzstd fails when its caller's workspace is too small for a table. The port's functions have workspaces large enough for any table, so those errors cannot happen; libzstd's callers never meet them either.
- **A saved Huffman table.** When libzstd keeps a new Huffman table for the next block, it copies the whole array from its workspace, cells past the table's largest symbol included, which hold whatever the workspace held. The port's are zeros. libzstd never reads those cells: a saved table is checked before it is used again, and the check stops at the table's largest symbol.

libzstd keeps literals inside the output buffer when it has room, and the port puts them in the same place: corrupted input can make the output run over them, and the result must still match.

When streaming, the port follows libzstd's ring buffer exactly: its size, when the decoder goes back to the buffer's start, and where the older part of the window is, so that even damaged frames give the same output. Three differences:

- **Positions after an error.** When `decompress_stream` fails, the input and output positions stay where they were. libzstd leaves them too, except after an error in the first bytes of a header, where it marks the input as read.
- **Where the window is.** libzstd tells whether output continues the previous output by comparing addresses; the port compares positions within the frame's buffer. They differ only if another buffer happened to end exactly where that one starts.
- **No bufferless API.** `ZSTD_decompressBegin`, `ZSTD_decompressContinue`, `ZSTD_nextSrcSizeToDecompress`, `ZSTD_nextInputType` and `ZSTD_insertBlock` keep the caller's earlier output buffers as the window between calls, which safe Rust cannot. The port has them inside, for `decompress_stream`.

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
  - the sizes of C structures (`ZSTD_sizeof_*`, `ZSTD_estimate*Size`);
  - libzstd's own thread pool (the port uses Rust threads);
  - `ZSTD_trace`.
- Deprecated functions that other calls replace: `ZSTD_initDStream_usingDict`, `ZSTD_initDStream_usingDDict` and `ZSTD_resetDStream` are `reset` followed by `load_dictionary` or `ref_ddict`.
- The bufferless streaming API (see above).

## Following new releases

When libzstd releases a new version:

1. Diff `lib/` between the two tags and port each change.
2. Update `UPSTREAM_VERSION`, the `zstd` crate that provides the reference, and `testdata/zstd/regression/results.csv`.
3. Run everything again.

## Licenses

The port is derived from libzstd, which is under BSD-3-Clause (or GPLv2, at the user's choice). That is why `hivepack-zstd` is under BSD-3-Clause and its [LICENSE](../crates/zstd/LICENSE) keeps Meta's copyright notice. The rest of hivepack is MIT.

- `lib/dictBuilder/divsufsort.c` is under MIT (Yuta Mori). When it is ported, its notice goes with it.
- Nothing is taken from zstd's `tests/gzip`, which is GPLv3.
