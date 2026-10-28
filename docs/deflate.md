# Porting zlib

`hivepack-deflate` is a port of the official Deflate library, [zlib](https://zlib.net), to safe Rust. ZIP needs it first (see [zip.md](zip.md)), and gzip and every other Deflate-based format will use it too. The goal is the one [porting.md](porting.md) sets for zstd: the same output as zlib, at the same speed.

## The version

The port follows zlib **1.3.2** (tag `v1.3.2`, commit `da607da739fa6047df13e66a2af6b8bec7c2a498`, February 2026), the latest release as of October 2026. `hivepack_deflate::UPSTREAM_VERSION` names it.

## What following the official code means

The rules of [porting.md](porting.md):

- **The same layout.** Each file of zlib becomes a module of the same name: `inflate.c` becomes `crates/deflate/src/inflate.rs`, `inffixed.h` becomes `inffixed.rs`.
- **The same names**, in snake case, with the C name in every doc comment. The stream and its state are one type, `Inflate`, whose methods drop the `inflate` prefix: `inflateSetDictionary` becomes `Inflate::set_dictionary`.
- **The same algorithms, constants and tables.** The fixed-code tables of `inffixed.h` are copied as they are. The CRC tables of `crc32.h` are computed while compiling, by the functions zlib uses to write that file, and a test compares them with it.
- **The same results.** A call returns zlib's code, as `Result<Status, Error>`, and an error carries the message zlib leaves in `strm->msg`, such as `"invalid distance too far back"`.
- **Differences are marked** with a comment starting `Differs from zlib:`.

The main difference is the stream itself. zlib's `z_stream` holds pointers to the caller's input and output; the port takes them for each call as an `InBuffer` and an `OutBuffer`, a slice and a position, as `hivepack-zstd` does. Positions in the window, the code tables and the buffers are indices. A stream cannot be used before it is initialised or after it ends, so the checks zlib makes for that (`inflateStateCheck`) have nothing to check.

## How it is shown

The reference is zlib 1.3.2 itself, built from the sources bundled in `libz-sys` 1.1.30 (its `static` feature, so that a system zlib of another version is never used), called through `flate2`. They are development dependencies only.

- **`tests/zlib.rs`** decompresses streams that zlib's own compressor wrote, with the port and with zlib, in the same pieces of input and output, chosen at random from one byte up. Every call must return the same result and message and read and write the same number of bytes, and the output must be the same. The streams are raw, zlib and gzip; at levels 0, 1, 6 and 9; with windows of 512 bytes to 32 KiB; with sync, full and partial flushes in between; with preset dictionaries, right and wrong; decompressed with a smaller window than they need; with a gzip header that has every field; and 2,880 of them damaged, with bytes changed, bits flipped and cut short. The inputs are text, random bytes, runs, matches from up to 40 KiB back, and the uncompressed files in `testdata/zstd/golden-compression`.
- **`tests/infcover.rs`** is zlib's own coverage test of inflate, `test/infcover.c`, ported with the same inputs and expected results, including the messages of every data error.
- **Unit tests** compare the CRC tables with `crc32.h`, build `inffixed.h`'s tables with the ported `inflate_table` as zlib's `makefixed()` does, and check CRC-32 and Adler-32, combined or not, against their definitions.
- **`fuzz/fuzz_targets/inflate.rs`** does what `tests/zlib.rs` does with the fuzzer's input as the stream (see [fuzz/README.md](../fuzz/README.md)).

What `flate2` cannot reach is not compared with zlib call by call yet: `Flush::Block` and `Flush::Trees`, `data_type`, `inflateMark`, `inflateSync` and the gzip header fields. `infcover.rs` covers them with zlib's own expectations; a small C oracle, as `tools/zstd-oracle` is for libzstd, is the way to compare them directly.

## The speed target

At least 0.95× zlib's speed, as for zstd, measured with `tools/deflate-bench` on the Silesia corpus:

```sh
cargo run --release -p deflate-bench -- [--levels 1,6,9] [--stream] PATH...
```

### Where decompression stands

The port as it is, before any speed work. AMD Ryzen 9 9950X (x86-64, Linux), October 2026, the Silesia corpus compressed by zlib at levels 1, 6 and 9, best of three rounds taken in turn:

| | Mean | Range |
|---|---|---|
| In one call | 0.82× zlib | 0.72–0.86× |
| Streaming, in pieces of 16 KiB as zlib's `zpipe.c` | 0.89× | 0.75–1.02× |

Almost all of the time is in `inflate_fast`, and what is left is bounds checks: each input byte, table entry and output byte is checked, where zlib's pointers are not. Tried so far, with no clear gain: copying matches eight bytes at a time, tables of a fixed size so that a mask replaces the check, and reading two input bytes with one check. The speed work comes next, as it did for zstd.

## Progress

| zlib | Port | Status | Checked against zlib by |
|---|---|---|---|
| `zlib.h`, `zconf.h`, `zutil.{h,c}` (the parts inflate uses) | `zutil.rs` | done | the return codes and messages in every comparison |
| `adler32.c` | `adler32.rs` | done | the definition; the trailers of zlib streams |
| `crc32.c`, `crc32.h` | `crc32.rs` | done | `crc32.h`'s tables; the definition; the trailers of gzip streams |
| `inftrees.{h,c}`, `inffixed.h` | `inftrees.rs`, `inffixed.rs` | done | `inffixed.h` rebuilt; `infcover.c`'s `cover_trees`; every dynamic block in `tests/zlib.rs` |
| `inffast.{h,c}` | `inffast.rs` | done | `tests/zlib.rs`; `infcover.c`'s `cover_fast` |
| `inflate.{h,c}` | `inflate.rs` | done | `tests/zlib.rs`; `infcover.c`'s `cover_support`, `cover_wrap` and `cover_inflate` |
| `deflate.{h,c}`, `trees.{h,c}`, `compress.c` | | next | the output, byte for byte, at every level, strategy and flush |
| `uncompr.c` | | later | |
| Deflate64 (not in zlib itself) | | after the encoder | zlib's `contrib/infback9`, which decodes it; ZIP archives from Windows and 7-Zip |

## Not ported, for now

- `infback.c`: `inflateBack`, a callback interface to the same decoder.
- `gzlib.c`, `gzread.c`, `gzwrite.c`, `gzclose.c`: reading and writing gzip files. The gzip format itself is in `inflate.c` and is ported.
- Parts that exist only because zlib is in C: custom allocators (`zalloc`, `zfree`), `inflateInit_`'s version check, the checks of a null or uninitialised stream, and building the CRC tables on first use (`DYNAMIC_CRC_TABLE`).
- Build options that zlib leaves off by default: `INFLATE_STRICT`, `INFLATE_ALLOW_INVALID_DISTANCE_TOOFAR_ARRR` (so `inflateUndermine` always fails, as in a default build), `PKZIP_BUG_WORKAROUND`, `BUILDFIXED`, and the ARMv8 CRC instructions.
- `contrib/`, except `infback9`, for Deflate64, later.

## Following new releases

When zlib releases a new version:

1. Diff the two tags and port each change.
2. Update `UPSTREAM_VERSION` and the `libz-sys` version that bundles the new release.
3. Run everything again.

## Licenses

The port is derived from zlib, which is under the zlib license. That is why `hivepack-deflate` is under the zlib license, and its [LICENSE](../crates/deflate/LICENSE) keeps zlib's notice and says that this is an altered version, as the license asks. `tests/infcover.rs` is derived from zlib's `test/infcover.c`, under the same license.
