# hivepack-lz4

LZ4 compression and decompression in safe Rust, ported from the official library, [liblz4](https://github.com/lz4/lz4) 1.10.0.

> **Status:** compresses blocks and frames with liblz4's output, byte for byte, at every acceleration and level, with dictionaries, call by call as `LZ4F_compressUpdate` does; decodes blocks with liblz4's results, the error position included, and the same bytes written in the output, past what is decoded too; decodes frames call by call as `LZ4F_decompress` does, with the same hints, bytes read and written, and errors; writes `.lz4` files as liblz4's file functions do, and reads them as `lz4 -d` does. This crate is not on crates.io.

```rust
use std::io::{Read, Write};

let text = b"hello, hello, hello\n".repeat(100);
let mut encoder = hivepack_lz4::Encoder::new(Vec::new(), None)?;
encoder.write_all(&text)?;
let lz4 = encoder.finish()?;

let mut back = Vec::new();
hivepack_lz4::Decoder::new(&lz4[..]).read_to_end(&mut back)?;
assert_eq!(back, text);
# Ok::<(), std::io::Error>(())
```

Three layers, as in liblz4:

- **Blocks** (`hivepack_lz4::block`, `lz4.h`, and `hivepack_lz4::hc`, `lz4hc.h`): `compress_fast` at every acceleration, `compress_hc` at every level, as much as fits in an output (`compress_dest_size`), and `decompress_safe`, partially, with a dictionary apart or before the output; streams of blocks with dictionaries, loaded or attached (`Stream`, `StreamHc`, `StreamDecode`).
- **Frames** (`hivepack_lz4::frame`, `lz4frame.h`): `CompressionContext` and `DecompressionContext`, in as many calls as the input and output come in, with dictionaries (and `CDict`, digested once for many frames), `compress_frame` in one call, and `get_frame_info`.
- **`.lz4` files** (`hivepack_lz4::Encoder` and `hivepack_lz4::Decoder`): an `std::io::Write` of one frame, and an `std::io::Read` of frames one after another, skippable frames and the legacy format.

The goals:

- **No unsafe code.** The crate forbids it, unless the `unsafe-fast` feature is on; see [docs/safety.md](../../docs/safety.md).
- **The same results as liblz4**, call by call.
- **The same speed as liblz4**, on x86-64 and arm64: 0.75× so far with safe code, 0.96× with the `unsafe-fast` feature, off by default, which drops the bounds checks of the decoder's fast loop (see [docs/unsafe.md](../../docs/unsafe.md)).

How the port follows liblz4, how it is checked, and what is left are in [docs/lz4.md](../../docs/lz4.md).

## Speed

Against liblz4 1.10.0, with `tools/lz4-bench`, on the 12 Silesia files. Above 1× the port is faster.

| | Mean | Range |
|---|---|---|
| Decoding blocks | 0.75× | 0.70–0.83× |
| Decoding blocks, with the `unsafe-fast` feature | 0.96× | 0.92–0.99× |
| Compressing blocks, level 1 | 0.95× | 0.92–0.98× |
| Compressing blocks, acceleration 9 | | 0.81–0.95× |
| Compressing blocks, high compression, levels 2, 9 and 12 | | 0.74–0.98× |
| Writing frames, level 1 | | 0.87–1.30× |
| Writing frames, level 9 | | 0.76–0.91× |

**Measured on:** AMD Ryzen 9 9950X (x86-64, Linux), in October 2026, the best of three or five rounds taken in turn. More, with lz4_flex beside it, is in [docs/lz4.md](../../docs/lz4.md#the-speed-target).

### On GitHub's runners

Against liblz4 1.10.0, without `unsafe-fast`, each row the mean and the range over its files or workloads.

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Decoding blocks | 0.77× (0.72–0.84×) | 0.76× (0.68–0.83×) | 0.75× (0.65–0.83×) |
| Reading frames | 0.77× (0.73–0.83×) | 0.77× (0.56–0.97×) | 0.99× (0.90–1.21×) |
| Compressing blocks, level 1 | 0.93× (0.87–0.98×) | 1.03× (0.93–1.20×) | 0.98× (0.85–1.03×) |
| Compressing blocks, level 9 | 0.90× (0.81–0.95×) | 0.89× (0.78–0.99×) | 0.86× (0.75–0.89×) |

**Measured on** `.github/workflows/bench.yml`, on October 31, 2026, with rustc 1.99.1: Linux x86-64 on AMD EPYC 9V74 80-Core Processor (4 threads); Windows x86-64 on AMD64 Family 26 Model 2 Stepping 1 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). Each job gets what the runner has that day, so these are not the same processor from format to format, and they are shared machines: the ratios hold better than the speeds.

## License

BSD-2-Clause, the license of the code it is ported from, liblz4's `lib/` (lz4's programs and tests are under the GPL, and are not ported). See [LICENSE](LICENSE). Copyright (c) 2011-2020 Yann Collet, and (c) 2026 HivePaaS.
