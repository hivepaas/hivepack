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

- **No unsafe code.** The crate forbids it; see [docs/safety.md](../../docs/safety.md).
- **The same results as liblz4**, call by call.
- **The same speed as liblz4**, on x86-64 and arm64.

How the port follows liblz4, how it is checked, and what is left are in [docs/lz4.md](../../docs/lz4.md).

## License

BSD-2-Clause, the license of the code it is ported from, liblz4's `lib/` (lz4's programs and tests are under the GPL, and are not ported). See [LICENSE](LICENSE). Copyright (c) 2011-2020 Yann Collet, and (c) 2026 HivePaaS.
