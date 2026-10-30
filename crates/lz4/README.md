# hivepack-lz4

LZ4 decompression in safe Rust, ported from the official library, [liblz4](https://github.com/lz4/lz4) 1.10.0. Compression comes next.

> **Status:** decodes blocks with liblz4's results, the error position included, and the same bytes written in the output, past what is decoded too; decodes frames call by call as `LZ4F_decompress` does, with the same hints, bytes read and written, and errors; reads `.lz4` files as `lz4 -d` does. This crate is not on crates.io.

```rust
use std::io::Read;

// "hello, hello, hello\n" as `lz4` writes it.
let lz4 = [
    0x04, 0x22, 0x4d, 0x18, 0x64, 0x40, 0xa7, 0x10, 0x00, 0x00, 0x00, 0x74,
    0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x07, 0x00, 0x50, 0x65, 0x6c,
    0x6c, 0x6f, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x27, 0x7b, 0x7a, 0x9f,
];
let mut text = String::new();
hivepack_lz4::Decoder::new(&lz4[..]).read_to_string(&mut text)?;
assert_eq!(text, "hello, hello, hello\n");
# Ok::<(), std::io::Error>(())
```

Three layers, as in liblz4:

- **Blocks** (`hivepack_lz4::block`, `lz4.h`): `decompress_safe`, partially, with a dictionary apart or before the output, and blocks one after another (`StreamDecode`).
- **Frames** (`hivepack_lz4::frame`, `lz4frame.h`): `DecompressionContext`, in as many calls as the input and output come in, with dictionaries, and `get_frame_info`.
- **`.lz4` files** (`hivepack_lz4::Decoder`): an `std::io::Read` of frames one after another, skippable frames and the legacy format.

The goals:

- **No unsafe code.** The crate forbids it, unless the `unsafe-fast` feature is on; see [docs/safety.md](../../docs/safety.md).
- **The same results as liblz4**, call by call.
- **The same speed as liblz4**, on x86-64 and arm64: 0.75× so far with safe code, 0.96× with the `unsafe-fast` feature, off by default, which drops the bounds checks of the decoder's fast loop (see [docs/unsafe.md](../../docs/unsafe.md)).

How the port follows liblz4, how it is checked, and what is left are in [docs/lz4.md](../../docs/lz4.md).

## License

BSD-2-Clause, the license of the code it is ported from, liblz4's `lib/` (lz4's programs and tests are under the GPL, and are not ported). See [LICENSE](LICENSE). Copyright (c) 2011-2020 Yann Collet, and (c) 2026 HivePaaS.
