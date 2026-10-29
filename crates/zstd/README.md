# hivepack-zstd

Zstandard (zstd) compression and decompression in safe Rust, ported from the official library, [libzstd](https://github.com/facebook/zstd) 1.5.7.

> **Status:** decompression works, in one call or streaming, with dictionaries, and gives the same output and errors as libzstd on all the test data. It runs at about 0.9× libzstd's speed on Apple M1, and about 0.95× with the `unsafe-fast` feature (x86-64 is not measured yet). Compression works at every level, with every strategy, the block splitter after the sequences and long distance matching, in one call (`hivepack_zstd::compress`, `CCtx::compress2`) or streaming (`CCtx::compress_stream2`), with libzstd's parameters, and gives the frames libzstd gives, byte for byte, at about 0.88× libzstd's speed at levels 1 to 3, 0.71–0.86× at levels 5 to 12, and 0.89–1.05× from level 13 on. With dictionaries too: loaded, prefixes, and `CDict`s attached, copied in or loaded again as libzstd decides. This crate is not on crates.io.

```rust
let frame = [
    0x28, 0xb5, 0x2f, 0xfd, // magic number
    0x20, 0x05, // header: single segment, content size 5
    0x29, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o', // one raw block, the last
];
let mut out = [0u8; 5];
let size = hivepack_zstd::decompress(&mut out, &frame)?;
assert_eq!(&out[..size], b"hello");
```

The goals:

- **No unsafe code.** The crate forbids it; see [docs/safety.md](../../docs/safety.md). The one exception is opt-in: the `unsafe-fast` feature copies without bounds checks in the decoder's hottest loop, for 4–6% more speed. See [docs/unsafe.md](../../docs/unsafe.md).
- **The same output as libzstd.** Compressed output is identical byte for byte at every level. Decompression gives the same result and the same errors.
- **The same speed as libzstd**, on x86-64 and arm64.

How the port follows libzstd, and the order of work, are in [docs/porting.md](../../docs/porting.md).

## License

BSD-3-Clause, the license of the code it is ported from. See [LICENSE](LICENSE). Copyright (c) Meta Platforms, Inc. and affiliates, and (c) 2026 HivePaaS.
