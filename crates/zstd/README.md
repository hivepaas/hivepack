# hivepack-zstd

Zstandard (zstd) compression and decompression in safe Rust, ported from the official library, [libzstd](https://github.com/facebook/zstd) 1.5.7.

> **Status:** decompression works, in one call or streaming, with dictionaries, and gives the same output and errors as libzstd on all the test data. It runs at about 0.9× libzstd's speed on Apple M1 and arm64 Linux, about 0.95× with the `unsafe-fast` feature, and at 0.72× (0.78×) on x86-64 Linux ([docs/porting.md](../../docs/porting.md#on-linux-x86-64-and-arm64)). Compression works at every level, with every strategy, the block splitter after the sequences, long distance matching and a target size for compressed blocks (`CParameter::TargetCBlockSize`), in one call (`hivepack_zstd::compress`, `CCtx::compress2`) or streaming (`CCtx::compress_stream2`), with libzstd's parameters, and gives the frames libzstd gives, byte for byte, at about 0.88× libzstd's speed at levels 1 to 3, 0.81–0.84× at levels 5 to 8 and 0.68–0.74× at levels 9 to 12 (0.83–0.87× at levels 5 to 12 with the `unsafe-fast` feature), and 0.89–1.05× from level 13 on. With dictionaries too: loaded, prefixes, and `CDict`s attached, copied in or loaded again as libzstd decides. On several threads (`CParameter::NbWorkers`), with the frames libzstd writes with its workers, whatever their number, its speed scaling as libzstd's; the context's own threads, or a pool that contexts share (`ThreadPool`, `CCtx::ref_thread_pool`), and how far a frame has got (`CCtx::get_frame_progression`, `CCtx::to_flush_now`). And from sequences found outside its match finder, with the frames libzstd writes from them: the caller's (`CCtx::compress_sequences`, `CCtx::compress_sequences_and_literals`), or those a match finder of the caller's gives for each block (`CCtx::register_sequence_producer`). And dictionaries trained from samples, the dictionaries libzstd trains, byte for byte: with the default trainer (`hivepack_zstd::train_from_buffer`), the COVER and fast COVER trainers and their optimizers, on several threads too, the legacy trainer (`train_from_buffer_legacy`), and the headers of contents given (`finalize_dictionary`). This crate is not on crates.io.

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

- **No unsafe code.** The crate forbids it; see [docs/safety.md](../../docs/safety.md). The one exception is opt-in: the `unsafe-fast` feature copies without bounds checks in the decoder's hottest loop, for 4–6% more speed, and prefetches in the encoder's row match finder, as libzstd does, for 2–28% more at levels 5 to 12. See [docs/unsafe.md](../../docs/unsafe.md).
- **The same output as libzstd.** Compressed output is identical byte for byte at every level. Decompression gives the same result and the same errors. Trained dictionaries are identical too.
- **The same speed as libzstd**, on x86-64 and arm64.

How the port follows libzstd, and the order of work, are in [docs/porting.md](../../docs/porting.md).

## License

BSD-3-Clause, the license of the code it is ported from. See [LICENSE](LICENSE). Copyright (c) Meta Platforms, Inc. and affiliates, and (c) 2026 HivePaaS. The suffix sort of the dictionary builder, `src/dict_builder/divsufsort.rs`, is ported from libdivsufsort-lite, which libzstd ships, and is under the MIT license, with its notice there and in [LICENSE](LICENSE): Copyright (c) 2003-2008 Yuta Mori.
