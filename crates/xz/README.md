# hivepack-xz

.xz and .lzma compression, and .xz, .lzma and .lz decompression, in safe Rust, ported from the official library, liblzma of [XZ Utils](https://tukaani.org/xz/) 5.8.4.

> **Status:** the encoders of `.xz` and `.lzma` and of raw LZMA1 and LZMA2 write liblzma's output, byte for byte, call by call, with every preset, option and match finder and every flush, at about liblzma's speed. The decoders of `.xz`, `.lzma` and `.lz`, the automatic one, and raw LZMA1 and LZMA2 give liblzma's results, call by call, with its memory limits and flags; they run at 1.06–1.34× liblzma's speed where liblzma is C, and at 0.74–0.89× on x86-64, where liblzma's range decoder is assembly (Silesia). The delta and BCJ filters (x86, PowerPC, IA-64, ARM, ARM-Thumb, ARM64, SPARC, RISC-V) are in both, and the `.xz` encoder and decoder run in threads too. This crate is not on crates.io.

```rust
use hivepack_xz::{Action, InBuffer, OutBuffer, Status, Stream};

let mut xz = vec![0; hivepack_xz::stream_buffer_bound(5)];
let mut len = 0;
hivepack_xz::easy_buffer_encode(6, hivepack_xz::Check::CRC64, b"hello", &mut xz, &mut len)?;
let xz = &xz[..len];
let mut stream = Stream::stream_decoder(u64::MAX, 0)?;
let mut out = vec![0; 1 << 20];
let mut output = OutBuffer::new(&mut out);
let status = stream.code(&mut output, &mut InBuffer::new(xz), Action::Finish)?;
assert_eq!(status, Status::StreamEnd);
```

The goals:

- **No unsafe code.** The crate forbids it; see [docs/safety.md](../../docs/safety.md).
- **The same results as liblzma**: the same output, byte for byte, return codes, bytes read and written, memory usage and limits.
- **The same speed as liblzma**, on x86-64 and arm64.

How the port follows liblzma, how it is checked, and what is left are in [docs/xz.md](../../docs/xz.md).

## Speed

Against liblzma 5.8.4, with `tools/xz-bench`, on the 12 Silesia files with CRC64. Above 1× the port is faster.

| | Mean | Range |
|---|---|---|
| Compression, presets 0, 3, 6 and 9 | 1.02× | 0.93–1.18× |
| Decompression, against liblzma with its x86-64 assembly | 0.81× | 0.74–0.89× |
| Decompression, against liblzma's C | 1.18× | 1.06–1.34× |

**Measured on:** AMD Ryzen 9 9950X (x86-64, Linux), in October 2026, the best of two or three rounds taken in turn. Threads and more are in [docs/xz.md](../../docs/xz.md#the-speed-target).

## License

The BSD Zero Clause License (`0BSD`), liblzma's license. See [LICENSE](LICENSE). Copyright (C) The XZ Utils authors and contributors, and (c) 2026 HivePaaS.
