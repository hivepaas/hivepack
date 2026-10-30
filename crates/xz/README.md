# hivepack-xz

.xz, .lzma and .lz decompression in safe Rust, ported from the official library, liblzma of [XZ Utils](https://tukaani.org/xz/) 5.8.4.

> **Status:** the decoders of `.xz`, `.lzma` and `.lz`, the automatic one, and raw LZMA1 and LZMA2 give liblzma's results, call by call, whatever pieces the input and output come in, with its memory limits and flags. The encoders, the delta and BCJ filters, and threads come next. This crate is not on crates.io.

```rust
use hivepack_xz::{Action, InBuffer, OutBuffer, Status, Stream};

let xz: &[u8] = &[/* an .xz file */];
let mut stream = Stream::stream_decoder(u64::MAX, 0)?;
let mut out = vec![0; 1 << 20];
let mut output = OutBuffer::new(&mut out);
let status = stream.code(&mut output, &mut InBuffer::new(xz), Action::Finish)?;
assert_eq!(status, Status::StreamEnd);
```

The goals:

- **No unsafe code.** The crate forbids it; see [docs/safety.md](../../docs/safety.md).
- **The same results as liblzma**: the same output, return codes, bytes read and written, memory usage and limits.
- **The same speed as liblzma**, on x86-64 and arm64.

How the port follows liblzma, how it is checked, and what is left are in [docs/xz.md](../../docs/xz.md).

## License

The BSD Zero Clause License (`0BSD`), liblzma's license. See [LICENSE](LICENSE). Copyright (C) The XZ Utils authors and contributors, and (c) 2026 HivePaaS.
