# hivepack-deflate

Deflate, zlib and gzip compression and decompression in safe Rust, ported from the official library, [zlib](https://zlib.net) 1.3.2.

> **Status:** compression gives zlib's output, byte for byte, at every level, strategy, memory level and flush, and decompression zlib's results and messages, raw or with the zlib and gzip wrappers, with dictionaries and gzip headers. It decodes Deflate64 too, ZIP's method 9, as zlib's `contrib/infback9` does, whole or a piece at a time. All run at about zlib's speed on x86-64 (Silesia). This crate is not on crates.io.

```rust
use hivepack_deflate::{Flush, InBuffer, Inflate, OutBuffer, Status};

// "hello", deflated with no header or trailer, as in a ZIP archive.
let raw = [0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];
let mut inflate = Inflate::new(-15)?;
let mut out = [0; 16];
let mut output = OutBuffer::new(&mut out);
let status = inflate.inflate(&mut output, &mut InBuffer::new(&raw), Flush::Finish)?;
assert_eq!(status, Status::StreamEnd);
let written = output.pos;
assert_eq!(&out[..written], b"hello");
```

It also has zlib's checksums, `crc32` and `adler32`, with their `_combine` functions.

The goals:

- **No unsafe code.** The crate forbids it; see [docs/safety.md](../../docs/safety.md).
- **The same output as zlib.** Compressed output is identical byte for byte; decompression gives the same output, return codes and error messages.
- **The same speed as zlib**, on x86-64 and arm64.

How the port follows zlib, how it is checked, and what is left are in [docs/deflate.md](../../docs/deflate.md).

## License

The zlib license, the license of the code it is ported from. See [LICENSE](LICENSE). Copyright (C) 1995-2026 Jean-loup Gailly and Mark Adler, and (c) 2026 HivePaaS.
