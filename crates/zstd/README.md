# hivepack-zstd

Zstandard (zstd) compression and decompression in safe Rust, ported from the official library, [libzstd](https://github.com/facebook/zstd) 1.5.7.

> **Status:** nothing is implemented yet. This crate is not on crates.io.

The goals:

- **No unsafe code.** The crate forbids it; see [docs/safety.md](../../docs/safety.md).
- **The same output as libzstd.** Compressed output is identical byte for byte at every level. Decompression gives the same result and the same errors.
- **The same speed as libzstd**, on x86-64 and arm64.

How the port follows libzstd, and the order of work, are in [docs/porting.md](../../docs/porting.md).

## License

BSD-3-Clause, the license of the code it is ported from. See [LICENSE](LICENSE). Copyright (c) Meta Platforms, Inc. and affiliates, and (c) 2026 HivePaaS.
