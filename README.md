# hivepack

Read and write archives and compressed files in Rust: one library for many formats, in the spirit of [libarchive](https://github.com/libarchive/libarchive).

> **Status:** early development. Nothing is published on crates.io yet.

## 🎯 Plans

- **zstd**: a Rust port of the official [Zstandard](https://github.com/facebook/zstd) library, for both compressing and decompressing.
- **ZIP**: reading and writing, including split archives (`.z01`, `.z02`, …, `.zip`).
- **RAR**: reading through [rars](https://github.com/bitplane/rars).
- **tar**, and tar inside zstd (`.tar.zst`).
- **Safe extraction by default**: no writing outside the destination, through links, or past size limits set for archive bombs.

## 📦 Crates

| Crate | What it is | Status |
|---|---|---|
| [`hivepack-zstd`](crates/zstd) | Zstandard in safe Rust, ported from libzstd 1.5.7: the same output, at the same speed | Decompresses, in one call or streaming, with the same output and errors as libzstd, at about 0.9× its speed. Compresses at the levels up to 3, in one call or streaming, with libzstd's frames; the rest of the encoder comes next |

Every crate forbids `unsafe` code; the one exception, `hivepack-zstd`'s `unsafe-fast` feature, is off by default (see [docs/unsafe.md](docs/unsafe.md)). The rules are in [docs/safety.md](docs/safety.md), and how the zstd port follows the official library is in [docs/porting.md](docs/porting.md).

## 🧪 Tests

```sh
python3 scripts/testdata.py fetch    # the test files too big to commit (16 MB)
cargo test --workspace
```

The test files come from zstd itself and from other zstd implementations (Go, Java, Rust), with their licenses. [testdata/README.md](testdata/README.md) lists them.

## 🐝 Made by HivePaaS

hivepack is built and maintained by HivePaaS, who also make:

- [hivepaas](https://github.com/hivepaas/hivepaas): a self-hosted PaaS.
- [shellwing](https://shellwing.app): a fast, native SSH client for macOS, Windows and Linux.
- [authwing](https://github.com/hivepaas/authwing): a two-factor code app for macOS, Windows and Linux that knows the window you are in.

## 📜 License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 HivePaaS.

The exception is `hivepack-zstd`, which is under BSD-3-Clause, the license of the Zstandard code it is ported from (see [crates/zstd/LICENSE](crates/zstd/LICENSE)). The test files in `testdata/` keep their own licenses, listed in [testdata/README.md](testdata/README.md).
