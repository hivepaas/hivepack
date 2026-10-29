# hivepack

Read and write archives and compressed files in Rust: one library for many formats, in the spirit of [libarchive](https://github.com/libarchive/libarchive).

> **Status:** early development. Nothing is published on crates.io yet.

## 🎯 Plans

- **zstd**: a Rust port of the official [Zstandard](https://github.com/facebook/zstd) library, for both compressing and decompressing.
- **Deflate**: a Rust port of [zlib](https://zlib.net), for both too, with the zlib and gzip formats.
- **ZIP**: reading and writing, including split archives (`.z01`, `.z02`, …, `.zip`), its rules ported from [libzip](https://libzip.org) (see [docs/zip.md](docs/zip.md)).
- **RAR**: reading through [rars](https://github.com/bitplane/rars).
- **tar**, and tar inside zstd (`.tar.zst`).
- **Safe extraction by default**: no writing outside the destination, through links, or past size limits set for archive bombs.

## 📦 Crates

| Crate | What it is | Status |
|---|---|---|
| [`hivepack-deflate`](crates/deflate) | Deflate, zlib and gzip in safe Rust, ported from zlib 1.3.2: the same output, at the same speed | Compresses with zlib's output, byte for byte, and decompresses with its results and messages, both at about its speed. Decodes Deflate64 as zlib's `contrib/infback9` does |
| [`hivepack-zip`](crates/zip) | ZIP archives in safe Rust, the container logic ported from libzip 1.12.1 | Opens archives, reads their headers, and reads stored, deflated and Deflate64 entries with libzip's rules and errors, compared with libzip. `ziptool` and libzip's own tests come next |
| [`hivepack-zstd`](crates/zstd) | Zstandard in safe Rust, ported from libzstd 1.5.7: the same output, at the same speed | Decompresses, in one call or streaming, with the same output and errors as libzstd, at about 0.9× its speed. Compresses at every level, in one call or streaming, with dictionaries, with libzstd's frames |

Every crate forbids `unsafe` code; the one exception, `hivepack-zstd`'s `unsafe-fast` feature, is off by default (see [docs/unsafe.md](docs/unsafe.md)). The rules are in [docs/safety.md](docs/safety.md), and how the ports follow the official libraries is in [docs/porting.md](docs/porting.md) (zstd) and [docs/deflate.md](docs/deflate.md) (zlib).

## 🧪 Tests

```sh
python3 scripts/testdata.py fetch    # the test files too big to commit (16 MB)
cargo test --workspace
```

The test files come from zstd itself and from other zstd implementations (Go, Java, Rust), with their licenses. [testdata/README.md](testdata/README.md) lists them.

## 🦀 Rust versions

- **Oldest supported: 1.88**, `rust-version` in `Cargo.toml`, which CI checks.
  It is a promise to the crates' users: raised only when the code needs
  something newer, never to a Rust less than a year old, and, once the crates
  are published, in a minor release with a line in its notes.
- **Development:** `rust-toolchain.toml` pins the stable Rust that formats,
  lints, documents and tests, so a new Rust never turns CI red on its own. It
  is raised by hand every second Rust release (about every twelve weeks), once
  that release is two weeks old, in a pull request of its own, together with
  the nightly that Miri and cargo-fuzz use (`NIGHTLY` in
  `.github/workflows/ci.yml`).
- **Newer Rust:** a weekly workflow (`.github/workflows/newer-rust.yml`) lints
  and tests with the latest stable and beta, which users may build with before
  the pin is raised. A failure there warns; it blocks nothing.

## 🐝 Made by HivePaaS

hivepack is built and maintained by HivePaaS, who also make:

- [hivepaas](https://github.com/hivepaas/hivepaas): a self-hosted PaaS.
- [shellwing](https://shellwing.app): a fast, native SSH client for macOS, Windows and Linux.
- [authwing](https://github.com/hivepaas/authwing): a two-factor code app for macOS, Windows and Linux that knows the window you are in.

## 📜 License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 HivePaaS.

The exceptions are the ports, under the licenses of the code they are ported from: `hivepack-zstd` under BSD-3-Clause (see [crates/zstd/LICENSE](crates/zstd/LICENSE)), and `hivepack-deflate` under the zlib license (see [crates/deflate/LICENSE](crates/deflate/LICENSE)). The test files in `testdata/` keep their own licenses, listed in [testdata/README.md](testdata/README.md).
