# hivepack

Read and write archives and compressed files in Rust: one library for many formats, in the spirit of [libarchive](https://github.com/libarchive/libarchive).

> **Status:** early development. Nothing is published on crates.io yet.

## 🎯 Plans

- **zstd**: a Rust port of the official [Zstandard](https://github.com/facebook/zstd) library, for both compressing and decompressing.
- **Deflate**: a Rust port of [zlib](https://zlib.net), for both too, with the zlib and gzip formats.
- **bzip2**: a Rust port of [libbzip2](https://sourceware.org/bzip2/), for both too.
- **ZIP**: reading and writing, including split archives (`.z01`, `.z02`, …, `.zip`), its rules ported from [libzip](https://libzip.org) (see [docs/zip.md](docs/zip.md)).
- **RAR**: reading through [rars](https://github.com/bitplane/rars).
- **tar**, and tar inside zstd (`.tar.zst`).
- **age**: decrypting files of the [age](https://age-encryption.org) encryption tool, often archives (`.tar.zst.age`), its rules ported from age's Go code (see [docs/age.md](docs/age.md)).
- **Safe extraction by default**: no writing outside the destination, through links, or past size limits set for archive bombs (see [docs/extract.md](docs/extract.md)).

## 📦 Crates

| Crate | What it is | Status |
|---|---|---|
| [`hivepack-age`](crates/age) | Decrypting [age](https://age-encryption.org) files in safe Rust, ported from age v1.3.2, the reference implementation in Go | Decrypts with passphrases and X25519 keys, armored or not, with age's outcomes on all 128 of C2SP's test vectors it reads (the other 19 need post-quantum keys) and on files age encrypts and that are then damaged. SSH keys come next |
| [`hivepack-bzip2`](crates/bzip2) | bzip2 in safe Rust, ported from libbzip2 1.0.8: the same output, at the same speed | Compresses with libbzip2's output, byte for byte, at every block size and work factor, and decompresses with its results, fast or small, randomised blocks included, both at about its speed |
| [`hivepack-crypto`](crates/crypto) | The cryptography of ZIP's encryption and of age in safe Rust, ported from BearSSL 0.6: AES, SHA-1, SHA-256, SHA-512, HMAC, HKDF, PBKDF2, ChaCha20-Poly1305, X25519 and scrypt | AES, ChaCha20-Poly1305 and X25519 run in constant time, as BearSSL's do; all checked against the published vectors, and against nettle for ZIP's or Go's `x/crypto` for age's. `hivepack-zip` encrypts and decrypts WinZip AES with them |
| [`hivepack-deflate`](crates/deflate) | Deflate, zlib and gzip in safe Rust, ported from zlib 1.3.2: the same output, at the same speed | Compresses with zlib's output, byte for byte, and decompresses with its results and messages, both at about its speed. Decodes Deflate64 as zlib's `contrib/infback9` does |
| [`hivepack-extract`](crates/extract) | Extracting archives to disk, safe by default: nothing outside the destination, through links, over what is there, or past limits | Extracts ZIP archives, refusing unportable names, the same path twice, links and overlapping data, writing by handle and counting what is written. tar and RAR come later |
| [`hivepack-zip`](crates/zip) | ZIP archives in safe Rust, the container logic ported from libzip 1.12.1 | Opens archives, reads their headers, and reads stored, deflated, bzip2 and Deflate64 entries with libzip's rules and errors; edits names, comments, times and attributes, deletes entries, adds and replaces data, stored, deflated or bzip2, and writes the archive as libzip does, byte for byte; encrypts and decrypts ZipCrypto and WinZip AES. All compared with libzip, and 167 of libzip's own tests pass through the port's `ziptool` |
| [`hivepack-zstd`](crates/zstd) | Zstandard in safe Rust, ported from libzstd 1.5.7: the same output, at the same speed | Decompresses, in one call or streaming, with the same output and errors as libzstd, at about 0.9× its speed. Compresses at every level, in one call or streaming, with dictionaries, on several threads, with libzstd's frames |

Every crate forbids `unsafe` code; the one exception, `hivepack-zstd`'s `unsafe-fast` feature, is off by default (see [docs/unsafe.md](docs/unsafe.md)). The one dependency with `unsafe` code, cap-std, is in `hivepack-extract`, until the standard library can open files from a directory's handle. The rules are in [docs/safety.md](docs/safety.md), and how the ports follow the official libraries is in [docs/porting.md](docs/porting.md) (zstd), [docs/deflate.md](docs/deflate.md) (zlib), [docs/bzip2.md](docs/bzip2.md) (libbzip2), [docs/zip.md](docs/zip.md) (libzip), [docs/crypto.md](docs/crypto.md) (BearSSL) and [docs/age.md](docs/age.md) (age).

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

The exceptions are the ports, under the licenses of the code they are ported from: `hivepack-zstd` under BSD-3-Clause (see [crates/zstd/LICENSE](crates/zstd/LICENSE)), `hivepack-deflate` under the zlib license (see [crates/deflate/LICENSE](crates/deflate/LICENSE)), `hivepack-bzip2` under libbzip2's license (see [crates/bzip2/LICENSE](crates/bzip2/LICENSE)), `hivepack-zip` under BSD-3-Clause (see [crates/zip/LICENSE](crates/zip/LICENSE)), and `hivepack-age` under BSD-3-Clause (see [crates/age/LICENSE](crates/age/LICENSE)). `hivepack-crypto`, ported from BearSSL, is under the MIT license too, with BearSSL's notice (see [crates/crypto/LICENSE](crates/crypto/LICENSE)). The test files in `testdata/` keep their own licenses, listed in [testdata/README.md](testdata/README.md).
