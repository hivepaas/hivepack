# hivepack

Read and write archives and compressed files in Rust: one library for many formats, in the spirit of [libarchive](https://github.com/libarchive/libarchive).

> **Status:** early development. Nothing is published on crates.io yet.

## 🎯 Plans

- **zstd**: a Rust port of the official [Zstandard](https://github.com/facebook/zstd) library, for both compressing and decompressing.
- **ZIP**: reading and writing, including split archives (`.z01`, `.z02`, …, `.zip`).
- **RAR**: reading through [rars](https://github.com/bitplane/rars).
- **tar**, and tar inside zstd (`.tar.zst`).
- **Safe extraction by default**: no writing outside the destination, through links, or past size limits set for archive bombs.

## 🐝 Made by HivePaaS

hivepack is built and maintained by HivePaaS, who also make:

- [hivepaas](https://github.com/hivepaas/hivepaas): a self-hosted PaaS.
- [shellwing](https://shellwing.app): a fast, native SSH client for macOS, Windows and Linux.
- [authwing](https://github.com/hivepaas/authwing): a two-factor code app for macOS, Windows and Linux that knows the window you are in.

## 📜 License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 HivePaaS.
