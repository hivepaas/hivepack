# hivepack-7z

Reading 7z archives in safe Rust, ported from the 7z decoder of the [LZMA SDK](https://7-zip.org/sdk.html) (7-Zip 26.05), which is in the public domain.

> **Status:** opens what the SDK opens, encoded headers included, and decodes what it decodes (Copy, LZMA, LZMA2 and PPMd, after a branch converter, the delta filter or BCJ2), with the SDK's answers, its error numbers included, on archives 7-Zip makes and on damaged copies of them. Past the SDK, it reads what 7-Zip's program reads: any graph of coders, with Deflate, Deflate64, BZip2 and the swap filters, Zstandard as 7-Zip's forks write it, and AES with a password. This crate is not on crates.io.

```rust,no_run
use std::io::Read;

let mut archive = hivepack_7z::Archive::open(std::fs::File::open("backup.7z")?)?;
let mut files = archive.files();
while let Some(entry) = files.next()? {
    let mut data = Vec::new();
    files.read_to_end(&mut data)?;
    println!("{} {} bytes", entry.name, data.len());
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Two ways to read a file's data:

- **`Archive::files`** reads the files one after another, each folder decoded once, in pieces, so that a solid block of any size takes little memory: what its coders need.
- **`Archive::extract`** decodes a file's whole folder into memory, as `SzArEx_Extract` does, and keeps it for the folder's next file.

An encrypted archive takes its password in `Options::password`, or later in `Archive::set_password` when its names can be read without it. 7z has nothing to check a password with but the data, so `Error::WrongPassword` may also be damaged data.

An archive says how much memory it needs, so `Options` limits it: the description of the archive, 1 GiB by default, and a folder's dictionaries and models, 4 GiB by default. An application that opens archives from strangers lowers them.

The goals:

- **No unsafe code.** The crate forbids it; see [docs/safety.md](../../docs/safety.md).
- **The same answers as the SDK**, error numbers included.
- **The same speed**: LZMA and LZMA2 go through [`hivepack-xz`](../xz), which is faster than the SDK's C decoder without its assembly; PPMd takes 0.92× the SDK's speed.

How the port follows the SDK, how it is checked, and what is left are in [docs/7z.md](../../docs/7z.md).

## Speed

Against the LZMA SDK 26.05's C decoder and, for what that does not read, `7zz t -mmt=1` from the same release, with `tools/7z-bench`. Above 1× the port is faster.

| | hivepack-7z / the reference |
|---|---|
| LZMA, LZMA2 and their filters, against the SDK | 1.10–1.24× |
| PPMd, against the SDK | 0.88–0.92× |
| LZMA with `lc + lp` above 4, against the SDK | 0.77× |
| Copy, against the SDK | 0.59× |
| Opening 100,000 files, against the SDK | 0.66–0.81× |
| Deflate and Deflate64, against `7zz` | 1.00–1.39× |
| BZip2 and Swap4, against `7zz` | 0.62–0.64× |
| AES-256 behind a compressor, against `7zz` | 0.87–0.93× |
| AES-256 with Copy, against `7zz` | 0.08× |

**Measured on:** AMD Ryzen 9 9950X (16 cores, x86-64), 45 GiB of memory, Ubuntu 26.04 with Linux 7.0 and the `powersave` governor, rustc 1.99.1 in the workspace's release profile, in October 2026. The SDK and `7zz` are built with GCC 15.2 and their makefile's flags, without the assembly decoders that 7-Zip's releases use. The data is the Silesia corpus cut to 64 MiB, the best of five rounds taken in turn.

The LZMA figures are against C only. AES with Copy is the processor's AES instructions in 7-Zip against constant-time AES in safe Rust. The whole table and the reasons are in [docs/7z.md](../../docs/7z.md#the-speed).

## License

MIT, as hivepack is. The code it is ported from, the LZMA SDK's C files, is in the public domain, by Igor Pavlov, and PPMd var.H by Dmitry Shkarin. See [LICENSE](../../LICENSE). Copyright (c) 2026 HivePaaS.
