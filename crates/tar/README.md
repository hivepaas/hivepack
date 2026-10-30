# hivepack-tar

Reading tar archives in safe Rust, ported from the reading half of Go's `archive/tar` (Go 1.27.2).

> **Status:** reads V7, USTAR, PAX, GNU and STAR archives: PAX records and GNU long names merged into their entries, global PAX headers, and sparse files in GNU's formats 0.0, 0.1, 1.0 and the old one, their holes read as zeros. Every header, byte of data and error is the same as Go's, on Go's own test archives, archives Go's writer makes, and thousands of damaged ones. Writing is not ported. This crate is not on crates.io.

```rust
use std::io::Read;

let mut tar = hivepack_tar::Reader::new(std::fs::File::open("backup.tar")?);
while let Some(header) = tar.next()? {
    let mut data = Vec::new();
    tar.read_to_end(&mut data)?;
    println!("{} {} bytes", String::from_utf8_lossy(&header.name), data.len());
}
```

Names are bytes, as tar keeps them. Data not read is skipped by the next `next`. An error stays: every later call returns it. Extracting to disk, with its checks on names and links, belongs to hivepack-extract.

How the port follows Go, and how it is checked, is in [docs/tar.md](../../docs/tar.md).

## Speed

Against Go 1.27.2's `archive/tar`, with `tools/tar-bench`. Above 1× the port is faster.

| | hivepack-tar / Go |
|---|---|
| Going through entries, USTAR, PAX and sparse | 2.18–2.61× |
| Going through entries, GNU long names | 1.48× |
| Reading data, from memory | 1.20–2.00× |
| Reading data, from a file | 1.02–1.05× |
| Skipping data, through a buffer | 0.96× |
| Skipping data, a file given as it is | 0.01×: Go seeks, and the port reads through |

**Measured on:** AMD Ryzen 9 9950X (16 cores, x86-64), 45 GiB of memory, Ubuntu 26.04 with Linux 7.0 and the `powersave` governor, rustc 1.99.1 in the workspace's release profile, Go 1.27.2, in October 2026. The data is the Silesia corpus cut to 64 MiB, and archives of 200,000 entries, the best of five rounds taken in turn. Both found the same entries and read the same bytes. The whole table and the reasons are in [docs/tar.md](../../docs/tar.md#the-speed).

## License

BSD-3-Clause, as Go is (see [LICENSE](LICENSE)).
