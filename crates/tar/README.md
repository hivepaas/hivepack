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

## License

BSD-3-Clause, as Go is (see [LICENSE](LICENSE)).
