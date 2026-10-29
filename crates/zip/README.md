# hivepack-zip

ZIP archives in safe Rust, the container logic ported from [libzip](https://libzip.org) 1.12.1.

> **Status:** opens archives, reads their central directory and local headers, and reads stored and deflated entries, with libzip's rules and errors, compared with libzip itself. Deflate64 entries and `ziptool` come next, then writing. This crate is not on crates.io.

```rust
use hivepack_zip::{Archive, Flags, OpenFlags};

let file = std::fs::File::open("archive.zip")?;
let archive = Archive::open(file, OpenFlags::CHECKCONS)?;
for i in 0..archive.get_num_entries(Flags::NONE) {
    let st = archive.stat_index(i, Flags::NONE)?;
    println!("{} {}", String::from_utf8_lossy(st.name.unwrap_or_default()), st.size);
}
// Decompressed, its CRC-32 and length checked at the end.
let mut data = Vec::new();
let mut file = archive.fopen(b"README.md", Flags::NONE)?;
std::io::Read::read_to_end(&mut file, &mut data)?;
file.fclose()?;
```

`OpenFlags::CHECKCONS` compares every local header with the central directory and checks more strictly, as libzip's `ZIP_CHECKCONS` does. Without it, the archive opens as libzip opens it by default.

The goals:

- **No unsafe code.** The crate forbids it; see [docs/safety.md](../../docs/safety.md).
- **libzip's answers.** An archive libzip opens opens, with the same entries; one it refuses is refused with the same error and detail.

How the port follows libzip, how it is checked, and what is left are in [docs/zip.md](../../docs/zip.md).

## License

BSD-3-Clause, the license of the code it is ported from. See [LICENSE](LICENSE). Copyright (C) 1999-2026 Dieter Baron and Thomas Klausner, and (c) 2026 HivePaaS.
