# hivepack-rar

Reading RAR archives in safe Rust: a port of [UnRAR](https://www.rarlab.com/rar_add.htm) 7.3.2, RARLAB's source, under UnRAR's license. It reads RAR and never writes it.

> **Status:** reads the headers of RAR 1.4, 1.5 to 4.x and 5.0 as UnRAR does, broken ones included, compared with UnRAR on libarchive's RAR archives and a quarter of a million damaged copies, and reads stored entries as UnRAR tests them, checked against CRC-32, BLAKE2sp or RAR 1.4's checksum. Decompression and decryption come next. This crate is not on crates.io.

```rust
use hivepack_rar::{Archive, HEAD_FILE, name};

let mut archive = Archive::open(std::fs::File::open("archive.rar")?, false)?;
while archive.read_header()? != 0 {
    if archive.cur_header_type == HEAD_FILE {
        println!("{}", name::to_string_lossy(&archive.file_head.file_name));
    }
    archive.seek_to_next();
}
```

An `Extract` goes through the entries, giving out each one's data and checking its hash; see the crate's documentation.

The plan, the license and how the port is checked are in [docs/rar.md](../../docs/rar.md).

## License

UnRAR's license; see [LICENSE](LICENSE). In its words:

> UnRAR source code may be used in any software to handle RAR archives without limitations free of charge, but cannot be used to develop RAR (WinRAR) compatible archiver and to re-create RAR compression algorithm, which is proprietary. Distribution of modified UnRAR source code in separate form or as a part of other software is permitted, provided that full text of this paragraph, starting from "UnRAR source code" words, is included in license, or in documentation if license is not available, and in source code comments of resulting package.

All copyrights to RAR and to UnRAR are Alexander Roshal's.
