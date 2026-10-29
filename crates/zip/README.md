# hivepack-zip

ZIP archives in safe Rust, the container logic ported from [libzip](https://libzip.org) 1.12.1.

> **Status:** opens archives, reads their central directory and local headers, and reads stored, deflated and Deflate64 entries, with libzip's rules and errors; edits entries' names, comments, times and attributes, deletes them, adds and replaces data, stored or deflated, and writes the archive as libzip writes it, byte for byte; decrypts ZipCrypto and WinZip AES entries. All compared with libzip itself. Encrypting comes next. This crate is not on crates.io.

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

Entries encrypted with ZipCrypto or WinZip AES are read with a password, the archive's default one or one given to `fopen_index_encrypted`; a wrong one fails with `ErrorCode::WrongPasswd`, or for WinZip AES with `ErrorCode::Crc` at the end if the data was changed:

```rust
archive.set_default_password(Some(b"secret"));
let mut file = archive.fopen(b"notes.txt", Flags::NONE)?;
```

Changes are kept until the archive is written, to an output of the caller's:

```rust
use hivepack_zip::{Archive, BufferSource, Closed, Flags, OpenFlags};

let mut archive = Archive::open(std::fs::File::open("archive.zip")?, OpenFlags::CHECKCONS)?;
let index = archive.name_locate(b"old.txt", Flags::NONE)?;
archive.file_rename(index, b"new.txt", Flags::NONE)?;
archive.file_add(b"notes.txt", BufferSource::new(b"added".to_vec()), Flags::NONE)?;
archive.set_archive_comment(b"renamed")?;
let mut out = std::fs::File::create("archive.zip.new")?;
if archive.close_to(&mut out)? == Closed::Written {
    drop(archive);
    std::fs::rename("archive.zip.new", "archive.zip")?;
}
```

The goals:

- **No unsafe code.** The crate forbids it; see [docs/safety.md](../../docs/safety.md).
- **libzip's answers.** An archive libzip opens opens, with the same entries; one it refuses is refused with the same error and detail.

How the port follows libzip, how it is checked, and what is left are in [docs/zip.md](../../docs/zip.md).

## License

BSD-3-Clause, the license of the code it is ported from. See [LICENSE](LICENSE). Copyright (C) 1999-2026 Dieter Baron and Thomas Klausner, and (c) 2026 HivePaaS.
