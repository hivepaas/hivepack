# hivepack-open

Opening what hivepack reads through the layers around it, in safe Rust: age encryption and zstd, xz, lzip, .lzma, LZ4, gzip or bzip2 compression, found by their first bytes and taken off one after the other, until what is under them is a tar or ZIP archive, an ISO 9660 image, a UDF volume, or plain data.

> **Status:** opens `backup.tar.zst.age`, `logs.tar.gz`, `notes.txt.xz` and any stack of these layers, up to a limit, with hivepack's own ports of each library. A file reads as its tools read it: zstd and LZ4 frames and skippable frames, gzip members, bzip2 streams, xz streams and lzip members one after the other, and zeros after gzip and bzip2. Files that age encrypts open with a passphrase, asked for once however often the file is opened, or with X25519 or SSH keys. This crate is not on crates.io.

```rust
use std::sync::Arc;

use hivepack_age::{BoxedIdentity, LazyScryptIdentity};
use hivepack_open::{Container, Opener};

let ask = Arc::new(|_| Ok(b"correct horse battery staple".to_vec()));
let identities: Vec<BoxedIdentity> = vec![Box::new(LazyScryptIdentity::new(ask))];
let mut opener = Opener::new(|| std::fs::File::open("backup.tar.zst.age"))
    .name("backup.tar.zst.age")
    .identities(identities);
let opened = opener.open()?;
assert_eq!(opened.container(), Container::Tar);
drop(opened);
// Read twice, to check everything before writing: no second prompt.
hivepack_extract::extract_tar(|| Ok(opener.open()?), "out".as_ref(), &Default::default())?;
```

Each `open` reads the file from its start: an age layer's file key is kept from the first, so a later one neither asks for the passphrase again nor runs scrypt, and a file that changed between them fails. A ZIP archive is read by random access: under layers, it must be taken out to a file first. An ISO 9660 image is read in order, under layers too, and extracts with `hivepack_extract::extract_iso` as a tar archive does. A UDF volume (Windows' and DVD images, with ISO 9660 beside UDF or not) is read by random access, as a ZIP archive is: `hivepack_udf::Udf::open` on the file, and `hivepack_extract::extract_udf`.

How layers are found and read, and what is checked, is in [docs/open.md](../../docs/open.md).

## License

MIT. See [LICENSE](../../LICENSE). Copyright (c) 2026 HivePaaS.
