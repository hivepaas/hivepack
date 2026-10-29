# hivepack-extract

Extracting archives to disk, safe by default: nothing is written outside the destination, through a link, over what is there, or past limits set against archive bombs.

> **Status:** extracts ZIP archives that `hivepack-zip` opened, refusing unportable names, the same path twice, links, special files and overlapping data, writing by handle, and counting what is written against its limits. tar and RAR come later. This crate is not on crates.io.

```rust
use hivepack_extract::{Options, extract_zip};
use hivepack_zip::{Archive, OpenFlags};

let archive = Archive::open(std::fs::File::open("archive.zip")?, OpenFlags::CHECKCONS)?;
let summary = extract_zip(&archive, "out".as_ref(), &Options::default())?;
println!("{} files, {} bytes", summary.files, summary.bytes);
```

The rules, and why each is there, are in [docs/extract.md](../../docs/extract.md). Writing by handle takes cap-std, the one dependency with `unsafe` code in hivepack's libraries, until the standard library's directory handles are stable (see [docs/safety.md](../../docs/safety.md)).

## License

MIT. See [LICENSE](../../LICENSE). Copyright (c) 2026 HivePaaS.
