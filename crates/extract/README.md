# hivepack-extract

Extracting archives to disk, safe by default: nothing is written outside the destination, through a link, over what is there, or past limits set against archive bombs.

> **Status:** extracts ZIP archives that `hivepack-zip` opened, refusing unportable names, the same path twice (ignoring case and how accents are written), links and overlapping data, writing by handle, and counting what is written against its limits, with named options to relax each rule, a time limit, cancelling and progress. tar and RAR come later. This crate is not on crates.io.

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

The tables names are compared with (`src/unicode/tables.rs`) are made by `scripts/unicode.py` from the Unicode Character Database, under the Unicode License v3: see [LICENSE-UNICODE](LICENSE-UNICODE).
