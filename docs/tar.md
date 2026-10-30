# Porting Go's archive/tar

`hivepack-tar` reads tar archives in safe Rust. It is a port of the reading half of `archive/tar` in Go's standard library: a small, well-tested reader of every format in use, hardened by years of fuzzing, under the BSD-3-Clause license. Most `.tar.gz`, `.tar.zst`, `.tar.xz` and `.tar.zst.age` files are tar inside a compressor, which hivepack's other crates read.

## The source

The port follows **Go 1.27.2** (`src/archive/tar`), the latest release as of October 2026. `hivepack_tar::UPSTREAM_VERSION` names it. As in the other ports ([porting.md](porting.md)), each Go file is a module, functions keep their names in snake case, and each doc comment names its Go original.

| Go | Port | What |
|---|---|---|
| `reader.go` | `reader.rs` (`Reader`) | entries in order: PAX records and GNU long names merged into the entries they describe, global PAX headers as entries of their own, data read and skipped, sparse files in GNU's formats 0.0, 0.1, 1.0 and the old one |
| `format.go` | `format.rs` | the 512-byte block, its checksum (unsigned or signed) and layouts: V7, USTAR, PAX, GNU, STAR |
| `strconv.go` | `strconv.rs` | numbers in octal or GNU's base-256, PAX records and times |
| `common.go` | `common.rs` (`Header`, `Format`, `Time`, `Error`, the `TYPE_` constants) | headers, formats, sparse maps validated and turned into holes |

## What differs

- **Bytes, not strings.** Go's strings hold any bytes; here names, link targets, owners and PAX records are `Vec<u8>`, which most archives fill with UTF-8. PAX records and extended attributes are `BTreeMap`s, in key order.
- **Times are `Time`** (seconds and nanoseconds since 1970, normalised as `time.Unix` does), and `Option<Time>` where Go would leave its zero time: the access and change times when the archive has none, and a global PAX header's modification time.
- **Errors are a type.** Go's `ErrHeader`, `ErrFieldTooLong`, `errSparseTooLong`, `errMissData`, `errUnrefData` and `io.ErrUnexpectedEOF` are `Error`'s variants; the data's errors travel inside `io::Error` and come back out with `Error::from`. A failure is kept and returned again by every later call, as Go keeps it.
- **An error that comes with the last bytes comes after them.** Go's `Read` can return bytes and an error at once (a sparse file with more data than its map ends so); Rust's cannot, so the bytes come first and the error at the next call, which `read_to_end` sees the same way.
- **No seeking.** Go skips the rest of an entry with `Seek` when the input can; the port reads past it. The outcome is the same; the tests give Go an input that cannot seek.
- **No `GODEBUG=tarinsecurepath`.** Names are checked where files are written, in hivepack-extract.
- **The global PAX header's records are merged in key order.** Go merges them in its map's random order and ignores the error of a bad one, so a global header with both a bad record and a `path` can come out either way in Go; here the order is fixed.
- **Not ported:** the writer (`writer.go`), `FileInfoHeader` and `Header.FileInfo`, which convert to and from the file system's `fs.FileInfo`.

## Bounded resources

As in Go: PAX records and GNU long names at most 1 MiB, sparse maps at most 1 MiB and a million entries, one header block at a time. An entry's data is read as the caller reads it, and skipped otherwise; a sparse file's holes are produced as zeros, so a reader that takes all of a terabyte of holes reads a terabyte. hivepack-extract will write holes without reading them.

## The speed

`tools/tar-bench` times the port against Go's `archive/tar`, in a program of its own (`tools/tar-bench/go`), on the same archives:

```sh
python3 scripts/testdata.py fetch --group bench
cargo run --release -p tar-bench -- [--only TEXT] [--rounds 5] [--seconds 0.5]
```

AMD Ryzen 9 9950X (16 cores, x86-64), 45 GiB of memory, Ubuntu 26.04 with Linux 7.0 and the `powersave` governor, rustc 1.99.1 in the workspace's release profile, Go 1.27.2, October 2026. "Many" archives hold 200,000 entries of 16 bytes (200 entries and their folder for the sparse ones, files of 1 MiB with 4 KiB of data every 64 KiB, which GNU tar 1.35 makes); "big" ones the Silesia corpus cut to 64 MiB; "small" ones 20,000 pieces of 4 KiB. Each speed is the best of five rounds taken in turn. Both found the same entries and read the same bytes.

| Workload | The port | Go | Port / Go |
|---|---|---|---|
| **Going through entries, from memory** | | | |
| USTAR | 2108 k entries/s | 878 k entries/s | 2.40× |
| PAX, long names and times in nanoseconds | 934 k entries/s | 358 k entries/s | 2.61× |
| GNU, long names | 1217 k entries/s | 822 k entries/s | 1.48× |
| GNU sparse | 812 k entries/s | 337 k entries/s | 2.41× |
| PAX sparse 1.0 | 494 k entries/s | 209 k entries/s | 2.37× |
| **Going through entries, from a file** | | | |
| USTAR, through a buffer of 64 KiB | 1983 k entries/s | 817 k entries/s | 2.43× |
| USTAR, one read at a time | 1185 k entries/s | 544 k entries/s | 2.18× |
| **Reading data, from memory** | | | |
| Big entries | 46.5 GB/s | 34.9 GB/s | 1.33× |
| Small entries | 1583 k entries/s | 793 k entries/s | 2.00× |
| GNU sparse, the holes as zeros | 168 GB/s | 141 GB/s | 1.20× |
| PAX sparse 1.0, the holes as zeros | 149 GB/s | 115 GB/s | 1.30× |
| **Reading data, from a file** | | | |
| Big entries, through a buffer of 64 KiB | 41.6 GB/s | 39.6 GB/s | 1.05× |
| Big entries, one read at a time | 41.4 GB/s | 40.5 GB/s | 1.02× |
| **Skipping data** | | | |
| Big entries, from memory | 4,772 GB/s | 35.5 GB/s | 134× |
| Big entries, through a buffer of 64 KiB | 32.4 GB/s | 33.9 GB/s | 0.96× |
| Big entries, a file given as it is | 34.0 GB/s | 2,422 GB/s | 0.01× |

What to read in it:

- **Headers** are where a tar reader does its own work, and the port takes about half of Go's time. Neither was profiled, so why is not shown; Go's `Header` holds strings and maps, and Go has a garbage collector.
- **Data** is mostly a copy, so it measures memory: from a file, the page cache. Compressors in front of tar will set the speed, not this.
- **Skipping a file given as it is** is the real gap. `archive/tar` seeks past data when its reader can seek, and `hivepack_tar::Reader` takes any `Read` and goes through it, so listing a large archive on disk reads all of it. Reading and extracting are not affected, and neither is a compressed archive, which cannot seek. From memory, the 134× is not the port's doing: its skip reads into a buffer nothing looks at, and about 14 µs for 64 MiB can only mean the compiler took the copy out, where Go's copy through a plain reader stays. A real source is a file or a decompressor, as in the rows beside it.

## How it is shown

- **`src/strconv.rs`'s tests**: the tables of Go's `strconv_test.go` for `parseNumeric`, `parsePAXTime` and `parsePAXRecord`, the last two generated from Go's test source.
- **`tests/oracle.rs`**: comparison with Go 1.27.2's `archive/tar` through `tools/tar-oracle`, a small Go program built by `scripts/testdata.py`; CI installs the Go its `go.mod` names. Both read every entry and up to 8 MiB of its data, the port in pieces of random sizes; the headers (every field, the PAX records and extended attributes as hashes), the data's length and SHA-256, its error, and how the archive ends must be the same. The archives:
  - Go's own 46 test archives (`testdata/go-tar`, from Go 1.27.2, the base64 and bzip2 ones decoded), as they are and each damaged twenty ways: a bit flipped; a field of a block (name, mode, owner, size, time, type, link, magic, version, devices, prefix, GNU's sparse map, its extension flag and real size) given zeros, spaces, octal, base-256, a type or random bytes, with the checksum fixed so that the damage gets past it; cut at a block's end or anywhere; zero blocks inserted, a block repeated or removed; garbage after the end; a PAX record's bytes scribbled on.
  - 1,500 archives that Go's `tar.Writer` makes from random headers, as they are or damaged: every type, names around USTAR's 100 and 155 bytes in ASCII and UTF-8, link names, owners and devices past what octal holds, times before 1970 and with nanoseconds, PAX records and extended attributes, global headers, the format chosen or left to the writer.
  - 800 sparse files built by the test in GNU's formats 0.1, 1.0 and the old one, with maps that are random and sometimes overlap, and a few bytes more or less of data than the map needs, as they are or damaged; Go's writer does not write sparse files.

  About 3,300 archives are compared where the oracle is built (Linux and macOS in CI), every ending among them: the end, a bad header, an archive cut short, a field or sparse map too long, a sparse file with data missing or left over. `testdata/oracle/tar.txt` replays 1,066 everywhere else, Go's archives and their damage by name and number, which the test makes again.
- **Fuzzing**: the `tar` target reads any input, every entry and up to 4 MiB of its data, twice, in pieces of different sizes: the same headers, data and end both times, and no panic. CI seeds it with Go's test archives.

## Following new releases

A new Go release's changes to `src/archive/tar` are ported, `tools/tar-oracle/go.mod` names the release, and `testdata/go-tar` takes its test archives.

## Licenses

The port is derived from Go, under the BSD-3-Clause license (Copyright 2009 The Go Authors); `hivepack-tar` is under the same license, with Go's notice in its [LICENSE](../crates/tar/LICENSE). Go's test archives in `testdata/go-tar` are under it too, with the same notice beside them.
