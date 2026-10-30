# Fuzzing

`cargo-fuzz` targets that compare hivepack-zstd with libzstd,
hivepack-deflate with zlib, and hivepack-bzip2 with libbzip2. They need
nightly, where `rust-toolchain.toml` pins a stable: the nightly CI uses
(`NIGHTLY` in `.github/workflows/ci.yml`), chosen for the shell with
`export RUSTUP_TOOLCHAIN=<that nightly>`, and
`cargo install cargo-fuzz`.

| Target | What it checks |
|---|---|
| `decompress` | Decoding the input in one call: the same output as libzstd, or the same error |
| `compress` | Compressing the input in one call, at a level its first byte picks, with the blocks split after their sequences when a bit of it is set, and with worker threads when another is (then also streamed with its size unknown, which takes them), and with a target size for compressed blocks for some sizes: the same frame as libzstd, which decodes back |
| `compress_stream` | Streaming the input, with parameters (long distance matching and a target size for compressed blocks among them), pieces, directives and room for output its first 8 bytes pick: every call the same as libzstd's, and a frame that decodes back. A quarter of the time with worker threads, a different number on each side, where each side goes through the same steps on its own: the same frame |
| `sequences` | The sequence API, which zstd-safe does not offer (the oracle's tests compare it with libzstd): with the input's first byte, its sequences generated at a level and compressed back with `compress_sequences`, with their block delimiters and merged without, and with `compress_sequences_and_literals`, every frame decoding back to it; or sequences of any values read from its start, compressed over the rest as given and as a sequence producer's for every block: a frame or an error, never a panic |
| `divsufsort` | The suffix array of a text, as the dictionary builder sorts its samples (`divsufsort`; the oracle's tests compare it with libzstd's): the rest of the input as it is, repeated, twice over or as runs, its first byte picks which, so that long repeats come easily. A permutation of the text's positions, each suffix smaller than the next, and for texts up to 512 bytes the suffixes sorted as slices |
| `inflate` | Inflating the input (raw, zlib or gzip, chosen by its first byte) in pieces chosen by its next eight: every call gives the same result, message, bytes read and written, and output as zlib |
| `deflate` | Compressing the input at a level and with a wrapper its first byte picks, in pieces and with flushes its next eight pick: every call gives the same result, bytes read and written, and bytes as zlib |
| `zip_open` | Opening the input as a ZIP archive, leniently and with `ZIP_CHECKCONS`, asking the reading API about every entry, and reading every entry's data, decompressed, raw, and decrypted with the password "foo": no panic (`crates/zip/tests/oracle.rs` compares the answers with libzip) |
| `extract` | Extracting the input as a ZIP archive with hivepack-extract, with options its first byte picks, cancelled after some progress if it says so: nothing written beside the destination, every link created staying inside it, the summary counting what is there, and no file left cut off |
| `zip_edit` | Opening the input as a ZIP archive, making the edits its first bytes pick (encrypting among them) and writing it: the archive written opens with the entries as edited, their names, comments, attributes, times, sizes and data, read with the passwords the edits set (`crates/zip/tests/oracle.rs` compares the edits and the bytes written with libzip) |
| `inflate9` | Decoding the input as Deflate64 all at once and in pieces its first eight bytes pick: the same result, message, input used and output calls both ways, and with `Inflate9` in pieces of input and output the same end, message and output (zlib's Deflate64 decoder is not in libz-sys; `crates/deflate/tests/deflate64.rs` compares with it) |
| `bzip2` | With an even first byte, decompressing the rest, fast or small, in pieces chosen by the next eight bytes: every call, up to the first error, gives the same result, bytes read and written, and output as libbzip2. With an odd one, compressing the rest at a block size and work factor the first byte picks, in pieces with flushes on the way: every call the same as libbzip2's, and a stream that decompresses back |

Seed the corpus with the frames in `testdata`, then run, with the
`unsafe-fast` feature or without:

```sh
mkdir -p fuzz/corpus/decompress
find testdata -name '*.zst' -exec cp {} fuzz/corpus/decompress/ \;
cargo fuzz run --features unsafe-fast decompress -- -max_total_time=3600
```

CI seeds `sequences` with the same files as `compress`.

`compress` and `compress_stream` take the feature too: with it, the row
match finder gathers its candidates and prefetches them, as libzstd does,
so fuzz them both ways (CI runs `compress` with it, `compress_stream`
without).

The `inflate`, `deflate`, `inflate9` and `divsufsort` targets start from
an empty corpus, and CI seeds `bzip2` with the streams and inputs of
`testdata/oracle/bzip2.txt`:

```sh
cargo fuzz run inflate -- -max_total_time=3600
cargo fuzz run deflate -- -max_total_time=3600
cargo fuzz run inflate9 -- -max_total_time=3600
cargo fuzz run bzip2 -- -max_total_time=3600
cargo fuzz run divsufsort -- -max_total_time=3600 -rss_limit_mb=4096
```

CI seeds `zip_open` with the archives of `testdata/oracle/zip-open.txt` and
those libzip encrypted in `testdata/oracle/zip-decrypt.txt` (some with
"foo"), and `zip_edit` with the same archives behind two edits (encrypting, for
the encrypted ones).

`cargo fuzz` builds with AddressSanitizer, so with the feature an access out
of bounds in its unchecked copies stops the run as a crash, as a difference
from libzstd does. CI runs each target for a few minutes.
