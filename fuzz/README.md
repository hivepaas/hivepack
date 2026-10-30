# Fuzzing

`cargo-fuzz` targets that compare hivepack-zstd with libzstd,
hivepack-deflate with zlib, hivepack-bzip2 with libbzip2, hivepack-lz4 with
liblz4, and hivepack-xz with liblzma, and that feed hivepack-zip,
hivepack-extract, hivepack-age, hivepack-tar and hivepack-open any input. They need
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
| `inflate` | Inflating the input (raw, zlib or gzip, chosen by its first byte) in pieces chosen by its next eight: every call gives the same result, message, bytes read and written, and output as zlib |
| `deflate` | Compressing the input at a level and with a wrapper its first byte picks, in pieces and with flushes its next eight pick: every call gives the same result, bytes read and written, and bytes as zlib |
| `zip_open` | Opening the input as a ZIP archive, leniently and with `ZIP_CHECKCONS`, asking the reading API about every entry, and reading every entry's data, decompressed, raw, and decrypted with the password "foo": no panic (`crates/zip/tests/oracle.rs` compares the answers with libzip) |
| `extract` | Extracting the input as a ZIP archive with hivepack-extract, with options its first byte picks, cancelled after some progress if it says so: nothing written beside the destination, every link created staying inside it, the summary counting what is there, and no file left cut off |
| `zip_edit` | Opening the input as a ZIP archive, making the edits its first bytes pick (encrypting among them) and writing it: the archive written opens with the entries as edited, their names, comments, attributes, times, sizes and data, read with the passwords the edits set (`crates/zip/tests/oracle.rs` compares the edits and the bytes written with libzip) |
| `inflate9` | Decoding the input as Deflate64 all at once and in pieces its first eight bytes pick: the same result, message, input used and output calls both ways, and with `Inflate9` in pieces of input and output the same end, message and output (zlib's Deflate64 decoder is not in libz-sys; `crates/deflate/tests/deflate64.rs` compares with it) |
| `lz4` | After a mode byte and eight bytes of seed: decoding the rest as a block with `LZ4_decompress_safe` into an output of a size the seed picks, with the same result and every byte of the output the same, past what is decoded too, as liblz4; reading it as a frame in reads of sizes the seed picks, through the lz4 crate's `Decoder` and the same loop over the port's context, with the same bytes from every read; decoding it partially, with dictionaries, after a prefix and in a stream, and reading it with the port's `Decoder`: no panic (`crates/lz4/tests/oracle.rs` compares those with liblz4) |
| `bzip2` | With an even first byte, decompressing the rest, fast or small, in pieces chosen by the next eight bytes: every call, up to the first error, gives the same result, bytes read and written, and output as libbzip2. With an odd one, compressing the rest at a block size and work factor the first byte picks, in pieces with flushes on the way: every call the same as libbzip2's, and a stream that decompresses back |
| `xz` | Decoding the rest of the input with the decoder its first byte picks (`.xz`, automatic, `.lz`, `.lzma`, raw LZMA1 or LZMA2 with up to three delta and BCJ filters before it), with flags, a memory limit or options and pieces its next eight pick, and memory limits set between calls: every call, up to the first error, gives the same result, bytes read and written, and output as liblzma (built from liblzma-sys's bundled 5.8.4 sources). The automatic decoder skips `.lz` input, which liblzma-sys's build of the automatic decoder takes for `.lzma` |
| `xz_encode` | Encoding the rest of the input with the encoder its first byte picks (`.xz` of a preset, `.xz` of LZMA2 with options, `.lzma`, raw LZMA1 or LZMA2, all but `.lzma` and the preset with up to three delta and BCJ filters before LZMA), with the preset, check, options, filters, pieces and flushes its next eight bytes pick: every call gives the same result, bytes read and written, and output as liblzma |
| `age` | Decrypting the input as an age file, armored or not, with CCTV's usual X25519 key and the passphrase `password` (work factors up to 2^4), twice, in pieces of different sizes its first eight bytes pick: the same plaintext and the same end both times, and no panic (`crates/age/tests/oracle.rs` compares the outcomes with age) |
| `age_keys` | Reading the input as an identity file, as `age -i` does (a file of keys, an SSH key, a file of keys encrypted with age): no panic. Only the parsing, as decrypting an encrypted key file could ask scrypt for 4 GiB |
| `tar` | Reading the input as a tar archive, every entry and up to 4 MiB of each one's data, twice, in pieces of different sizes its first eight bytes pick: the same headers, data and end both times, and no panic (`crates/tar/tests/oracle.rs` compares the answers with Go's archive/tar) |
| `extract_tar` | Extracting the input as a tar archive with hivepack-extract, as `extract` does a ZIP archive: options from its first byte, cancelled after some progress if it says so; nothing written beside the destination, every link created staying inside it, the summary counting what is there (a hard link's file once), and no file left cut off |
| `open` | Opening the input through its layers with hivepack-open (the age key of `crates/open/tests/age.rs`'s files; a name ending in `.lzma` if its first byte is odd; small limits), three times with one opener, the later opens with the file keys kept, and reading up to 4 MiB in pieces of different sizes: the same layers, container and end each time, the same data, or after an error data of which one starts the other (libzstd gives out less before an error when its output buffer is larger), and no panic |

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

The `inflate`, `deflate` and `inflate9` targets start from an empty
corpus, CI seeds `bzip2` with the streams and inputs of
`testdata/oracle/bzip2.txt`, `xz` with the inputs of
`testdata/oracle/xz.txt`, behind the byte for their decoder, and `xz_encode`
with those of `testdata/oracle/xz-encode.txt`, behind the byte for their
encoder:

```sh
cargo fuzz run inflate -- -max_total_time=3600
cargo fuzz run deflate -- -max_total_time=3600
cargo fuzz run inflate9 -- -max_total_time=3600
cargo fuzz run bzip2 -- -max_total_time=3600
cargo fuzz run xz -- -max_total_time=3600 -rss_limit_mb=4096
cargo fuzz run xz_encode -- -max_total_time=3600 -rss_limit_mb=4096
```

CI seeds `lz4` with the blocks and frames of `testdata/oracle/lz4.txt`, each
behind the mode bytes that decode it as a block and as a frame:

```sh
cargo fuzz run lz4 -- -max_total_time=3600 -rss_limit_mb=4096
```

CI seeds `zip_open` with the archives of `testdata/oracle/zip-open.txt` and
those libzip encrypted in `testdata/oracle/zip-decrypt.txt` (some with
"foo"), and `zip_edit` with the same archives behind two edits (encrypting, for
the encrypted ones).

`cargo fuzz` builds with AddressSanitizer, so with the feature an access out
of bounds in its unchecked copies stops the run as a crash, as a difference
from libzstd does. CI runs each target for a few minutes.
