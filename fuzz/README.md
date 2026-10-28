# Fuzzing

`cargo-fuzz` targets that compare hivepack-zstd with libzstd, and
hivepack-deflate with zlib. They need nightly, where
`rust-toolchain.toml` pins a stable: the nightly CI uses (`NIGHTLY` in
`.github/workflows/ci.yml`), chosen for the shell with
`export RUSTUP_TOOLCHAIN=<that nightly>`, and `cargo install cargo-fuzz`.

| Target | What it checks |
|---|---|
| `decompress` | Decoding the input in one call: the same output as libzstd, or the same error |
| `compress` | Compressing the input in one call, at a level its first byte picks: the same frame as libzstd, which decodes back |
| `compress_stream` | Streaming the input, with parameters, pieces, directives and room for output its first 8 bytes pick: every call the same as libzstd's, and a frame that decodes back |
| `inflate` | Inflating the input (raw, zlib or gzip, chosen by its first byte) in pieces chosen by its next eight: every call gives the same result, message, bytes read and written, and output as zlib |
| `deflate` | Compressing the input at a level and with a wrapper its first byte picks, in pieces and with flushes its next eight pick: every call gives the same result, bytes read and written, and bytes as zlib |
| `inflate9` | Decoding the input as Deflate64 all at once and in pieces its first eight bytes pick: the same result, message, input used and output calls both ways (zlib's Deflate64 decoder is not in libz-sys; `crates/deflate/tests/deflate64.rs` compares with it) |

Seed the corpus with the frames in `testdata`, then run, with the
`unsafe-fast` feature or without:

```sh
mkdir -p fuzz/corpus/decompress
find testdata -name '*.zst' -exec cp {} fuzz/corpus/decompress/ \;
cargo fuzz run --features unsafe-fast decompress -- -max_total_time=3600
```

The `inflate`, `deflate` and `inflate9` targets start from an empty
corpus:

```sh
cargo fuzz run inflate -- -max_total_time=3600
cargo fuzz run deflate -- -max_total_time=3600
cargo fuzz run inflate9 -- -max_total_time=3600
```

`cargo fuzz` builds with AddressSanitizer, so with the feature an access out
of bounds in its unchecked copies stops the run as a crash, as a difference
from libzstd does. CI runs each target for a few minutes.
