# Safety rules

These rules hold for every crate in the repository. CI checks the parts a tool can check.

## No unsafe code

The workspace sets `unsafe_code = "forbid"`, and every crate inherits it with `[lints] workspace = true`. `forbid` cannot be lifted by an `allow` further in, so no `unsafe` block, `unsafe fn` or `#[no_mangle]` compiles anywhere.

There is one exception, and it is opt-in: the `unsafe-fast` feature of `hivepack-zstd`, which copies without bounds checks in the decoder's main sequence loop (see [unsafe.md](unsafe.md)). Without the feature, that crate forbids unsafe code too. Adding an exception takes all of these steps:

1. Show with numbers from `tools/zstd-bench` (same machine, interleaved rounds) that the safe code misses the speed target in [porting.md](porting.md), and that the unsafe code closes the gap.
2. Keep the unsafe code in one module, as small as it can be. Every block gets a `// SAFETY:` comment that says why it is sound, and preconditions are checked once at the module's entry.
3. Cover it with tests, fuzzing and Miri.
4. Record it in [unsafe.md](unsafe.md): where it is, why, the numbers, and how it is checked.
5. HivePaaS approves it before it merges. Only that crate then moves from `forbid` to `deny`, with `#[allow(unsafe_code)]` on that one module. Where it can be, it is a feature that is off by default, and the crate forbids unsafe code without it.

These are the places in libzstd where safe Rust is known to fall short. Each one is measured first, while the safe code is tried; only the last but one is an exception so far, behind a feature.

| In libzstd | Why safe Rust cannot do the same (Rust 1.99) | Safe approach first |
|---|---|---|
| Choosing BMI2 code at run time (`DYNAMIC_BMI2`) | Calling a `#[target_feature]` function from ordinary code needs `unsafe`, even after `is_x86_feature_detected!` | BMI2 only when built with `-C target-cpu`, such as `x86-64-v3` |
| The x86-64 Huffman decoding loop in assembly (`huf_decompress_amd64.S`) | No assembly | Port the C loop that libzstd uses everywhere else |
| SSE2 and NEON in the row-based match finder (`zstd_lazy.c`) | Loads through `core::arch` take raw pointers, and any `#[target_feature]` call needs `unsafe`, even for SSE2 and NEON, which are always present | Eight-byte words (SWAR), and loops the compiler vectorises |
| Prefetching (`PREFETCH_L1`) in the decoder and the match finders | No safe prefetch on stable Rust | Measure what it is worth. In the decoder it is worth nothing: a `prfm` where libzstd prefetches each match, tried through `asm!`, changed speeds by −2.5% to +0.2% (Apple M1 Pro, October 2026). The match finders are measured with the encoder |
| Unchecked reads in hot loops | Bounds checks cost time | Buffers with slack and fixed-size arrays, so the checks fold away. Measured in the decoder (Apple M1 Pro, October 2026): the compiler cannot see that libzstd's fast-path condition keeps the sequence loop's copies in bounds. With them unchecked, decompression goes from 0.92× to 0.95× libzstd on average over Silesia in one call, and from 0.90× to 0.96× streaming: the `unsafe-fast` feature, approved (see [unsafe.md](unsafe.md)). The bitstreams' 8-byte reads stay checked. In the encoder's match finders (same machine, October 2026), measured on a scratch copy: with their input reads and hash table accesses unchecked, compression gains 4% to 40% (`sao` at level −1 the most, to 0.71× libzstd). Not proposed: the finders' loops reshaped in safe code since gained more (`sao` at level −1 at 0.76×; see [porting.md](porting.md#where-compression-stands)) |
| Output buffers that are never initialised | Needs `unsafe` | Zero them first, which costs little |

## Untrusted input never panics

Library code returns errors and never panics, whatever the input:

- Clippy denies `unwrap`, `expect`, `panic!`, `todo!` and `unimplemented!` outside tests.
- Indexing is allowed, since a failed bounds check panics instead of reading out of bounds. No input may reach such a panic, though, and fuzzing, seeded with zstd's own corpora, is how that is shown. A panic found by a fuzzer is a bug.
- Where libzstd relies on unsigned integers wrapping around, the port says so with `wrapping_*`. Tests and fuzzing run with overflow checks, so an overflow nobody meant panics there instead of passing silently.
- A failure gives the same error as libzstd's `ZSTD_ErrorCode` for that input.

## Bounded resources

- Decoding refuses windows larger than libzstd's default limit (`ZSTD_WINDOWLOG_LIMIT_DEFAULT`, 2^27 bytes = 128 MiB) unless the caller raises it, as `ZSTD_d_windowLogMax` does.
- Streaming keeps one block of input and, unless the output buffer is stable, the window plus two blocks of output, at most the frame's content size. Buffers much larger than the frames need shrink after 128 frames, as in libzstd.
- No allocation is sized from a header before that size is checked against the limits.
- Nothing recurses to a depth the input chooses.

## No C in the libraries

libzstd is a development dependency only: it is the reference in tests and benchmarks, and it never ends up in a library. `cargo deny` (see `deny.toml`) keeps every dependency under a permissive license, from crates.io, and free of open security advisories.
