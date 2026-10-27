# Unsafe code

Every crate in this repository forbids unsafe code. The process for an exception is in [safety.md](safety.md).

## Approved exceptions

One, and it is opt-in: without the feature, the crate has no unsafe code at all.

| Crate and module | What it does | Why safe code is not enough (with numbers) | How it is checked | Approved |
|---|---|---|---|---|
| `hivepack-zstd`, feature `unsafe-fast`: `src/decompress/unchecked.rs`, and the block in `decompress_sequences_body_with` (`src/decompress/zstd_decompress_block.rs`) that turns it on | The fast path of the main sequence loop copies literals and matches in 16- and 32-byte pieces without a bounds check per piece, as libzstd's `ZSTD_execSequence` does | Apple M1 Pro, October 2026, Silesia at levels 1, 3, 9 and 19 against libzstd 1.5.7: in one call 0.95× libzstd on average (0.92–0.98×; the safe code, in the same run, 0.92×, 0.85–0.98×), streaming 0.96× (0.87–1.00×; safe 0.90×, 0.86–0.97×). 29 of the 48 cases reach 0.95× in one call (safe: 7), 41 streaming (safe: 2). libzstd's fast-path condition keeps every piece within the buffers, but the compiler cannot see it, and keeps a check on each | The checks it relies on are made once per block: `unchecked_loop_fits`; if they fail, the block is decoded with the checks (the tests assert this never happens). Tests: the unchecked copies against the checked ones, byte for byte (`unchecked_tests`), the whole test suite with the feature, and the committed frames decoded with it (`tests/unchecked.rs`). Miri runs the first and the last, and fails on any access out of bounds. `fuzz/` compares the decoder with libzstd under AddressSanitizer. CI runs all of these | HivePaaS, 27 October 2026, as a feature that is off by default |

## The `unsafe-fast` feature

```toml
hivepack-zstd = { version = "…", features = ["unsafe-fast"] }
```

or `--features hivepack-zstd/unsafe-fast` on the command line. Cargo turns a feature on for the whole build as soon as one crate in it asks for it, so a program can check which build it got with `hivepack_zstd::UNSAFE_FAST`.

What the feature changes:

- The copies take a `Mode` (`zstd_decompress_block.rs`): `Checked`, with bounds checks, or `unchecked::Unchecked`, whose reads and writes are `read_unaligned` and `write_unaligned` on raw pointers. Only `unsafe fn Unchecked::new` makes an `Unchecked`, so safe code cannot reach those accesses by itself.
- `decompress_sequences_body_with` checks, once per block, that the output reaches `oend`, that the literals have libzstd's 32 bytes of margin past their end (`WILDCOPY_OVERLENGTH`), and where the loop starts. Then it makes an `Unchecked` and runs the loop with it; its `SAFETY` comment shows how the loop keeps every fast-path copy within those bounds. If the check fails, which the decoder never lets happen, the loop runs `Checked`.
- Everything else, the slow path near the end of the output, the other sequence loops and the Huffman and FSE decoders, keeps its bounds checks.
- Only on 64-bit machines: the `SAFETY` argument uses positions below 2^63. On 32-bit machines the feature changes nothing.
- Without the feature, `lib.rs` forbids unsafe code again (`forbid(unsafe_code)`), and the crate is as safe as the others. The crate's own lints are `deny` rather than the workspace's `forbid`, since `forbid` cannot be lifted for the one module.
