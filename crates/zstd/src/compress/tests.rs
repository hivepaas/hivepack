//! Frames from the port's compressor against libzstd's, through the `zstd`
//! crate (`ZSTD_compressCCtx`), byte for byte, and decoded back with the
//! port's decoder, for random data, at the levels the port has. The test
//! data is compressed in `tests/compress.rs`.

use crate::compress::zstd_compress::{
    CCtx, CParamMode, zstd_compress_bound, zstd_get_cparams_internal,
};
use crate::compress::zstd_compress_internal::Strategy;
use crate::decompress::zstd_decompress::decompress;
use crate::oracle::Rng;

/// Whether `level` compresses `len` bytes with a strategy the port has.
fn is_fast(level: i32, len: usize) -> bool {
    zstd_get_cparams_internal(level, len as u64, 0, CParamMode::NoAttachDict).strategy
        <= Strategy::Dfast
}

/// Compresses `data` with the port and libzstd, and checks they agree and
/// that the frame decodes back. Returns what differed, if anything.
fn check(cctx: &mut CCtx, data: &[u8], level: i32) -> Option<String> {
    let want = zstd::bulk::compress(data, level).expect("libzstd compresses");
    let mut got = vec![0u8; zstd_compress_bound(data.len()).expect("a bound")];
    let size = match cctx.compress(&mut got, data, level) {
        Ok(size) => size,
        Err(error) => return Some(format!("the port failed: {error:?}")),
    };
    if got[..size] != want[..] {
        let at = got[..size]
            .iter()
            .zip(&want)
            .position(|(a, b)| a != b)
            .unwrap_or(size.min(want.len()));
        return Some(format!(
            "{size} bytes, libzstd {}, first difference at {at}",
            want.len()
        ));
    }
    let mut back = vec![0u8; data.len()];
    match decompress(&mut back, &got[..size]) {
        Ok(n) if back[..n] == *data => None,
        other => Some(format!("does not decode back: {:?}", other.map(|_| ()))),
    }
}

#[test]
fn frames_match_libzstd_at_fast_levels() {
    let mut rng = Rng::new(0x5EED_0201);
    let mut cctx = CCtx::new();
    let mut problems = Vec::new();
    for i in 0..600 {
        let len = match i % 6 {
            0 => rng.range(0, 64),
            1 => rng.range(0, 5000),
            2 => rng.range(16_000, 140_000),
            3 => rng.range(200_000, 600_000),
            _ => rng.range(0, 40_000),
        } as usize;
        let data = match i % 4 {
            0 => rng.lz_data(len),
            1 => rng.huffman_data(len),
            2 => rng.bytes(len),
            _ => {
                // Pieces of different kinds, where blocks may end early.
                let mut data = rng.lz_data(len / 2);
                data.extend(rng.bytes(len / 4));
                data.extend(rng.huffman_data(len - data.len()));
                data
            }
        };
        let level = [-1, -3, -20, -1000, -131_072, 1, 1, 2, 3, 3, 4][rng.range(0, 10) as usize];
        if !is_fast(level, len) {
            continue;
        }
        if let Some(problem) = check(&mut cctx, &data, level) {
            problems.push(format!(
                "{len} bytes of kind {} at level {level}: {problem}",
                i % 4
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
