//! Frames from the port's compressor against libzstd's, through the `zstd`
//! crate (`ZSTD_compressCCtx`), byte for byte, and decoded back with the
//! port's decoder, for random data, at the levels the port has. The test
//! data is compressed in `tests/compress.rs`.

use crate::compress::zstd_compress::{
    CCtx, CParameter, EndDirective, zstd_compress_bound, zstd_level_ported,
};
use crate::compress::zstd_compress_internal::OVERFLOW_CORRECT_FREQUENTLY;
use crate::decompress::zstd_decompress::decompress;
use crate::decompress::zstd_decompress::{InBuffer, OutBuffer};
use crate::oracle::Rng;

/// Whether `level` compresses `len` bytes with a strategy the port has.
fn is_ported(level: i32, len: usize) -> bool {
    zstd_level_ported(level, len as u64)
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
fn frames_match_libzstd_at_the_levels_ported() {
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
        let level = [
            -1, -3, -20, -1000, -131_072, 1, 1, 2, 3, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 19,
        ][rng.range(0, 21) as usize];
        if !is_ported(level, len) {
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

/// `data` streamed through `cctx` in pieces drawn from `seed`, as one
/// frame.
fn stream(cctx: &mut CCtx, data: &[u8], seed: u64) -> Result<Vec<u8>, String> {
    let mut rng = Rng::new(seed);
    let mut frame = Vec::new();
    let mut piece = vec![0u8; 1 << 17];
    let mut taken = 0;
    for _ in 0..1_000_000 {
        let end = (taken + rng.range(1, 70_000) as usize).min(data.len());
        let directive = if end == data.len() {
            EndDirective::End
        } else if rng.range(0, 9) == 0 {
            EndDirective::Flush
        } else {
            EndDirective::Continue
        };
        let room = rng.range(1, piece.len() as u64) as usize;
        let mut output = OutBuffer::new(&mut piece[..room]);
        let mut input = InBuffer::new(&data[taken..end]);
        let remaining = cctx
            .compress_stream2(&mut output, &mut input, directive)
            .map_err(|error| format!("{error:?}"))?;
        taken += input.pos;
        let written = output.pos;
        frame.extend_from_slice(&piece[..written]);
        if directive == EndDirective::End && remaining == 0 {
            return Ok(frame);
        }
    }
    Err("no end".into())
}

/// With the indices lowered as soon as they can be (libzstd's
/// `ZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY`, which its fuzzers are built
/// with), the frames come out the same: in one call, and streaming with
/// small windows, where matches reach into the window's older segment.
#[test]
fn lowering_the_indices_changes_no_frame() {
    let mut rng = Rng::new(0x5EED_0202);
    let mut corrections = 0;
    let mut problems = Vec::new();
    for i in 0..24 {
        let len = rng.range(100_000, 1_200_000) as usize;
        let data = rng.lz_data(len);
        let level = [-5, -1, 1, 2, 3][rng.range(0, 4) as usize];
        let window_log = if i % 3 == 0 {
            0
        } else {
            rng.range(10, 17) as u32
        };
        let seed = rng.next();
        let frames: Vec<Result<(Vec<u8>, u32), String>> = [false, true]
            .into_iter()
            .map(|frequently| {
                OVERFLOW_CORRECT_FREQUENTLY.with(|flag| flag.set(frequently));
                let mut cctx = CCtx::new();
                let set = cctx
                    .set_parameter(CParameter::CompressionLevel(level))
                    .and_then(|()| cctx.set_parameter(CParameter::WindowLog(window_log)));
                if let Err(error) = set {
                    return Err(format!("{error:?}"));
                }
                let frame = if i % 2 == 0 {
                    let mut dst = vec![0u8; zstd_compress_bound(len).unwrap_or(0)];
                    let size = cctx
                        .compress2(&mut dst, &data)
                        .map_err(|error| format!("{error:?}"))?;
                    dst.truncate(size);
                    dst
                } else {
                    stream(&mut cctx, &data, seed)?
                };
                Ok((frame, cctx.nb_overflow_corrections()))
            })
            .collect();
        OVERFLOW_CORRECT_FREQUENTLY.with(|flag| flag.set(false));
        match (&frames[0], &frames[1]) {
            (Ok((want, 0)), Ok((got, lowered))) => {
                corrections += lowered;
                if want != got {
                    problems.push(format!(
                        "{len} bytes at level {level}, window log {window_log}, {}: \
                         the frames differ after {lowered} corrections",
                        if i % 2 == 0 { "one call" } else { "streaming" }
                    ));
                }
                let mut back = vec![0u8; len];
                if decompress(&mut back, got).ok() != Some(len) || back != data {
                    problems.push(format!("{len} bytes: does not decode back"));
                }
            }
            other => problems.push(format!("{len} bytes at level {level}: {other:?}")),
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    eprintln!("{corrections} corrections");
    assert!(corrections > 100, "only {corrections} corrections");
}
