//! Frames from the port's compressor against libzstd's, through the `zstd`
//! crate (`ZSTD_compressCCtx`), byte for byte, and decoded back with the
//! port's decoder, for random data, at the levels the port has. Each side
//! uses one context again for every frame. The test data is compressed in
//! `tests/compress.rs`.

use crate::compress::zstd_compress::{
    CCtx, CParameter, EndDirective, zstd_compress_bound, zstd_level_ported, zstd_level_strategy,
};
use crate::compress::zstd_compress_internal::{OVERFLOW_CORRECT_FREQUENTLY, ParamSwitch, Strategy};
use crate::compress::zstd_lazy::row_get_match_mask;
use crate::decompress::zstd_decompress::decompress;
use crate::decompress::zstd_decompress::{InBuffer, OutBuffer};
use crate::oracle::Rng;
use zstd::zstd_safe;

/// Whether `level` compresses `len` bytes with a strategy the port has,
/// and libzstd gives the frames it gives on little-endian machines. On
/// big-endian ones its block splitter, which the strategies from `greedy`
/// up use on full blocks, hashes pairs of bytes in the machine's order and
/// splits elsewhere (the port gives the same frames everywhere).
fn is_ported(level: i32, len: usize) -> bool {
    zstd_level_ported(level, len as u64)
        && !(cfg!(target_endian = "big")
            && len >= 128 << 10
            && zstd_level_strategy(level, len as u64) >= Strategy::Greedy)
}

/// Compresses `data` with the port's context and libzstd's, and checks
/// they agree and that the frame decodes back. Returns what differed, if
/// anything.
fn check(
    cctx: &mut CCtx,
    c_cctx: &mut zstd_safe::CCtx<'_>,
    data: &[u8],
    level: i32,
) -> Option<String> {
    let bound = zstd_compress_bound(data.len()).expect("a bound");
    let mut want = vec![0u8; bound];
    let want_size = c_cctx
        .compress(&mut want[..], data, level)
        .expect("libzstd compresses");
    want.truncate(want_size);
    let mut got = vec![0u8; bound];
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
    let mut c_cctx = zstd_safe::CCtx::create();
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
        if let Some(problem) = check(&mut cctx, &mut c_cctx, &data, level) {
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
/// small windows, where matches reach into the window's older segment. A
/// quarter of the frames are btlazy2, whose tree keeps its unsorted
/// positions through the lowering; half are at a lazy level with the row
/// match finder, whose tags stay as they are when the indices are lowered
/// (its chain log, small, only sets how soon they are).
#[test]
fn lowering_the_indices_changes_no_frame() {
    let mut rng = Rng::new(0x5EED_0202);
    let mut corrections = 0;
    let mut row_corrections = 0;
    let mut problems = Vec::new();
    for i in 0..32 {
        let len = rng.range(100_000, 1_200_000) as usize;
        let data = rng.lz_data(len);
        // 0: the fast levels, 1 and 3: the row match finder, 2: btlazy2;
        // each in one call and streaming.
        let kind = i % 4;
        let one_call = (i + i / 4) % 2 == 0;
        let row = kind == 1 || kind == 3;
        let (level, chain_log, row_mode) = if row {
            (
                rng.range(5, 8) as i32,
                rng.range(6, 16) as u32,
                ParamSwitch::Enable,
            )
        } else {
            (
                [-5, -1, 1, 2, 3][rng.range(0, 4) as usize],
                0,
                ParamSwitch::Auto,
            )
        };
        let strategy = (kind == 2).then_some(Strategy::Btlazy2);
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
                    .and_then(|()| cctx.set_parameter(CParameter::WindowLog(window_log)))
                    .and_then(|()| cctx.set_parameter(CParameter::ChainLog(chain_log)))
                    .and_then(|()| cctx.set_parameter(CParameter::UseRowMatchFinder(row_mode)))
                    .and_then(|()| cctx.set_parameter(CParameter::Strategy(strategy)));
                if let Err(error) = set {
                    return Err(format!("{error:?}"));
                }
                let frame = if one_call {
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
                if row {
                    row_corrections += lowered;
                }
                if want != got {
                    problems.push(format!(
                        "{len} bytes at level {level}, strategy {strategy:?}, window log \
                         {window_log}, {}: the frames differ after {lowered} corrections",
                        if one_call { "one call" } else { "streaming" }
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
    eprintln!("{corrections} corrections, {row_corrections} with the row match finder");
    assert!(corrections > 100, "only {corrections} corrections");
    assert!(
        row_corrections > 50,
        "only {row_corrections} corrections with the row match finder"
    );
}

/// The row match finder's mask of the tags that match, from eight bytes at
/// a time, against its definition: bit `i` for entry `(head + i) % entries`.
#[test]
fn row_match_masks_follow_their_definition() {
    fn check<const ROW_LOG: u32>(rng: &mut Rng) {
        let entries = 1usize << ROW_LOG;
        // Few tag values, for many matches.
        let values = rng.range(1, 255);
        let tags: Vec<u8> = (0..entries).map(|_| rng.range(0, values) as u8).collect();
        let tag = rng.range(0, values) as u8;
        for head in 0..entries as u32 {
            let want = (0..entries).fold(0u64, |mask, i| {
                mask | u64::from(tags[(head as usize + i) % entries] == tag) << i
            });
            let got = row_get_match_mask::<ROW_LOG>(&tags, tag, head);
            assert_eq!(
                got, want,
                "{entries} entries, head {head}, tag {tag}: {tags:?}"
            );
        }
    }
    let mut rng = Rng::new(0x5EED_0203);
    for _ in 0..2000 {
        check::<4>(&mut rng);
        check::<5>(&mut rng);
        check::<6>(&mut rng);
    }
}

/// The row match finder's salt goes on from frame to frame, as libzstd's
/// does, and changes no frame: a context used again compresses as a new
/// one, at the levels and with the parameters that use it.
#[test]
fn the_row_match_finders_salt_changes_no_frame() {
    let mut rng = Rng::new(0x5EED_0204);
    let mut cctx = CCtx::new();
    for i in 0..40 {
        let len = rng.range(0, 300_000) as usize;
        let data = if i % 2 == 0 {
            rng.lz_data(len)
        } else {
            rng.huffman_data(len)
        };
        let level = rng.range(4, 12) as i32;
        let search_log = rng.range(0, 7) as u32;
        let compress = |cctx: &mut CCtx| {
            let set = cctx
                .set_parameter(CParameter::CompressionLevel(level))
                .and_then(|()| cctx.set_parameter(CParameter::SearchLog(search_log)))
                .and_then(|()| {
                    cctx.set_parameter(CParameter::UseRowMatchFinder(ParamSwitch::Enable))
                });
            let mut dst = vec![0u8; zstd_compress_bound(len).expect("a bound")];
            set.and_then(|()| cctx.compress2(&mut dst, &data))
                .map(|size| dst[..size].to_vec())
        };
        let again = compress(&mut cctx);
        let new = compress(&mut CCtx::new());
        match (again, new) {
            (Ok(again), Ok(new)) => assert!(
                again == new,
                "{len} bytes at level {level}, search log {search_log}: the frames differ"
            ),
            (again, new) => assert!(
                again.is_err() && new.is_err(),
                "level {level}: again {again:?}, new {new:?}"
            ),
        }
    }
}
