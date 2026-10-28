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

/// A frame, and how many times the indices of the match state, and those
/// of long distance matching, were lowered in it.
type Lowered = (Vec<u8>, u32, u32);

/// With the indices lowered as soon as they can be (libzstd's
/// `ZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY`, which its fuzzers are built
/// with), the frames come out the same: in one call, and streaming with
/// small windows, where matches reach into the window's older segment. A
/// quarter of the frames are btlazy2, whose tree keeps its unsorted
/// positions through the lowering; half are at a lazy level with the row
/// match finder, whose tags stay as they are when the indices are lowered
/// (its chain log, small, only sets how soon they are). Half of each have
/// long distance matching, whose window lowers its own indices.
#[test]
fn lowering_the_indices_changes_no_frame() {
    let mut rng = Rng::new(0x5EED_0202);
    let mut corrections = 0;
    let mut row_corrections = 0;
    let mut ldm_corrections = 0;
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
        // Long distance matching for each kind, in one call and streaming,
        // with small parameters; and a hash table of its own size, which
        // the window, up to 2^27 bytes without one set, would make large.
        let ldm = (i / 4 + i / 8) % 2 == 1;
        let ldm_mode = if ldm {
            ParamSwitch::Enable
        } else {
            ParamSwitch::Disable
        };
        let ldm_min_match = 4 + (seed % 61) as u32;
        let ldm_hash_rate_log = 1 + (seed >> 8) as u32 % 5;
        let ldm_hash_log = 10 + (seed >> 16) as u32 % 9;
        let frames: Vec<Result<Lowered, String>> = [false, true]
            .into_iter()
            .map(|frequently| {
                OVERFLOW_CORRECT_FREQUENTLY.with(|flag| flag.set(frequently));
                let mut cctx = CCtx::new();
                let set = cctx
                    .set_parameter(CParameter::CompressionLevel(level))
                    .and_then(|()| cctx.set_parameter(CParameter::WindowLog(window_log)))
                    .and_then(|()| cctx.set_parameter(CParameter::ChainLog(chain_log)))
                    .and_then(|()| cctx.set_parameter(CParameter::UseRowMatchFinder(row_mode)))
                    .and_then(|()| cctx.set_parameter(CParameter::Strategy(strategy)))
                    .and_then(|()| {
                        cctx.set_parameter(CParameter::EnableLongDistanceMatching(ldm_mode))
                    })
                    .and_then(|()| cctx.set_parameter(CParameter::LdmMinMatch(ldm_min_match)))
                    .and_then(|()| {
                        cctx.set_parameter(CParameter::LdmHashRateLog(ldm_hash_rate_log))
                    })
                    .and_then(|()| cctx.set_parameter(CParameter::LdmHashLog(ldm_hash_log)));
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
                Ok((
                    frame,
                    cctx.nb_overflow_corrections(),
                    cctx.nb_ldm_overflow_corrections(),
                ))
            })
            .collect();
        OVERFLOW_CORRECT_FREQUENTLY.with(|flag| flag.set(false));
        match (&frames[0], &frames[1]) {
            (Ok((want, 0, 0)), Ok((got, lowered, ldm_lowered))) => {
                corrections += lowered;
                ldm_corrections += ldm_lowered;
                if row {
                    row_corrections += lowered;
                }
                if want != got {
                    problems.push(format!(
                        "{len} bytes at level {level}, strategy {strategy:?}, window log \
                         {window_log}, long distance matching {ldm}, {}: the frames differ after \
                         {lowered} corrections, {ldm_lowered} of long distance matching",
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
    eprintln!(
        "{corrections} corrections, {row_corrections} with the row match finder, \
         {ldm_corrections} of long distance matching"
    );
    assert!(corrections > 100, "only {corrections} corrections");
    assert!(
        ldm_corrections > 50,
        "only {ldm_corrections} corrections of long distance matching"
    );
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

/// Data with repeats far back: pieces of LZ-like and random bytes, and
/// copies of earlier stretches from anywhere before, a few bytes changed.
/// The copies of random bytes only long distance matching finds, past the
/// reach of the strategy's tables.
fn far_repeats(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(len + 70_000);
    while data.len() < len {
        if data.len() > 4096 && rng.range(0, 2) != 0 {
            let size = (rng.range(16, 65_536) as usize).min(data.len() / 2);
            let at = rng.range(0, (data.len() - size) as u64) as usize;
            let start = data.len();
            data.extend_from_within(at..at + size);
            for _ in 0..rng.range(0, 4) {
                let i = start + rng.range(0, size as u64 - 1) as usize;
                data[i] = rng.next() as u8;
            }
        } else {
            let n = rng.range(1, 20_000) as usize;
            let piece = if rng.range(0, 1) == 0 {
                rng.lz_data(n)
            } else {
                rng.bytes(n)
            };
            data.extend(piece);
        }
    }
    data.truncate(len);
    data
}

/// The parameters of long distance matching, for both: small, so that it
/// finds matches in inputs of a few MB; with the strategy, the row match
/// finder for the lazy ones, and the window.
fn ldm_parameters(rng: &mut Rng, strategy: Strategy) -> Vec<(CParameter, zstd_safe::CParameter)> {
    use zstd_safe::CParameter as C;
    let mut list = vec![(
        CParameter::EnableLongDistanceMatching(ParamSwitch::Enable),
        C::EnableLongDistanceMatching(true),
    )];
    let level = rng.range(1, 15) as i32;
    list.push((
        CParameter::CompressionLevel(level),
        C::CompressionLevel(level),
    ));
    let c_strategy = match strategy {
        Strategy::Fast => zstd_safe::Strategy::ZSTD_fast,
        Strategy::Dfast => zstd_safe::Strategy::ZSTD_dfast,
        Strategy::Greedy => zstd_safe::Strategy::ZSTD_greedy,
        Strategy::Lazy => zstd_safe::Strategy::ZSTD_lazy,
        Strategy::Lazy2 => zstd_safe::Strategy::ZSTD_lazy2,
        _ => zstd_safe::Strategy::ZSTD_btlazy2,
    };
    list.push((
        CParameter::Strategy(Some(strategy)),
        C::Strategy(c_strategy),
    ));
    let (p_row, c_row) = [
        (ParamSwitch::Auto, zstd_safe::ParamSwitch::Auto),
        (ParamSwitch::Enable, zstd_safe::ParamSwitch::Enable),
        (ParamSwitch::Disable, zstd_safe::ParamSwitch::Disable),
    ][rng.range(0, 2) as usize];
    list.push((
        CParameter::UseRowMatchFinder(p_row),
        C::UseRowMatchFinder(c_row),
    ));
    if rng.range(0, 3) != 0 {
        let value = rng.range(10, 23) as u32;
        list.push((CParameter::WindowLog(value), C::WindowLog(value)));
    }
    if rng.range(0, 2) != 0 {
        // Small tables for the strategy, which then misses what is far.
        let value = rng.range(8, 16) as u32;
        list.push((CParameter::HashLog(value), C::HashLog(value)));
        let value = rng.range(8, 16) as u32;
        list.push((CParameter::ChainLog(value), C::ChainLog(value)));
    }
    if rng.range(0, 3) != 0 {
        let value = rng.range(4, 80) as u32;
        list.push((CParameter::LdmMinMatch(value), C::LdmMinMatch(value)));
    }
    if rng.range(0, 3) != 0 {
        // Not past the smallest window log less 6: libzstd then takes a
        // hash table of 2^30 entries.
        let value = rng.range(0, 4) as u32;
        list.push((CParameter::LdmHashRateLog(value), C::LdmHashRateLog(value)));
    }
    if rng.range(0, 3) == 0 {
        let value = rng.range(6, 20) as u32;
        list.push((CParameter::LdmHashLog(value), C::LdmHashLog(value)));
    }
    if rng.range(0, 3) == 0 {
        let value = rng.range(1, 8) as u32;
        list.push((
            CParameter::LdmBucketSizeLog(value),
            C::LdmBucketSizeLog(value),
        ));
    }
    list
}

/// Long distance matching with every strategy the port has, in one call
/// (`compress2`), against libzstd, over data with repeats far back; and
/// decoded back.
#[test]
fn long_distance_matching_matches_libzstd() {
    let mut rng = Rng::new(0x5EED_0205);
    let mut problems = Vec::new();
    let strategies = [
        Strategy::Fast,
        Strategy::Dfast,
        Strategy::Greedy,
        Strategy::Lazy,
        Strategy::Lazy2,
        Strategy::Btlazy2,
    ];
    let mut cctx = CCtx::new();
    let mut c_cctx = zstd_safe::CCtx::create();
    for i in 0..60 {
        let strategy = strategies[i % strategies.len()];
        let len = match i % 4 {
            0 => rng.range(0, 5000),
            1 => rng.range(100_000, 400_000),
            _ => rng.range(400_000, 2_500_000),
        } as usize;
        let data = far_repeats(&mut rng, len);
        cctx.reset(crate::decompress::zstd_decompress::ResetDirective::Parameters)
            .expect("between frames");
        c_cctx
            .reset(zstd_safe::ResetDirective::Parameters)
            .expect("between frames");
        let parameters = ldm_parameters(&mut rng, strategy);
        for &(p, c) in &parameters {
            cctx.set_parameter(p).expect("the port takes it");
            c_cctx.set_parameter(c).expect("libzstd takes it");
        }
        let bound = zstd_compress_bound(len).expect("a bound");
        let mut want = vec![0u8; bound];
        let want_size = c_cctx
            .compress2(&mut want[..], &data)
            .expect("libzstd compresses");
        want.truncate(want_size);
        let mut got = vec![0u8; bound];
        match cctx.compress2(&mut got, &data) {
            Ok(size) if got[..size] == want[..] => {
                let mut back = vec![0u8; len];
                if decompress(&mut back, &want).ok() != Some(len) || back != data {
                    problems.push(format!("{len} bytes: does not decode back"));
                }
            }
            Ok(size) => {
                let at = got[..size].iter().zip(&want).position(|(a, b)| a != b);
                problems.push(format!(
                    "{len} bytes, {parameters:?}: {size} bytes, libzstd {want_size}, first \
                     difference at {at:?}"
                ));
            }
            Err(error) => problems.push(format!("{len} bytes, {parameters:?}: {error:?}")),
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
