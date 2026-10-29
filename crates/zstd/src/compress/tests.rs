//! Frames from the port's compressor against libzstd's, through the `zstd`
//! crate (`ZSTD_compressCCtx`), byte for byte, and decoded back with the
//! port's decoder, for random data, at the levels the port has. Each side
//! uses one context again for every frame. The test data is compressed in
//! `tests/compress.rs`.

use std::sync::Arc;

use crate::compress::zstd_cdict::CDict;
use crate::compress::zstd_compress::{
    CCtx, CParameter, EndDirective, zstd_compress_bound, zstd_level_ported, zstd_level_strategy,
};
use crate::compress::zstd_compress_internal::{
    DictAttachPref, OVERFLOW_CORRECT_FREQUENTLY, ParamSwitch, Strategy,
};
use crate::compress::zstd_lazy::row_get_match_mask;
use crate::decompress::zstd_decompress::decompress;
use crate::decompress::zstd_decompress::{InBuffer, OutBuffer};
use crate::decompress::zstd_decompress_internal::DCtx;
use crate::oracle::Rng;
use zstd::zstd_safe;

/// Whether the port has what `level` needs to compress `len` bytes, and
/// libzstd gives the frames it gives on little-endian machines. On
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
            -1, -3, -20, -1000, -131_072, 1, 1, 2, 3, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22,
        ][rng.range(0, 28) as usize];
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

/// Data whose kind changes within blocks, where the block splitter after
/// the sequences cuts them: text-like pieces with repeats near and far,
/// skewed bytes, and random bytes with copies of 4 bytes from far back,
/// some at the offset of the copy before. Those are many sequences that
/// save too little: cut off, they are stored raw, and a repeat code after
/// them can stand for another offset in the decoder than in the encoder.
/// And runs of one byte, for blocks stored RLE.
fn changing_data(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(len + 70_000);
    while data.len() < len {
        let piece = rng.range(1000, 70_000) as usize;
        match rng.range(0, 8) {
            0 | 1 => data.extend(rng.lz_data(piece)),
            2 => data.extend(rng.huffman_data(piece)),
            3 => {
                let byte = rng.next() as u8;
                data.resize(data.len() + piece, byte);
            }
            _ => {
                let end = data.len() + piece;
                let spacing = rng.range(30, 80);
                let mut back = 0;
                while data.len() < end {
                    if data.len() > 8000 && rng.range(0, spacing) == 0 {
                        if back == 0 || rng.range(0, 1) == 0 {
                            back = rng.range(4, data.len().min(100_000) as u64) as usize;
                        }
                        for _ in 0..4 {
                            let byte = data[data.len() - back];
                            data.push(byte);
                        }
                    } else {
                        data.push(rng.next() as u8);
                    }
                }
            }
        }
    }
    data.truncate(len);
    data
}

/// The raw blocks of a frame.
fn raw_blocks(frame: &[u8]) -> usize {
    let descriptor = frame[4];
    let single_segment = descriptor & 0x20 != 0;
    let dict_id = [0, 1, 2, 4][usize::from(descriptor & 3)];
    let fcs = [usize::from(single_segment), 2, 4, 8][usize::from(descriptor >> 6)];
    let mut at = 5 + usize::from(!single_segment) + dict_id + fcs;
    let mut raw = 0;
    loop {
        let header = u32::from_le_bytes([frame[at], frame[at + 1], frame[at + 2], 0]);
        let (last, kind, size) = (header & 1, (header >> 1) & 3, (header >> 3) as usize);
        raw += usize::from(kind == 0);
        at += 3 + if kind == 1 { 1 } else { size };
        if last != 0 {
            return raw;
        }
    }
}

/// With the block splitter after the sequences on (libzstd's
/// `ZSTD_c_splitAfterSequences`, for `btopt` and up by default), at every
/// strategy the port has, in one call: the frames are libzstd's, and decode
/// back. Some with smaller blocks or windows, or other shortest matches.
#[test]
fn frames_split_after_their_sequences_match_libzstd() {
    use zstd_safe::{CParameter as C, ParamSwitch as S};
    const STRATEGIES: [(Strategy, zstd_safe::Strategy); 6] = [
        (Strategy::Fast, zstd_safe::Strategy::ZSTD_fast),
        (Strategy::Dfast, zstd_safe::Strategy::ZSTD_dfast),
        (Strategy::Greedy, zstd_safe::Strategy::ZSTD_greedy),
        (Strategy::Lazy, zstd_safe::Strategy::ZSTD_lazy),
        (Strategy::Lazy2, zstd_safe::Strategy::ZSTD_lazy2),
        (Strategy::Btlazy2, zstd_safe::Strategy::ZSTD_btlazy2),
    ];
    let mut rng = Rng::new(0x5EED_0205);
    let mut problems = Vec::new();
    let (mut compared, mut split, mut raw) = (0, 0, 0);
    for i in 0..200 {
        let len = match i % 4 {
            0 => rng.range(0, 20_000),
            1 => rng.range(100_000, 140_000),
            _ => rng.range(140_000, 450_000),
        } as usize;
        let data = if i % 6 == 0 {
            rng.lz_data(len)
        } else {
            changing_data(&mut rng, len)
        };
        let level = rng.range(0, 17) as i32 - 2;
        let mut parameters = vec![
            (
                CParameter::CompressionLevel(level),
                C::CompressionLevel(level),
            ),
            (
                CParameter::SplitAfterSequences(ParamSwitch::Enable),
                C::UseBlockSplitter(S::Enable),
            ),
        ];
        // A strategy the port has, at random, and where the level's is
        // btopt or up.
        let mut strategy = zstd_level_strategy(level, len as u64);
        if strategy > Strategy::Btlazy2 || rng.range(0, 3) == 0 {
            let (p, c) = STRATEGIES[rng.range(0, 5) as usize];
            parameters.push((CParameter::Strategy(Some(p)), C::Strategy(c)));
            strategy = p;
        }
        if rng.range(0, 3) == 0 {
            let window_log = rng.range(10, 20) as u32;
            parameters.push((CParameter::WindowLog(window_log), C::WindowLog(window_log)));
        }
        // Short matches, for the copies of 4 bytes, most of the time.
        if rng.range(0, 3) != 0 {
            let min_match = rng.range(3, 6) as u32;
            parameters.push((CParameter::MinMatch(min_match), C::MinMatch(min_match)));
        }
        if rng.range(0, 4) == 0 {
            let max_block = [1024, 5000, 65_536][rng.range(0, 2) as usize];
            parameters.push((
                CParameter::MaxBlockSize(max_block),
                C::MaxBlockSize(max_block),
            ));
        }
        // On big-endian machines libzstd splits full blocks elsewhere before
        // finding their sequences (see is_ported).
        if cfg!(target_endian = "big") && len >= 128 << 10 && strategy >= Strategy::Greedy {
            continue;
        }

        let mut cctx = CCtx::new();
        let mut c_cctx = zstd_safe::CCtx::create();
        for &(p, c) in &parameters {
            cctx.set_parameter(p).expect("the port sets it");
            c_cctx.set_parameter(c).expect("libzstd sets it");
        }
        let bound = zstd_compress_bound(len).expect("a bound");
        let mut want = vec![0u8; bound];
        let want_size = c_cctx
            .compress2(&mut want[..], &data)
            .expect("libzstd compresses");
        want.truncate(want_size);
        let mut got = vec![0u8; bound];
        let tag = format!("{len} bytes, {parameters:?}");
        let size = match cctx.compress2(&mut got, &data) {
            Ok(size) => size,
            Err(error) => {
                problems.push(format!("{tag}: the port failed: {error:?}"));
                continue;
            }
        };
        compared += 1;
        if got[..size] != want[..] {
            let at = got[..size].iter().zip(&want).position(|(a, b)| a != b);
            problems.push(format!(
                "{tag}: {size} bytes, libzstd {want_size}, first difference at {at:?}"
            ));
            continue;
        }
        let mut back = vec![0u8; len];
        if decompress(&mut back, &got[..size]).ok() != Some(len) || back != data {
            problems.push(format!("{tag}: does not decode back"));
        }
        // Whether the splitter cut a block, and stored a piece raw: libzstd's
        // frame without it.
        c_cctx
            .set_parameter(C::UseBlockSplitter(S::Disable))
            .expect("libzstd sets it");
        let mut unsplit = vec![0u8; bound];
        let unsplit_size = c_cctx
            .compress2(&mut unsplit[..], &data)
            .expect("libzstd compresses");
        split += usize::from(unsplit[..unsplit_size] != want[..]);
        raw += usize::from(raw_blocks(&want) > raw_blocks(&unsplit[..unsplit_size]));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    eprintln!(
        "{compared} frames compared, {split} with blocks cut after their sequences, {raw} with \
         more raw blocks"
    );
    let least = if cfg!(target_endian = "big") { 15 } else { 40 };
    assert!(split > least, "only {split} frames with blocks cut");
    assert!(raw > 0, "no frame with a piece stored raw");
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
/// fifth of the frames are btlazy2, whose tree keeps its unsorted positions
/// through the lowering; a fifth are the optimal parser's, with a shortest
/// match of 3 bytes for its 3-byte hash table; two fifths are at a lazy
/// level with the row match finder, whose tags stay as they are when the
/// indices are lowered (the chain log, small, only sets how soon they
/// are). Half of each have long distance matching, whose window lowers its
/// own indices.
#[test]
fn lowering_the_indices_changes_no_frame() {
    let mut rng = Rng::new(0x5EED_0202);
    let mut corrections = 0;
    let mut row_corrections = 0;
    let mut opt_corrections = 0;
    let mut ldm_corrections = 0;
    let mut problems = Vec::new();
    for i in 0..40 {
        // 0: the fast levels, 1 and 3: the row match finder, 2: btlazy2,
        // 4: the optimal parser; each in one call and streaming.
        let kind = i % 5;
        let one_call = (i + i / 5) % 2 == 0;
        let row = kind == 1 || kind == 3;
        let opt = kind == 4;
        // The optimal parser is slow without optimizations.
        let len = if opt && cfg!(debug_assertions) {
            rng.range(100_000, 300_000)
        } else {
            rng.range(100_000, 1_200_000)
        } as usize;
        let data = rng.lz_data(len);
        let (level, chain_log, row_mode) = if row {
            (
                rng.range(5, 8) as i32,
                rng.range(6, 16) as u32,
                ParamSwitch::Enable,
            )
        } else if opt {
            (
                rng.range(1, 19) as i32,
                rng.range(6, 16) as u32,
                ParamSwitch::Auto,
            )
        } else {
            (
                [-5, -1, 1, 2, 3][rng.range(0, 4) as usize],
                0,
                ParamSwitch::Auto,
            )
        };
        let strategy = match kind {
            2 => Some(Strategy::Btlazy2),
            4 => Some([Strategy::Btopt, Strategy::Btultra, Strategy::Btultra2][i / 5 % 3]),
            _ => None,
        };
        let (min_match, search_log) = if opt {
            (3, rng.range(1, 4) as u32)
        } else {
            (0, 0)
        };
        let window_log = if i % 3 == 0 {
            0
        } else {
            rng.range(10, 17) as u32
        };
        let seed = rng.next();
        // Long distance matching for each kind, in one call and streaming,
        // with small parameters; and a hash table of its own size, which
        // the window, up to 2^27 bytes without one set, would make large.
        let ldm = (i / 5 + i / 10) % 2 == 1 && !opt;
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
                    .and_then(|()| cctx.set_parameter(CParameter::MinMatch(min_match)))
                    .and_then(|()| cctx.set_parameter(CParameter::SearchLog(search_log)))
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
                if opt {
                    opt_corrections += lowered;
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
         {opt_corrections} with the optimal parser, {ldm_corrections} of long distance matching"
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
    assert!(
        opt_corrections > 20,
        "only {opt_corrections} corrections with the optimal parser"
    );
}

/// How [`lowering_the_indices_with_a_dictionary_changes_no_frame`] gives a
/// frame its dictionary.
#[derive(Clone, Copy, Debug)]
enum DictWay {
    /// A prefix: loaded for the frame.
    Prefix,
    /// Loaded into the context, its CDict copied in.
    LoadCopy,
    /// A CDict referenced, loaded again (long distance matching then takes
    /// a raw dictionary's content too).
    RefLoad,
}

/// [`lowering_the_indices_changes_no_frame`], with a dictionary: raw
/// content, or a zstd dictionary libzstd trains, before the input. libzstd
/// invalidates a dictionary when it lowers the indices
/// (`ZSTD_overflowCorrectIfNeeded`), and only lowers them as soon as it can
/// once the dictionary is out of the window (`ZSTD_window_canOverflowCorrect`),
/// where the window's checks drop it anyway; so the frames come out the
/// same. Every strategy, in one call and streaming, some with long
/// distance matching. The frames without the lowering are also libzstd's.
#[test]
fn lowering_the_indices_with_a_dictionary_changes_no_frame() {
    let mut rng = Rng::new(0x5EED_0203);
    let mut corrections = 0;
    let mut ldm_corrections = 0;
    let mut lowered_frames = 0;
    let mut problems = Vec::new();
    for i in 0..48 {
        let strategy = [
            Strategy::Fast,
            Strategy::Dfast,
            Strategy::Greedy,
            Strategy::Lazy2,
            Strategy::Btlazy2,
            Strategy::Btultra,
        ][i % 6];
        let way = [DictWay::Prefix, DictWay::LoadCopy, DictWay::RefLoad][i / 6 % 3];
        let one_call = (i / 18 + i / 3) % 2 == 0;
        let slow = strategy >= Strategy::Btlazy2 && cfg!(debug_assertions);
        let len = if slow {
            rng.range(100_000, 250_000)
        } else {
            rng.range(100_000, 900_000)
        } as usize;
        // The dictionary and the input, from the same data.
        let all = rng.lz_data(len + 200_000);
        let data = all[200_000..].to_vec();
        let dict = if i % 4 == 1 {
            let samples: Vec<&[u8]> = all[..200_000].chunks(500).collect();
            zstd::dict::from_samples(&samples, 8 << 10).unwrap_or_else(|_| all[..9000].to_vec())
        } else {
            let at = rng.range(0, 100_000) as usize;
            all[at..at + rng.range(8, 90_000) as usize].to_vec()
        };
        let window_log = rng.range(10, 17) as u32;
        let level = rng.range(1, 19) as i32;
        let row_mode = [ParamSwitch::Enable, ParamSwitch::Disable][i / 3 % 2];
        let ldm = i % 5 == 2;
        let seed = rng.next();
        let parameters = [
            CParameter::CompressionLevel(level),
            CParameter::Strategy(Some(strategy)),
            CParameter::WindowLog(window_log),
            CParameter::UseRowMatchFinder(row_mode),
            CParameter::EnableLongDistanceMatching(if ldm {
                ParamSwitch::Enable
            } else {
                ParamSwitch::Disable
            }),
            CParameter::LdmMinMatch(16),
            CParameter::LdmHashRateLog(4),
            CParameter::ForceAttachDict(match way {
                DictWay::RefLoad => DictAttachPref::ForceLoad,
                _ => DictAttachPref::ForceCopy,
            }),
        ];
        let frames: Vec<Result<Lowered, String>> = [false, true]
            .into_iter()
            .map(|frequently| {
                OVERFLOW_CORRECT_FREQUENTLY.with(|flag| flag.set(frequently));
                let mut cctx = CCtx::new();
                for parameter in parameters {
                    cctx.set_parameter(parameter)
                        .map_err(|error| format!("{error:?}"))?;
                }
                let set = match way {
                    DictWay::Prefix => cctx.ref_prefix(&dict),
                    DictWay::LoadCopy => cctx.load_dictionary(&dict),
                    DictWay::RefLoad => cctx.ref_cdict(Some(Arc::new(
                        CDict::new(&dict, level).map_err(|error| format!("{error:?}"))?,
                    ))),
                };
                set.map_err(|error| format!("{error:?}"))?;
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
        let what = format!(
            "{len} bytes, a dictionary of {} bytes {way:?}, level {level}, {strategy:?}, window \
             log {window_log}, long distance matching {ldm}, {}",
            dict.len(),
            if one_call { "one call" } else { "streaming" }
        );
        match (&frames[0], &frames[1]) {
            (Ok((want, 0, 0)), Ok((got, lowered, ldm_lowered))) => {
                corrections += lowered;
                ldm_corrections += ldm_lowered;
                lowered_frames += usize::from(*lowered > 0);
                if want != got {
                    problems.push(format!(
                        "{what}: the frames differ after {lowered} corrections, {ldm_lowered} \
                         of long distance matching"
                    ));
                }
                let mut back = vec![0u8; len];
                if DCtx::new()
                    .decompress_using_dict(&mut back, got, &dict)
                    .ok()
                    != Some(len)
                    || back != data
                {
                    problems.push(format!("{what}: does not decode back"));
                }
                // And libzstd's frame, in one call; on big-endian machines
                // not for the strategies whose block splitter differs there
                // (see `is_ported`).
                let big_endian = cfg!(target_endian = "big") && strategy >= Strategy::Greedy;
                if one_call && !big_endian {
                    let c_cdict = zstd_safe::CDict::create(&dict, level);
                    let mut c = zstd_safe::CCtx::create();
                    let set = |c: &mut zstd_safe::CCtx<'_>| -> Result<(), usize> {
                        use zstd_safe::CParameter as C;
                        c.set_parameter(C::CompressionLevel(level))?;
                        c.set_parameter(C::Strategy(match strategy {
                            Strategy::Fast => zstd_safe::Strategy::ZSTD_fast,
                            Strategy::Dfast => zstd_safe::Strategy::ZSTD_dfast,
                            Strategy::Greedy => zstd_safe::Strategy::ZSTD_greedy,
                            Strategy::Lazy2 => zstd_safe::Strategy::ZSTD_lazy2,
                            Strategy::Btlazy2 => zstd_safe::Strategy::ZSTD_btlazy2,
                            _ => zstd_safe::Strategy::ZSTD_btultra,
                        }))?;
                        c.set_parameter(C::WindowLog(window_log))?;
                        c.set_parameter(C::UseRowMatchFinder(match row_mode {
                            ParamSwitch::Enable => zstd_safe::ParamSwitch::Enable,
                            _ => zstd_safe::ParamSwitch::Disable,
                        }))?;
                        c.set_parameter(C::EnableLongDistanceMatching(ldm))?;
                        c.set_parameter(C::LdmMinMatch(16))?;
                        c.set_parameter(C::LdmHashRateLog(4))?;
                        c.set_parameter(C::ForceAttachDict(match way {
                            DictWay::RefLoad => zstd_safe::DictAttachPref::ForceLoad,
                            _ => zstd_safe::DictAttachPref::ForceCopy,
                        }))?;
                        Ok(())
                    };
                    let mut out = vec![0u8; zstd_compress_bound(len).unwrap_or(0)];
                    let result = set(&mut c).and_then(|()| {
                        match way {
                            DictWay::Prefix => c.ref_prefix(&dict)?,
                            DictWay::LoadCopy => c.load_dictionary(&dict)?,
                            DictWay::RefLoad => c.ref_cdict(&c_cdict)?,
                        };
                        c.compress2(&mut out[..], &data)
                    });
                    match result {
                        Ok(size) if out[..size] == want[..] => {}
                        other => problems.push(format!(
                            "{what}: not libzstd's frame ({:?}, {} bytes)",
                            other,
                            want.len()
                        )),
                    }
                }
            }
            other => problems.push(format!("{what}: {other:?}")),
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    eprintln!(
        "{corrections} corrections in {lowered_frames} frames, {ldm_corrections} of long \
         distance matching"
    );
    assert!(lowered_frames > 20, "only {lowered_frames} frames lowered");
    assert!(corrections > 50, "only {corrections} corrections");
    assert!(
        ldm_corrections > 10,
        "only {ldm_corrections} corrections of long distance matching"
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
        // On big-endian machines libzstd's block splitter, which the
        // strategies from `greedy` up use on full blocks, splits elsewhere
        // (see `is_ported`).
        if cfg!(target_endian = "big") && strategy >= Strategy::Greedy && len >= 128 << 10 {
            continue;
        }
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
