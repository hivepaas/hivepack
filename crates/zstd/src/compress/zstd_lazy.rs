//! The `greedy`, `lazy` and `lazy2` strategies: port of
//! `compress/zstd_lazy.c`, without a dictionary so far: the parser they
//! share, and the hash chain match finder.
//!
//! Positions are indices into `src`, the buffer the window's prefix is in,
//! and `dict`, the one its older segment is in; the tables hold window
//! indices, `position + window.base` (or `window.dict_base`).

use crate::common::bits::highbit32;
use crate::common::zstd_internal::ZSTD_REP_NUM;
use crate::compress::zstd_compress_internal::{
    K_SEARCH_STRENGTH, MatchState, REPCODE1_TO_OFFBASE, SeqStore, mem_read32, offset_to_offbase,
    zstd_count, zstd_count_2segments, zstd_hash_ptr, zstd_index_overlap_check,
};

/// `kLazySkippingStep`: past steps this long over input without matches,
/// the tables get only the positions searched.
const K_LAZY_SKIPPING_STEP: usize = 8;

/// `searchMethod_e`, as the const parameter of the parser.
pub(crate) const SEARCH_HASH_CHAIN: u8 = 0;

/// What `ZSTD_searchMax` gives when it finds no match: a length under 4,
/// and libzstd's offset base filler, never used then.
const NO_OFFBASE: u32 = 999_999_999;

/// `OFFBASE_IS_OFFSET`
#[inline(always)]
fn offbase_is_offset(off_base: u32) -> bool {
    off_base > ZSTD_REP_NUM as u32
}

/// `OFFBASE_TO_OFFSET`
#[inline(always)]
fn offbase_to_offset(off_base: u32) -> u32 {
    debug_assert!(offbase_is_offset(off_base));
    off_base - ZSTD_REP_NUM as u32
}

// ---------------------------------------------------------------------------
// Hash chain

/// `ZSTD_insertAndFindFirstIndex_internal`: inserts the positions from
/// `next_to_update` up to `ip`, not included, into the hash and chain
/// tables (only the first in the lazy skipping mode), and returns the
/// first candidate for `ip`. The positions are in the prefix.
#[inline(always)]
fn insert_and_find_first_index<const MLS: u32>(ms: &mut MatchState, src: &[u8], ip: usize) -> u32 {
    let hash_log = ms.c_params.hash_log;
    let chain_mask = (1u32 << ms.c_params.chain_log) - 1;
    let base = ms.window.base;
    let target = ms.window.index(ip);
    let mut idx = ms.next_to_update;

    while idx < target {
        let h = zstd_hash_ptr(src, (i64::from(idx) - base) as usize, hash_log, MLS);
        ms.chain_table[(idx & chain_mask) as usize] = ms.hash_table[h];
        ms.hash_table[h] = idx;
        idx += 1;
        // Not every position in the lazy skipping mode.
        if ms.lazy_skipping {
            break;
        }
    }

    ms.next_to_update = target;
    ms.hash_table[zstd_hash_ptr(src, ip, hash_log, MLS)]
}

/// `ZSTD_HcFindBestMatch`: the longest match at `ip`, up to `i_limit`, of
/// those the hash chain gives, and its offset base; a length under 4 for
/// none. With `EXT`, candidates below the prefix are in `dict`.
#[inline(always)]
fn hc_find_best_match<const MLS: u32, const EXT: bool>(
    ms: &mut MatchState,
    src: &[u8],
    dict: &[u8],
    ip: usize,
    i_limit: usize,
) -> (usize, u32) {
    let c_params = ms.c_params;
    let chain_size = 1u32 << c_params.chain_log;
    let chain_mask = chain_size - 1;
    let base = ms.window.base;
    let dict_base = ms.window.dict_base;
    let dict_limit = ms.window.dict_limit;
    let prefix_start = (i64::from(dict_limit) - base) as usize;
    let dict_end = (i64::from(dict_limit) - dict_base) as usize;
    let curr = ms.window.index(ip);
    let low_limit = ms.lowest_match_index(curr, c_params.window_log);
    let min_chain = curr.saturating_sub(chain_size);
    let mut nb_attempts = 1u32 << c_params.search_log;
    let mut ml = 4 - 1;
    let mut off_base = NO_OFFBASE;

    let mut match_index = insert_and_find_first_index::<MLS>(ms, src, ip);

    while match_index >= low_limit && nb_attempts > 0 {
        let mut current_ml = 0;
        if !EXT || match_index >= dict_limit {
            let m = (i64::from(match_index) - base) as usize;
            // The 4 bytes that end one past the best length so far: a
            // match must have them to be longer.
            if mem_read32(src, m + ml - 3) == mem_read32(src, ip + ml - 3) {
                current_ml = zstd_count(src, ip, m, i_limit);
            }
        } else {
            // A candidate in the older segment has its 4 bytes there: it
            // was inserted with 8 bytes after it in its block.
            let m = (i64::from(match_index) - dict_base) as usize;
            if mem_read32(dict, m) == mem_read32(src, ip) {
                current_ml =
                    zstd_count_2segments(src, ip + 4, dict, m + 4, i_limit, dict_end, prefix_start)
                        + 4;
            }
        }

        // The best so far.
        if current_ml > ml {
            ml = current_ml;
            off_base = offset_to_offbase(curr - match_index);
            if ip + current_ml == i_limit {
                // As long as it can be, and the next test would read past
                // the end.
                break;
            }
        }

        if match_index <= min_chain {
            break;
        }
        match_index = ms.chain_table[(match_index & chain_mask) as usize];
        nb_attempts -= 1;
    }

    (ml, off_base)
}

// ---------------------------------------------------------------------------
// The parser

/// `ZSTD_searchMax`: the longest match at `ip` the search method finds,
/// and its offset base; a length under 4 for none.
#[inline(always)]
fn search_max<const SEARCH: u8, const MLS: u32, const EXT: bool>(
    ms: &mut MatchState,
    src: &[u8],
    dict: &[u8],
    ip: usize,
    iend: usize,
) -> (usize, u32) {
    match SEARCH {
        SEARCH_HASH_CHAIN => hc_find_best_match::<MLS, EXT>(ms, src, dict, ip, iend),
        _ => unreachable!("a search method the port does not have"),
    }
}

/// libzstd's gain of a match: its length times `scale`, less what its
/// offset costs, plus `bonus`; as the `int` libzstd makes of it.
#[inline(always)]
fn gain(length: usize, scale: usize, off_base: u32, bonus: usize) -> i64 {
    (length * scale + bonus) as i64 - i64::from(highbit32(off_base))
}

/// `ZSTD_compressBlock_lazy_generic`, without a dictionary: the sequences
/// of the block `src[istart..iend]` into `seq_store`, searching `DEPTH`
/// positions past each match found (0 for `greedy`, 1 for `lazy`, 2 for
/// `lazy2`). Returns the size of the literals left after the last
/// sequence.
#[allow(clippy::too_many_lines)]
fn zstd_compress_block_lazy_generic<const SEARCH: u8, const DEPTH: u32, const MLS: u32>(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    istart: usize,
    iend: usize,
) -> usize {
    let mut ip = istart;
    let mut anchor = istart;
    // Before the block for small blocks, where libzstd's pointer goes
    // before the buffer and the search ends at once.
    let ilimit = iend as i64 - 8;
    let base = ms.window.base;
    let prefix_lowest_index = ms.window.dict_limit;
    let prefix_lowest = (i64::from(prefix_lowest_index) - base) as usize;

    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];
    let mut offset_saved1 = 0;
    let mut offset_saved2 = 0;

    ip += usize::from(ip == prefix_lowest);
    {
        let curr = ms.window.index(ip);
        let window_low = ms.lowest_prefix_index(curr, ms.c_params.window_log);
        let max_rep = curr - window_low;
        if offset_2 > max_rep {
            offset_saved2 = offset_2;
            offset_2 = 0;
        }
        if offset_1 > max_rep {
            offset_saved1 = offset_1;
            offset_1 = 0;
        }
    }

    // Reset the lazy skipping state.
    ms.lazy_skipping = false;

    // The repcode `offset` at `at`: its length, or 0.
    let rep_at = |at: usize, offset: u32| {
        if offset > 0 && mem_read32(src, at - offset as usize) == mem_read32(src, at) {
            zstd_count(src, at + 4, at + 4 - offset as usize, iend) + 4
        } else {
            0
        }
    };

    'match_loop: while (ip as i64) < ilimit {
        let mut match_length = 0;
        let mut off_base = REPCODE1_TO_OFFBASE;
        let mut start = ip + 1;

        'store: {
            // The repcode at ip + 1.
            let rep_length = rep_at(ip + 1, offset_1);
            if rep_length != 0 {
                match_length = rep_length;
                if DEPTH == 0 {
                    break 'store;
                }
            }

            // The first search (depth 0).
            {
                let (ml2, off_found) = search_max::<SEARCH, MLS, false>(ms, src, &[], ip, iend);
                if ml2 > match_length {
                    match_length = ml2;
                    start = ip;
                    off_base = off_found;
                }
            }

            if match_length < 4 {
                // Faster over input without matches.
                let step = ((ip - anchor) >> K_SEARCH_STRENGTH) + 1;
                ip += step;
                // Past steps of 8, about 2 KB without a match, only the
                // positions searched go into the tables.
                ms.lazy_skipping = step > K_LAZY_SKIPPING_STEP;
                continue 'match_loop;
            }

            // A better match at the next positions.
            if DEPTH >= 1 {
                while (ip as i64) < ilimit {
                    ip += 1;
                    let ml_rep = rep_at(ip, offset_1);
                    if ml_rep >= 4 && gain(ml_rep, 3, 1, 0) > gain(match_length, 3, off_base, 1) {
                        match_length = ml_rep;
                        off_base = REPCODE1_TO_OFFBASE;
                        start = ip;
                    }
                    {
                        let (ml2, off_candidate) =
                            search_max::<SEARCH, MLS, false>(ms, src, &[], ip, iend);
                        if ml2 >= 4
                            && gain(ml2, 4, off_candidate, 0) > gain(match_length, 4, off_base, 4)
                        {
                            match_length = ml2;
                            off_base = off_candidate;
                            start = ip;
                            // And one better still.
                            continue;
                        }
                    }

                    // An even better one.
                    if DEPTH == 2 && (ip as i64) < ilimit {
                        ip += 1;
                        let ml_rep = rep_at(ip, offset_1);
                        if ml_rep >= 4 && gain(ml_rep, 4, 1, 0) > gain(match_length, 4, off_base, 1)
                        {
                            match_length = ml_rep;
                            off_base = REPCODE1_TO_OFFBASE;
                            start = ip;
                        }
                        let (ml2, off_candidate) =
                            search_max::<SEARCH, MLS, false>(ms, src, &[], ip, iend);
                        if ml2 >= 4
                            && gain(ml2, 4, off_candidate, 0) > gain(match_length, 4, off_base, 7)
                        {
                            match_length = ml2;
                            off_base = off_candidate;
                            start = ip;
                            continue;
                        }
                    }
                    // Nothing better: the match found.
                    break;
                }
            }

            // Catch up, within the prefix.
            if offbase_is_offset(off_base) {
                let offset = offbase_to_offset(off_base) as usize;
                while start > anchor
                    && start - offset > prefix_lowest
                    && src[start - 1] == src[start - offset - 1]
                {
                    start -= 1;
                    match_length += 1;
                }
                offset_2 = offset_1;
                offset_1 = offset as u32;
            }
        }

        // _storeSequence
        seq_store.store_seq(src, anchor, start - anchor, off_base, match_length);
        ip = start + match_length;
        anchor = ip;
        if ms.lazy_skipping {
            // A match: out of the lazy skipping mode.
            ms.lazy_skipping = false;
        }

        // Immediate repcodes.
        while (ip as i64) <= ilimit && offset_2 > 0 {
            if mem_read32(src, ip) != mem_read32(src, ip - offset_2 as usize) {
                break;
            }
            match_length = zstd_count(src, ip + 4, ip + 4 - offset_2 as usize, iend) + 4;
            // Swap offset_2 and offset_1.
            std::mem::swap(&mut offset_1, &mut offset_2);
            seq_store.store_seq(src, anchor, 0, REPCODE1_TO_OFFBASE, match_length);
            ip += match_length;
            anchor = ip;
        }
    }

    // The repcodes outside the prefix were set to zero before the loop;
    // those still zero are restored, as in the fast strategy.
    offset_saved2 = if offset_saved1 != 0 && offset_1 != 0 {
        offset_saved1
    } else {
        offset_saved2
    };

    // The repcodes for the next block.
    rep[0] = if offset_1 != 0 {
        offset_1
    } else {
        offset_saved1
    };
    rep[1] = if offset_2 != 0 {
        offset_2
    } else {
        offset_saved2
    };

    // The size of the last literals.
    iend - anchor
}

/// `ZSTD_compressBlock_lazy_extDict_generic`: as the parser without a
/// dictionary, with matches in the window's older segment too, `dict`; a
/// match there may run on into the prefix.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn zstd_compress_block_lazy_ext_dict_generic<const SEARCH: u8, const DEPTH: u32, const MLS: u32>(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dict: &[u8],
    istart: usize,
    iend: usize,
) -> usize {
    let mut ip = istart;
    let mut anchor = istart;
    let ilimit = iend as i64 - 8;
    let base = ms.window.base;
    let dict_base = ms.window.dict_base;
    let dict_limit = ms.window.dict_limit;
    let prefix_start = (i64::from(dict_limit) - base) as usize;
    let dict_end = (i64::from(dict_limit) - dict_base) as usize;
    let dict_start = (i64::from(ms.window.low_limit) - dict_base) as usize;
    let window_log = ms.c_params.window_log;

    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];

    // Reset the lazy skipping state.
    ms.lazy_skipping = false;

    ip += usize::from(ip == prefix_start);

    // Where index `i` is: its segment, its position there, and where the
    // segment ends.
    let locate = |i: u32| {
        if i < dict_limit {
            (dict, (i64::from(i) - dict_base) as usize, dict_end)
        } else {
            (src, (i64::from(i) - base) as usize, iend)
        }
    };
    // The repcode `offset` at `at`, whose index is `curr`: its length, or
    // 0. It is valid within the window, with its 4 bytes in one segment.
    let rep_at = |ms: &MatchState, at: usize, curr: u32, offset: u32| {
        let window_low = ms.lowest_match_index(curr, window_log);
        let rep_index = curr.wrapping_sub(offset);
        if zstd_index_overlap_check(dict_limit, rep_index)
            & (offset <= curr.wrapping_sub(window_low))
        {
            let (rbuf, rpos, rep_end) = locate(rep_index);
            if mem_read32(src, at) == mem_read32(rbuf, rpos) {
                return zstd_count_2segments(
                    src,
                    at + 4,
                    rbuf,
                    rpos + 4,
                    iend,
                    rep_end,
                    prefix_start,
                ) + 4;
            }
        }
        0
    };

    'match_loop: while (ip as i64) < ilimit {
        let mut match_length = 0;
        let mut off_base = REPCODE1_TO_OFFBASE;
        let mut start = ip + 1;
        let mut curr = ms.window.index(ip);

        'store: {
            // The repcode, searching at curr + 1.
            let rep_length = rep_at(ms, ip + 1, curr + 1, offset_1);
            if rep_length != 0 {
                match_length = rep_length;
                if DEPTH == 0 {
                    break 'store;
                }
            }

            // The first search (depth 0).
            {
                let (ml2, off_candidate) = search_max::<SEARCH, MLS, true>(ms, src, dict, ip, iend);
                if ml2 > match_length {
                    match_length = ml2;
                    start = ip;
                    off_base = off_candidate;
                }
            }

            if match_length < 4 {
                // Faster over input without matches.
                let step = (ip - anchor) >> K_SEARCH_STRENGTH;
                ip += step + 1;
                // See the parser without a dictionary.
                ms.lazy_skipping = step > K_LAZY_SKIPPING_STEP;
                continue 'match_loop;
            }

            // A better match at the next positions.
            if DEPTH >= 1 {
                while (ip as i64) < ilimit {
                    ip += 1;
                    curr += 1;
                    let rep_length = rep_at(ms, ip, curr, offset_1);
                    if rep_length >= 4
                        && gain(rep_length, 3, 1, 0) > gain(match_length, 3, off_base, 1)
                    {
                        match_length = rep_length;
                        off_base = REPCODE1_TO_OFFBASE;
                        start = ip;
                    }

                    // The search, depth 1.
                    {
                        let (ml2, off_candidate) =
                            search_max::<SEARCH, MLS, true>(ms, src, dict, ip, iend);
                        if ml2 >= 4
                            && gain(ml2, 4, off_candidate, 0) > gain(match_length, 4, off_base, 4)
                        {
                            match_length = ml2;
                            off_base = off_candidate;
                            start = ip;
                            // And one better still.
                            continue;
                        }
                    }

                    // An even better one.
                    if DEPTH == 2 && (ip as i64) < ilimit {
                        ip += 1;
                        curr += 1;
                        let rep_length = rep_at(ms, ip, curr, offset_1);
                        if rep_length >= 4
                            && gain(rep_length, 4, 1, 0) > gain(match_length, 4, off_base, 1)
                        {
                            match_length = rep_length;
                            off_base = REPCODE1_TO_OFFBASE;
                            start = ip;
                        }

                        // The search, depth 2.
                        let (ml2, off_candidate) =
                            search_max::<SEARCH, MLS, true>(ms, src, dict, ip, iend);
                        if ml2 >= 4
                            && gain(ml2, 4, off_candidate, 0) > gain(match_length, 4, off_base, 7)
                        {
                            match_length = ml2;
                            off_base = off_candidate;
                            start = ip;
                            continue;
                        }
                    }
                    // Nothing better: the match found.
                    break;
                }
            }

            // Catch up, within the match's segment.
            if offbase_is_offset(off_base) {
                let offset = offbase_to_offset(off_base);
                let match_index = ms.window.index(start).wrapping_sub(offset);
                let (mbuf, mut m, _) = locate(match_index);
                let m_start = if match_index < dict_limit {
                    dict_start
                } else {
                    prefix_start
                };
                while start > anchor && m > m_start && src[start - 1] == mbuf[m - 1] {
                    start -= 1;
                    m -= 1;
                    match_length += 1;
                }
                offset_2 = offset_1;
                offset_1 = offset;
            }
        }

        // _storeSequence
        seq_store.store_seq(src, anchor, start - anchor, off_base, match_length);
        ip = start + match_length;
        anchor = ip;
        if ms.lazy_skipping {
            // A match: out of the lazy skipping mode.
            ms.lazy_skipping = false;
        }

        // Immediate repcodes.
        while (ip as i64) <= ilimit {
            let rep_length = rep_at(ms, ip, ms.window.index(ip), offset_2);
            if rep_length == 0 {
                break;
            }
            // Swap offset_2 and offset_1.
            std::mem::swap(&mut offset_1, &mut offset_2);
            seq_store.store_seq(src, anchor, 0, REPCODE1_TO_OFFBASE, rep_length);
            ip += rep_length;
            anchor = ip;
        }
    }

    // The repcodes for the next block.
    rep[0] = offset_1;
    rep[1] = offset_2;

    // The size of the last literals.
    iend - anchor
}

// ---------------------------------------------------------------------------
// The block compressors

/// The parser for `DEPTH` and the shortest match, 4 to 6 bytes (libzstd
/// takes 3 as 4 and 7 as 6 here).
#[allow(clippy::too_many_arguments)]
fn lazy<const SEARCH: u8, const DEPTH: u32>(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dict: Option<&[u8]>,
    istart: usize,
    iend: usize,
) -> usize {
    macro_rules! with_mls {
        ($mls:literal) => {
            match dict {
                None => zstd_compress_block_lazy_generic::<SEARCH, DEPTH, $mls>(
                    ms, seq_store, rep, src, istart, iend,
                ),
                Some(dict) => zstd_compress_block_lazy_ext_dict_generic::<SEARCH, DEPTH, $mls>(
                    ms, seq_store, rep, src, dict, istart, iend,
                ),
            }
        };
    }
    match ms.c_params.min_match.clamp(4, 6) {
        5 => with_mls!(5),
        6 => with_mls!(6),
        _ => with_mls!(4),
    }
}

/// `ZSTD_compressBlock_greedy`, `_lazy` and `_lazy2`, with the hash chain,
/// and their `_extDict` variants when `dict` is given: the sequences of
/// the block `src[istart..iend]` into `seq_store`. Returns the size of the
/// literals left after the last sequence.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zstd_compress_block_lazy_hc(
    depth: u32,
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dict: Option<&[u8]>,
    istart: usize,
    iend: usize,
) -> usize {
    match depth {
        0 => lazy::<SEARCH_HASH_CHAIN, 0>(ms, seq_store, rep, src, dict, istart, iend),
        1 => lazy::<SEARCH_HASH_CHAIN, 1>(ms, seq_store, rep, src, dict, istart, iend),
        _ => lazy::<SEARCH_HASH_CHAIN, 2>(ms, seq_store, rep, src, dict, istart, iend),
    }
}
