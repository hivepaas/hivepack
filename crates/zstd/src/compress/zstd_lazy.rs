//! The `greedy`, `lazy`, `lazy2` and `btlazy2` strategies: port of
//! `compress/zstd_lazy.c`, without a dictionary so far: the parser they
//! share, the hash chain match finder, and `btlazy2`'s binary tree.
//!
//! Positions are indices into `src`, the buffer the window's prefix is in,
//! and `dict`, the one its older segment is in; the tables hold window
//! indices, `position + window.base` (or `window.dict_base`).

use crate::common::bits::highbit32;
use crate::common::zstd_internal::ZSTD_REP_NUM;
use crate::compress::zstd_compress_internal::{
    K_SEARCH_STRENGTH, MatchState, REPCODE1_TO_OFFBASE, SeqStore, ZSTD_DUBT_UNSORTED_MARK,
    mem_read32, offset_to_offbase, zstd_count, zstd_count_2segments, zstd_hash_ptr,
    zstd_index_overlap_check,
};

/// `kLazySkippingStep`: past steps this long over input without matches,
/// the tables get only the positions searched.
const K_LAZY_SKIPPING_STEP: usize = 8;

/// `searchMethod_e`, as the const parameter of the parser.
pub(crate) const SEARCH_HASH_CHAIN: u8 = 0;

/// The offset base the parser sets before each search, 999999999: what
/// `ZSTD_searchMax` gives when it finds no match, with a length under 4.
/// The binary tree weighs its first match against it.
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
// Binary tree
//
// `btlazy2`'s match finder, the deferred-update binary tree (DUBT). The
// chain table holds two entries per position, `bt[2 * (i & bt_mask)]` and
// the one after, for the `1 << (chain_log - 1)` positions before the
// current one. A position is first inserted unsorted, as in a hash chain:
// its first entry is the previous position of its hash, its second
// `ZSTD_DUBT_UNSORTED_MARK`. It is sorted when a search reaches it: its
// entries then point to the positions smaller and larger than it, in the
// order of the bytes that follow them.

/// `search_binaryTree`, the search method of the parser.
pub(crate) const SEARCH_BINARY_TREE: u8 = 1;

/// libzstd's `dummy32`: where a search that stops early ends the side it
/// stopped on.
///
/// Differs from libzstd: the write there is left out. Nothing reads it, so
/// the tree is the same.
const DUMMY32: usize = usize::MAX;

/// `ZSTD_updateDUBT`: inserts the positions from `next_to_update` up to
/// `ip`, not included, into the hash table and the tree, unsorted. The
/// positions are in the prefix.
#[inline(always)]
fn update_dubt<const MLS: u32>(ms: &mut MatchState, src: &[u8], ip: usize) {
    let hash_log = ms.c_params.hash_log;
    let bt_mask = (1u32 << (ms.c_params.chain_log - 1)) - 1;
    let base = ms.window.base;
    let target = ms.window.index(ip);
    let mut idx = ms.next_to_update;
    debug_assert!(idx >= ms.window.dict_limit);

    while idx < target {
        let h = zstd_hash_ptr(src, (i64::from(idx) - base) as usize, hash_log, MLS);
        let match_index = ms.hash_table[h];
        let next_candidate = 2 * (idx & bt_mask) as usize;
        ms.hash_table[h] = idx;
        // Linked as in a hash chain, and marked unsorted.
        ms.chain_table[next_candidate] = match_index;
        ms.chain_table[next_candidate + 1] = ZSTD_DUBT_UNSORTED_MARK;
        idx += 1;
    }
    ms.next_to_update = target;
}

/// `ZSTD_insertDUBT1`: sorts `curr`, inserted but unsorted, into the tree,
/// comparing at most `nb_compares` positions, down to `bt_low`. Its bytes
/// end at `input_end` of `src` in the prefix. With `EXT`, `curr` and the
/// positions it is compared with may be in the older segment, `dict`,
/// where its bytes end at the segment's end.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn insert_dubt1<const EXT: bool>(
    ms: &mut MatchState,
    src: &[u8],
    dict: &[u8],
    curr: u32,
    input_end: usize,
    mut nb_compares: u32,
    bt_low: u32,
) {
    let c_params = ms.c_params;
    let bt_mask = (1u32 << (c_params.chain_log - 1)) - 1;
    let base = ms.window.base;
    let dict_base = ms.window.dict_base;
    let dict_limit = ms.window.dict_limit;
    let prefix_start = (i64::from(dict_limit) - base) as usize;
    let dict_end = (i64::from(dict_limit) - dict_base) as usize;
    // Where `curr` is: its segment, the index of the segment's first byte,
    // and where the bytes after `curr` end.
    let (ibuf, ibase, iend) = if !EXT || curr >= dict_limit {
        (src, base, input_end)
    } else {
        (dict, dict_base, dict_end)
    };
    let ip = (i64::from(curr) - ibase) as usize;
    let window_valid = ms.window.low_limit;
    let max_distance = 1u32 << c_params.window_log;
    let window_low = if curr.wrapping_sub(window_valid) > max_distance {
        curr - max_distance
    } else {
        window_valid
    };
    let bt = &mut ms.chain_table;
    let mut common_length_smaller = 0;
    let mut common_length_larger = 0;
    let mut smaller_ptr = 2 * (curr & bt_mask) as usize;
    let mut larger_ptr = smaller_ptr + 1;
    // `curr` is unsorted: its first entry leads to the next candidate,
    // sorted; its second holds the previous unsorted one, already saved,
    // and is written over.
    let mut match_index = bt[smaller_ptr];
    debug_assert!(curr >= bt_low);
    debug_assert!(ip < iend);

    while nb_compares > 0 && match_index > window_low {
        let next_ptr = 2 * (match_index & bt_mask) as usize;
        // The bytes it has in common with `curr` at least.
        let mut match_length = common_length_smaller.min(common_length_larger);
        debug_assert!(match_index < curr);

        // The candidate's segment, and the index of its first byte, for
        // the byte after the common run.
        let (mbuf, mbase) = if !EXT
            || match_index as usize + match_length >= dict_limit as usize
            || curr < dict_limit
        {
            // Both in one segment: the prefix (where a candidate of the
            // older segment is from its byte `match_length` on), or the
            // older one.
            //
            // Differs from libzstd: the candidate is read in `curr`'s
            // segment, where libzstd picks the prefix when the run reaches
            // it. The same: with `curr` in the older segment, the common
            // run ends before the segment's end, as `curr`'s bytes do, and
            // the candidate is before `curr`.
            debug_assert!(
                !EXT || curr >= dict_limit
                    || match_index as usize + match_length < dict_limit as usize
            );
            let m = (i64::from(match_index) + match_length as i64 - ibase) as usize;
            match_length += zstd_count(ibuf, ip + match_length, m, iend);
            (ibuf, ibase)
        } else {
            // A candidate of the older segment, `curr` in the prefix.
            let m = (i64::from(match_index) - dict_base) as usize;
            match_length += zstd_count_2segments(
                src,
                ip + match_length,
                dict,
                m + match_length,
                iend,
                dict_end,
                prefix_start,
            );
            if match_index as usize + match_length >= dict_limit as usize {
                // The match runs on into the prefix: its next byte is
                // there.
                (src, base)
            } else {
                (dict, dict_base)
            }
        };

        if ip + match_length == iend {
            // Equal up to the end: no way to know if smaller or larger.
            // Dropped, to keep the tree consistent: a bit less compression,
            // where other ways can corrupt the tree.
            break;
        }

        let match_byte = mbuf[(i64::from(match_index) + match_length as i64 - mbase) as usize];
        if match_byte < ibuf[ip + match_length] {
            // The candidate is smaller than `curr`.
            bt[smaller_ptr] = match_index;
            // Every smaller one has at least this in common.
            common_length_smaller = match_length;
            if match_index <= bt_low {
                // Beyond the tree's size: stop.
                smaller_ptr = DUMMY32;
                break;
            }
            // The next one is larger than the candidate.
            smaller_ptr = next_ptr + 1;
            match_index = bt[next_ptr + 1];
        } else {
            // The candidate is larger than `curr`.
            bt[larger_ptr] = match_index;
            common_length_larger = match_length;
            if match_index <= bt_low {
                // Beyond the tree's size: stop.
                larger_ptr = DUMMY32;
                break;
            }
            larger_ptr = next_ptr;
            match_index = bt[next_ptr];
        }
        nb_compares -= 1;
    }

    // *smallerPtr = *largerPtr = 0
    for ptr in [smaller_ptr, larger_ptr] {
        if ptr != DUMMY32 {
            bt[ptr] = 0;
        }
    }
}

/// `ZSTD_DUBT_findBestMatch`: sorts the unsorted positions of `ip`'s hash
/// (up to `1 << search_log` of them, the oldest first), then inserts `ip`
/// into the tree, sorted, and returns the best match the way down gave, up
/// to `iend`, and its offset base. With `EXT`, candidates below the prefix
/// are in `dict`.
#[allow(clippy::too_many_lines)]
#[inline(always)]
fn dubt_find_best_match<const MLS: u32, const EXT: bool>(
    ms: &mut MatchState,
    src: &[u8],
    dict: &[u8],
    ip: usize,
    iend: usize,
) -> (usize, u32) {
    let c_params = ms.c_params;
    let h = zstd_hash_ptr(src, ip, c_params.hash_log, MLS);
    let mut match_index = ms.hash_table[h];

    let base = ms.window.base;
    let curr = ms.window.index(ip);
    let window_low = ms.lowest_match_index(curr, c_params.window_log);

    let bt_mask = (1u32 << (c_params.chain_log - 1)) - 1;
    // The oldest position the tree holds, or 0.
    let bt_low = curr.saturating_sub(bt_mask);
    let unsort_limit = bt_low.max(window_low);

    let mut nb_compares = 1u32 << c_params.search_log;
    let mut nb_candidates = nb_compares;
    let mut previous_candidate = 0;
    debug_assert!(ip + 8 <= iend);

    // The end of the list of unsorted candidates: on the way, their marks
    // become a chain back up.
    {
        let bt = &mut ms.chain_table;
        let mut next_candidate = 2 * (match_index & bt_mask) as usize;
        let mut unsorted_mark = next_candidate + 1;
        while match_index > unsort_limit
            && bt[unsorted_mark] == ZSTD_DUBT_UNSORTED_MARK
            && nb_candidates > 1
        {
            bt[unsorted_mark] = previous_candidate;
            previous_candidate = match_index;
            match_index = bt[next_candidate];
            next_candidate = 2 * (match_index & bt_mask) as usize;
            unsorted_mark = next_candidate + 1;
            nb_candidates -= 1;
        }

        // The last candidate, if still unsorted, is cut off: worse
        // compression, but faster.
        if match_index > unsort_limit && bt[unsorted_mark] == ZSTD_DUBT_UNSORTED_MARK {
            bt[unsorted_mark] = 0;
            bt[next_candidate] = 0;
        }
    }

    // Sorts the candidates stacked, the oldest first, back up the chain;
    // it ends at 0.
    match_index = previous_candidate;
    while match_index != 0 {
        let next_candidate_idx = ms.chain_table[2 * (match_index & bt_mask) as usize + 1];
        insert_dubt1::<EXT>(
            ms,
            src,
            dict,
            match_index,
            iend,
            nb_candidates,
            unsort_limit,
        );
        match_index = next_candidate_idx;
        nb_candidates += 1;
    }

    // The longest match.
    let dict_base = ms.window.dict_base;
    let dict_limit = ms.window.dict_limit;
    let dict_end = (i64::from(dict_limit) - dict_base) as usize;
    let prefix_start = (i64::from(dict_limit) - base) as usize;
    let mut common_length_smaller = 0;
    let mut common_length_larger = 0;
    let mut smaller_ptr = 2 * (curr & bt_mask) as usize;
    let mut larger_ptr = smaller_ptr + 1;
    let mut match_end_idx = curr + 8 + 1;
    let mut best_length = 0;
    // What the parser's offset base is before the search: the first match
    // is weighed against it.
    let mut off_base = NO_OFFBASE;

    match_index = ms.hash_table[h];
    ms.hash_table[h] = curr;

    let bt = &mut ms.chain_table;
    while nb_compares > 0 && match_index > window_low {
        let next_ptr = 2 * (match_index & bt_mask) as usize;
        // The bytes it has in common with `ip` at least.
        let mut match_length = common_length_smaller.min(common_length_larger);

        // The candidate's segment, and the index of its first byte, for
        // the byte after the common run.
        let (mbuf, mbase) = if !EXT || match_index as usize + match_length >= dict_limit as usize {
            let m = (i64::from(match_index) + match_length as i64 - base) as usize;
            match_length += zstd_count(src, ip + match_length, m, iend);
            (src, base)
        } else {
            let m = (i64::from(match_index) - dict_base) as usize;
            match_length += zstd_count_2segments(
                src,
                ip + match_length,
                dict,
                m + match_length,
                iend,
                dict_end,
                prefix_start,
            );
            if match_index as usize + match_length >= dict_limit as usize {
                // The match runs on into the prefix: its next byte is
                // there.
                (src, base)
            } else {
                (dict, dict_base)
            }
        };

        if match_length > best_length {
            if match_length > (match_end_idx - match_index) as usize {
                match_end_idx = match_index + match_length as u32;
            }
            // Longer, unless its offset costs more than the bytes gained.
            if 4 * (match_length - best_length) as i32
                > highbit32(curr - match_index + 1) as i32 - highbit32(off_base) as i32
            {
                best_length = match_length;
                off_base = offset_to_offbase(curr - match_index);
            }
            if ip + match_length == iend {
                // Equal up to the end: no way to know if smaller or
                // larger. Dropped, to keep the tree consistent.
                break;
            }
        }

        let match_byte = mbuf[(i64::from(match_index) + match_length as i64 - mbase) as usize];
        if match_byte < src[ip + match_length] {
            // The candidate is smaller than `ip`.
            bt[smaller_ptr] = match_index;
            // Every smaller one has at least this in common.
            common_length_smaller = match_length;
            if match_index <= bt_low {
                // Beyond the tree's size: stop.
                smaller_ptr = DUMMY32;
                break;
            }
            // The next one is larger than the candidate.
            smaller_ptr = next_ptr + 1;
            match_index = bt[next_ptr + 1];
        } else {
            // The candidate is larger than `ip`.
            bt[larger_ptr] = match_index;
            common_length_larger = match_length;
            if match_index <= bt_low {
                // Beyond the tree's size: stop.
                larger_ptr = DUMMY32;
                break;
            }
            larger_ptr = next_ptr;
            match_index = bt[next_ptr];
        }
        nb_compares -= 1;
    }

    // *smallerPtr = *largerPtr = 0
    for ptr in [smaller_ptr, larger_ptr] {
        if ptr != DUMMY32 {
            bt[ptr] = 0;
        }
    }

    // Past the longest match: repetitive data is not inserted again.
    debug_assert!(match_end_idx > curr + 8);
    ms.next_to_update = match_end_idx - 8;
    (best_length, off_base)
}

/// `ZSTD_BtFindBestMatch`: the tree updated up to `ip`, then searched at
/// `ip`. Nothing for a position a long match skipped. Not inlined, as
/// libzstd's search functions: one copy serves the parser's three
/// searches.
#[inline(never)]
fn bt_find_best_match<const MLS: u32, const EXT: bool>(
    ms: &mut MatchState,
    src: &[u8],
    dict: &[u8],
    ip: usize,
    i_limit: usize,
) -> (usize, u32) {
    if ms.window.index(ip) < ms.next_to_update {
        // A skipped area.
        return (0, NO_OFFBASE);
    }
    update_dubt::<MLS>(ms, src, ip);
    dubt_find_best_match::<MLS, EXT>(ms, src, dict, ip, i_limit)
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
        SEARCH_BINARY_TREE => bt_find_best_match::<MLS, EXT>(ms, src, dict, ip, iend),
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

/// `ZSTD_compressBlock_btlazy2`, and `ZSTD_compressBlock_btlazy2_extDict`
/// when `dict` is given: the parser of `lazy2` with the binary tree.
/// Returns the size of the literals left after the last sequence.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zstd_compress_block_btlazy2(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dict: Option<&[u8]>,
    istart: usize,
    iend: usize,
) -> usize {
    lazy::<SEARCH_BINARY_TREE, 2>(ms, seq_store, rep, src, dict, istart, iend)
}
