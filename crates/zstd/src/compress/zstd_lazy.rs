//! The `greedy`, `lazy` and `lazy2` strategies: port of
//! `compress/zstd_lazy.c`, without a dictionary so far: the parser they
//! share, the hash chain match finder, and the row match finder.
//!
//! Positions are indices into `src`, the buffer the window's prefix is in,
//! and `dict`, the one its older segment is in; the tables hold window
//! indices, `position + window.base` (or `window.dict_base`).

use crate::common::bits::highbit32;
use crate::common::zstd_internal::ZSTD_REP_NUM;
use crate::compress::zstd_compress_internal::{
    K_SEARCH_STRENGTH, MatchState, REPCODE1_TO_OFFBASE, SeqStore, ZSTD_ROW_HASH_CACHE_SIZE,
    mem_read32, offset_to_offbase, zstd_count, zstd_count_2segments, zstd_hash_ptr,
    zstd_hash_ptr_salted, zstd_index_overlap_check,
};

/// `kLazySkippingStep`: past steps this long over input without matches,
/// the tables get only the positions searched.
const K_LAZY_SKIPPING_STEP: usize = 8;

/// `searchMethod_e`, as the const parameter of the parser.
pub(crate) const SEARCH_HASH_CHAIN: u8 = 0;
pub(crate) const SEARCH_ROW_HASH: u8 = 2;

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
// The row match finder
//
// The hash table is cut into rows of 16, 32 or 64 entries (`1 << ROW_LOG`).
// A position's salted hash, `row_hash_log + 8` bits long, picks a row with
// its top bits, and its low 8 bits are its tag. Each row is a circular
// buffer of the latest positions with that row's hashes, newest first from
// its head; the tag table holds the head at entry 0 and each entry's tag,
// so that a search compares the tags of a whole row at once and only reads
// the positions whose tag is the one sought.

/// `ZSTD_ROW_HASH_TAG_BITS`: the bits of the tag.
pub(crate) const ZSTD_ROW_HASH_TAG_BITS: u32 = 8;
/// `ZSTD_ROW_HASH_TAG_MASK`
const ZSTD_ROW_HASH_TAG_MASK: u32 = (1 << ZSTD_ROW_HASH_TAG_BITS) - 1;
/// `ZSTD_ROW_HASH_CACHE_MASK`
const ZSTD_ROW_HASH_CACHE_MASK: u32 = ZSTD_ROW_HASH_CACHE_SIZE as u32 - 1;

/// `ZSTD_row_nextIndex`: the entry of the row to write next, which becomes
/// its head: from the head back, around the row, never entry 0.
#[inline(always)]
fn row_next_index(tag_row: &mut [u8], row_mask: u32) -> u32 {
    let mut next = u32::from(tag_row[0]).wrapping_sub(1) & row_mask;
    // Skip the first entry.
    next += if next == 0 { row_mask } else { 0 };
    tag_row[0] = next as u8;
    next
}

/// `ZSTD_row_fillHashCache`: the hashes of the positions from index `idx`
/// on into the hash cache, `ZSTD_ROW_HASH_CACHE_SIZE` of them but none past
/// `i_limit`, a position of `src` (before it for small blocks).
///
/// Differs from libzstd: no prefetching of the rows, which changes no
/// output.
#[inline(always)]
fn row_fill_hash_cache<const MLS: u32>(ms: &mut MatchState, src: &[u8], idx: u32, i_limit: i64) {
    let hash_log = ms.row_hash_log;
    let base = ms.window.base;
    let at = i64::from(idx) - base;
    let max_elems_to_prefetch = if at > i_limit {
        0
    } else {
        (i_limit - at + 1) as u32
    };
    let lim = idx + (ZSTD_ROW_HASH_CACHE_SIZE as u32).min(max_elems_to_prefetch);

    for idx in idx..lim {
        let hash = zstd_hash_ptr_salted(
            src,
            (i64::from(idx) - base) as usize,
            hash_log + ZSTD_ROW_HASH_TAG_BITS,
            MLS,
            ms.hash_salt,
        );
        ms.hash_cache[(idx & ZSTD_ROW_HASH_CACHE_MASK) as usize] = hash;
    }
}

/// `ZSTD_row_nextCachedHash`: the hash of index `idx` (at `base`), from the
/// cache, where the hash of `ZSTD_ROW_HASH_CACHE_SIZE` positions later
/// takes its place.
///
/// Differs from libzstd: no prefetching of the new hash's row. And in a
/// context used again, the indices are not libzstd's (see
/// `CCtx::reset_cctx_internal`), so a hash may sit in another slot of the
/// cache. That changes nothing: the cache is filled at each block's start
/// and after the lazy skipping mode, and each slot read holds the hash of
/// its position, which the fill or the turn 8 positions before wrote.
#[inline(always)]
fn row_next_cached_hash<const MLS: u32>(
    cache: &mut [u32; ZSTD_ROW_HASH_CACHE_SIZE],
    src: &[u8],
    base: i64,
    idx: u32,
    hash_log: u32,
    hash_salt: u64,
) -> u32 {
    let new_hash = zstd_hash_ptr_salted(
        src,
        (i64::from(idx) - base) as usize + ZSTD_ROW_HASH_CACHE_SIZE,
        hash_log + ZSTD_ROW_HASH_TAG_BITS,
        MLS,
        hash_salt,
    );
    let slot = (idx & ZSTD_ROW_HASH_CACHE_MASK) as usize;
    let hash = cache[slot];
    cache[slot] = new_hash;
    hash
}

/// `ZSTD_row_update_internalImpl`, with the hash cache: inserts the
/// positions of indices `update_start_idx` to `update_end_idx`, not
/// included. libzstd hashes without the cache only to load a dictionary.
#[inline(always)]
fn row_update_internal_impl<const MLS: u32, const ROW_LOG: u32>(
    ms: &mut MatchState,
    src: &[u8],
    mut update_start_idx: u32,
    update_end_idx: u32,
) {
    let row_mask = (1u32 << ROW_LOG) - 1;
    let hash_log = ms.row_hash_log;
    let base = ms.window.base;
    let hash_salt = ms.hash_salt;
    let MatchState {
        hash_table,
        tag_table,
        hash_cache,
        ..
    } = ms;

    while update_start_idx < update_end_idx {
        let hash = row_next_cached_hash::<MLS>(
            hash_cache,
            src,
            base,
            update_start_idx,
            hash_log,
            hash_salt,
        );
        let rel_row = ((hash >> ZSTD_ROW_HASH_TAG_BITS) << ROW_LOG) as usize;
        let row = &mut hash_table[rel_row..][..1 << ROW_LOG];
        let tag_row = &mut tag_table[rel_row..][..1 << ROW_LOG];
        let pos = (row_next_index(tag_row, row_mask) & row_mask) as usize;
        tag_row[pos] = (hash & ZSTD_ROW_HASH_TAG_MASK) as u8;
        row[pos] = update_start_idx;
        update_start_idx += 1;
    }
}

/// `ZSTD_row_update_internal`, with the hash cache: inserts the positions
/// from `next_to_update` up to `ip`, not included. After a long match, only
/// the 96 positions at its start and the 32 at its end.
#[inline(always)]
fn row_update_internal<const MLS: u32, const ROW_LOG: u32>(
    ms: &mut MatchState,
    src: &[u8],
    ip: usize,
) {
    const K_SKIP_THRESHOLD: u32 = 384;
    const K_MAX_MATCH_START_POSITIONS_TO_UPDATE: u32 = 96;
    const K_MAX_MATCH_END_POSITIONS_TO_UPDATE: u32 = 32;
    let mut idx = ms.next_to_update;
    let target = ms.window.index(ip);

    // Past a long match, only its start and its end. libzstd skips only
    // with the hash cache, which is always the case here: it goes without
    // only to load a dictionary.
    if target.wrapping_sub(idx) > K_SKIP_THRESHOLD {
        let bound = idx + K_MAX_MATCH_START_POSITIONS_TO_UPDATE;
        row_update_internal_impl::<MLS, ROW_LOG>(ms, src, idx, bound);
        idx = target - K_MAX_MATCH_END_POSITIONS_TO_UPDATE;
        row_fill_hash_cache::<MLS>(ms, src, idx, ip as i64 + 1);
    }
    debug_assert!(target >= idx);
    row_update_internal_impl::<MLS, ROW_LOG>(ms, src, idx, target);
    ms.next_to_update = target;
}

/// `ZSTD_row_getMatchMask`: the entries of a row whose tag is `tag`, as a
/// mask in which bit `i` is entry `(head + i) % entries`: from the newest
/// entry to the oldest, around the row.
///
/// Differs from libzstd: libzstd compares the tags 16 at a time with SSE2
/// or NEON; here 8 at a time in a `u64`, as libzstd's own fallback for
/// other machines does (SWAR), with the same mask. On NEON, libzstd's mask
/// for rows of 16 or 32 entries has 4 or 2 bits per entry
/// (`ZSTD_row_matchMaskGroupWidth`), rotated by `head` times that, with one
/// bit of each entry kept; each entry's bits are together and the entries
/// in order, so its bits come in the same order as here and name the same
/// entries, `(headGrouped + bit) / groupWidth`.
#[inline(always)]
pub(crate) fn row_get_match_mask<const ROW_LOG: u32>(tag_row: &[u8], tag: u8, head: u32) -> u64 {
    const X01: u64 = u64::MAX / 0xFF;
    const X80: u64 = X01 << 7;
    // Gathers the top bit of each byte into the top byte.
    const EXTRACT_MAGIC: u64 = (u64::MAX / 0x7F) >> 8;
    let splat_char = u64::from(tag) * X01;
    let mut matches = 0u64;
    // From the last 8 tags to the first, for entry i to be bit i.
    for chunk in tag_row[..1 << ROW_LOG].as_chunks::<8>().0.iter().rev() {
        let mut chunk = u64::from_le_bytes(*chunk) ^ splat_char;
        // 0x80 in each byte that is not 0: the tags that differ.
        chunk = (((chunk | X80) - X01) | chunk) & X80;
        matches <<= 8;
        matches |= chunk.wrapping_mul(EXTRACT_MAGIC) >> 56;
    }
    matches = !matches;
    match ROW_LOG {
        4 => u64::from((matches as u16).rotate_right(head)),
        5 => u64::from((matches as u32).rotate_right(head)),
        _ => matches.rotate_right(head),
    }
}

/// `ZSTD_RowFindBestMatch`: the longest match at `ip`, up to `i_limit`, of
/// those in its row with its tag, and its offset base; a length under 4 for
/// none. The row is first brought up to `ip`, and `ip` inserted after the
/// search. With `EXT`, candidates below the prefix are in `dict`.
///
/// Outlined, as libzstd's search functions are: inlined at each search of
/// each parser, it would be many copies.
///
/// Differs from libzstd: libzstd first gathers the candidates into a
/// buffer, prefetching each, then inserts `ip`, then compares them. Without
/// prefetching, the port compares each candidate as it finds it, and
/// inserts `ip` last. The candidates are the same, compared in the same
/// order, and the comparisons read nothing the insertion writes; the
/// table's reads and writes come in libzstd's order, but for the reads of
/// candidates after a match that reaches `i_limit`, which libzstd then
/// leaves unused.
#[inline(never)]
fn row_find_best_match<const MLS: u32, const ROW_LOG: u32, const EXT: bool>(
    ms: &mut MatchState,
    src: &[u8],
    dict: &[u8],
    ip: usize,
    i_limit: usize,
) -> (usize, u32) {
    let hash_log = ms.row_hash_log;
    let c_params = ms.c_params;
    let base = ms.window.base;
    let dict_base = ms.window.dict_base;
    let dict_limit = ms.window.dict_limit;
    let prefix_start = (i64::from(dict_limit) - base) as usize;
    let dict_end = (i64::from(dict_limit) - dict_base) as usize;
    let curr = ms.window.index(ip);
    let low_limit = ms.lowest_match_index(curr, c_params.window_log);
    let row_entries = 1usize << ROW_LOG;
    let row_mask = (1u32 << ROW_LOG) - 1;
    // No more searches than entries in a row.
    let capped_search_log = c_params.search_log.min(ROW_LOG);
    let hash_salt = ms.hash_salt;
    let mut nb_attempts = 1u32 << capped_search_log;
    let mut ml = 4 - 1;
    let mut off_base = NO_OFFBASE;

    // Update the hash table and the tag table up to ip, not included.
    let hash = if ms.lazy_skipping {
        // In the lazy skipping mode, only the positions searched are
        // inserted, and the hash cache is not kept up to date.
        let hash = zstd_hash_ptr_salted(src, ip, hash_log + ZSTD_ROW_HASH_TAG_BITS, MLS, hash_salt);
        ms.next_to_update = curr;
        hash
    } else {
        row_update_internal::<MLS, ROW_LOG>(ms, src, ip);
        row_next_cached_hash::<MLS>(&mut ms.hash_cache, src, base, curr, hash_log, hash_salt)
    };
    // Entropy for the next salt.
    ms.hash_salt_entropy = ms.hash_salt_entropy.wrapping_add(hash);

    // The row of ip's hash.
    let rel_row = ((hash >> ZSTD_ROW_HASH_TAG_BITS) << ROW_LOG) as usize;
    let tag = hash & ZSTD_ROW_HASH_TAG_MASK;
    let MatchState {
        hash_table,
        tag_table,
        next_to_update,
        ..
    } = ms;
    let row = &mut hash_table[rel_row..][..row_entries];
    let tag_row = &mut tag_table[rel_row..][..row_entries];
    let head = u32::from(tag_row[0]) & row_mask;
    let mut matches = row_get_match_mask::<ROW_LOG>(tag_row, tag as u8, head);

    // The candidates, newest first, up to the first out of the window, and
    // the longest match.
    while matches > 0 && nb_attempts > 0 {
        let match_pos = (head + matches.trailing_zeros()) & row_mask;
        let match_index = row[match_pos as usize];
        matches &= matches - 1;
        if match_pos == 0 {
            // The head, not an entry.
            continue;
        }
        if match_index < low_limit {
            break;
        }
        nb_attempts -= 1;

        let mut current_ml = 0;
        debug_assert!(match_index < curr && match_index >= low_limit);
        if !EXT || match_index >= dict_limit {
            let m = (i64::from(match_index) - base) as usize;
            // The 4 bytes that end one past the best length so far: a
            // match must have them to be longer.
            if mem_read32(src, m + ml - 3) == mem_read32(src, ip + ml - 3) {
                current_ml = zstd_count(src, ip, m, i_limit);
            }
        } else {
            // A candidate in the older segment has its 4 bytes there: it
            // was inserted with 16 bytes after it in its block.
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
    }

    // ip into the row too, which saves the next search a turn of the
    // update.
    {
        let pos = (row_next_index(tag_row, row_mask) & row_mask) as usize;
        tag_row[pos] = tag as u8;
        row[pos] = *next_to_update;
        *next_to_update += 1;
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
        // Rows of 16 entries up to a search log of 4, then 32, then 64.
        SEARCH_ROW_HASH => match ms.c_params.search_log.clamp(4, 6) {
            5 => row_find_best_match::<MLS, 5, EXT>(ms, src, dict, ip, iend),
            6 => row_find_best_match::<MLS, 6, EXT>(ms, src, dict, ip, iend),
            _ => row_find_best_match::<MLS, 4, EXT>(ms, src, dict, ip, iend),
        },
        _ => unreachable!("a search method the port does not have"),
    }
}

/// How much sooner than 8 bytes before the end the parser stops: by
/// `ZSTD_ROW_HASH_CACHE_SIZE` with the row match finder, which hashes the
/// positions that far ahead.
#[inline(always)]
const fn row_hash_lookahead<const SEARCH: u8>() -> i64 {
    if SEARCH == SEARCH_ROW_HASH {
        ZSTD_ROW_HASH_CACHE_SIZE as i64
    } else {
        0
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
    // before the buffer and the search ends at once. The row match finder
    // hashes positions ahead, and stops sooner.
    let ilimit = iend as i64 - 8 - row_hash_lookahead::<SEARCH>();
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

    if SEARCH == SEARCH_ROW_HASH {
        row_fill_hash_cache::<MLS>(ms, src, ms.next_to_update, ilimit);
    }

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
            // A match: out of the lazy skipping mode, with the hash cache
            // filled again.
            if SEARCH == SEARCH_ROW_HASH {
                row_fill_hash_cache::<MLS>(ms, src, ms.next_to_update, ilimit);
            }
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
    let ilimit = iend as i64 - 8 - row_hash_lookahead::<SEARCH>();
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
    if SEARCH == SEARCH_ROW_HASH {
        row_fill_hash_cache::<MLS>(ms, src, ms.next_to_update, ilimit);
    }

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
            // A match: out of the lazy skipping mode, with the hash cache
            // filled again.
            if SEARCH == SEARCH_ROW_HASH {
                row_fill_hash_cache::<MLS>(ms, src, ms.next_to_update, ilimit);
            }
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

/// `ZSTD_compressBlock_greedy_row`, `_lazy_row` and `_lazy2_row`, with the
/// row match finder, and their `_extDict` variants when `dict` is given:
/// the sequences of the block `src[istart..iend]` into `seq_store`.
/// Returns the size of the literals left after the last sequence.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zstd_compress_block_lazy_row(
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
        0 => lazy::<SEARCH_ROW_HASH, 0>(ms, seq_store, rep, src, dict, istart, iend),
        1 => lazy::<SEARCH_ROW_HASH, 1>(ms, seq_store, rep, src, dict, istart, iend),
        _ => lazy::<SEARCH_ROW_HASH, 2>(ms, seq_store, rep, src, dict, istart, iend),
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
