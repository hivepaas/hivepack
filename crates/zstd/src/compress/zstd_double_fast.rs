//! The `dfast` strategy's match finder: port of
//! `compress/zstd_double_fast.c`, without a dictionary so far.
//!
//! Two hash tables: a long one, of 8-byte hashes (the match state's hash
//! table), and a short one of `minMatch`-byte hashes (its chain table).
//! Positions are indices into `src`, the buffer the window's prefix is in,
//! and `dict`, the one its older segment is in; the tables hold window
//! indices, `position + window.base` (or `window.dict_base`). The extDict
//! variant cuts the two segments out of those buffers, and its positions
//! are in the segments.

use crate::common::mem::idx;
use crate::common::zstd_internal::ZSTD_REP_NUM;
use crate::compress::zstd_compress_internal::{
    HASH_READ_SIZE, HashTable, K_SEARCH_STRENGTH, MatchState, REPCODE1_TO_OFFBASE, SeqStore,
    mem_read32, mem_read32_within, mem_read64, mem_read64_within, offset_to_offbase, zstd_count,
    zstd_count_2segments,
};

/// How the inner search loop ended: which test found a match. `hl1` is
/// the long hash of the next position.
enum Found {
    /// The repcode, at the next position.
    Rep,
    /// A long match, at `matchl0`.
    Long { matchl0: usize, hl1: usize },
    /// A short match, at `matchs0`.
    Short { matchs0: usize, hl1: usize },
    /// The end of the block.
    End,
}

/// How the extDict search loop ended: which test found a match, with the
/// index of the candidate.
enum FoundExt {
    /// The repcode, at the next position.
    Rep,
    /// A long match.
    Long(u32),
    /// A short match; a long one at the next position is tried after.
    Short(u32),
    /// The end of the block.
    End,
}

/// `ZSTD_compressBlock_doubleFast_noDict_generic`: the sequences of the
/// block `src[istart..iend]` into `seq_store`. Returns the size of the
/// literals left after the last sequence.
///
/// libzstd tests its candidates without branching on whether they are in
/// the window, reading from a dummy array when they are not
/// (`ZSTD_selectAddr`); that gives the same answers as testing the window
/// first: a long candidate counts from `prefixLowestIndex` on, the long
/// candidate at the next position only above it.
#[allow(clippy::too_many_lines)]
fn zstd_compress_block_double_fast_no_dict_generic<const MLS: u32>(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    istart: usize,
    iend: usize,
) -> usize {
    // The shortest match, a constant in each copy, as libzstd's templates
    // make it.
    let mls = MLS;
    let c_params = ms.c_params;
    let h_bits_l = c_params.hash_log;
    let h_bits_s = c_params.chain_log;
    let base = ms.window.base;
    let mut anchor = istart;
    let end_index = ms.window.index(iend);
    // With a dictionary, it would be attached.
    let prefix_lowest_index = ms.lowest_prefix_index(end_index, c_params.window_log);
    let prefix_lowest = (i64::from(prefix_lowest_index) - base) as usize;
    // Before the block for blocks under 8 bytes, where libzstd's pointer
    // goes before the buffer and the search ends at once; 0 does the same.
    let ilimit = iend.saturating_sub(HASH_READ_SIZE);
    // Differs from libzstd: the search loop tests `ip1 <= ilimit` as
    // whether 8 bytes fit at ip1 in the block, the same test as the bounds
    // check of the read there, which the compiler then drops. It gives the
    // same answers, for blocks under 8 bytes too.
    let block = &src[..iend];
    let in_limit = |position: usize| idx(position) + HASH_READ_SIZE <= block.len();
    // Differs from libzstd: the candidates at ip are read from the prefix,
    // at their index less prefix_lowest_index, so that one test tells both
    // whether they are in the window and whether the bytes are there. An
    // index below the window wraps past the prefix's end, as end_index is
    // under 2^32; one in it is before ip, so its bytes are there.
    let prefix = &src[prefix_lowest..iend];
    let in_prefix = |index: u32| index.wrapping_sub(prefix_lowest_index) as usize;
    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];
    let mut offset_saved1 = 0;
    let mut offset_saved2 = 0;

    // How many positions to search before taking bigger steps.
    let k_step_incr = 1usize << K_SEARCH_STRENGTH;

    let index = |position: usize| (position as i64 + base) as u32;
    let at = |index: u32| (i64::from(index) - base) as usize;

    // The current position.
    let mut ip = istart;

    // Initialization.
    ip += usize::from(ip == prefix_lowest);
    {
        let current = index(ip);
        let window_low = ms.lowest_prefix_index(current, c_params.window_log);
        let max_rep = current.wrapping_sub(window_low);
        if offset_2 > max_rep {
            offset_saved2 = offset_2;
            offset_2 = 0;
        }
        if offset_1 > max_rep {
            offset_saved1 = offset_1;
            offset_1 = 0;
        }
    }

    let mut hash_long = HashTable::new(&mut ms.hash_table, h_bits_l);
    let mut hash_small = HashTable::new(&mut ms.chain_table, h_bits_s);

    // The outer loop: one turn per match found and stored.
    'outer: loop {
        // The current step size.
        let mut step = 1;
        // Where to take a bigger step if no match is found.
        let mut next_step = ip + k_step_incr;
        // The next position.
        let mut ip1 = ip + step;

        if !in_limit(ip1) {
            break;
        }

        // Differs from libzstd: the 8 bytes at ip and at ip1 are read once
        // each, those at ip1 kept for when it becomes ip; the 4 bytes at
        // ip and at ip + 1 are taken from those at ip.
        let mut val0 = mem_read64(block, ip);
        let mut val1 = mem_read64(block, ip1);

        // The long hash at ip.
        let mut hl0 = hash_long.hash_u64(val0, 8);
        let mut curr;

        // How far back the repcode is. Differs from libzstd, which tests
        // that offset_1 is not 0: for 0, the repcode is read at
        // ip + 1 + iend, past the block, where no bytes are and no match is
        // found. The compiler then makes one search loop instead of two.
        let rep_back = if offset_1 > 0 {
            offset_1 as usize
        } else {
            iend.wrapping_neg()
        };

        // The inner loop: one turn per position searched, until a test
        // finds a match.
        let found = loop {
            // The long candidate at ip. Differs from libzstd: it is read
            // here instead of as the candidate at ip1 of the position
            // before, which only the short match needs; no write to the
            // table comes in between.
            let idxl0 = hash_long.get(hl0);
            let hs0 = hash_small.hash_u64(val0, mls);
            let idxs0 = hash_small.get(hs0);
            curr = index(ip);

            // Update the hash tables.
            hash_long.set(hl0, curr);
            hash_small.set(hs0, curr);

            // The repcode, without a dictionary.
            if mem_read32_within(block, (ip + 1).wrapping_sub(rep_back)) == Some((val0 >> 8) as u32)
            {
                break Found::Rep;
            }

            // The long hash at ip1.
            let hl1 = hash_long.hash_u64(val1, 8);

            // A long match in the prefix.
            if mem_read64_within(prefix, in_prefix(idxl0)) == Some(val0) {
                break Found::Long {
                    matchl0: at(idxl0),
                    hl1,
                };
            }

            // A short match in the prefix.
            if mem_read32_within(prefix, in_prefix(idxs0)) == Some(val0 as u32) {
                break Found::Short {
                    matchs0: at(idxs0),
                    hl1,
                };
            }

            if ip1 >= next_step {
                step += 1;
                next_step += k_step_incr;
            }
            ip = ip1;
            ip1 += step;

            hl0 = hl1;
            val0 = val1;

            if !in_limit(ip1) {
                break Found::End;
            }
            val1 = mem_read64(block, ip1);
        };

        let m_length = 'match_stored: {
            // The match, and its length so far.
            let (mut match_pos, mut m_length, hl1) = match found {
                Found::End => break 'outer,
                Found::Rep => {
                    let m_length =
                        zstd_count(src, ip + 1 + 4, ip + 1 + 4 - offset_1 as usize, iend) + 4;
                    ip += 1;
                    seq_store.store_seq(src, anchor, ip - anchor, REPCODE1_TO_OFFBASE, m_length);
                    break 'match_stored m_length;
                }
                Found::Long { matchl0, hl1 } => {
                    let m_length = zstd_count(src, ip + 8, matchl0 + 8, iend) + 8;
                    (matchl0, m_length, hl1)
                }
                Found::Short { mut matchs0, hl1 } => {
                    // The long candidate at ip1.
                    let idxl1 = hash_long.get(hl1);

                    // _search_next_long: a short match; try a longer one.
                    let mut m_length = zstd_count(src, ip + 4, matchs0 + 4, iend) + 4;

                    // A long match at the next position.
                    if idxl1 > prefix_lowest_index && mem_read64(src, at(idxl1)) == val1 {
                        let matchl1 = at(idxl1);
                        let l1len = zstd_count(src, ip1 + 8, matchl1 + 8, iend) + 8;
                        if l1len > m_length {
                            // Take the long match instead.
                            ip = ip1;
                            m_length = l1len;
                            matchs0 = matchl1;
                        }
                    }
                    (matchs0, m_length, hl1)
                }
            };
            let offset = (ip - match_pos) as u32;

            // Catch up. Differs from libzstd: one loop for both kinds of
            // match.
            while (ip > anchor) & (match_pos > prefix_lowest) && src[ip - 1] == src[match_pos - 1] {
                ip -= 1;
                match_pos -= 1;
                m_length += 1;
            }

            // _match_found: needs ip, offset, m_length.
            offset_2 = offset_1;
            offset_1 = offset;

            if step < 4 {
                // Writing ip1 back is unsafe once it is at or past where
                // the match ends; with a step under 4, the distance from
                // ip to ip1, and matches of 4 bytes at least, it is
                // before.
                hash_long.set(hl1, index(ip1));
            }

            seq_store.store_seq(
                src,
                anchor,
                ip - anchor,
                offset_to_offbase(offset),
                m_length,
            );
            m_length
        };

        // _match_stored
        ip += m_length;
        anchor = ip;

        if ip <= ilimit {
            // Complementary insertion, after the ilimit test, as candidates
            // could be past iend - 8.
            {
                let index_to_insert = curr + 2;
                hash_long.set(hash_long.hash(src, at(index_to_insert), 8), index_to_insert);
                hash_long.set(hash_long.hash(src, ip - 2, 8), index(ip - 2));
                hash_small.set(
                    hash_small.hash(src, at(index_to_insert), mls),
                    index_to_insert,
                );
                hash_small.set(hash_small.hash(src, ip - 1, mls), index(ip - 1));
            }

            // An immediate repcode.
            while ip <= ilimit
                && ((offset_2 > 0)
                    & (mem_read32(src, ip) == mem_read32(src, ip - offset_2 as usize)))
            {
                // Store the sequence.
                let r_length = zstd_count(src, ip + 4, ip + 4 - offset_2 as usize, iend) + 4;
                // Swap offset_2 and offset_1.
                std::mem::swap(&mut offset_1, &mut offset_2);
                hash_small.set(hash_small.hash(src, ip, mls), index(ip));
                hash_long.set(hash_long.hash(src, ip, 8), index(ip));
                seq_store.store_seq(src, anchor, 0, REPCODE1_TO_OFFBASE, r_length);
                ip += r_length;
                anchor = ip;
            }
        }
    }

    // _cleanup: if offset_1 started invalid (offsetSaved1 != 0) and became
    // valid (offset_1 != 0), rotate the saved offsets; see the fast
    // strategy.
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

/// `ZSTD_compressBlock_doubleFast`, without a dictionary: dispatches on the
/// shortest match, 4 to 7 bytes (3 counts as 4).
pub(crate) fn zstd_compress_block_double_fast(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    istart: usize,
    iend: usize,
) -> usize {
    let f = match ms.c_params.min_match {
        5 => zstd_compress_block_double_fast_no_dict_generic::<5>,
        6 => zstd_compress_block_double_fast_no_dict_generic::<6>,
        7 => zstd_compress_block_double_fast_no_dict_generic::<7>,
        _ => zstd_compress_block_double_fast_no_dict_generic::<4>,
    };
    f(ms, seq_store, rep, src, istart, iend)
}

/// `ZSTD_compressBlock_doubleFast_extDict_generic`: the sequences of the
/// block, with matches in the window's older segment too, `dict`; a match
/// there may run on into the prefix. Without that segment in reach, the
/// noDict variant.
///
/// Differs from libzstd: the two segments are cut out of their buffers
/// once, and positions are in them; see below. The table reads and writes,
/// in their order, and the sequences are libzstd's.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn zstd_compress_block_double_fast_ext_dict_generic<const MLS: u32>(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dict: &[u8],
    istart: usize,
    iend: usize,
) -> usize {
    // The shortest match, a constant in each copy, as libzstd's templates
    // make it.
    let mls = MLS;
    let c_params = ms.c_params;
    let h_bits_l = c_params.hash_log;
    let h_bits_s = c_params.chain_log;
    let base = ms.window.base;
    let end_index = ms.window.index(iend);
    let low_limit = ms.lowest_match_index(end_index, c_params.window_log);
    let dict_start_index = low_limit;
    let dict_limit = ms.window.dict_limit;
    let prefix_start_index = dict_limit.max(low_limit);
    let prefix_start = (i64::from(prefix_start_index) - base) as usize;
    let dict_base = ms.window.dict_base;
    let dict_start = (i64::from(dict_start_index) - dict_base) as usize;
    let dict_end = (i64::from(prefix_start_index) - dict_base) as usize;
    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];

    // Back to the noDict variant if the older segment is out of the window.
    if prefix_start_index == dict_start_index {
        return zstd_compress_block_double_fast(ms, seq_store, rep, src, istart, iend);
    }

    // Differs from libzstd: the prefix, up to the block's end, and the
    // older segment are cut out of their buffers, which the window checks
    // hold them, and positions from here on are in them. `ip`, `anchor`
    // and `iend` are libzstd's less prefixStart; a match in the older
    // segment is at its index less dictStartIndex. The bytes read are the
    // same, as libzstd's reads stay in the segments: its counts stop at
    // their ends, its catch-ups at their starts, and for the candidates,
    // see below. The literals are stored from the prefix too, which
    // decides how they are copied against iend, as libzstd's litLimit does;
    // the literals stored are the same either way.
    let prefix = &src[prefix_start..iend];
    let dict_segment = &dict[dict_start..dict_end];
    // Its length, prefixStartIndex - dictStartIndex: not 0, as the noDict
    // variant takes that case.
    let dict_len = dict_segment.len();
    let mut ip = istart - prefix_start;
    let mut anchor = ip;
    let iend = prefix.len();
    // Before the block for blocks under 8 bytes; see the noDict variant.
    let ilimit = iend.saturating_sub(HASH_READ_SIZE);
    let index = |position: usize| (position as u32).wrapping_add(prefix_start_index);
    // Where index `i` is: its segment, its position there, and where the
    // segment ends. Each segment starts at 0, libzstd's lowMatchPtr; a
    // match past the older segment's end goes on at 0 of the prefix,
    // libzstd's prefixStart.
    let locate = |i: u32| {
        if i < prefix_start_index {
            (
                dict_segment,
                i.wrapping_sub(dict_start_index) as usize,
                dict_len,
            )
        } else {
            (prefix, (i - prefix_start_index) as usize, iend)
        }
    };

    // Differs from libzstd: the search loop tests `ip < ilimit` as whether
    // more than 8 bytes are left at ip in the prefix. It is the same test,
    // and the compiler then drops the bounds check of the read at ip.
    let in_limit = |position: usize| idx(position) + HASH_READ_SIZE < prefix.len();
    // Differs from libzstd: a candidate is read from its segment, at its
    // index less the segment's first, so that one test tells both whether
    // it is in the window and whether its bytes are there. Those of the
    // older segment are read from the byte after its start, as libzstd
    // takes the ones above dictStartIndex only; an index at or below it
    // wraps past that slice's end, as indices are under 2^32. As in
    // libzstd, an index below prefixStartIndex is in the older segment.
    //
    // This gives libzstd's answers because a table entry above
    // dictStartIndex is a position with its 8 bytes in its segment. The
    // tables are written only at positions at or before ilimit, iend - 8,
    // in both variants: those searched, the one after a short match, the
    // complementary insertions and the immediate repcodes. The older
    // segment ends where the input before it did, so where its last block
    // did. And an entry in the prefix is a position before ip. libzstd
    // reads no byte past a segment's end then, and neither does the port.
    let dict_candidates = &dict_segment[1..];
    let dict_candidates_len = dict_candidates.len() as u32;
    let candidate = |i: u32| {
        let at = i.wrapping_sub(prefix_start_index);
        if i < prefix_start_index {
            (
                dict_candidates,
                at.wrapping_add(dict_candidates_len) as usize,
            )
        } else {
            (prefix, at as usize)
        }
    };
    // The 4 bytes `offset` back from `position`, where the repcode is.
    // Differs from libzstd: they are read from the prefix if they are all
    // in it, else from the older segment if they are all in it, in place
    // of libzstd's tests of repIndex: in the window, offset <=
    // curr - dictStartIndex, and its 4 bytes in one segment,
    // ZSTD_index_overlap_check. It is the same test. repIndex is in the
    // prefix when offset <= position, and then so are its bytes, as they
    // start at or before `position`, whose 4 bytes are in the prefix
    // wherever this is called.
    // Otherwise it is position + dict_len - offset into the older segment,
    // libzstd's two tests being that it is at least 0 and at most
    // dict_len - 4: the bounds of the read there. An offset past the
    // prefix's start wraps the position past its end, as it is computed
    // on 64 bits, then masked so that the read's end does not overflow;
    // one past the older segment's start wraps past both ends.
    let rep_read = |position: usize, offset: u32| {
        let at = position.wrapping_sub(offset as usize);
        match mem_read32_within(prefix, idx(at)) {
            Some(rep) => Some(rep),
            None => mem_read32_within(dict_segment, idx(at.wrapping_add(dict_len))),
        }
    };

    let mut hash_long = HashTable::new(&mut ms.hash_table, h_bits_l);
    let mut hash_small = HashTable::new(&mut ms.chain_table, h_bits_s);

    // The outer loop: one turn per match found and stored.
    'outer: loop {
        // The search loop: one turn per position searched, until a test
        // finds a match. Differs from libzstd: it only searches; the match
        // is counted and stored after it, as libzstd does after its tests.
        let found = loop {
            // ip < ilimit: < instead of <=, because of ip + 1.
            if !in_limit(ip) {
                break FoundExt::End;
            }
            // Differs from libzstd: the 8 bytes at ip are read once, and
            // the 4 bytes at ip and at ip + 1 (and those of the hash of
            // `mls` bytes) taken from them.
            let val0 = mem_read64(prefix, ip);
            let h_small = hash_small.hash_u64(val0, mls);
            let match_index = hash_small.get(h_small);

            let h_long = hash_long.hash_u64(val0, 8);
            let match_long_index = hash_long.get(h_long);

            let curr = index(ip);
            // Update the hash tables.
            hash_small.set(h_small, curr);
            hash_long.set(h_long, curr);

            // The repcode, searching at curr + 1.
            if rep_read(ip + 1, offset_1) == Some((val0 >> 8) as u32) {
                break FoundExt::Rep;
            }

            // A long match.
            let (segment, at) = candidate(match_long_index);
            if mem_read64_within(segment, at) == Some(val0) {
                break FoundExt::Long(match_long_index);
            }

            // A short match.
            let (segment, at) = candidate(match_index);
            if mem_read32_within(segment, at) == Some(val0 as u32) {
                break FoundExt::Short(match_index);
            }

            ip += ((ip - anchor) >> K_SEARCH_STRENGTH) + 1;
        };

        let curr = index(ip);
        let m_length = match found {
            FoundExt::End => break 'outer,
            FoundExt::Rep => {
                let rep_index = (curr + 1).wrapping_sub(offset_1);
                let (rbuf, rpos, rep_match_end) = locate(rep_index);
                let m_length = zstd_count_2segments(
                    prefix,
                    ip + 1 + 4,
                    rbuf,
                    rpos + 4,
                    iend,
                    rep_match_end,
                    0,
                ) + 4;
                ip += 1;
                seq_store.store_seq(prefix, anchor, ip - anchor, REPCODE1_TO_OFFBASE, m_length);
                m_length
            }
            FoundExt::Long(match_long_index) => {
                let (lbuf, mut lpos, match_end) = locate(match_long_index);
                let mut length =
                    zstd_count_2segments(prefix, ip + 8, lbuf, lpos + 8, iend, match_end, 0) + 8;
                let offset = curr - match_long_index;
                // Catch up.
                while (ip > anchor) & (lpos > 0) && prefix[ip - 1] == lbuf[lpos - 1] {
                    ip -= 1;
                    lpos -= 1;
                    length += 1;
                }
                offset_2 = offset_1;
                offset_1 = offset;
                seq_store.store_seq(
                    prefix,
                    anchor,
                    ip - anchor,
                    offset_to_offbase(offset),
                    length,
                );
                length
            }
            FoundExt::Short(match_index) => {
                let val1 = mem_read64(prefix, ip + 1);
                let h3 = hash_long.hash_u64(val1, 8);
                let match_index3 = hash_long.get(h3);
                let offset;
                let mut length;
                hash_long.set(h3, curr + 1);
                let (segment, at) = candidate(match_index3);
                if mem_read64_within(segment, at) == Some(val1) {
                    let (buf3, mut pos3, match_end) = locate(match_index3);
                    length =
                        zstd_count_2segments(prefix, ip + 9, buf3, pos3 + 8, iend, match_end, 0)
                            + 8;
                    ip += 1;
                    offset = curr + 1 - match_index3;
                    // Catch up.
                    while (ip > anchor) & (pos3 > 0) && prefix[ip - 1] == buf3[pos3 - 1] {
                        ip -= 1;
                        pos3 -= 1;
                        length += 1;
                    }
                } else {
                    let (sbuf, mut spos, match_end) = locate(match_index);
                    length =
                        zstd_count_2segments(prefix, ip + 4, sbuf, spos + 4, iend, match_end, 0)
                            + 4;
                    offset = curr - match_index;
                    // Catch up.
                    while (ip > anchor) & (spos > 0) && prefix[ip - 1] == sbuf[spos - 1] {
                        ip -= 1;
                        spos -= 1;
                        length += 1;
                    }
                }
                offset_2 = offset_1;
                offset_1 = offset;
                seq_store.store_seq(
                    prefix,
                    anchor,
                    ip - anchor,
                    offset_to_offbase(offset),
                    length,
                );
                length
            }
        };

        // The next sequence starts after the match.
        ip += m_length;
        anchor = ip;

        if ip <= ilimit {
            // Complementary insertion, after the ilimit test, as candidates
            // could be past iend - 8.
            {
                let index_to_insert = curr + 2;
                let at = (index_to_insert - prefix_start_index) as usize;
                hash_long.set(hash_long.hash(prefix, at, 8), index_to_insert);
                hash_long.set(hash_long.hash(prefix, ip - 2, 8), index(ip - 2));
                hash_small.set(hash_small.hash(prefix, at, mls), index_to_insert);
                hash_small.set(hash_small.hash(prefix, ip - 1, mls), index(ip - 1));
            }

            // An immediate repcode.
            while ip <= ilimit && rep_read(ip, offset_2) == Some(mem_read32(prefix, ip)) {
                let current2 = index(ip);
                let rep_index2 = current2.wrapping_sub(offset_2);
                let (rbuf, rpos, rep_end2) = locate(rep_index2);
                let rep_length2 =
                    zstd_count_2segments(prefix, ip + 4, rbuf, rpos + 4, iend, rep_end2, 0) + 4;
                // Swap offset_2 and offset_1.
                std::mem::swap(&mut offset_1, &mut offset_2);
                seq_store.store_seq(prefix, anchor, 0, REPCODE1_TO_OFFBASE, rep_length2);
                hash_small.set(hash_small.hash(prefix, ip, mls), current2);
                hash_long.set(hash_long.hash(prefix, ip, 8), current2);
                ip += rep_length2;
                anchor = ip;
            }
        }
    }

    // The repcodes for the next block.
    rep[0] = offset_1;
    rep[1] = offset_2;

    // The size of the last literals.
    iend - anchor
}

/// `ZSTD_compressBlock_doubleFast_extDict`: dispatches on the shortest
/// match, 4 to 7 bytes (3 counts as 4).
pub(crate) fn zstd_compress_block_double_fast_ext_dict(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dict: &[u8],
    istart: usize,
    iend: usize,
) -> usize {
    let f = match ms.c_params.min_match {
        5 => zstd_compress_block_double_fast_ext_dict_generic::<5>,
        6 => zstd_compress_block_double_fast_ext_dict_generic::<6>,
        7 => zstd_compress_block_double_fast_ext_dict_generic::<7>,
        _ => zstd_compress_block_double_fast_ext_dict_generic::<4>,
    };
    f(ms, seq_store, rep, src, dict, istart, iend)
}
