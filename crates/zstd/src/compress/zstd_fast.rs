//! The `fast` strategy's match finder: port of `compress/zstd_fast.c`,
//! without a dictionary so far.
//!
//! Positions are indices into `src`, the buffer the window is over; the
//! hash table holds window indices, `position + window.base`.

use crate::common::mem::read_le32;
use crate::common::zstd_internal::ZSTD_REP_NUM;
use crate::compress::zstd_compress_internal::{
    HASH_READ_SIZE, K_SEARCH_STRENGTH, MatchState, REPCODE1_TO_OFFBASE, SeqStore,
    offset_to_offbase, zstd_count, zstd_hash_ptr,
};

/// `ZSTD_compressBlock_fast_noDict_generic`: the sequences of the block
/// `src[istart..iend]` into `seq_store`. Returns the size of the literals
/// left after the last sequence.
///
/// libzstd interleaves the work on the next few positions: hashing one,
/// looking up the next, comparing the one after, two positions at a time,
/// and starts that pipeline again after each match. The port does the same
/// steps in the same order, which the tables and the sequences depend on.
///
/// libzstd's two ways of testing a candidate (`ZSTD_match4Found_cmov` and
/// `_branch`, chosen by the window log) give the same answer: the candidate
/// is in the window and its first 4 bytes are the same.
#[allow(clippy::too_many_lines)]
fn zstd_compress_block_fast_no_dict_generic(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    istart: usize,
    iend: usize,
    mls: u32,
) -> usize {
    let c_params = ms.c_params;
    let hlog = c_params.hash_log;
    // At least 2.
    let step_size = c_params.target_length as usize + usize::from(c_params.target_length == 0) + 1;
    let base = ms.window.base;
    let end_index = (iend as u32).wrapping_add(base);
    let prefix_start_index = ms.lowest_prefix_index(end_index, c_params.window_log);
    let prefix_start = prefix_start_index.wrapping_sub(base) as usize;
    // Before the block for blocks under 8 bytes, where libzstd's pointer
    // goes before the buffer and the search ends at once; 0 does the same.
    let ilimit = iend.saturating_sub(HASH_READ_SIZE);

    let mut anchor = istart;
    let mut ip0 = istart;
    let mut ip1;
    let mut ip2;
    let mut ip3;
    let mut current0: u32;

    let mut rep_offset1 = rep[0];
    let mut rep_offset2 = rep[1];
    let mut offset_saved1 = 0;
    let mut offset_saved2 = 0;

    let mut hash0;
    let mut hash1;
    let mut match_idx: u32;

    let mut offcode: u32;
    let mut match0: usize;
    let mut m_length: usize;

    // ip0 and ip1 are always adjacent. The targetLength skipping and the
    // acceleration over incompressible data apply to every other position,
    // so `step` is the gap between pairs of positions, from ip0 to ip2 or
    // ip1 to ip3.
    let mut step;
    let mut next_step;
    let k_step_incr = 1usize << (K_SEARCH_STRENGTH - 1);
    let index = |position: usize| (position as u32).wrapping_add(base);
    // ZSTD_match4Found
    let match_found = |current: usize, match_idx: u32| {
        match_idx >= prefix_start_index
            && read_le32(src, current) == read_le32(src, (match_idx - base) as usize)
    };

    ip0 += usize::from(ip0 == prefix_start);
    {
        let curr = index(ip0);
        let window_low = ms.lowest_prefix_index(curr, c_params.window_log);
        let max_rep = curr.wrapping_sub(window_low);
        if rep_offset2 > max_rep {
            offset_saved2 = rep_offset2;
            rep_offset2 = 0;
        }
        if rep_offset1 > max_rep {
            offset_saved1 = rep_offset1;
            rep_offset1 = 0;
        }
    }

    let hash_table = &mut ms.hash_table;

    'start: loop {
        // Needs ip0.
        step = step_size;
        next_step = ip0 + k_step_incr;

        // The positions; ip0 - anchor == 0, so no step to work out.
        ip1 = ip0 + 1;
        ip2 = ip0 + step;
        ip3 = ip2 + 1;

        if ip3 >= ilimit {
            break 'start;
        }

        hash0 = zstd_hash_ptr(src, ip0, hlog, mls);
        hash1 = zstd_hash_ptr(src, ip1, hlog, mls);

        match_idx = hash_table[hash0];

        'search: loop {
            // The repcode match for ip2.
            let rval = read_le32(src, ip2 - rep_offset1 as usize);

            // Write back the hash table entry.
            current0 = index(ip0);
            hash_table[hash0] = current0;

            // Check the repcode at ip2.
            if (read_le32(src, ip2) == rval) & (rep_offset1 > 0) {
                ip0 = ip2;
                match0 = ip0 - rep_offset1 as usize;
                m_length = usize::from(src[ip0 - 1] == src[match0 - 1]);
                ip0 -= m_length;
                match0 -= m_length;
                offcode = REPCODE1_TO_OFFBASE;
                m_length += 4;

                // The next hash table entry, already computed. Safe to
                // write, since ip1 is before the repcode (ip2).
                hash_table[hash1] = index(ip1);

                break 'search;
            }

            if match_found(ip0, match_idx) {
                // The next hash table entry, already computed. Safe since
                // ip1 == ip0 + 1, and the search resumes after ip1.
                hash_table[hash1] = index(ip1);
                (offcode, match0, m_length) = offset_match(
                    &mut rep_offset1,
                    &mut rep_offset2,
                    src,
                    ip0,
                    match_idx,
                    base,
                    anchor,
                    prefix_start,
                    &mut ip0,
                );
                break 'search;
            }

            // Look up ip1.
            match_idx = hash_table[hash1];

            // Hash ip2.
            hash0 = hash1;
            hash1 = zstd_hash_ptr(src, ip2, hlog, mls);

            // Advance to the next positions.
            ip0 = ip1;
            ip1 = ip2;
            ip2 = ip3;

            // Write back the hash table entry.
            current0 = index(ip0);
            hash_table[hash0] = current0;

            if match_found(ip0, match_idx) {
                // The next hash table entry, already computed. Not written
                // if it is at or past where the search will resume: the
                // shortest match has 4 bytes, so it resumes at ip0 + 4.
                if step <= 4 {
                    hash_table[hash1] = index(ip1);
                }
                (offcode, match0, m_length) = offset_match(
                    &mut rep_offset1,
                    &mut rep_offset2,
                    src,
                    ip0,
                    match_idx,
                    base,
                    anchor,
                    prefix_start,
                    &mut ip0,
                );
                break 'search;
            }

            // Look up ip1.
            match_idx = hash_table[hash1];

            // Hash ip2.
            hash0 = hash1;
            hash1 = zstd_hash_ptr(src, ip2, hlog, mls);

            // Advance to the next positions.
            ip0 = ip1;
            ip1 = ip2;
            ip2 = ip0 + step;
            ip3 = ip1 + step;

            // The step.
            if ip2 >= next_step {
                step += 1;
                next_step += k_step_incr;
            }

            if ip3 >= ilimit {
                break 'start;
            }
        }

        // _match: needs ip0, match0, offcode.

        // The forward length.
        m_length += zstd_count(src, ip0 + m_length, match0 + m_length, iend);

        seq_store.store_seq(src, anchor, ip0 - anchor, offcode, m_length);

        ip0 += m_length;
        anchor = ip0;

        // Fill the table, and check for an immediate repcode.
        if ip0 <= ilimit {
            // Here because current + 2 could be past iend - 8.
            let at = (current0 + 2).wrapping_sub(base) as usize;
            hash_table[zstd_hash_ptr(src, at, hlog, mls)] = current0 + 2;
            hash_table[zstd_hash_ptr(src, ip0 - 2, hlog, mls)] = index(ip0 - 2);

            if rep_offset2 > 0 {
                // rep_offset2 == 0 means it is invalid.
                while ip0 <= ilimit
                    && read_le32(src, ip0) == read_le32(src, ip0 - rep_offset2 as usize)
                {
                    // Store the sequence.
                    let r_length =
                        zstd_count(src, ip0 + 4, ip0 + 4 - rep_offset2 as usize, iend) + 4;
                    // Swap rep_offset2 and rep_offset1.
                    std::mem::swap(&mut rep_offset1, &mut rep_offset2);
                    hash_table[zstd_hash_ptr(src, ip0, hlog, mls)] = index(ip0);
                    ip0 += r_length;
                    seq_store.store_seq(src, anchor, 0, REPCODE1_TO_OFFBASE, r_length);
                    anchor = ip0;
                }
            }
        }
    }

    // _cleanup: a couple of positions could still be searched, but it costs
    // speed for little.

    // The repcodes outside the prefix were set to zero before the loop;
    // those still zero are restored, so that the history stays right. When
    // both were invalid, which to restore: if rep_offset1 became valid, it
    // is rep[0], and offsetSaved1 rep[1].
    offset_saved2 = if offset_saved1 != 0 && rep_offset1 != 0 {
        offset_saved1
    } else {
        offset_saved2
    };

    // The repcodes for the next block.
    rep[0] = if rep_offset1 != 0 {
        rep_offset1
    } else {
        offset_saved1
    };
    rep[1] = if rep_offset2 != 0 {
        rep_offset2
    } else {
        offset_saved2
    };

    // The size of the last literals.
    iend - anchor
}

/// `_offset`: a match found in the hash table at `match_idx`, extended
/// backwards. Needs ip0 and the index; returns the offset code, the match
/// and its length so far, and moves `ip0` back with it.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn offset_match(
    rep_offset1: &mut u32,
    rep_offset2: &mut u32,
    src: &[u8],
    ip0_in: usize,
    match_idx: u32,
    base: u32,
    anchor: usize,
    prefix_start: usize,
    ip0: &mut usize,
) -> (u32, usize, usize) {
    let mut ip = ip0_in;
    let mut match0 = (match_idx - base) as usize;
    *rep_offset2 = *rep_offset1;
    *rep_offset1 = (ip - match0) as u32;
    let offcode = offset_to_offbase(*rep_offset1);
    let mut m_length = 4;

    // The backwards match length.
    while (ip > anchor) & (match0 > prefix_start) && src[ip - 1] == src[match0 - 1] {
        ip -= 1;
        match0 -= 1;
        m_length += 1;
    }
    *ip0 = ip;
    (offcode, match0, m_length)
}

/// `ZSTD_compressBlock_fast`, without a dictionary: dispatches on the
/// shortest match, 4 to 7 bytes (3 counts as 4).
pub(crate) fn zstd_compress_block_fast(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    istart: usize,
    iend: usize,
) -> usize {
    let mml = ms.c_params.min_match;
    let mls = match mml {
        5..=7 => mml,
        _ => 4,
    };
    zstd_compress_block_fast_no_dict_generic(ms, seq_store, rep, src, istart, iend, mls)
}
