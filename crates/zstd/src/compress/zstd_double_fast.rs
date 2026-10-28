//! The `dfast` strategy's match finder: port of
//! `compress/zstd_double_fast.c`, without a dictionary so far.
//!
//! Two hash tables: a long one, of 8-byte hashes (the match state's hash
//! table), and a short one of `minMatch`-byte hashes (its chain table).
//! Positions are indices into `src`, the buffer the window is over; the
//! tables hold window indices, `position + window.base`.

use crate::common::mem::{read_le32, read_le64};
use crate::common::zstd_internal::ZSTD_REP_NUM;
use crate::compress::zstd_compress_internal::{
    HASH_READ_SIZE, K_SEARCH_STRENGTH, MatchState, REPCODE1_TO_OFFBASE, SeqStore,
    offset_to_offbase, zstd_count, zstd_hash_ptr,
};

/// How the inner search loop ended.
enum Found {
    /// A repcode match, already stored.
    Stored(usize),
    /// A match at `offset`, of `m_length` bytes, at the current position;
    /// `hl1` is the long hash of the next position.
    Match {
        offset: u32,
        m_length: usize,
        hl1: usize,
    },
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
fn zstd_compress_block_double_fast_no_dict_generic(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    istart: usize,
    iend: usize,
    mls: u32,
) -> usize {
    let c_params = ms.c_params;
    let h_bits_l = c_params.hash_log;
    let h_bits_s = c_params.chain_log;
    let base = ms.window.base;
    let mut anchor = istart;
    let end_index = (iend as u32).wrapping_add(base);
    // With a dictionary, it would be attached.
    let prefix_lowest_index = ms.lowest_prefix_index(end_index, c_params.window_log);
    let prefix_lowest = prefix_lowest_index.wrapping_sub(base) as usize;
    // Before the block for blocks under 8 bytes, where libzstd's pointer
    // goes before the buffer and the search ends at once; 0 does the same.
    let ilimit = iend.saturating_sub(HASH_READ_SIZE);
    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];
    let mut offset_saved1 = 0;
    let mut offset_saved2 = 0;

    // How many positions to search before taking bigger steps.
    let k_step_incr = 1usize << K_SEARCH_STRENGTH;

    let index = |position: usize| (position as u32).wrapping_add(base);
    let at = |index: u32| (index - base) as usize;

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

    let hash_long = &mut ms.hash_table;
    let hash_small = &mut ms.chain_table;

    // The outer loop: one turn per match found and stored.
    loop {
        // The current step size.
        let mut step = 1;
        // Where to take a bigger step if no match is found.
        let mut next_step = ip + k_step_incr;
        // The next position.
        let mut ip1 = ip + step;

        if ip1 > ilimit {
            break;
        }

        // The long hash at ip, and its candidate.
        let mut hl0 = zstd_hash_ptr(src, ip, h_bits_l, 8);
        let mut idxl0 = hash_long[hl0];
        // The long hash at ip1, and its candidate.
        let mut hl1;
        let mut idxl1;
        let mut curr;

        // The inner loop: one turn per position searched.
        let found = loop {
            let hs0 = zstd_hash_ptr(src, ip, h_bits_s, mls);
            let idxs0 = hash_small[hs0];
            curr = index(ip);

            // Update the hash tables.
            hash_long[hl0] = curr;
            hash_small[hs0] = curr;

            // The repcode, without a dictionary.
            if (offset_1 > 0)
                & (read_le32(src, ip + 1 - offset_1 as usize) == read_le32(src, ip + 1))
            {
                let m_length =
                    zstd_count(src, ip + 1 + 4, ip + 1 + 4 - offset_1 as usize, iend) + 4;
                ip += 1;
                seq_store.store_seq(src, anchor, ip - anchor, REPCODE1_TO_OFFBASE, m_length);
                break Found::Stored(m_length);
            }

            hl1 = zstd_hash_ptr(src, ip1, h_bits_l, 8);

            // A long match in the prefix.
            if idxl0 >= prefix_lowest_index && read_le64(src, at(idxl0)) == read_le64(src, ip) {
                let mut matchl0 = at(idxl0);
                let mut m_length = zstd_count(src, ip + 8, matchl0 + 8, iend) + 8;
                let offset = (ip - matchl0) as u32;
                // Catch up.
                while (ip > anchor) & (matchl0 > prefix_lowest) && src[ip - 1] == src[matchl0 - 1] {
                    ip -= 1;
                    matchl0 -= 1;
                    m_length += 1;
                }
                break Found::Match {
                    offset,
                    m_length,
                    hl1,
                };
            }

            idxl1 = hash_long[hl1];

            // A short match in the prefix.
            if idxs0 >= prefix_lowest_index && read_le32(src, at(idxs0)) == read_le32(src, ip) {
                // _search_next_long: a short match; try a longer one.
                let mut matchs0 = at(idxs0);
                let mut m_length = zstd_count(src, ip + 4, matchs0 + 4, iend) + 4;
                let mut offset = (ip - matchs0) as u32;

                // A long match at the next position.
                if idxl1 > prefix_lowest_index && read_le64(src, at(idxl1)) == read_le64(src, ip1) {
                    let matchl1 = at(idxl1);
                    let l1len = zstd_count(src, ip1 + 8, matchl1 + 8, iend) + 8;
                    if l1len > m_length {
                        // Take the long match instead.
                        ip = ip1;
                        m_length = l1len;
                        offset = (ip - matchl1) as u32;
                        matchs0 = matchl1;
                    }
                }

                // Complete backwards.
                while (ip > anchor) & (matchs0 > prefix_lowest) && src[ip - 1] == src[matchs0 - 1] {
                    ip -= 1;
                    matchs0 -= 1;
                    m_length += 1;
                }
                break Found::Match {
                    offset,
                    m_length,
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
            idxl0 = idxl1;

            if ip1 > ilimit {
                break Found::End;
            }
        };

        let m_length = match found {
            Found::End => break,
            Found::Stored(m_length) => m_length,
            Found::Match {
                offset,
                m_length,
                hl1,
            } => {
                // _match_found: needs ip, offset, m_length.
                offset_2 = offset_1;
                offset_1 = offset;

                if step < 4 {
                    // Writing ip1 back is unsafe once it is at or past where
                    // the match ends; with a step under 4, the distance from
                    // ip to ip1, and matches of 4 bytes at least, it is
                    // before.
                    hash_long[hl1] = index(ip1);
                }

                seq_store.store_seq(
                    src,
                    anchor,
                    ip - anchor,
                    offset_to_offbase(offset),
                    m_length,
                );
                m_length
            }
        };

        // _match_stored
        ip += m_length;
        anchor = ip;

        if ip <= ilimit {
            // Complementary insertion, after the ilimit test, as candidates
            // could be past iend - 8.
            {
                let index_to_insert = curr + 2;
                hash_long[zstd_hash_ptr(src, at(index_to_insert), h_bits_l, 8)] = index_to_insert;
                hash_long[zstd_hash_ptr(src, ip - 2, h_bits_l, 8)] = index(ip - 2);
                hash_small[zstd_hash_ptr(src, at(index_to_insert), h_bits_s, mls)] =
                    index_to_insert;
                hash_small[zstd_hash_ptr(src, ip - 1, h_bits_s, mls)] = index(ip - 1);
            }

            // An immediate repcode.
            while ip <= ilimit
                && ((offset_2 > 0) & (read_le32(src, ip) == read_le32(src, ip - offset_2 as usize)))
            {
                // Store the sequence.
                let r_length = zstd_count(src, ip + 4, ip + 4 - offset_2 as usize, iend) + 4;
                // Swap offset_2 and offset_1.
                std::mem::swap(&mut offset_1, &mut offset_2);
                hash_small[zstd_hash_ptr(src, ip, h_bits_s, mls)] = index(ip);
                hash_long[zstd_hash_ptr(src, ip, h_bits_l, 8)] = index(ip);
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
    let mls = match ms.c_params.min_match {
        m @ 5..=7 => m,
        _ => 4,
    };
    zstd_compress_block_double_fast_no_dict_generic(ms, seq_store, rep, src, istart, iend, mls)
}
