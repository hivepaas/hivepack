//! Huffman decoding tables: port of the table-building half of
//! `decompress/huf_decompress.c`. The decoding loops come with the decoder.
//!
//! libzstd keeps both kinds of table in one `HUF_DTable` array, with a
//! descriptor in its first cell that says which kind it holds: X1 tables
//! decode one symbol per lookup, X2 tables up to two.

use crate::common::entropy_common::huf_read_stats_wksp;
use crate::common::error_private::{Result, error};
use crate::common::fse_decompress::FseDecompressWksp;
use crate::common::huf::{HUF_SYMBOLVALUE_MAX, HUF_TABLELOG_ABSOLUTEMAX, HUF_TABLELOG_MAX};

/// `HUF_DECODER_FAST_TABLELOG`: the table log of the fast decoding loops.
pub(crate) const HUF_DECODER_FAST_TABLELOG: u32 = 11;

/// The cells a table holds: `1 << HUF_TABLELOG_MAX`, like the decoder's
/// table of `ZSTD_HUFFDTABLE_CAPACITY_LOG`.
pub(crate) const HUF_DTABLE_CELLS: usize = 1 << HUF_TABLELOG_MAX;

/// `DTableDesc`, the first cell of a `HUF_DTable`.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct DTableDesc {
    pub(crate) max_table_log: u8,
    pub(crate) table_type: u8,
    pub(crate) table_log: u8,
}

/// `HUF_DEltX1`: one symbol per lookup.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct HufDEltX1 {
    pub(crate) nb_bits: u8,
    pub(crate) byte: u8,
}

/// `HUF_DEltX2`: up to two symbols per lookup. `sequence` holds them as the
/// two bytes to write, in little-endian order: the first symbol in the low
/// byte.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct HufDEltX2 {
    pub(crate) sequence: u16,
    pub(crate) nb_bits: u8,
    pub(crate) length: u8,
}

/// `HUF_DTable`.
///
/// Differs from libzstd: the two kinds of cell are kept in two typed arrays
/// instead of sharing one `U32` array, so a table takes 24 KiB instead of
/// 16 KiB.
#[derive(Clone)]
pub(crate) struct HufDTable {
    pub(crate) desc: DTableDesc,
    pub(crate) x1: [HufDEltX1; HUF_DTABLE_CELLS],
    pub(crate) x2: [HufDEltX2; HUF_DTABLE_CELLS],
}

impl HufDTable {
    /// A table whose descriptor allows `max_table_log`, as
    /// `HUF_CREATE_STATIC_DTABLEX1` and the decoder set it up.
    pub(crate) fn new(max_table_log: u32) -> Self {
        HufDTable {
            desc: DTableDesc {
                max_table_log: max_table_log as u8,
                table_type: 0,
                table_log: 0,
            },
            x1: [HufDEltX1::default(); HUF_DTABLE_CELLS],
            x2: [HufDEltX2::default(); HUF_DTABLE_CELLS],
        }
    }
}

/// `HUF_rescaleStats`: raises the table log to `target_table_log`, if it is
/// below, and rescales the weights to match. Returns the new table log.
fn huf_rescale_stats(
    huff_weight: &mut [u8],
    rank_val: &mut [u32],
    nb_symbols: u32,
    table_log: u32,
    target_table_log: u32,
) -> u32 {
    if table_log > target_table_log {
        return table_log;
    }
    if table_log < target_table_log {
        let scale = target_table_log - table_log;
        // Raise the weight of every symbol that has one.
        for weight in &mut huff_weight[..nb_symbols as usize] {
            *weight += if *weight == 0 { 0 } else { scale as u8 };
        }
        // Move the counts: every weight but 0 goes to weight + scale, and
        // weights 1 to scale are now empty.
        let mut s = target_table_log as usize;
        while s > scale as usize {
            rank_val[s] = rank_val[s - scale as usize];
            s -= 1;
        }
        for s in (1..=scale as usize).rev() {
            rank_val[s] = 0;
        }
    }
    target_table_log
}

/// `HUF_ReadDTableX1_Workspace`
pub(crate) struct HufReadDTableX1Workspace {
    rank_val: [u32; HUF_TABLELOG_ABSOLUTEMAX as usize + 1],
    rank_start: [u32; HUF_TABLELOG_ABSOLUTEMAX as usize + 1],
    stats_wksp: FseDecompressWksp<64>,
    symbols: [u8; HUF_SYMBOLVALUE_MAX as usize + 1],
    huff_weight: [u8; HUF_SYMBOLVALUE_MAX as usize + 1],
}

impl Default for HufReadDTableX1Workspace {
    fn default() -> Self {
        HufReadDTableX1Workspace {
            rank_val: [0; HUF_TABLELOG_ABSOLUTEMAX as usize + 1],
            rank_start: [0; HUF_TABLELOG_ABSOLUTEMAX as usize + 1],
            stats_wksp: FseDecompressWksp::default(),
            symbols: [0; HUF_SYMBOLVALUE_MAX as usize + 1],
            huff_weight: [0; HUF_SYMBOLVALUE_MAX as usize + 1],
        }
    }
}

/// `HUF_readDTableX1_wksp`: reads a Huffman tree description from `src` and
/// builds a single-symbol table from it. Returns the size of the description.
pub(crate) fn huf_read_dtable_x1_wksp(
    dtable: &mut HufDTable,
    src: &[u8],
    wksp: &mut HufReadDTableX1Workspace,
) -> Result<usize> {
    let mut table_log = 0u32;
    let mut nb_symbols = 0u32;

    let rank_val: &mut [u32; HUF_TABLELOG_MAX as usize + 1] = &mut wksp.rank_val;
    let i_size = huf_read_stats_wksp(
        &mut wksp.huff_weight,
        rank_val,
        &mut nb_symbols,
        &mut table_log,
        src,
        &mut wksp.stats_wksp,
    )?;

    // Table header.
    {
        let mut dtd = dtable.desc;
        let max_table_log = u32::from(dtd.max_table_log) + 1;
        let target_table_log = max_table_log.min(HUF_DECODER_FAST_TABLELOG);
        table_log = huf_rescale_stats(
            &mut wksp.huff_weight,
            &mut wksp.rank_val,
            nb_symbols,
            table_log,
            target_table_log,
        );
        if table_log > u32::from(dtd.max_table_log) + 1 {
            // The table is too small for this tree.
            return error!(TableLogTooLarge);
        }
        dtd.table_type = 0;
        dtd.table_log = table_log as u8;
        dtable.desc = dtd;
    }
    // Differs from libzstd: C trusts its callers' tables to have room for a
    // log of max_table_log + 1; the port's tables have room for
    // HUF_TABLELOG_MAX, which every caller in libzstd passes.
    if (1usize << table_log) > HUF_DTABLE_CELLS {
        return error!(TableLogTooLarge);
    }

    // Order the symbols by weight (symbols), and find where each weight
    // starts in the table (rank_start). symbols[0] is filled but unused.
    {
        let mut next_rank_start = 0u32;
        let unroll = 4;
        let n_limit = nb_symbols as i32 - unroll + 1;
        for n in 0..(table_log as usize + 1) {
            let curr = next_rank_start;
            next_rank_start += wksp.rank_val[n];
            wksp.rank_start[n] = curr;
        }
        let mut n = 0i32;
        while n < n_limit {
            for u in 0..unroll {
                let w = usize::from(wksp.huff_weight[(n + u) as usize]);
                wksp.symbols[wksp.rank_start[w] as usize] = (n + u) as u8;
                wksp.rank_start[w] += 1;
            }
            n += unroll;
        }
        while n < nb_symbols as i32 {
            let w = usize::from(wksp.huff_weight[n as usize]);
            wksp.symbols[wksp.rank_start[w] as usize] = n as u8;
            wksp.rank_start[w] += 1;
            n += 1;
        }
    }

    // Fill the table, all the cells of each weight in turn. libzstd writes
    // four cells at a time where it can; the cells end up the same.
    {
        let dt = &mut dtable.x1;
        let mut symbol = wksp.rank_val[0] as usize;
        let mut rank_start = 0usize;
        for w in 1..(table_log + 1) {
            let symbol_count = wksp.rank_val[w as usize] as usize;
            let length = (1usize << w) >> 1;
            let nb_bits = (table_log + 1 - w) as u8;
            let mut u_start = rank_start;
            for s in 0..symbol_count {
                let d = HufDEltX1 {
                    nb_bits,
                    byte: wksp.symbols[symbol + s],
                };
                dt[u_start..u_start + length].fill(d);
                u_start += length;
            }
            symbol += symbol_count;
            rank_start += symbol_count * length;
        }
    }
    Ok(i_size)
}

/// `HUF_buildDEltX2`
#[inline(always)]
fn huf_build_delt_x2(symbol: u32, nb_bits: u32, base_seq: u32, level: u32) -> HufDEltX2 {
    let sequence = if level == 1 {
        symbol
    } else {
        base_seq + (symbol << 8)
    };
    HufDEltX2 {
        sequence: sequence as u16,
        nb_bits: nb_bits as u8,
        length: level as u8,
    }
}

/// `HUF_fillDTableX2ForWeight`: fills the cells from `at` for the symbols
/// `sorted_symbols[begin..end]`, each `nb_bits` long.
#[allow(clippy::too_many_arguments)]
fn huf_fill_dtable_x2_for_weight(
    dtable: &mut [HufDEltX2],
    mut at: usize,
    sorted_symbols: &[u8],
    begin: usize,
    end: usize,
    nb_bits: u32,
    table_log: u32,
    base_seq: u16,
    level: u32,
) {
    let length = 1usize << ((table_log.wrapping_sub(nb_bits)) & 0x1F);
    debug_assert!((1..=2).contains(&level));
    for &symbol in &sorted_symbols[begin..end] {
        let d_elt = huf_build_delt_x2(u32::from(symbol), nb_bits, u32::from(base_seq), level);
        dtable[at..at + length].fill(d_elt);
        at += length;
    }
}

/// `HUF_fillDTableX2Level2`
#[allow(clippy::too_many_arguments)]
fn huf_fill_dtable_x2_level2(
    dtable: &mut [HufDEltX2],
    at: usize,
    target_log: u32,
    consumed_bits: u32,
    rank_val: &[u32; HUF_TABLELOG_MAX as usize + 1],
    min_weight: i32,
    max_weight1: i32,
    sorted_symbols: &[u8],
    rank_start: &[u32],
    nb_bits_baseline: u32,
    base_seq: u16,
) {
    // Fill the skipped cells, up to rankVal[minWeight]: they only get one
    // symbol, as the combined length would be too long.
    if min_weight > 1 {
        let length = 1usize << (target_log.wrapping_sub(consumed_bits) & 0x1F);
        let d_elt = huf_build_delt_x2(u32::from(base_seq), consumed_bits, 0, 1);
        let skip_size = rank_val[min_weight as usize] as usize;
        debug_assert!(length > 1);
        debug_assert!(skip_size < length);
        // libzstd writes 2, 4, or groups of 8 cells; the same cells, as the
        // rest of these are written again below.
        let written = match length {
            2 => 2,
            4 => 4,
            _ => skip_size.div_ceil(8) * 8,
        };
        dtable[at..at + written].fill(d_elt);
    }

    // Fill each of the second-level symbols, by weight.
    for w in min_weight..max_weight1 {
        let begin = rank_start[w as usize] as usize;
        let end = rank_start[w as usize + 1] as usize;
        let nb_bits = nb_bits_baseline - w as u32;
        let total_bits = nb_bits + consumed_bits;
        huf_fill_dtable_x2_for_weight(
            dtable,
            at + rank_val[w as usize] as usize,
            sorted_symbols,
            begin,
            end,
            total_bits,
            target_log,
            base_seq,
            2,
        );
    }
}

/// `HUF_fillDTableX2`. `rank_start` is libzstd's `rankStart0`: the start of
/// weight `w`'s symbols is `rank_start[w]`.
fn huf_fill_dtable_x2(
    dtable: &mut [HufDEltX2],
    target_log: u32,
    sorted_list: &[u8],
    rank_start: &[u32],
    rank_val_origin: &[[u32; HUF_TABLELOG_MAX as usize + 1]; HUF_TABLELOG_MAX as usize],
    max_weight: u32,
    nb_bits_baseline: u32,
) {
    let rank_val = &rank_val_origin[0];
    // targetLog >= srcLog, so scaleLog <= 1.
    let scale_log = nb_bits_baseline as i32 - target_log as i32;
    let min_bits = nb_bits_baseline - max_weight;
    let w_end = max_weight as i32 + 1;

    // Fill the table in order of weight.
    for w in 1..w_end {
        let begin = rank_start[w as usize] as usize;
        let end = rank_start[w as usize + 1] as usize;
        let nb_bits = nb_bits_baseline - w as u32;

        if target_log - nb_bits >= min_bits {
            // Room for a second symbol.
            let mut start = rank_val[w as usize] as usize;
            let length = 1usize << ((target_log - nb_bits) & 0x1F);
            let mut min_weight = nb_bits as i32 + scale_log;
            if min_weight < 1 {
                min_weight = 1;
            }
            // Every symbol of weight w gets at least one second symbol.
            for &symbol in &sorted_list[begin..end] {
                huf_fill_dtable_x2_level2(
                    dtable,
                    start,
                    target_log,
                    nb_bits,
                    &rank_val_origin[nb_bits as usize],
                    min_weight,
                    w_end,
                    sorted_list,
                    rank_start,
                    nb_bits_baseline,
                    u16::from(symbol),
                );
                start += length;
            }
        } else {
            // Only one symbol.
            huf_fill_dtable_x2_for_weight(
                dtable,
                rank_val[w as usize] as usize,
                sorted_list,
                begin,
                end,
                nb_bits,
                target_log,
                0,
                1,
            );
        }
    }
}

/// `HUF_ReadDTableX2_Workspace`
pub(crate) struct HufReadDTableX2Workspace {
    rank_val: [[u32; HUF_TABLELOG_MAX as usize + 1]; HUF_TABLELOG_MAX as usize],
    rank_stats: [u32; HUF_TABLELOG_MAX as usize + 1],
    rank_start0: [u32; HUF_TABLELOG_MAX as usize + 3],
    sorted_symbol: [u8; HUF_SYMBOLVALUE_MAX as usize + 1],
    weight_list: [u8; HUF_SYMBOLVALUE_MAX as usize + 1],
    callee_wksp: FseDecompressWksp<64>,
}

impl Default for HufReadDTableX2Workspace {
    fn default() -> Self {
        HufReadDTableX2Workspace {
            rank_val: [[0; HUF_TABLELOG_MAX as usize + 1]; HUF_TABLELOG_MAX as usize],
            rank_stats: [0; HUF_TABLELOG_MAX as usize + 1],
            rank_start0: [0; HUF_TABLELOG_MAX as usize + 3],
            sorted_symbol: [0; HUF_SYMBOLVALUE_MAX as usize + 1],
            weight_list: [0; HUF_SYMBOLVALUE_MAX as usize + 1],
            callee_wksp: FseDecompressWksp::default(),
        }
    }
}

/// `HUF_readDTableX2_wksp`: reads a Huffman tree description from `src` and
/// builds a double-symbol table from it. Returns the size of the description.
pub(crate) fn huf_read_dtable_x2_wksp(
    dtable: &mut HufDTable,
    src: &[u8],
    wksp: &mut HufReadDTableX2Workspace,
) -> Result<usize> {
    let mut table_log = 0u32;
    let mut nb_symbols = 0u32;
    let mut dtd = dtable.desc;
    let mut max_table_log = u32::from(dtd.max_table_log);

    wksp.rank_stats.fill(0);
    wksp.rank_start0.fill(0);

    if max_table_log > HUF_TABLELOG_MAX {
        return error!(TableLogTooLarge);
    }

    let i_size = huf_read_stats_wksp(
        &mut wksp.weight_list,
        &mut wksp.rank_stats,
        &mut nb_symbols,
        &mut table_log,
        src,
        &mut wksp.callee_wksp,
    )?;

    // Check the result.
    if table_log > max_table_log {
        // The table cannot hold codes this long.
        return error!(TableLogTooLarge);
    }
    if table_log <= HUF_DECODER_FAST_TABLELOG && max_table_log > HUF_DECODER_FAST_TABLELOG {
        max_table_log = HUF_DECODER_FAST_TABLELOG;
    }

    // Find the largest weight; there is necessarily one before 0.
    let mut max_w = table_log;
    while wksp.rank_stats[max_w as usize] == 0 {
        max_w -= 1;
    }

    // rankStart is rankStart0 + 1, as in C.
    {
        let rank_start = &mut wksp.rank_start0[1..];

        // The start of each weight.
        let mut next_rank_start = 0u32;
        for w in 1..(max_w as usize + 1) {
            let curr = next_rank_start;
            next_rank_start += wksp.rank_stats[w];
            rank_start[w] = curr;
        }
        rank_start[0] = next_rank_start; // weight-0 symbols go at the end
        rank_start[max_w as usize + 1] = next_rank_start;

        // Sort the symbols by weight.
        for s in 0..nb_symbols as usize {
            let w = usize::from(wksp.weight_list[s]);
            let r = rank_start[w] as usize;
            rank_start[w] += 1;
            wksp.sorted_symbol[r] = s as u8;
        }
        rank_start[0] = 0; // forget weight-0 symbols: this is where weight 1 starts
    }

    // Build rankVal.
    {
        let rescale = (max_table_log - table_log) as i32 - 1; // tableLog <= maxTableLog
        let mut next_rank_val = 0u32;
        for w in 1..(max_w as usize + 1) {
            let curr = next_rank_val;
            next_rank_val += wksp.rank_stats[w] << (w as i32 + rescale);
            wksp.rank_val[0][w] = curr;
        }
        let min_bits = table_log + 1 - max_w;
        let mut consumed = min_bits;
        while consumed < max_table_log - min_bits + 1 {
            for w in 1..(max_w as usize + 1) {
                wksp.rank_val[consumed as usize][w] = wksp.rank_val[0][w] >> consumed;
            }
            consumed += 1;
        }
    }

    huf_fill_dtable_x2(
        &mut dtable.x2,
        max_table_log,
        &wksp.sorted_symbol,
        &wksp.rank_start0,
        &wksp.rank_val,
        max_w,
        table_log + 1,
    );

    dtd.table_log = max_table_log as u8;
    dtd.table_type = 1;
    dtable.desc = dtd;
    Ok(i_size)
}
