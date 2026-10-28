//! Port of `compress/zstd_compress.c`: the compression context, its
//! parameters, frames in one call and streaming, and the entropy coding of
//! a block from its sequences and literals.

use crate::common::bits::highbit32;
use crate::common::error_private::{ErrorCode, Result, error};
use crate::common::huf::{HUF_FLAGS_OPTIMAL_DEPTH, HUF_SYMBOLVALUE_MAX};
use crate::common::mem::{write_le16, write_le32, write_le64};
use crate::common::xxhash::Xxh64State;
use crate::common::zstd_internal::{
    BlockType, DEFAULT_MAX_OFF, LIT_HUF_LOG, LL_BITS, LL_DEFAULT_NORM, LL_DEFAULT_NORM_LOG,
    LL_FSE_LOG, LONGNBSEQ, MAX_LL, MAX_ML, MAX_OFF, MAX_SEQ, MIN_CBLOCK_SIZE, MINMATCH, ML_BITS,
    ML_DEFAULT_NORM, ML_DEFAULT_NORM_LOG, ML_FSE_LOG, OF_DEFAULT_NORM, OF_DEFAULT_NORM_LOG,
    OFF_FSE_LOG, REP_START_VALUE, SymbolEncodingType, ZSTD_BLOCKHEADERSIZE, ZSTD_BLOCKSIZE_MAX,
    ZSTD_MAGICNUMBER, ZSTD_REP_NUM, ZSTD_WINDOWLOG_ABSOLUTEMIN,
};
use crate::compress::clevels::{ZSTD_DEFAULT_CPARAMETERS, ZSTD_MAX_CLEVEL};
use crate::compress::hist::{HIST_WKSP_SIZE_U32, hist_count_fast_wksp, hist_count_wksp};
use crate::compress::huf_compress::{
    HUF_CTABLE_SIZE, HufRepeat, huf_build_ctable_wksp, huf_estimate_compressed_size,
    huf_optimal_table_log, huf_validate_ctable, huf_write_ctable_wksp,
};
use crate::compress::zstd_compress_internal::{
    Buffers, CompressedBlockState, CompressionParameters, EntropyCTables, FrameParameters,
    FseCTables, FseRepeat, HufCTables, LdmEntry, LdmParams, LdmState, LongLengthType, MatchState,
    ParamSwitch, RawSeqStore, SeqDef, SeqStore, SeqStoreChunk, SeqStoreView, Strategy, Window,
    WindowBuffer, ZSTD_HASHLOG_MIN, ZSTD_ROW_HASH_CACHE_SIZE, ZSTD_WINDOWLOG_MAX,
    offset_to_offbase, zstd_literals_compression_is_disabled, zstd_ll_code, zstd_min_gain,
    zstd_ml_code, zstd_no_compress_block, zstd_reduce_table, zstd_reduce_table_btlazy2,
};
use crate::compress::zstd_compress_literals::{
    HUF_OPTIMAL_DEPTH_THRESHOLD, zstd_compress_literals,
};
use crate::compress::zstd_compress_sequences::{
    DefaultPolicy, zstd_build_ctable, zstd_cross_entropy_cost, zstd_encode_sequences,
    zstd_fse_bit_cost, zstd_select_encoding_type,
};
use crate::compress::zstd_double_fast::{
    zstd_compress_block_double_fast, zstd_compress_block_double_fast_ext_dict,
};
use crate::compress::zstd_fast::{zstd_compress_block_fast, zstd_compress_block_fast_ext_dict};
use crate::compress::zstd_lazy::{
    ZSTD_ROW_HASH_TAG_BITS, zstd_compress_block_btlazy2, zstd_compress_block_lazy_hc,
    zstd_compress_block_lazy_row,
};
use crate::compress::zstd_ldm::{
    ZSTD_LDM_BUCKETSIZELOG_MAX, ZSTD_LDM_DEFAULT_WINDOW_LOG, zstd_ldm_adjust_parameters,
    zstd_ldm_block_compress, zstd_ldm_generate_sequences, zstd_ldm_get_max_nb_seq,
};
use crate::compress::zstd_pre_split::zstd_split_block;
use crate::decompress::zstd_decompress::{InBuffer, OutBuffer, ResetDirective};
use crate::decompress::zstd_decompress_internal::Format;

/// `ZSTD_seqToCodes`: the codes of the sequences' lengths and offsets, into
/// the store (or the chunk of it). Returns `longOffsets`, which is only
/// ever set on 32-bit machines.
pub(crate) fn zstd_seq_to_codes(seqs: &mut SeqStoreView<'_>) -> bool {
    let nb_seq = seqs.sequences.len();
    // Over slices, apart: written through the store, each code would make
    // the compiler read its buffer's place again.
    let codes = seqs
        .ll_code
        .iter_mut()
        .zip(seqs.of_code.iter_mut())
        .zip(seqs.ml_code.iter_mut());
    for (seq, ((ll_code, of_code), ml_code)) in seqs.sequences.iter().zip(codes) {
        *ll_code = zstd_ll_code(u32::from(seq.lit_length)) as u8;
        *of_code = highbit32(seq.off_base) as u8;
        *ml_code = zstd_ml_code(u32::from(seq.ml_base)) as u8;
    }
    // Differs from libzstd: a chunk that ends just before the sequence with
    // the long length keeps it, at its end (see
    // zstd_derive_seq_store_chunk). libzstd then writes the code past the
    // chunk, into the store's, the code the store has there anyway; the
    // port writes nothing. No code is read before the chunk it is in has
    // written it.
    let pos = seqs.long_length_pos as usize;
    match seqs.long_length_type {
        LongLengthType::LiteralLength if pos < nb_seq => seqs.ll_code[pos] = MAX_LL as u8,
        LongLengthType::MatchLength if pos < nb_seq => seqs.ml_code[pos] = MAX_ML as u8,
        _ => {}
    }
    false
}

/// `ZSTD_symbolEncodingTypeStats_t`: how each kind of code is encoded, and
/// the size of their table descriptions.
#[derive(Clone, Copy, Debug)]
struct SymbolEncodingTypeStats {
    ll_type: SymbolEncodingType,
    off_type: SymbolEncodingType,
    ml_type: SymbolEncodingType,
    size: usize,
    /// The size of the last new table's description: see
    /// [`zstd_entropy_compress_seq_store_internal`].
    last_count_size: usize,
}

/// The encoding and table of one kind of code, for
/// [`zstd_build_sequences_statistics`].
struct CodeKind<'a> {
    max: u32,
    codes: &'a [u8],
    fse_log: u32,
    default_norm: &'a [i16],
    default_norm_log: u32,
    default_max: u32,
}

/// `ZSTD_buildSequencesStatistics`: the codes of the sequences, then how
/// to encode each kind of code; writes the descriptions of the new tables
/// into `dst`, and the tables and their repeat modes into `next_entropy`.
/// `nb_seq` must not be 0.
#[allow(clippy::too_many_arguments)]
fn zstd_build_sequences_statistics(
    seqs: &mut SeqStoreView<'_>,
    nb_seq: usize,
    prev_entropy: &FseCTables,
    next_entropy: &mut FseCTables,
    dst: &mut [u8],
    strategy: Strategy,
    count: &mut [u32; MAX_SEQ as usize + 1],
    hist_wksp: &mut [u32; HIST_WKSP_SIZE_U32],
) -> Result<SymbolEncodingTypeStats> {
    let mut op = 0;
    let mut last_count_size = 0;
    // Lengths and offsets into codes.
    zstd_seq_to_codes(seqs);
    let seqs = &*seqs;
    debug_assert!(nb_seq != 0); // ZSTD_selectEncodingType() divides by nbSeq

    let mut types = [SymbolEncodingType::Basic; 3];
    let kinds = [
        // Literal lengths.
        CodeKind {
            max: MAX_LL,
            codes: seqs.ll_code,
            fse_log: LL_FSE_LOG,
            default_norm: &LL_DEFAULT_NORM,
            default_norm_log: LL_DEFAULT_NORM_LOG,
            default_max: MAX_LL,
        },
        // Offsets.
        CodeKind {
            max: MAX_OFF,
            codes: seqs.of_code,
            fse_log: OFF_FSE_LOG,
            default_norm: &OF_DEFAULT_NORM,
            default_norm_log: OF_DEFAULT_NORM_LOG,
            default_max: DEFAULT_MAX_OFF,
        },
        // Match lengths.
        CodeKind {
            max: MAX_ML,
            codes: seqs.ml_code,
            fse_log: ML_FSE_LOG,
            default_norm: &ML_DEFAULT_NORM,
            default_norm_log: ML_DEFAULT_NORM_LOG,
            default_max: MAX_ML,
        },
    ];
    for (which, kind) in kinds.iter().enumerate() {
        let mut max = kind.max;
        // Cannot fail.
        let most_frequent =
            hist_count_fast_wksp(count, &mut max, &kind.codes[..nb_seq], hist_wksp)?;
        // The default offsets table only has codes up to DefaultMaxOff.
        let default_policy = if which != 1 || max <= DEFAULT_MAX_OFF {
            DefaultPolicy::Allowed
        } else {
            DefaultPolicy::Disallowed
        };
        let (prev_ctable, next_ctable, prev_mode, next_mode): (&[u32], &mut [u32], _, _) =
            match which {
                0 => (
                    &prev_entropy.litlength_ctable,
                    &mut next_entropy.litlength_ctable,
                    prev_entropy.litlength_repeat_mode,
                    &mut next_entropy.litlength_repeat_mode,
                ),
                1 => (
                    &prev_entropy.offcode_ctable,
                    &mut next_entropy.offcode_ctable,
                    prev_entropy.offcode_repeat_mode,
                    &mut next_entropy.offcode_repeat_mode,
                ),
                _ => (
                    &prev_entropy.matchlength_ctable,
                    &mut next_entropy.matchlength_ctable,
                    prev_entropy.matchlength_repeat_mode,
                    &mut next_entropy.matchlength_repeat_mode,
                ),
            };
        *next_mode = prev_mode;
        let encoding_type = zstd_select_encoding_type(
            next_mode,
            count,
            max,
            most_frequent,
            nb_seq,
            kind.fse_log,
            prev_ctable,
            kind.default_norm,
            kind.default_norm_log,
            default_policy,
            strategy,
        );
        let count_size = zstd_build_ctable(
            &mut dst[op..],
            next_ctable,
            kind.fse_log,
            encoding_type,
            count,
            max,
            kind.codes,
            nb_seq,
            kind.default_norm,
            kind.default_norm_log,
            kind.default_max,
            prev_ctable,
        )?;
        if encoding_type == SymbolEncodingType::Compressed {
            last_count_size = count_size;
        }
        op += count_size;
        types[which] = encoding_type;
    }
    Ok(SymbolEncodingTypeStats {
        ll_type: types[0],
        off_type: types[1],
        ml_type: types[2],
        size: op,
        last_count_size,
    })
}

/// `SUSPECT_UNCOMPRESSIBLE_LITERAL_RATIO`: with this many literals per
/// sequence or more, the literals are suspected not to compress.
const SUSPECT_UNCOMPRESSIBLE_LITERAL_RATIO: usize = 20;

/// `ZSTD_entropyCompressSeqStore_internal`: the block's literals and
/// sequences (or a chunk's), entropy-coded, into `dst`. Returns the size,
/// or 0 for a block to store raw instead.
#[allow(clippy::too_many_arguments)]
fn zstd_entropy_compress_seq_store_internal(
    dst: &mut [u8],
    seqs: &mut SeqStoreView<'_>,
    prev_entropy: &EntropyCTables,
    next_entropy: &mut EntropyCTables,
    strategy: Strategy,
    disable_literal_compression: bool,
    bmi2: bool,
) -> Result<usize> {
    let mut count = [0u32; MAX_SEQ as usize + 1];
    let mut hist_wksp = [0u32; HIST_WKSP_SIZE_U32];
    let nb_seq = seqs.sequences.len();
    let literals = seqs.literals;
    let oend = dst.len();
    let mut op = 0;

    // The literals.
    {
        // Suspect the literals not to compress from their ratio to the
        // sequences.
        let suspect_uncompressible =
            nb_seq == 0 || literals.len() / nb_seq >= SUSPECT_UNCOMPRESSIBLE_LITERAL_RATIO;
        let c_size = zstd_compress_literals(
            &mut dst[op..],
            literals,
            &prev_entropy.huf,
            &mut next_entropy.huf,
            strategy,
            disable_literal_compression,
            suspect_uncompressible,
            bmi2,
        )?;
        op += c_size;
    }

    // The sequences' header.
    if oend - op < 3 /* the largest nbSeq */ + 1
    /* seqHead */
    {
        return error!(DstSizeTooSmall);
    }
    if nb_seq < 128 {
        dst[op] = nb_seq as u8;
        op += 1;
    } else if nb_seq < LONGNBSEQ {
        dst[op] = ((nb_seq >> 8) + 0x80) as u8;
        dst[op + 1] = nb_seq as u8;
        op += 2;
    } else {
        dst[op] = 0xFF;
        write_le16(dst, op + 1, (nb_seq - LONGNBSEQ) as u16);
        op += 3;
    }
    if nb_seq == 0 {
        // Copy the old tables over, as if they were used again.
        next_entropy.fse.clone_from(&prev_entropy.fse);
        return Ok(op);
    }
    let last_count_size;
    {
        let seq_head = op;
        op += 1;
        // The statistics of the sequences.
        let stats = zstd_build_sequences_statistics(
            seqs,
            nb_seq,
            &prev_entropy.fse,
            &mut next_entropy.fse,
            &mut dst[op..],
            strategy,
            &mut count,
            &mut hist_wksp,
        )?;
        dst[seq_head] = (((stats.ll_type as u32) << 6)
            + ((stats.off_type as u32) << 4)
            + ((stats.ml_type as u32) << 2)) as u8;
        last_count_size = stats.last_count_size;
        op += stats.size;
    }

    {
        let fse = &next_entropy.fse;
        let bitstream_size = zstd_encode_sequences(
            &mut dst[op..],
            &fse.matchlength_ctable,
            seqs.ml_code,
            &fse.offcode_ctable,
            seqs.of_code,
            &fse.litlength_ctable,
            seqs.ll_code,
            seqs.sequences,
        )?;
        op += bitstream_size;
        // zstd 1.3.4 and earlier report corruption when FSE_readNCount()
        // gets fewer than 4 bytes (fixed in zstd pull request 1146). That
        // happens when the last new table's description is 2 bytes and the
        // bitstream 1 byte. In this very rare case the block is stored raw.
        if last_count_size != 0 && last_count_size + bitstream_size < 4 {
            debug_assert!(last_count_size + bitstream_size == 3);
            return Ok(0);
        }
    }

    Ok(op)
}

/// `ZSTD_entropyCompressSeqStore`, for the whole store: see
/// [`zstd_entropy_compress_seq_chunk`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn zstd_entropy_compress_seq_store(
    seq_store: &mut SeqStore,
    prev_entropy: &EntropyCTables,
    next_entropy: &mut EntropyCTables,
    strategy: Strategy,
    disable_literal_compression: bool,
    dst: &mut [u8],
    block_size: usize,
    bmi2: bool,
) -> Result<usize> {
    let whole = seq_store.whole();
    zstd_entropy_compress_seq_chunk(
        &mut seq_store.view(&whole),
        prev_entropy,
        next_entropy,
        strategy,
        disable_literal_compression,
        dst,
        block_size,
        bmi2,
    )
}

/// `ZSTD_entropyCompressSeqStore_wExtLitBuffer`, with the store's literals
/// (or the chunk's): the block entropy-coded, or 0 when it is better
/// stored raw: when it does not save `ZSTD_minGain` over the `block_size`
/// bytes it holds, or does not fit `dst` where a raw block would.
#[allow(clippy::too_many_arguments)]
fn zstd_entropy_compress_seq_chunk(
    seqs: &mut SeqStoreView<'_>,
    prev_entropy: &EntropyCTables,
    next_entropy: &mut EntropyCTables,
    strategy: Strategy,
    disable_literal_compression: bool,
    dst: &mut [u8],
    block_size: usize,
    bmi2: bool,
) -> Result<usize> {
    let dst_capacity = dst.len();
    let c_size = zstd_entropy_compress_seq_store_internal(
        dst,
        seqs,
        prev_entropy,
        next_entropy,
        strategy,
        disable_literal_compression,
        bmi2,
    );
    let c_size = match c_size {
        Ok(0) => return Ok(0),
        // Out of room where there is room for a raw block: the block does
        // not compress, so store it raw.
        Err(error) if error.code() == ErrorCode::DstSizeTooSmall && block_size <= dst_capacity => {
            return Ok(0);
        }
        result => result?,
    };

    // Check that it compresses. libzstd's subtraction wraps around for
    // blocks of a byte or none, which then always pass.
    let max_c_size = block_size.wrapping_sub(zstd_min_gain(block_size, strategy));
    if c_size >= max_c_size {
        return Ok(0);
    }
    Ok(c_size)
}

// ---------------------------------------------------------------------------
// Splitting blocks after their sequences

/// `ZSTD_MAX_HUF_HEADER_SIZE`: the room for a Huffman table's description.
const ZSTD_MAX_HUF_HEADER_SIZE: usize = 128;
/// `ZSTD_MAX_FSE_HEADERS_SIZE`: the room for the descriptions of the three
/// FSE tables.
const ZSTD_MAX_FSE_HEADERS_SIZE: usize =
    ((MAX_ML + 1) * ML_FSE_LOG + (MAX_LL + 1) * LL_FSE_LOG + (MAX_OFF + 1) * OFF_FSE_LOG)
        .div_ceil(8) as usize;
const _: () = assert!(ZSTD_MAX_FSE_HEADERS_SIZE == 133);
/// `COMPRESS_LITERALS_SIZE_MIN`: up to this many literals are not worth
/// compressing (a heuristic).
const COMPRESS_LITERALS_SIZE_MIN: usize = 63;
/// `MIN_SEQUENCES_BLOCK_SPLITTING`: fewer sequences are not split.
const MIN_SEQUENCES_BLOCK_SPLITTING: usize = 300;
/// `ZSTD_MAX_NB_BLOCK_SPLITS`: no more splits are looked for after this
/// many.
const ZSTD_MAX_NB_BLOCK_SPLITS: usize = 196;

/// `ZSTD_hufCTablesMetadata_t`: how the literals would be encoded, and the
/// size of a new table's description.
///
/// Differs from libzstd: without the description itself, which libzstd
/// keeps for its superblocks (`ZSTD_c_targetCBlockSize`). The port writes
/// it into a buffer as large, so that it fails where libzstd's does, and
/// keeps only its size. The estimates read nothing else.
#[derive(Clone, Copy, Debug)]
struct HufCTablesMetadata {
    h_type: SymbolEncodingType,
    huf_des_size: usize,
}

/// `ZSTD_fseCTablesMetadata_t`: how each kind of code would be encoded,
/// and the size of the new tables' descriptions.
///
/// Differs from libzstd: without the descriptions themselves, nor the
/// size of the last one, which only its superblocks read. The port writes
/// them into a buffer as large, as libzstd does.
#[derive(Clone, Copy, Debug)]
struct FseCTablesMetadata {
    ll_type: SymbolEncodingType,
    of_type: SymbolEncodingType,
    ml_type: SymbolEncodingType,
    fse_tables_size: usize,
}

/// `ZSTD_entropyCTablesMetadata_t`
#[derive(Clone, Copy, Debug)]
struct EntropyCTablesMetadata {
    huf: HufCTablesMetadata,
    fse: FseCTablesMetadata,
}

/// libzstd's `size_t` for `result`: the size, or the error's code, as
/// `(size_t)-code`.
fn size_or_code(result: &Result<usize>) -> usize {
    match result {
        Ok(size) => *size,
        Err(error) => (error.code().number() as usize).wrapping_neg(),
    }
}

/// `ZSTD_buildBlockEntropyStats_literals`: how the literals `src` would be
/// encoded, as `ZSTD_compressLiterals` would choose, roughly; the table
/// into `next_huf`, or the previous one.
fn zstd_build_block_entropy_stats_literals(
    src: &[u8],
    prev_huf: &HufCTables,
    next_huf: &mut HufCTables,
    literals_compression_is_disabled: bool,
    huf_flags: i32,
) -> Result<HufCTablesMetadata> {
    let src_size = src.len();
    let mut count = [0u32; HUF_SYMBOLVALUE_MAX as usize + 1];
    let mut hist_wksp = [0u32; HIST_WKSP_SIZE_U32];
    let mut max_symbol_value = HUF_SYMBOLVALUE_MAX;
    let mut huff_log = LIT_HUF_LOG;
    let mut repeat = prev_huf.repeat_mode;
    let metadata = |h_type, huf_des_size| HufCTablesMetadata {
        h_type,
        huf_des_size,
    };

    // Prepare the next tables as if the previous ones were used again.
    next_huf.clone_from(prev_huf);

    if literals_compression_is_disabled {
        return Ok(metadata(SymbolEncodingType::Basic, 0));
    }

    // Too few to try compressing (a speed optimization).
    let min_lit_size = if prev_huf.repeat_mode == HufRepeat::Valid {
        6
    } else {
        COMPRESS_LITERALS_SIZE_MIN
    };
    if src_size <= min_lit_size {
        return Ok(metadata(SymbolEncodingType::Basic, 0));
    }

    // The symbol statistics.
    {
        let largest = hist_count_wksp(&mut count, &mut max_symbol_value, src, &mut hist_wksp)?;
        if largest == src_size {
            // A single symbol.
            return Ok(metadata(SymbolEncodingType::Rle, 0));
        }
        if largest <= (src_size >> 7) + 4 {
            // A heuristic: probably not compressible.
            return Ok(metadata(SymbolEncodingType::Basic, 0));
        }
    }

    // Check the previous table.
    if repeat == HufRepeat::Check
        && !huf_validate_ctable(&prev_huf.ctable, &count, max_symbol_value)
    {
        repeat = HufRepeat::None;
    }

    // The Huffman tree.
    next_huf.ctable = [0; HUF_CTABLE_SIZE];
    huff_log = huf_optimal_table_log(
        huff_log,
        src_size,
        max_symbol_value,
        &mut next_huf.ctable,
        &count,
        huf_flags,
    );
    debug_assert!(huff_log <= LIT_HUF_LOG);
    huff_log = huf_build_ctable_wksp(&mut next_huf.ctable, &count, max_symbol_value, huff_log)?;

    // The table's description; or the previous table, or none, if better.
    let new_c_size = huf_estimate_compressed_size(&next_huf.ctable, &count, max_symbol_value);
    let mut huf_des_buffer = [0u8; ZSTD_MAX_HUF_HEADER_SIZE];
    let h_size = huf_write_ctable_wksp(
        &mut huf_des_buffer,
        &next_huf.ctable,
        max_symbol_value,
        huff_log,
    );
    // libzstd does not check the description's size for an error: the
    // error's code takes part in the sums, and fails the estimate if the
    // new table is kept.
    let h_size_or_code = size_or_code(&h_size);
    if repeat != HufRepeat::None {
        let old_c_size = huf_estimate_compressed_size(&prev_huf.ctable, &count, max_symbol_value);
        if old_c_size < src_size
            && (old_c_size <= h_size_or_code.wrapping_add(new_c_size)
                || h_size_or_code.wrapping_add(12) >= src_size)
        {
            next_huf.clone_from(prev_huf);
            return Ok(metadata(SymbolEncodingType::Repeat, 0));
        }
    }
    if new_c_size.wrapping_add(h_size_or_code) >= src_size {
        // No gain.
        next_huf.clone_from(prev_huf);
        return Ok(metadata(SymbolEncodingType::Basic, 0));
    }
    next_huf.repeat_mode = HufRepeat::Check;
    Ok(metadata(SymbolEncodingType::Compressed, h_size?))
}

/// `ZSTD_buildDummySequencesStatistics`: the encodings of no sequences;
/// no table may be used again after them.
fn zstd_build_dummy_sequences_statistics(next_entropy: &mut FseCTables) -> SymbolEncodingTypeStats {
    next_entropy.litlength_repeat_mode = FseRepeat::None;
    next_entropy.offcode_repeat_mode = FseRepeat::None;
    next_entropy.matchlength_repeat_mode = FseRepeat::None;
    SymbolEncodingTypeStats {
        ll_type: SymbolEncodingType::Basic,
        off_type: SymbolEncodingType::Basic,
        ml_type: SymbolEncodingType::Basic,
        size: 0,
        last_count_size: 0,
    }
}

/// `ZSTD_buildBlockEntropyStats_sequences`: how each kind of code of the
/// sequences would be encoded, with their tables into `next_entropy`, as
/// a block would encode them.
fn zstd_build_block_entropy_stats_sequences(
    seqs: &mut SeqStoreView<'_>,
    prev_entropy: &FseCTables,
    next_entropy: &mut FseCTables,
    strategy: Strategy,
) -> Result<FseCTablesMetadata> {
    let nb_seq = seqs.sequences.len();
    let mut fse_tables_buffer = [0u8; ZSTD_MAX_FSE_HEADERS_SIZE];
    let mut count = [0u32; MAX_SEQ as usize + 1];
    let mut hist_wksp = [0u32; HIST_WKSP_SIZE_U32];
    let stats = if nb_seq != 0 {
        zstd_build_sequences_statistics(
            seqs,
            nb_seq,
            prev_entropy,
            next_entropy,
            &mut fse_tables_buffer,
            strategy,
            &mut count,
            &mut hist_wksp,
        )?
    } else {
        zstd_build_dummy_sequences_statistics(next_entropy)
    };
    Ok(FseCTablesMetadata {
        ll_type: stats.ll_type,
        of_type: stats.off_type,
        ml_type: stats.ml_type,
        fse_tables_size: stats.size,
    })
}

/// `ZSTD_buildBlockEntropyStats`: how the literals and the sequences of
/// `seqs` would be encoded, and the tables, into `next_entropy`.
fn zstd_build_block_entropy_stats(
    seqs: &mut SeqStoreView<'_>,
    prev_entropy: &EntropyCTables,
    next_entropy: &mut EntropyCTables,
    params: &CCtxParams,
) -> Result<EntropyCTablesMetadata> {
    let strategy = params.c_params.strategy;
    let huf_flags = if strategy >= HUF_OPTIMAL_DEPTH_THRESHOLD {
        HUF_FLAGS_OPTIMAL_DEPTH
    } else {
        0
    };
    let huf = zstd_build_block_entropy_stats_literals(
        seqs.literals,
        &prev_entropy.huf,
        &mut next_entropy.huf,
        zstd_literals_compression_is_disabled(
            params.literal_compression_mode,
            strategy,
            params.c_params.target_length,
        ),
        huf_flags,
    )?;
    let fse = zstd_build_block_entropy_stats_sequences(
        seqs,
        &prev_entropy.fse,
        &mut next_entropy.fse,
        strategy,
    )?;
    Ok(EntropyCTablesMetadata { huf, fse })
}

/// `ZSTD_estimateBlockSize_literal`: the size of the literals section,
/// its header included, with the table's description if `write_entropy`.
fn zstd_estimate_block_size_literal(
    literals: &[u8],
    huf: &HufCTables,
    huf_metadata: &HufCTablesMetadata,
    write_entropy: bool,
) -> usize {
    let lit_size = literals.len();
    let literal_section_header_size =
        3 + usize::from(lit_size >= 1024) + usize::from(lit_size >= 16 * 1024);
    let single_stream = lit_size < 256;
    match huf_metadata.h_type {
        SymbolEncodingType::Basic => lit_size,
        SymbolEncodingType::Rle => 1,
        SymbolEncodingType::Compressed | SymbolEncodingType::Repeat => {
            let mut count = [0u32; HUF_SYMBOLVALUE_MAX as usize + 1];
            let mut hist_wksp = [0u32; HIST_WKSP_SIZE_U32];
            let mut max_symbol_value = HUF_SYMBOLVALUE_MAX;
            if hist_count_wksp(&mut count, &mut max_symbol_value, literals, &mut hist_wksp).is_err()
            {
                return lit_size;
            }
            let mut c_lit_size_estimate =
                huf_estimate_compressed_size(&huf.ctable, &count, max_symbol_value);
            if write_entropy {
                c_lit_size_estimate += huf_metadata.huf_des_size;
            }
            if !single_stream {
                // The jump table of four streams.
                c_lit_size_estimate += 6;
            }
            c_lit_size_estimate + literal_section_header_size
        }
    }
}

/// `ZSTD_estimateBlockSize_symbolType`: the bytes of one kind of code,
/// `code_table`, with its encoding and table, and the codes' extra bits
/// (for offsets, the code itself).
#[allow(clippy::too_many_arguments)]
fn zstd_estimate_block_size_symbol_type(
    encoding_type: SymbolEncodingType,
    code_table: &[u8],
    max_code: u32,
    fse_ctable: &[u32],
    additional_bits: Option<&[u8]>,
    default_norm: &[i16],
    default_norm_log: u32,
    default_max: u32,
) -> usize {
    let nb_seq = code_table.len();
    let mut count = [0u32; MAX_SEQ as usize + 1];
    let mut hist_wksp = [0u32; HIST_WKSP_SIZE_U32];
    let mut max = max_code;

    // Cannot fail: the codes are trusted to be at most `max`.
    let _ = hist_count_fast_wksp(&mut count, &mut max, code_table, &mut hist_wksp);
    let size_in_bits = match encoding_type {
        SymbolEncodingType::Basic => {
            // Chosen, so valid.
            debug_assert!(max <= default_max);
            Ok(zstd_cross_entropy_cost(
                default_norm,
                default_norm_log,
                &count,
                max,
            ))
        }
        SymbolEncodingType::Rle => Ok(0),
        SymbolEncodingType::Compressed | SymbolEncodingType::Repeat => {
            zstd_fse_bit_cost(fse_ctable, &count, max)
        }
    };
    let Ok(mut size_in_bits) = size_in_bits else {
        return nb_seq * 10;
    };
    for &code in code_table {
        size_in_bits += match additional_bits {
            Some(bits) => usize::from(bits[usize::from(code)]),
            None => usize::from(code),
        };
    }
    size_in_bits >> 3
}

/// `ZSTD_estimateBlockSize_sequences`: the size of the sequences section,
/// its header included, with the tables' descriptions if `write_entropy`.
fn zstd_estimate_block_size_sequences(
    of_code: &[u8],
    ll_code: &[u8],
    ml_code: &[u8],
    fse_tables: &FseCTables,
    fse_metadata: &FseCTablesMetadata,
    write_entropy: bool,
) -> usize {
    let nb_seq = of_code.len();
    // seqHead, and nbSeq in 1 to 3 bytes.
    let sequences_section_header_size =
        1 + 1 + usize::from(nb_seq >= 128) + usize::from(nb_seq >= LONGNBSEQ);
    let mut c_seq_size_estimate = 0;
    c_seq_size_estimate += zstd_estimate_block_size_symbol_type(
        fse_metadata.of_type,
        of_code,
        MAX_OFF,
        &fse_tables.offcode_ctable,
        None,
        &OF_DEFAULT_NORM,
        OF_DEFAULT_NORM_LOG,
        DEFAULT_MAX_OFF,
    );
    c_seq_size_estimate += zstd_estimate_block_size_symbol_type(
        fse_metadata.ll_type,
        ll_code,
        MAX_LL,
        &fse_tables.litlength_ctable,
        Some(&LL_BITS),
        &LL_DEFAULT_NORM,
        LL_DEFAULT_NORM_LOG,
        MAX_LL,
    );
    c_seq_size_estimate += zstd_estimate_block_size_symbol_type(
        fse_metadata.ml_type,
        ml_code,
        MAX_ML,
        &fse_tables.matchlength_ctable,
        Some(&ML_BITS),
        &ML_DEFAULT_NORM,
        ML_DEFAULT_NORM_LOG,
        MAX_ML,
    );
    if write_entropy {
        c_seq_size_estimate += fse_metadata.fse_tables_size;
    }
    c_seq_size_estimate + sequences_section_header_size
}

/// `ZSTD_estimateBlockSize`: the size of a block of `literals` and of
/// sequences with these codes, encoded with `entropy` as `metadata` says,
/// its header included.
#[allow(clippy::too_many_arguments)]
fn zstd_estimate_block_size(
    literals: &[u8],
    of_code: &[u8],
    ll_code: &[u8],
    ml_code: &[u8],
    entropy: &EntropyCTables,
    metadata: &EntropyCTablesMetadata,
    write_lit_entropy: bool,
    write_seq_entropy: bool,
) -> usize {
    let literals_size =
        zstd_estimate_block_size_literal(literals, &entropy.huf, &metadata.huf, write_lit_entropy);
    let seq_size = zstd_estimate_block_size_sequences(
        of_code,
        ll_code,
        ml_code,
        &entropy.fse,
        &metadata.fse,
        write_seq_entropy,
    );
    seq_size + literals_size + ZSTD_BLOCKHEADERSIZE
}

/// `ZSTD_countSeqStoreLiteralsBytes`: the literals of the sequences of
/// `chunk`.
fn zstd_count_seq_store_literals_bytes(seq_store: &SeqStore, chunk: &SeqStoreChunk) -> usize {
    let mut literals_bytes = 0;
    let sequences = &seq_store.sequences[chunk.seq_start..chunk.seq_end];
    for (i, seq) in sequences.iter().enumerate() {
        literals_bytes += usize::from(seq.lit_length);
        if i == chunk.long_length_pos as usize
            && chunk.long_length_type == LongLengthType::LiteralLength
        {
            literals_bytes += 0x10000;
        }
    }
    literals_bytes
}

/// `ZSTD_countSeqStoreMatchBytes`: the bytes the matches of `chunk` copy.
fn zstd_count_seq_store_match_bytes(seq_store: &SeqStore, chunk: &SeqStoreChunk) -> usize {
    let mut match_bytes = 0;
    let sequences = &seq_store.sequences[chunk.seq_start..chunk.seq_end];
    for (i, seq) in sequences.iter().enumerate() {
        match_bytes += usize::from(seq.ml_base) + MINMATCH as usize;
        if i == chunk.long_length_pos as usize
            && chunk.long_length_type == LongLengthType::MatchLength
        {
            match_bytes += 0x10000;
        }
    }
    match_bytes
}

/// `ZSTD_deriveSeqStoreChunk`: the chunk of the store's sequences
/// `start_idx..end_idx`, with their literals; the chunk that reaches the
/// end has the block's last literals too.
fn zstd_derive_seq_store_chunk(
    seq_store: &SeqStore,
    start_idx: usize,
    end_idx: usize,
) -> SeqStoreChunk {
    let original = seq_store.whole();
    let mut result = original;
    if start_idx > 0 {
        // After the literals of the sequences before.
        result.seq_end = start_idx;
        result.lit_start += zstd_count_seq_store_literals_bytes(seq_store, &result);
    }

    // The sequence with the long length, from the chunk's start. A chunk
    // that ends just before it keeps it too, at its end, as libzstd checks
    // for `> endIdx`: there it counts for nothing.
    if original.long_length_type != LongLengthType::None {
        let pos = original.long_length_pos as usize;
        if pos < start_idx || pos > end_idx {
            result.long_length_type = LongLengthType::None;
        } else {
            result.long_length_pos -= start_idx as u32;
        }
    }
    result.seq_start = start_idx;
    result.seq_end = end_idx;
    if end_idx == original.seq_end {
        // The last literals, if the chunk reaches the end of the block.
        debug_assert!(result.lit_end == original.lit_end);
    } else {
        let literals_bytes = zstd_count_seq_store_literals_bytes(seq_store, &result);
        result.lit_end = result.lit_start + literals_bytes;
    }
    result
}

/// `OFFBASE_IS_REPCODE`
fn offbase_is_repcode(off_base: u32) -> bool {
    (1..=ZSTD_REP_NUM as u32).contains(&off_base)
}

/// `ZSTD_updateRep`: the repeat offsets `rep` after a sequence of
/// `off_base`, its literal length 0 if `ll0` is 1.
fn zstd_update_rep(rep: &mut [u32; ZSTD_REP_NUM], off_base: u32, ll0: u32) {
    if off_base > ZSTD_REP_NUM as u32 {
        // An offset.
        rep[2] = rep[1];
        rep[1] = rep[0];
        rep[0] = off_base - ZSTD_REP_NUM as u32;
    } else {
        // A repeat code; the first one, with literals, changes nothing.
        let rep_code = off_base - 1 + ll0;
        if rep_code > 0 {
            let current_offset = if rep_code == ZSTD_REP_NUM as u32 {
                rep[0].wrapping_sub(1)
            } else {
                rep[rep_code as usize]
            };
            rep[2] = if rep_code >= 2 { rep[1] } else { rep[2] };
            rep[1] = rep[0];
            rep[0] = current_offset;
        }
    }
}

/// `ZSTD_resolveRepcodeToRawOffset`: the offset the repeat code `off_base`
/// stands for with the repeat offsets `rep`, its literal length 0 if
/// `ll0` is 1. That can be 0, not an offset, when `rep[0]` is 1:
/// `zstd_seq_store_resolve_off_codes` then finds it differs.
fn zstd_resolve_repcode_to_raw_offset(rep: &[u32; ZSTD_REP_NUM], off_base: u32, ll0: u32) -> u32 {
    // 0 to 3.
    let adjusted_rep_code = off_base - 1 + ll0;
    debug_assert!(offbase_is_repcode(off_base));
    if adjusted_rep_code == ZSTD_REP_NUM as u32 {
        debug_assert!(ll0 != 0);
        // A literal length of 0 and the third repeat code: the first
        // repeat offset, minus 1.
        return rep[0].wrapping_sub(1);
    }
    rep[adjusted_rep_code as usize]
}

/// `ZSTD_seqStore_resolveOffCodes`: the repeat codes of `sequences`, a
/// partition of a block, checked against the repeat offsets the decoder
/// will have, `d_rep`: those of the encoder, `c_rep`, followed the
/// sequences of every partition before; the decoder's skip those of the
/// partitions stored raw or RLE. A repeat code that stands for another
/// offset in the decoder becomes the offset it stands for in the encoder.
///
/// `c_rep` follows the sequences as found, `d_rep` the sequences as
/// written.
fn zstd_seq_store_resolve_off_codes(
    d_rep: &mut [u32; ZSTD_REP_NUM],
    c_rep: &mut [u32; ZSTD_REP_NUM],
    sequences: &mut [SeqDef],
    long_length_type: LongLengthType,
    long_length_pos: u32,
) {
    let nb_seq = sequences.len();
    let long_lit_len_idx = if long_length_type == LongLengthType::LiteralLength {
        long_length_pos as usize
    } else {
        nb_seq
    };
    for (idx, seq) in sequences.iter_mut().enumerate() {
        let ll0 = u32::from(seq.lit_length == 0 && idx != long_lit_len_idx);
        let off_base = seq.off_base;
        debug_assert!(off_base > 0);
        if offbase_is_repcode(off_base) {
            let d_raw_offset = zstd_resolve_repcode_to_raw_offset(d_rep, off_base, ll0);
            let c_raw_offset = zstd_resolve_repcode_to_raw_offset(c_rep, off_base, ll0);
            if d_raw_offset != c_raw_offset {
                seq.off_base = offset_to_offbase(c_raw_offset);
            }
        }
        zstd_update_rep(d_rep, seq.off_base, ll0);
        zstd_update_rep(c_rep, off_base, ll0);
    }
}

/// `ZSTD_rleCompressBlock`: a block of `src_size` bytes `byte`, with its
/// header.
fn zstd_rle_compress_block(
    dst: &mut [u8],
    byte: u8,
    src_size: usize,
    last_block: bool,
) -> Result<usize> {
    let c_block_header =
        u32::from(last_block) + ((BlockType::Rle as u32) << 1) + ((src_size as u32) << 3);
    if dst.len() < 4 {
        return error!(DstSizeTooSmall);
    }
    dst[..3].copy_from_slice(&c_block_header.to_le_bytes()[..3]);
    dst[3] = byte;
    Ok(4)
}

/// `writeBlockHeader`: the header of a compressed block of `c_size` bytes;
/// for a `c_size` of 1, of an RLE block of `block_size` bytes.
fn write_block_header(dst: &mut [u8], c_size: usize, block_size: usize, last_block: bool) {
    let c_block_header = if c_size == 1 {
        u32::from(last_block) + ((BlockType::Rle as u32) << 1) + ((block_size as u32) << 3)
    } else {
        u32::from(last_block) + ((BlockType::Compressed as u32) << 1) + ((c_size as u32) << 3)
    };
    dst[..3].copy_from_slice(&c_block_header.to_le_bytes()[..3]);
}

/// `ZSTD_blockSplitterEnabled`: whether a frame with `params` splits its
/// blocks after finding their sequences.
fn zstd_block_splitter_enabled(params: &CCtxParams) -> bool {
    debug_assert!(params.post_block_splitter != ParamSwitch::Auto);
    params.post_block_splitter == ParamSwitch::Enable
}

// ---------------------------------------------------------------------------
// Parameters

/// `ZSTD_CLEVEL_DEFAULT`: the level 0 stands for.
pub(crate) const ZSTD_CLEVEL_DEFAULT: i32 = 3;
/// `ZSTD_WINDOWLOG_MIN`
const ZSTD_WINDOWLOG_MIN: u32 = 10;
/// `ZSTD_HASHLOG_MAX` on 64-bit machines.
const ZSTD_HASHLOG_MAX: u32 = 30;
/// `ZSTD_CHAINLOG_MIN`
const ZSTD_CHAINLOG_MIN: u32 = ZSTD_HASHLOG_MIN;
/// `ZSTD_CHAINLOG_MAX` on 64-bit machines.
const ZSTD_CHAINLOG_MAX: u32 = 30;
/// `ZSTD_SEARCHLOG_MIN`
const ZSTD_SEARCHLOG_MIN: u32 = 1;
/// `ZSTD_SEARCHLOG_MAX`
const ZSTD_SEARCHLOG_MAX: u32 = ZSTD_WINDOWLOG_MAX - 1;
/// `ZSTD_MINMATCH_MIN`
const ZSTD_MINMATCH_MIN: u32 = 3;
/// `ZSTD_MINMATCH_MAX`
const ZSTD_MINMATCH_MAX: u32 = 7;
/// `ZSTD_TARGETLENGTH_MIN`
const ZSTD_TARGETLENGTH_MIN: u32 = 0;
/// `ZSTD_TARGETLENGTH_MAX`
const ZSTD_TARGETLENGTH_MAX: u32 = ZSTD_BLOCKSIZE_MAX as u32;
/// `ZSTD_SRCSIZEHINT_MIN`
const ZSTD_SRCSIZEHINT_MIN: u32 = 0;
/// `ZSTD_SRCSIZEHINT_MAX`
const ZSTD_SRCSIZEHINT_MAX: u32 = i32::MAX as u32;
/// `ZSTD_BLOCKSPLITTER_LEVEL_MAX`
const ZSTD_BLOCKSPLITTER_LEVEL_MAX: u32 = 6;
/// `ZSTD_BLOCKSIZE_MAX_MIN`: the smallest largest block.
const ZSTD_BLOCKSIZE_MAX_MIN: u32 = 1 << 10;
/// `ZSTD_LDM_HASHLOG_MIN`
const ZSTD_LDM_HASHLOG_MIN: u32 = ZSTD_HASHLOG_MIN;
/// `ZSTD_LDM_HASHLOG_MAX`
const ZSTD_LDM_HASHLOG_MAX: u32 = ZSTD_HASHLOG_MAX;
/// `ZSTD_LDM_MINMATCH_MIN`
const ZSTD_LDM_MINMATCH_MIN: u32 = 4;
/// `ZSTD_LDM_MINMATCH_MAX`
const ZSTD_LDM_MINMATCH_MAX: u32 = 4096;
/// `ZSTD_LDM_BUCKETSIZELOG_MIN`
const ZSTD_LDM_BUCKETSIZELOG_MIN: u32 = 1;
/// `ZSTD_LDM_HASHRATELOG_MIN`
const ZSTD_LDM_HASHRATELOG_MIN: u32 = 0;
/// `ZSTD_LDM_HASHRATELOG_MAX`
const ZSTD_LDM_HASHRATELOG_MAX: u32 = ZSTD_WINDOWLOG_MAX - ZSTD_HASHLOG_MIN;
/// `ZSTD_CONTENTSIZE_UNKNOWN`
pub(crate) const ZSTD_CONTENTSIZE_UNKNOWN: u64 = u64::MAX;
/// `ZSTD_FRAMEHEADERSIZE_MAX`
const ZSTD_FRAMEHEADERSIZE_MAX: usize = 18;
/// `ZSTD_MAX_INPUT_SIZE` on 64-bit machines.
const ZSTD_MAX_INPUT_SIZE: u64 = 0xFF00_FF00_FF00_FF00;

/// `ZSTD_minCLevel`: the fastest level.
pub(crate) const fn zstd_min_clevel() -> i32 {
    -(ZSTD_TARGETLENGTH_MAX as i32)
}

/// `ZSTD_minCLevel`: the fastest compression level, -131072.
pub fn min_c_level() -> i32 {
    zstd_min_clevel()
}

/// `ZSTD_maxCLevel`: the strongest compression level, 22.
pub fn max_c_level() -> i32 {
    ZSTD_MAX_CLEVEL
}

/// `ZSTD_defaultCLevel`: the level 0 stands for, 3.
pub fn default_c_level() -> i32 {
    ZSTD_CLEVEL_DEFAULT
}

/// `ZSTD_compressBound`: the most a frame of `src_size` bytes can take, so
/// the room to give [`compress`] for it to always succeed; `None` for sizes
/// too large for a frame.
pub fn compress_bound(src_size: usize) -> Option<usize> {
    zstd_compress_bound(src_size).ok()
}

/// `ZSTD_compressBound`: the most a frame of `src_size` bytes can take.
pub(crate) fn zstd_compress_bound(src_size: usize) -> Result<usize> {
    if src_size as u64 >= ZSTD_MAX_INPUT_SIZE {
        return error!(SrcSizeWrong);
    }
    let margin = if src_size < 128 << 10 {
        ((128 << 10) - src_size) >> 11
    } else {
        0
    };
    Ok(src_size + (src_size >> 8) + margin)
}

/// `ZSTD_CParamMode_e`: what the parameters are for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum CParamMode {
    /// Compressing, perhaps with a dictionary attached or loaded.
    Unknown,
    /// Compressing with a dictionary attached: only the input counts.
    AttachDict,
    /// Making a dictionary.
    CreateCDict,
    /// Compressing without attaching a dictionary.
    NoAttachDict,
}

/// `ZSTD_rowMatchFinderSupported`
fn zstd_row_match_finder_supported(strategy: Strategy) -> bool {
    (Strategy::Greedy..=Strategy::Lazy2).contains(&strategy)
}

/// `ZSTD_rowMatchFinderUsed`
fn zstd_row_match_finder_used(strategy: Strategy, mode: ParamSwitch) -> bool {
    debug_assert!(mode != ParamSwitch::Auto);
    zstd_row_match_finder_supported(strategy) && mode == ParamSwitch::Enable
}

/// `ZSTD_resolveRowMatchFinderMode`: whether a frame with `c_params` uses
/// the row match finder, for `Auto` from the strategy and the window.
pub(crate) fn zstd_resolve_row_match_finder_mode(
    mode: ParamSwitch,
    c_params: &CompressionParameters,
) -> ParamSwitch {
    if mode != ParamSwitch::Auto {
        return mode;
    }
    if zstd_row_match_finder_supported(c_params.strategy) && c_params.window_log > 14 {
        ParamSwitch::Enable
    } else {
        ParamSwitch::Disable
    }
}

/// Whether the port has what a frame with `params` needs, their modes
/// resolved: its strategy (every one up to `btlazy2`), the block splitter
/// after the sequences, and long distance matching. The context refuses
/// the others with `ParameterUnsupported`.
pub(crate) fn zstd_frame_ported(params: &CCtxParams) -> bool {
    // The strategies.
    params.c_params.strategy <= Strategy::Btlazy2
        // Long distance matching with the optimal parser (ZSTD_optLdm_* in
        // zstd_opt.c); below btopt, zstd_ldm.c is ported.
        && (params.ldm_enable != ParamSwitch::Enable || params.c_params.strategy < Strategy::Btopt)
}

/// Whether the port has what `ZSTD_compressCCtx` takes at `level` for
/// `src_size` bytes.
#[cfg(test)]
pub(crate) fn zstd_level_ported(level: i32, src_size: u64) -> bool {
    let (c_params, f_params) =
        zstd_get_params_internal(level, src_size, 0, CParamMode::NoAttachDict);
    zstd_frame_ported(&CCtxParams::new(c_params, f_params, level))
}

/// The strategy `ZSTD_compressCCtx` takes at `level` for `src_size` bytes.
#[cfg(test)]
pub(crate) fn zstd_level_strategy(level: i32, src_size: u64) -> Strategy {
    zstd_get_cparams_internal(level, src_size, 0, CParamMode::NoAttachDict).strategy
}

/// `ZSTD_resolveBlockSplitterMode`: whether a frame with `c_params` splits
/// its blocks after finding their sequences; for `Auto`, the optimal
/// parser's strategies with windows of 128 KB or more.
pub(crate) fn zstd_resolve_block_splitter_mode(
    mode: ParamSwitch,
    c_params: &CompressionParameters,
) -> ParamSwitch {
    if mode != ParamSwitch::Auto {
        return mode;
    }
    if c_params.strategy >= Strategy::Btopt && c_params.window_log >= 17 {
        ParamSwitch::Enable
    } else {
        ParamSwitch::Disable
    }
}

/// `ZSTD_resolveEnableLdm`: whether a frame with `c_params` uses long
/// distance matching; for `Auto`, the optimal parser's strategies with
/// windows of 128 MB or more.
pub(crate) fn zstd_resolve_enable_ldm(
    mode: ParamSwitch,
    c_params: &CompressionParameters,
) -> ParamSwitch {
    if mode != ParamSwitch::Auto {
        return mode;
    }
    if c_params.strategy >= Strategy::Btopt && c_params.window_log >= 27 {
        ParamSwitch::Enable
    } else {
        ParamSwitch::Disable
    }
}

/// `ZSTD_allocateChainTable`: whether the strategy needs a chain table (for
/// `dfast`, its short hash table).
fn zstd_allocate_chain_table(strategy: Strategy, use_row_match_finder: ParamSwitch) -> bool {
    strategy != Strategy::Fast && !zstd_row_match_finder_used(strategy, use_row_match_finder)
}

/// `ZSTD_bitmix`: the bits of `val` mixed, after `XXH3_rrmxmx`.
fn zstd_bitmix(mut val: u64, len: u64) -> u64 {
    val ^= val.rotate_right(49) ^ val.rotate_right(24);
    val = val.wrapping_mul(0x9FB2_1C65_1E98_DF25);
    val ^= (val >> 35).wrapping_add(len);
    val = val.wrapping_mul(0x9FB2_1C65_1E98_DF25);
    val ^ (val >> 28)
}

/// `ZSTD_advanceHashSalt`: the row match finder's next salt, from the last
/// one and the hashes searched since.
fn zstd_advance_hash_salt(ms: &mut MatchState) {
    ms.hash_salt = zstd_bitmix(ms.hash_salt, 8) ^ zstd_bitmix(u64::from(ms.hash_salt_entropy), 4);
}

/// `ZSTD_cycleLog`
pub(crate) fn zstd_cycle_log(hash_log: u32, strategy: Strategy) -> u32 {
    let bt_scale = u32::from(strategy >= Strategy::Btlazy2);
    hash_log - bt_scale
}

/// `ZSTD_dictAndWindowLog`: a window log large enough for the input and
/// the dictionary: a dictionary is valid whole as long as one byte of it is
/// in the window.
fn zstd_dict_and_window_log(window_log: u32, src_size: u64, dict_size: u64) -> u32 {
    let max_window_size = 1u64 << ZSTD_WINDOWLOG_MAX;
    if dict_size == 0 {
        return window_log;
    }
    debug_assert!(window_log <= ZSTD_WINDOWLOG_MAX);
    debug_assert!(src_size != ZSTD_CONTENTSIZE_UNKNOWN);
    let window_size = 1u64 << window_log;
    let dict_and_window_size = dict_size + window_size;
    if window_size >= dict_size + src_size {
        // Large enough already.
        window_log
    } else if dict_and_window_size >= max_window_size {
        ZSTD_WINDOWLOG_MAX
    } else {
        highbit32((dict_and_window_size - 1) as u32) + 1
    }
}

/// `ZSTD_adjustCParams_internal`: `c_par` fitted to an input of `src_size`
/// bytes (`ZSTD_CONTENTSIZE_UNKNOWN` when not known; 0 means 0) and a
/// dictionary of `dict_size`, mostly by making tables smaller.
pub(crate) fn zstd_adjust_cparams_internal(
    mut c_par: CompressionParameters,
    mut src_size: u64,
    mut dict_size: usize,
    mode: CParamMode,
    mut use_row_match_finder: ParamSwitch,
) -> CompressionParameters {
    // (1 << 9) + 1
    let min_src_size: u64 = 513;
    let max_window_resize: u64 = 1 << (ZSTD_WINDOWLOG_MAX - 1);

    match mode {
        CParamMode::Unknown | CParamMode::NoAttachDict => {
            // Without the input's size, assume nothing about it.
        }
        CParamMode::CreateCDict => {
            // Making a dictionary for inputs of unknown size: assume small.
            if dict_size != 0 && src_size == ZSTD_CONTENTSIZE_UNKNOWN {
                src_size = min_src_size;
            }
        }
        CParamMode::AttachDict => {
            // The dictionary has its own parameters: these are for the
            // input only.
            dict_size = 0;
        }
    }

    // A smaller window for a small input, to use less memory.
    if src_size <= max_window_resize && dict_size as u64 <= max_window_resize {
        let t_size = (src_size + dict_size as u64) as u32;
        let hash_size_min: u32 = 1 << ZSTD_HASHLOG_MIN;
        let src_log = if t_size < hash_size_min {
            ZSTD_HASHLOG_MIN
        } else {
            highbit32(t_size - 1) + 1
        };
        if c_par.window_log > src_log {
            c_par.window_log = src_log;
        }
    }
    if src_size != ZSTD_CONTENTSIZE_UNKNOWN {
        let dict_and_window_log =
            zstd_dict_and_window_log(c_par.window_log, src_size, dict_size as u64);
        let cycle_log = zstd_cycle_log(c_par.chain_log, c_par.strategy);
        if c_par.hash_log > dict_and_window_log + 1 {
            c_par.hash_log = dict_and_window_log + 1;
        }
        if cycle_log > dict_and_window_log {
            c_par.chain_log -= cycle_log - dict_and_window_log;
        }
    }

    if c_par.window_log < ZSTD_WINDOWLOG_ABSOLUTEMIN {
        // The smallest window a frame header can describe.
        c_par.window_log = ZSTD_WINDOWLOG_ABSOLUTEMIN;
    }

    // A dictionary's indices carry tags in their top bits; libzstd checks
    // that for dictionaries it makes (ZSTD_CDictIndicesAreTagged), which the
    // port does not make yet.

    // Whether the row match finder will be used is not known yet; unless it
    // is turned off, assume it is. It is only turned off for small inputs,
    // so a slightly smaller hash log costs nothing.
    if use_row_match_finder == ParamSwitch::Auto {
        use_row_match_finder = ParamSwitch::Enable;
    }

    // No more than 32 bits of hash in all: hashLog - rowLog + 8 <= 32.
    if zstd_row_match_finder_used(c_par.strategy, use_row_match_finder) {
        // Rows of 32 entries from a search log of 5 on.
        let row_log = c_par.search_log.clamp(4, 6);
        let max_row_hash_log = 32 - ZSTD_ROW_HASH_TAG_BITS;
        let max_hash_log = max_row_hash_log + row_log;
        debug_assert!(c_par.hash_log >= row_log);
        if c_par.hash_log > max_hash_log {
            c_par.hash_log = max_hash_log;
        }
    }

    c_par
}

/// `ZSTD_getCParamRowSize`: the size that decides which table of levels to
/// use.
fn zstd_get_cparam_row_size(src_size_hint: u64, mut dict_size: usize, mode: CParamMode) -> u64 {
    if mode == CParamMode::AttachDict {
        dict_size = 0;
    }
    let unknown = src_size_hint == ZSTD_CONTENTSIZE_UNKNOWN;
    let added_size = if unknown && dict_size > 0 { 500 } else { 0 };
    if unknown && dict_size == 0 {
        ZSTD_CONTENTSIZE_UNKNOWN
    } else {
        src_size_hint
            .wrapping_add(dict_size as u64)
            .wrapping_add(added_size)
    }
}

/// `ZSTD_getCParams_internal`: the parameters of a level, for an input of
/// about `src_size_hint` bytes.
pub(crate) fn zstd_get_cparams_internal(
    compression_level: i32,
    src_size_hint: u64,
    dict_size: usize,
    mode: CParamMode,
) -> CompressionParameters {
    let r_size = zstd_get_cparam_row_size(src_size_hint, dict_size, mode);
    let table_id = usize::from(r_size <= 256 << 10)
        + usize::from(r_size <= 128 << 10)
        + usize::from(r_size <= 16 << 10);

    let row = if compression_level == 0 {
        ZSTD_CLEVEL_DEFAULT
    } else if compression_level < 0 {
        // Row 0 is the base for the negative levels.
        0
    } else {
        compression_level.min(ZSTD_MAX_CLEVEL)
    };

    let mut cp = ZSTD_DEFAULT_CPARAMETERS[table_id][row as usize];
    // The acceleration.
    if compression_level < 0 {
        let clamped_compression_level = compression_level.max(zstd_min_clevel());
        cp.target_length = clamped_compression_level.unsigned_abs();
    }
    // Fitted to the input and the dictionary.
    zstd_adjust_cparams_internal(cp, src_size_hint, dict_size, mode, ParamSwitch::Auto)
}

/// `ZSTD_getParams_internal`: the level's parameters, and the frame's: with
/// the content size, without a checksum.
pub(crate) fn zstd_get_params_internal(
    compression_level: i32,
    src_size_hint: u64,
    dict_size: usize,
    mode: CParamMode,
) -> (CompressionParameters, FrameParameters) {
    let c_params = zstd_get_cparams_internal(compression_level, src_size_hint, dict_size, mode);
    (
        c_params,
        FrameParameters {
            content_size_flag: true,
            checksum_flag: false,
            no_dict_id_flag: false,
        },
    )
}

/// `ZSTD_bufferMode_e`: when streaming, whether the context copies the
/// input (or output) into a buffer of its own, or the caller's buffer stays
/// put between calls.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum BufferMode {
    Buffered,
    Stable,
}

/// The compression parameters set with [`CCtx::set_parameter`], to put over
/// the level's: 0 (or `None`) for those to take from the level. libzstd
/// keeps them in the `cParams` of its requested parameters.
#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct CParamOverrides {
    pub(crate) window_log: u32,
    pub(crate) hash_log: u32,
    pub(crate) chain_log: u32,
    pub(crate) search_log: u32,
    pub(crate) min_match: u32,
    pub(crate) target_length: u32,
    pub(crate) strategy: Option<Strategy>,
}

/// `ZSTD_overrideCParams`: the parameters set, over the level's.
fn zstd_override_cparams(c_params: &mut CompressionParameters, overrides: &CParamOverrides) {
    if overrides.window_log != 0 {
        c_params.window_log = overrides.window_log;
    }
    if overrides.hash_log != 0 {
        c_params.hash_log = overrides.hash_log;
    }
    if overrides.chain_log != 0 {
        c_params.chain_log = overrides.chain_log;
    }
    if overrides.search_log != 0 {
        c_params.search_log = overrides.search_log;
    }
    if overrides.min_match != 0 {
        c_params.min_match = overrides.min_match;
    }
    if overrides.target_length != 0 {
        c_params.target_length = overrides.target_length;
    }
    if let Some(strategy) = overrides.strategy {
        c_params.strategy = strategy;
    }
}

/// `ZSTD_CCtx_params`: the parameters a frame is compressed with, those the
/// port has so far.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CCtxParams {
    pub(crate) format: Format,
    pub(crate) c_params: CompressionParameters,
    pub(crate) f_params: FrameParameters,
    pub(crate) compression_level: i32,
    /// The input size to choose the parameters for when it is not known;
    /// 0 for none.
    pub(crate) src_size_hint: u32,
    pub(crate) literal_compression_mode: ParamSwitch,
    pub(crate) in_buffer_mode: BufferMode,
    pub(crate) out_buffer_mode: BufferMode,
    /// The largest block, 0 for `ZSTD_BLOCKSIZE_MAX`.
    pub(crate) max_block_size: usize,
    /// 0 for the strategy's level of block splitting, 1 for none, 2 to 6.
    pub(crate) pre_block_splitter_level: i32,
    /// Whether the lazy strategies use the row match finder: `Auto` until
    /// a frame resolves it.
    pub(crate) use_row_match_finder: ParamSwitch,
    /// `postBlockSplitter`: whether blocks are split after their sequences
    /// are found (`ZSTD_c_splitAfterSequences`); `Auto` until a frame
    /// resolves it.
    pub(crate) post_block_splitter: ParamSwitch,
    /// `ldmParams.enableLdm`: long distance matching
    /// (`ZSTD_c_enableLongDistanceMatching`); `Auto` until a frame resolves
    /// it.
    pub(crate) ldm_enable: ParamSwitch,
    /// `ldmParams`, but `enableLdm`: the parameters of long distance
    /// matching, 0 for those left to `ZSTD_ldm_adjustParameters`, which a
    /// frame with it applies.
    pub(crate) ldm: LdmParams,
}

impl CCtxParams {
    /// `ZSTD_CCtxParams_init_internal`
    pub(crate) fn new(
        c_params: CompressionParameters,
        f_params: FrameParameters,
        compression_level: i32,
    ) -> Self {
        CCtxParams {
            format: Format::Zstd1,
            c_params,
            f_params,
            compression_level,
            src_size_hint: 0,
            literal_compression_mode: ParamSwitch::Auto,
            in_buffer_mode: BufferMode::Buffered,
            out_buffer_mode: BufferMode::Buffered,
            max_block_size: 0,
            pre_block_splitter_level: 0,
            use_row_match_finder: zstd_resolve_row_match_finder_mode(ParamSwitch::Auto, &c_params),
            post_block_splitter: zstd_resolve_block_splitter_mode(ParamSwitch::Auto, &c_params),
            ldm_enable: zstd_resolve_enable_ldm(ParamSwitch::Auto, &c_params),
            ldm: LdmParams::default(),
        }
    }

    /// `ZSTD_CCtxParams_init`, at the default level: the requested
    /// parameters of a new context. Their `c_params` are not used, but
    /// those set, the overrides.
    fn requested_default() -> (Self, CParamOverrides) {
        let (c_params, f_params) = zstd_get_params_internal(
            ZSTD_CLEVEL_DEFAULT,
            ZSTD_CONTENTSIZE_UNKNOWN,
            0,
            CParamMode::Unknown,
        );
        let mut params = CCtxParams::new(c_params, f_params, ZSTD_CLEVEL_DEFAULT);
        params.use_row_match_finder = ParamSwitch::Auto;
        params.post_block_splitter = ParamSwitch::Auto;
        params.ldm_enable = ParamSwitch::Auto;
        (params, CParamOverrides::default())
    }
}

/// `ZSTD_getCParamsFromCCtxParams`: the compression parameters of a frame:
/// the level's, for about `src_size_hint` bytes, with those set over them,
/// fitted to the input.
fn zstd_get_cparams_from_cctx_params(
    params: &CCtxParams,
    overrides: &CParamOverrides,
    mut src_size_hint: u64,
    dict_size: usize,
    mode: CParamMode,
) -> CompressionParameters {
    if src_size_hint == ZSTD_CONTENTSIZE_UNKNOWN && params.src_size_hint > 0 {
        src_size_hint = u64::from(params.src_size_hint);
    }
    let mut c_params =
        zstd_get_cparams_internal(params.compression_level, src_size_hint, dict_size, mode);
    // Long distance matching, when set (not left to the library), has its
    // own window log, under those set.
    if params.ldm_enable == ParamSwitch::Enable {
        c_params.window_log = ZSTD_LDM_DEFAULT_WINDOW_LOG;
    }
    zstd_override_cparams(&mut c_params, overrides);
    // A size hint of 0 means 0.
    zstd_adjust_cparams_internal(
        c_params,
        src_size_hint,
        dict_size,
        mode,
        params.use_row_match_finder,
    )
}

/// `ZSTD_resolveMaxBlockSize`
fn zstd_resolve_max_block_size(max_block_size: usize) -> usize {
    if max_block_size == 0 {
        ZSTD_BLOCKSIZE_MAX
    } else {
        max_block_size
    }
}

/// `ZSTD_maxNbSeq`: the most sequences a block can have.
fn zstd_max_nb_seq(block_size: usize, min_match: u32) -> usize {
    let divider = if min_match == 3 { 3 } else { 4 };
    block_size / divider
}

/// `ZSTD_FRAMEHEADERSIZE_MIN`: the smallest frame header.
fn zstd_frameheadersize_min(format: Format) -> usize {
    match format {
        Format::Zstd1 => 6,
        Format::Zstd1Magicless => 2,
    }
}

/// `ZSTD_overflowCorrectIfNeeded`: lowers every index when those of the
/// block from `ip` to `iend` (positions in the prefix's buffer) near 2^32,
/// keeping the window.
fn zstd_overflow_correct_if_needed(
    ms: &mut MatchState,
    params: &CCtxParams,
    ip: usize,
    iend: usize,
) {
    let c_params = &params.c_params;
    let cycle_log = zstd_cycle_log(c_params.chain_log, c_params.strategy);
    let max_dist = 1u32 << c_params.window_log;
    let src = ms.window.index(ip);
    let src_end = ms.window.index(iend);
    if ms
        .window
        .need_overflow_correction(cycle_log, max_dist, ms.loaded_dict_end, src, src_end)
    {
        let correction = ms.window.correct_overflow(cycle_log, max_dist, src);
        // ZSTD_reduceIndex. The row match finder's tags stay as they are
        // (see reset_cctx_internal).
        zstd_reduce_table(&mut ms.hash_table, correction);
        if zstd_allocate_chain_table(c_params.strategy, params.use_row_match_finder) {
            if c_params.strategy == Strategy::Btlazy2 {
                zstd_reduce_table_btlazy2(&mut ms.chain_table, correction);
            } else {
                zstd_reduce_table(&mut ms.chain_table, correction);
            }
        }
        ms.next_to_update = ms.next_to_update.saturating_sub(correction);
        // Dictionaries are invalid after a correction.
        ms.loaded_dict_end = 0;
    }
}

/// Whether the window's segments lie in `bufs`. libzstd trusts its
/// pointers; the port checks, so that a context used out of order (or on
/// after an error) fails instead of reaching into a buffer an earlier call
/// had.
fn zstd_window_in_buffers(window: &Window, bufs: &Buffers<'_>) -> bool {
    let prefix = bufs.get(window.buffer);
    let prefix_fits = i64::from(window.dict_limit) - window.base >= 0
        && window.next_src - window.base <= prefix.len() as i64;
    let dict_fits = !window.has_ext_dict() || {
        let dict = bufs.get(window.dict_buffer);
        i64::from(window.low_limit) - window.dict_base >= 0
            && i64::from(window.dict_limit) - window.dict_base <= dict.len() as i64
    };
    prefix_fits && dict_fits
}

/// `ZSTD_selectBlockCompressor`'s choice: the block compressor of the
/// strategy, without a dictionary or with the window's older segment
/// (`ZSTD_noDict`, `ZSTD_extDict`), over the buffers of a block: `src`, the
/// prefix's, and `dict`, the older segment's when it has one.
///
/// Differs from libzstd: what picks the function, kept as a value, instead
/// of a pointer to it; [`BlockCompressor::compress`] calls the same one.
/// Long distance matching calls it on parts of a block.
pub(crate) struct BlockCompressor<'a> {
    pub(crate) strategy: Strategy,
    pub(crate) use_row_match_finder: ParamSwitch,
    pub(crate) src: &'a [u8],
    pub(crate) dict: Option<&'a [u8]>,
}

impl BlockCompressor<'_> {
    /// `ZSTD_BlockCompressor_f`: the sequences of `src[istart..iend]` into
    /// `seq_store`. Returns the size of the literals left after the last
    /// sequence. Fails for the strategies the port does not have yet; the
    /// context does not take them.
    pub(crate) fn compress(
        &self,
        ms: &mut MatchState,
        seq_store: &mut SeqStore,
        rep: &mut [u32; ZSTD_REP_NUM],
        istart: usize,
        iend: usize,
    ) -> Result<usize> {
        let src = self.src;
        Ok(match (self.strategy, self.dict) {
            (Strategy::Fast, None) => {
                zstd_compress_block_fast(ms, seq_store, rep, src, istart, iend)
            }
            (Strategy::Fast, Some(dict)) => {
                zstd_compress_block_fast_ext_dict(ms, seq_store, rep, src, dict, istart, iend)
            }
            (Strategy::Dfast, None) => {
                zstd_compress_block_double_fast(ms, seq_store, rep, src, istart, iend)
            }
            (Strategy::Dfast, Some(dict)) => zstd_compress_block_double_fast_ext_dict(
                ms, seq_store, rep, src, dict, istart, iend,
            ),
            (Strategy::Greedy | Strategy::Lazy | Strategy::Lazy2, dict) => {
                let depth = self.strategy as u32 - Strategy::Greedy as u32;
                if zstd_row_match_finder_used(self.strategy, self.use_row_match_finder) {
                    zstd_compress_block_lazy_row(depth, ms, seq_store, rep, src, dict, istart, iend)
                } else {
                    zstd_compress_block_lazy_hc(depth, ms, seq_store, rep, src, dict, istart, iend)
                }
            }
            (Strategy::Btlazy2, dict) => {
                zstd_compress_block_btlazy2(ms, seq_store, rep, src, dict, istart, iend)
            }
            // The other strategies are not ported yet; the context does not
            // take them.
            _ => return error!(ParameterUnsupported),
        })
    }
}

// ---------------------------------------------------------------------------
// The context

/// `ZSTD_compressionStage_e`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CompressionStage {
    Created,
    Init,
    Ongoing,
    Ending,
}

/// `ZSTD_cStreamStage`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StreamStage {
    /// No frame started.
    Init,
    /// Taking input.
    Load,
    /// Writing out a compressed block.
    Flush,
}

/// `ZSTD_EndDirective`: what [`CCtx::compress_stream2`] does with its input.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EndDirective {
    /// Take the input; compress blocks once there is enough of it.
    Continue,
    /// Compress all the input taken so far, and write it all out: what is
    /// written decodes to all the input so far.
    Flush,
    /// Compress all the input and end the frame. The next call starts a
    /// new frame, once this one is all written out.
    End,
}

/// The caller's input buffer as a call left it, to check a stable input
/// against.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
struct InBufferId {
    address: usize,
    size: usize,
    pos: usize,
}

impl InBufferId {
    fn of(input: &InBuffer<'_>) -> InBufferId {
        InBufferId {
            address: input.src.as_ptr() as usize,
            size: input.src.len(),
            pos: input.pos,
        }
    }
}

/// `ZSTD_cParameter`, with its value: what [`CCtx::set_parameter`] sets.
///
/// The parameters apply to the frames that start after; most can only be
/// set between frames. Compression parameters set override the level's
/// for every frame; 0 (or `None`) goes back to the level's.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CParameter {
    /// The compression level, from [`min_c_level`] to [`max_c_level`]
    /// (values beyond are clamped); 0 for the default, 3. The level gives
    /// the compression parameters not set.
    CompressionLevel(i32),
    /// The largest match distance, and the window a decoder needs, as a
    /// power of 2: 10 to 31.
    WindowLog(u32),
    /// The size of the hash table, as a power of 2: 6 to 30.
    HashLog(u32),
    /// The size of the chain table (for `dfast`, the short hash table), as
    /// a power of 2: 6 to 30.
    ChainLog(u32),
    /// How many searches the stronger strategies make, as a power of 2: 1
    /// to 30.
    SearchLog(u32),
    /// The shortest match: 3 to 7.
    MinMatch(u32),
    /// For `fast`, how fast to skip input without matches; for the others,
    /// the match length that stops a search: 0 to 131072.
    TargetLength(u32),
    /// The match finder.
    Strategy(Option<Strategy>),
    /// Write the content size in the frame header when it is known: when
    /// compressing in one call, or after [`CCtx::set_pledged_src_size`].
    /// On by default.
    ContentSizeFlag(bool),
    /// Write a checksum of the content at the end of the frame. Off by
    /// default.
    ChecksumFlag(bool),
    /// Write the dictionary's ID in the frame header. On by default.
    DictIdFlag(bool),
    /// Frames with or without the magic number.
    Format(Format),
    /// Huffman-compress the literals or not; `Auto` does, except at the
    /// negative levels.
    LiteralCompressionMode(ParamSwitch),
    /// When the input's size is not known, about how large it is, to choose
    /// the parameters for: up to `i32::MAX`; 0 for none.
    SrcSizeHint(u32),
    /// When streaming, the input buffer stays the same between calls of a
    /// frame: the context then compresses from it and keeps no copy of its
    /// own. Each call must get the same buffer, from where the previous
    /// call left it, with at least as much data (or fails with
    /// [`ErrorCode::StabilityConditionNotRespected`]); the data already
    /// taken must stay the same.
    StableInBuffer(bool),
    /// When streaming, the room left in the output buffer stays the same
    /// between calls (or they fail with
    /// [`ErrorCode::StabilityConditionNotRespected`]): the context then
    /// compresses into it and keeps no output buffer of its own. A frame
    /// that does not fit then fails with [`ErrorCode::DstSizeTooSmall`].
    StableOutBuffer(bool),
    /// How hard to look for where to split blocks: 0 for the strategy's
    /// choice, 1 for not at all, 2 to 6 from fastest to best.
    BlockSplitterLevel(u32),
    /// The largest block: 1024 to 131072; 0 for 131072.
    MaxBlockSize(u32),
    /// Whether `greedy`, `lazy` and `lazy2` search with the row match
    /// finder or the hash chain; `Auto` takes the row match finder for
    /// windows over 16 KB.
    UseRowMatchFinder(ParamSwitch),
    /// Whether to split blocks after finding their sequences, where the
    /// statistics change (`ZSTD_c_splitAfterSequences`); `Auto` does for
    /// `btopt` and up with windows of 128 KB or more.
    SplitAfterSequences(ParamSwitch),
    /// Long distance matching (`ZSTD_c_enableLongDistanceMatching`):
    /// matches far back, found ahead of the strategy's own; `Auto` uses it
    /// for `btopt` and up with windows of 128 MB or more. On, it takes a
    /// window of 128 MB (a window log of 27) when none is set, smaller for
    /// a smaller input of known size.
    EnableLongDistanceMatching(ParamSwitch),
    /// The size of the hash table of long distance matching, as a power of
    /// 2 (`ZSTD_c_ldmHashLog`): 6 to 30; 0 for the window log less the
    /// hash rate log.
    LdmHashLog(u32),
    /// The shortest match of long distance matching (`ZSTD_c_ldmMinMatch`):
    /// 4 to 4096; 0 for 64 (32 from `btultra` up).
    LdmMinMatch(u32),
    /// The size of a bucket of long distance matching's hash table, as a
    /// power of 2 (`ZSTD_c_ldmBucketSizeLog`): 1 to 8, and at most the hash
    /// log; 0 for the strategy's number, 4 at least.
    LdmBucketSizeLog(u32),
    /// How often long distance matching puts a position in its table, about
    /// one in `1 << value` (`ZSTD_c_ldmHashRateLog`): 0 to 25; 0 for the
    /// window log less the hash log when that is set, otherwise from 7 for
    /// `fast` to 4 for `btultra2`.
    LdmHashRateLog(u32),
}

/// A `ZSTD_cParameter`, for [`CCtx::get_parameter`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CParameterKind {
    CompressionLevel,
    WindowLog,
    HashLog,
    ChainLog,
    SearchLog,
    MinMatch,
    TargetLength,
    Strategy,
    ContentSizeFlag,
    ChecksumFlag,
    DictIdFlag,
    Format,
    LiteralCompressionMode,
    SrcSizeHint,
    StableInBuffer,
    StableOutBuffer,
    BlockSplitterLevel,
    MaxBlockSize,
    UseRowMatchFinder,
    SplitAfterSequences,
    EnableLongDistanceMatching,
    LdmHashLog,
    LdmMinMatch,
    LdmBucketSizeLog,
    LdmHashRateLog,
}

impl CParameter {
    /// Which parameter this is.
    pub fn kind(&self) -> CParameterKind {
        match self {
            CParameter::CompressionLevel(_) => CParameterKind::CompressionLevel,
            CParameter::WindowLog(_) => CParameterKind::WindowLog,
            CParameter::HashLog(_) => CParameterKind::HashLog,
            CParameter::ChainLog(_) => CParameterKind::ChainLog,
            CParameter::SearchLog(_) => CParameterKind::SearchLog,
            CParameter::MinMatch(_) => CParameterKind::MinMatch,
            CParameter::TargetLength(_) => CParameterKind::TargetLength,
            CParameter::Strategy(_) => CParameterKind::Strategy,
            CParameter::ContentSizeFlag(_) => CParameterKind::ContentSizeFlag,
            CParameter::ChecksumFlag(_) => CParameterKind::ChecksumFlag,
            CParameter::DictIdFlag(_) => CParameterKind::DictIdFlag,
            CParameter::Format(_) => CParameterKind::Format,
            CParameter::LiteralCompressionMode(_) => CParameterKind::LiteralCompressionMode,
            CParameter::SrcSizeHint(_) => CParameterKind::SrcSizeHint,
            CParameter::StableInBuffer(_) => CParameterKind::StableInBuffer,
            CParameter::StableOutBuffer(_) => CParameterKind::StableOutBuffer,
            CParameter::BlockSplitterLevel(_) => CParameterKind::BlockSplitterLevel,
            CParameter::MaxBlockSize(_) => CParameterKind::MaxBlockSize,
            CParameter::UseRowMatchFinder(_) => CParameterKind::UseRowMatchFinder,
            CParameter::SplitAfterSequences(_) => CParameterKind::SplitAfterSequences,
            CParameter::EnableLongDistanceMatching(_) => CParameterKind::EnableLongDistanceMatching,
            CParameter::LdmHashLog(_) => CParameterKind::LdmHashLog,
            CParameter::LdmMinMatch(_) => CParameterKind::LdmMinMatch,
            CParameter::LdmBucketSizeLog(_) => CParameterKind::LdmBucketSizeLog,
            CParameter::LdmHashRateLog(_) => CParameterKind::LdmHashRateLog,
        }
    }
}

/// `ZSTD_isUpdateAuthorized`: whether a parameter may be set while a frame
/// is being streamed; it then applies from the next frame.
fn zstd_is_update_authorized(kind: CParameterKind) -> bool {
    matches!(
        kind,
        CParameterKind::CompressionLevel
            | CParameterKind::HashLog
            | CParameterKind::ChainLog
            | CParameterKind::SearchLog
            | CParameterKind::MinMatch
            | CParameterKind::TargetLength
            | CParameterKind::Strategy
            | CParameterKind::BlockSplitterLevel
    )
}

/// `BOUNDCHECK`: `value` within `bounds`, or `ParameterOutOfBound`.
fn bound_check(value: u32, bounds: std::ops::RangeInclusive<u32>) -> Result<()> {
    if bounds.contains(&value) {
        Ok(())
    } else {
        error!(ParameterOutOfBound)
    }
}

/// `ZSTD_CCtx`: a compression context, reused across frames.
///
/// Create one with [`CCtx::new`] and keep it: it holds tables and buffers
/// that would otherwise be set up for every call. It compresses whole
/// frames in one call ([`CCtx::compress`], [`CCtx::compress2`]) or
/// streaming ([`CCtx::compress_stream2`]), without a dictionary so far.
pub struct CCtx {
    stage: CompressionStage,
    /// The parameters set for the next frames (`requestedParams`); the
    /// compression parameters set are in `requested_c_params`.
    requested_params: CCtxParams,
    requested_c_params: CParamOverrides,
    /// The parameters of the frame being compressed.
    applied_params: CCtxParams,
    /// The tables and repeat offsets of the block before, and of the one
    /// being compressed (`blockState.prevCBlock`, `nextCBlock`).
    prev_cblock: CompressedBlockState,
    next_cblock: CompressedBlockState,
    match_state: MatchState,
    seq_store: SeqStore,
    /// Long distance matching: its window and tables (`ldmState`), and the
    /// store of a block's sequences (`ldmSequences`, `maxNbLdmSequences`).
    ldm_state: LdmState,
    ldm_sequences: RawSeqStore,
    block_size_max: usize,
    is_first_block: bool,
    pledged_src_size_plus_one: u64,
    consumed_src_size: u64,
    produced_csize: u64,
    xxh_state: Xxh64State,
    dict_id: u32,

    // Streaming.
    /// The input taken and not compressed yet, and the window, when
    /// streaming with an input buffer of the context's own: `inBuffSize`
    /// is its length.
    in_buff: Vec<u8>,
    in_to_compress: usize,
    in_buff_pos: usize,
    in_buff_target: usize,
    /// A compressed block not written out yet, when streaming with an
    /// output buffer of the context's own: `outBuffSize` is its length.
    out_buff: Vec<u8>,
    out_buff_content_size: usize,
    out_buff_flushed_size: usize,
    stream_stage: StreamStage,
    frame_ended: bool,
    /// The input and the room for output the next call must have, with
    /// stable buffers.
    expected_in_buffer: InBufferId,
    expected_out_buffer_size: usize,
    /// With a stable input buffer, the input said to be taken but not
    /// compressed yet: it waits for a block's worth.
    stable_in_not_consumed: usize,
}

impl CCtx {
    /// `ZSTD_createCCtx`
    pub fn new() -> Self {
        let (requested_params, requested_c_params) = CCtxParams::requested_default();
        let c_params = requested_params.c_params;
        CCtx {
            stage: CompressionStage::Created,
            requested_params,
            requested_c_params,
            applied_params: requested_params,
            prev_cblock: CompressedBlockState {
                entropy: EntropyCTables::filled(0),
                rep: REP_START_VALUE,
            },
            next_cblock: CompressedBlockState {
                entropy: EntropyCTables::filled(0),
                rep: REP_START_VALUE,
            },
            match_state: MatchState {
                window: Window::new(),
                hash_table: Vec::new(),
                chain_table: Vec::new(),
                next_to_update: 0,
                loaded_dict_end: 0,
                lazy_skipping: false,
                c_params,
                row_hash_log: 0,
                tag_table: Vec::new(),
                hash_cache: [0; ZSTD_ROW_HASH_CACHE_SIZE],
                // A new context's salt, before the first frame advances it.
                hash_salt: 0,
                hash_salt_entropy: 0,
            },
            seq_store: SeqStore::with_capacity(0, 0),
            ldm_state: LdmState::new(),
            ldm_sequences: RawSeqStore::default(),
            block_size_max: 0,
            is_first_block: true,
            pledged_src_size_plus_one: 0,
            consumed_src_size: 0,
            produced_csize: 0,
            xxh_state: Xxh64State::new(0),
            dict_id: 0,
            in_buff: Vec::new(),
            in_to_compress: 0,
            in_buff_pos: 0,
            in_buff_target: 0,
            out_buff: Vec::new(),
            out_buff_content_size: 0,
            out_buff_flushed_size: 0,
            stream_stage: StreamStage::Init,
            frame_ended: false,
            expected_in_buffer: InBufferId::default(),
            expected_out_buffer_size: 0,
            stable_in_not_consumed: 0,
        }
    }

    /// `ZSTD_resetCCtx_internal`, for a frame of `pledged_src_size` bytes,
    /// with clean tables, and the streaming buffers if `buffered`. The
    /// indices start again at `ZSTD_WINDOW_START_INDEX`: libzstd continues
    /// them in a context used again, which compresses the same.
    ///
    /// Fails with `ParameterUnsupported` for the strategies the port does
    /// not have yet, where libzstd would compress.
    fn reset_cctx_internal(
        &mut self,
        params: &CCtxParams,
        pledged_src_size: u64,
        buffered: bool,
    ) -> Result<()> {
        if !zstd_frame_ported(params) {
            return error!(ParameterUnsupported);
        }
        self.is_first_block = true;
        self.applied_params = *params;
        self.applied_params.max_block_size = zstd_resolve_max_block_size(params.max_block_size);
        debug_assert!(params.ldm_enable != ParamSwitch::Auto);
        if params.ldm_enable == ParamSwitch::Enable {
            // The parameters of long distance matching, for the frame.
            zstd_ldm_adjust_parameters(&mut self.applied_params.ldm, &params.c_params);
            debug_assert!(
                self.applied_params.ldm.hash_log >= self.applied_params.ldm.bucket_size_log
            );
            debug_assert!(self.applied_params.ldm.hash_rate_log < 32);
        }
        let params = self.applied_params;
        let c_params = params.c_params;

        let window_size = (1u64 << c_params.window_log).min(pledged_src_size).max(1) as usize;
        let block_size = params.max_block_size.min(window_size);
        let max_nb_seq = zstd_max_nb_seq(block_size, c_params.min_match);
        let max_nb_ldm_seq = zstd_ldm_get_max_nb_seq(params.ldm_enable, &params.ldm, block_size);
        let buff_out_size = if buffered && params.out_buffer_mode == BufferMode::Buffered {
            zstd_compress_bound(block_size)? + 1
        } else {
            0
        };
        let buff_in_size = if buffered && params.in_buffer_mode == BufferMode::Buffered {
            window_size + block_size
        } else {
            0
        };

        self.pledged_src_size_plus_one = pledged_src_size.wrapping_add(1);
        self.consumed_src_size = 0;
        self.produced_csize = 0;
        if pledged_src_size == ZSTD_CONTENTSIZE_UNKNOWN {
            self.applied_params.f_params.content_size_flag = false;
        }
        self.block_size_max = block_size;

        self.xxh_state = Xxh64State::new(0);
        self.stage = CompressionStage::Init;
        self.dict_id = 0;

        // ZSTD_reset_compressedBlockState
        self.prev_cblock.rep = REP_START_VALUE;
        self.prev_cblock.entropy.huf.repeat_mode = HufRepeat::None;
        self.prev_cblock.entropy.fse.offcode_repeat_mode = FseRepeat::None;
        self.prev_cblock.entropy.fse.matchlength_repeat_mode = FseRepeat::None;
        self.prev_cblock.entropy.fse.litlength_repeat_mode = FseRepeat::None;

        // ZSTD_reset_matchState
        let ms = &mut self.match_state;
        ms.window = Window::new();
        ms.next_to_update = ms.window.dict_limit;
        ms.loaded_dict_end = 0;
        ms.lazy_skipping = false;
        ms.hash_table.clear();
        ms.hash_table.resize(1 << c_params.hash_log, 0);
        // ZSTD_allocateChainTable: none for fast, nor for the row match
        // finder.
        let chain_size =
            if zstd_allocate_chain_table(c_params.strategy, params.use_row_match_finder) {
                1 << c_params.chain_log
            } else {
                0
            };
        ms.chain_table.clear();
        ms.chain_table.resize(chain_size, 0);
        if zstd_row_match_finder_used(c_params.strategy, params.use_row_match_finder) {
            // The row match finder's table of tags, and a new salt. Unlike
            // the window, the salt goes on from frame to frame, as libzstd's
            // does. It changes no output: XORed into the hashes before
            // their shift, it changes which row and which tag a position
            // gets, never which positions share them.
            //
            // Differs from libzstd: the tags are zeroed at every frame, where
            // libzstd zeroes them only the first time its workspace holds
            // them (ZSTD_cwksp_reserve_aligned_init_once): later frames find
            // the tags and heads of earlier ones, or other bytes. They
            // change nothing. A search goes through a row from its head,
            // newest entry first, so the entries written in this frame come
            // first, wherever the head is. Every other entry holds an index
            // below the window: an earlier frame's in libzstd, whose
            // indices go on from frame to frame, or 0. A search stops at
            // the first entry below the window that has its tag, after
            // taking those with its tag before it; so it takes the same
            // candidates in the same order, whatever the other entries'
            // tags and the head. Lowering the indices (ZSTD_reduceIndex)
            // leaves the tags too: the entries it sets to 0 held indices
            // below the window already, the oldest of their rows.
            ms.tag_table.clear();
            ms.tag_table.resize(1 << c_params.hash_log, 0);
            zstd_advance_hash_salt(ms);
            // Rows of 16 entries, 32 from a search log of 5, 64 from 6.
            let row_log = c_params.search_log.clamp(4, 6);
            debug_assert!(c_params.hash_log >= row_log);
            ms.row_hash_log = c_params.hash_log - row_log;
        }
        ms.c_params = c_params;

        self.seq_store = SeqStore::with_capacity(block_size, max_nb_seq);

        // The tables of long distance matching, cleared, and its window,
        // new: unlike the match state's, libzstd starts its indices again
        // at every frame.
        //
        // Differs from libzstd: without long distance matching, libzstd
        // leaves them as they were, unused; the port lets them go. A frame
        // with it sets them up again either way.
        let ldm = &mut self.ldm_state;
        if params.ldm_enable == ParamSwitch::Enable {
            let ldm_h_size = 1usize << params.ldm.hash_log;
            ldm.hash_table.clear();
            // Parameters can ask for a table of up to 2^30 entries, 8 GB:
            // where that is not to be had, libzstd's allocation fails with
            // an error, and so does the port's, rather than abort.
            if ldm.hash_table.try_reserve_exact(ldm_h_size).is_err() {
                return error!(MemoryAllocation);
            }
            ldm.hash_table.resize(ldm_h_size, LdmEntry::default());
            self.ldm_sequences.reset();
            self.ldm_sequences.capacity = max_nb_ldm_seq;
            self.ldm_sequences.seq.reserve(max_nb_ldm_seq);
            ldm.window = Window::new();
            ldm.loaded_dict_end = 0;
            let num_buckets = 1usize << (params.ldm.hash_log - params.ldm.bucket_size_log);
            ldm.bucket_offsets.clear();
            ldm.bucket_offsets.resize(num_buckets, 0);
        } else {
            *ldm = LdmState::new();
            self.ldm_sequences = RawSeqStore::default();
        }

        // The buffers. What they hold is not used again: the window starts
        // over.
        self.in_buff.resize(buff_in_size, 0);
        self.out_buff.resize(buff_out_size, 0);
        Ok(())
    }

    /// `ZSTD_compressBegin_internal`, without a dictionary.
    fn compress_begin_internal(
        &mut self,
        params: &CCtxParams,
        pledged_src_size: u64,
        buffered: bool,
    ) -> Result<()> {
        self.reset_cctx_internal(params, pledged_src_size, buffered)?;
        self.dict_id = 0;
        Ok(())
    }

    /// `ZSTD_buildSeqStore`: the block `istart..iend` of the window's
    /// prefix: its sequences and literals. Returns whether to compress it:
    /// blocks too small are stored raw.
    fn build_seq_store(&mut self, bufs: Buffers<'_>, istart: usize, iend: usize) -> Result<bool> {
        let src_size = iend - istart;
        debug_assert!(src_size <= ZSTD_BLOCKSIZE_MAX);
        if src_size < MIN_CBLOCK_SIZE + ZSTD_BLOCKHEADERSIZE + 1 + 1 {
            // Too small to try compressing.
            return Ok(false);
        }
        self.seq_store.reset();

        let ms = &mut self.match_state;
        // A limited update after a very long match.
        {
            let curr = ms.window.index(istart);
            if curr > ms.next_to_update + 384 {
                ms.next_to_update = curr - 192.min(curr - ms.next_to_update - 384);
            }
        }

        // Find and store the sequences, with the window's older segment if
        // it has one.
        let src = bufs.get(ms.window.buffer);
        let dict = bufs.get(ms.window.dict_buffer);
        let ext_dict = ms.window.has_ext_dict();
        self.next_cblock.rep = self.prev_cblock.rep;
        let rep = &mut self.next_cblock.rep;
        let seq_store = &mut self.seq_store;
        let params = &self.applied_params;
        let block_compressor = BlockCompressor {
            strategy: params.c_params.strategy,
            use_row_match_finder: params.use_row_match_finder,
            src,
            dict: ext_dict.then_some(dict),
        };
        let last_ll_size = if params.ldm_enable == ParamSwitch::Enable {
            // Long distance matching: its sequences of the block, from its
            // own window, over the same buffers; then the block compressor
            // between them.
            let ldm_seq_store = &mut self.ldm_sequences;
            ldm_seq_store.reset();
            let ldm_window = &self.ldm_state.window;
            let ldm_src = bufs.get(ldm_window.buffer);
            let ldm_dict = bufs.get(ldm_window.dict_buffer);
            zstd_ldm_generate_sequences(
                &mut self.ldm_state,
                ldm_seq_store,
                &params.ldm,
                ldm_src,
                ldm_dict,
                istart,
                iend,
            )?;
            let last_ll_size = zstd_ldm_block_compress(
                ldm_seq_store,
                ms,
                seq_store,
                rep,
                &block_compressor,
                istart,
                iend,
            )?;
            debug_assert!(ldm_seq_store.pos == ldm_seq_store.size());
            last_ll_size
        } else {
            block_compressor.compress(ms, seq_store, rep, istart, iend)?
        };
        self.seq_store
            .store_last_literals(src, iend - last_ll_size, last_ll_size);
        Ok(true)
    }

    /// `ZSTD_blockState_confirmRepcodesAndEntropyTables`: the block's tables
    /// and repeat offsets become the previous ones.
    fn confirm_repcodes_and_entropy_tables(&mut self) {
        std::mem::swap(&mut self.prev_cblock, &mut self.next_cblock);
    }

    /// `ZSTD_compressBlock_internal`, in a frame: the content of the block
    /// `istart..iend` of the window's prefix, into `dst` after the block
    /// header. Returns its size, 0 to store the block raw, or 1 for a block
    /// of one byte repeated.
    fn compress_block_internal(
        &mut self,
        dst: &mut [u8],
        bufs: Buffers<'_>,
        istart: usize,
        iend: usize,
    ) -> Result<usize> {
        // RLE blocks only pay below this compressed size.
        const RLE_MAX_LENGTH: usize = 25;
        let block = &bufs.get(self.match_state.window.buffer)[istart..iend];
        let mut c_size = 0;
        if self.build_seq_store(bufs, istart, iend)? {
            // Encode the sequences and the literals.
            let params = &self.applied_params;
            let disable = zstd_literals_compression_is_disabled(
                params.literal_compression_mode,
                params.c_params.strategy,
                params.c_params.target_length,
            );
            c_size = zstd_entropy_compress_seq_store(
                &mut self.seq_store,
                &self.prev_cblock.entropy,
                &mut self.next_cblock.entropy,
                params.c_params.strategy,
                disable,
                dst,
                block.len(),
                false,
            )?;

            // The first block is never RLE, though it may qualify: zstd
            // 1.4.3 and earlier (the command line) then report that not all
            // input was consumed. Blocks too small to compress are not
            // either.
            if !self.is_first_block && c_size < RLE_MAX_LENGTH && zstd_is_rle(block) {
                c_size = 1;
                dst[0] = block[0];
            }
        }

        if c_size > 1 {
            self.confirm_repcodes_and_entropy_tables();
        }
        // A dictionary's offset codes are checked for the first block; after
        // it the table might not have codes far enough for the data.
        if self.prev_cblock.entropy.fse.offcode_repeat_mode == FseRepeat::Valid {
            self.prev_cblock.entropy.fse.offcode_repeat_mode = FseRepeat::Check;
        }

        Ok(c_size)
    }

    /// `ZSTD_buildEntropyStatisticsAndEstimateSubBlockSize`: the size
    /// `chunk` of the block's sequences would take as a block of its own,
    /// estimated with the tables it would get. They go into the next block
    /// state, which compressing the block writes over.
    fn build_entropy_statistics_and_estimate_sub_block_size(
        &mut self,
        chunk: &SeqStoreChunk,
    ) -> Result<usize> {
        let mut seqs = self.seq_store.view(chunk);
        let metadata = zstd_build_block_entropy_stats(
            &mut seqs,
            &self.prev_cblock.entropy,
            &mut self.next_cblock.entropy,
            &self.applied_params,
        )?;
        Ok(zstd_estimate_block_size(
            seqs.literals,
            seqs.of_code,
            seqs.ll_code,
            seqs.ml_code,
            &self.next_cblock.entropy,
            &metadata,
            metadata.huf.h_type == SymbolEncodingType::Compressed,
            true,
        ))
    }

    /// `ZSTD_compressSeqStore_singleBlock`: `chunk` of the block's
    /// sequences, whose content is `src`, as a block of its own, its header
    /// included, into `dst`: compressed, RLE, or raw. Returns its size.
    ///
    /// `d_rep` and `c_rep` are the repeat offsets of the decoder and of the
    /// encoder, before the chunk. Those of a partition of the block
    /// (`is_partition`) are first checked against the decoder's (see
    /// [`zstd_seq_store_resolve_off_codes`]). An RLE or raw block leaves
    /// the decoder's as they were.
    #[allow(clippy::too_many_arguments)]
    fn compress_seq_store_single_block(
        &mut self,
        chunk: &SeqStoreChunk,
        d_rep: &mut [u32; ZSTD_REP_NUM],
        c_rep: &mut [u32; ZSTD_REP_NUM],
        dst: &mut [u8],
        src: &[u8],
        last_block: bool,
        is_partition: bool,
    ) -> Result<usize> {
        // RLE blocks only pay below this compressed size.
        const RLE_MAX_LENGTH: usize = 25;
        let src_size = src.len();

        let d_rep_original = *d_rep;
        if is_partition {
            zstd_seq_store_resolve_off_codes(
                d_rep,
                c_rep,
                &mut self.seq_store.sequences[chunk.seq_start..chunk.seq_end],
                chunk.long_length_type,
                chunk.long_length_pos,
            );
        }

        if dst.len() < ZSTD_BLOCKHEADERSIZE {
            // The block header does not fit.
            return error!(DstSizeTooSmall);
        }
        let params = &self.applied_params;
        let disable = zstd_literals_compression_is_disabled(
            params.literal_compression_mode,
            params.c_params.strategy,
            params.c_params.target_length,
        );
        let mut c_seqs_size = zstd_entropy_compress_seq_chunk(
            &mut self.seq_store.view(chunk),
            &self.prev_cblock.entropy,
            &mut self.next_cblock.entropy,
            params.c_params.strategy,
            disable,
            &mut dst[ZSTD_BLOCKHEADERSIZE..],
            src_size,
            false,
        )?;

        // The first block is never RLE, though it may qualify: zstd 1.4.3
        // and earlier (the command line) then report that not all input
        // was consumed. Nor are its partitions.
        if !self.is_first_block && c_seqs_size < RLE_MAX_LENGTH && zstd_is_rle(src) {
            c_seqs_size = 1;
        }

        let c_size = match c_seqs_size {
            0 => {
                let c_size = zstd_no_compress_block(dst, src, last_block)?;
                *d_rep = d_rep_original;
                c_size
            }
            1 => {
                let c_size = zstd_rle_compress_block(dst, src[0], src_size, last_block)?;
                *d_rep = d_rep_original;
                c_size
            }
            _ => {
                self.confirm_repcodes_and_entropy_tables();
                write_block_header(dst, c_seqs_size, src_size, last_block);
                ZSTD_BLOCKHEADERSIZE + c_seqs_size
            }
        };

        // A dictionary's offset codes are checked for the first block; after
        // it the table might not have codes far enough for the data.
        if self.prev_cblock.entropy.fse.offcode_repeat_mode == FseRepeat::Valid {
            self.prev_cblock.entropy.fse.offcode_repeat_mode = FseRepeat::Check;
        }
        Ok(c_size)
    }

    /// `ZSTD_deriveBlockSplitsHelper`: where to split the sequences
    /// `start_idx..end_idx` of the block, onto `splits`, in order: in the
    /// middle, if the halves are estimated smaller than the whole, and then
    /// in each half. Not runs of fewer than `MIN_SEQUENCES_BLOCK_SPLITTING`
    /// sequences (so at most about ten deep, four in practice), nor once
    /// there are `ZSTD_MAX_NB_BLOCK_SPLITS` splits, nor when an estimate
    /// fails.
    ///
    /// Differs from libzstd: the splits are a vector, where libzstd has an
    /// array of `ZSTD_MAX_NB_BLOCK_SPLITS`. The splits pending up the
    /// recursion can pass that count; libzstd then writes them past the
    /// array, into the metadata after it, which nothing writes before they
    /// are read back. That takes some 38400 sequences in a block, matches
    /// of 3 bytes: the strategies the port has find 4 or more.
    fn derive_block_splits_helper(
        &mut self,
        splits: &mut Vec<u32>,
        start_idx: usize,
        end_idx: usize,
    ) {
        let mid_idx = (start_idx + end_idx) / 2;
        debug_assert!(end_idx >= start_idx);
        if end_idx - start_idx < MIN_SEQUENCES_BLOCK_SPLITTING
            || splits.len() >= ZSTD_MAX_NB_BLOCK_SPLITS
        {
            // Too few sequences.
            return;
        }
        let full_seq_store_chunk = zstd_derive_seq_store_chunk(&self.seq_store, start_idx, end_idx);
        let first_half_seq_store = zstd_derive_seq_store_chunk(&self.seq_store, start_idx, mid_idx);
        let second_half_seq_store = zstd_derive_seq_store_chunk(&self.seq_store, mid_idx, end_idx);
        let estimated_original_size =
            self.build_entropy_statistics_and_estimate_sub_block_size(&full_seq_store_chunk);
        let estimated_first_half_size =
            self.build_entropy_statistics_and_estimate_sub_block_size(&first_half_seq_store);
        let estimated_second_half_size =
            self.build_entropy_statistics_and_estimate_sub_block_size(&second_half_seq_store);
        let (Ok(original), Ok(first_half), Ok(second_half)) = (
            estimated_original_size,
            estimated_first_half_size,
            estimated_second_half_size,
        ) else {
            return;
        };
        if first_half + second_half < original {
            self.derive_block_splits_helper(splits, start_idx, mid_idx);
            splits.push(mid_idx as u32);
            self.derive_block_splits_helper(splits, mid_idx, end_idx);
        }
    }

    /// `ZSTD_deriveBlockSplits`: where to split the block's `nb_seq`
    /// sequences, as the ends of the partitions, onto `partitions`, the last
    /// `nb_seq`. Returns the number of splits, one less than of partitions;
    /// 0, and no partitions, for a block not split.
    fn derive_block_splits(&mut self, partitions: &mut Vec<u32>, nb_seq: u32) -> usize {
        if nb_seq <= 4 {
            // Too few sequences to split.
            return 0;
        }
        self.derive_block_splits_helper(partitions, 0, nb_seq as usize);
        partitions.push(nb_seq);
        partitions.len() - 1
    }

    /// `ZSTD_compressBlock_splitBlock_internal`: the block `src`, its
    /// `nb_seq` sequences found, as one block or several, each with its
    /// header, into `dst`. Returns their size.
    fn compress_block_split_block_internal(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        last_block: bool,
        nb_seq: u32,
    ) -> Result<usize> {
        let block_size = src.len();
        let mut ip = 0;
        let mut op = 0;
        let mut src_bytes_total = 0;
        let mut partitions = Vec::new();
        let num_splits = self.derive_block_splits(&mut partitions, nb_seq);

        // A block split, with some partitions stored RLE or raw, leaves the
        // decoder with other repeat offsets than the encoder: the sequences
        // of those partitions do not reach it. Two histories of the repeat
        // offsets tell which repeat codes then stand for other offsets, to
        // write the offsets instead (see zstd_seq_store_resolve_off_codes):
        // `c_rep`, the encoder's, follows every partition; `d_rep`, the
        // decoder's, only those compressed, with the offsets written. The
        // next block starts from the decoder's.
        let mut d_rep = self.prev_cblock.rep;
        let mut c_rep = self.prev_cblock.rep;

        if num_splits == 0 {
            let whole = self.seq_store.whole();
            let c_size_single_block = self.compress_seq_store_single_block(
                &whole, &mut d_rep, &mut c_rep, dst, src, last_block, false,
            )?;
            debug_assert!(self.block_size_max <= ZSTD_BLOCKSIZE_MAX);
            debug_assert!(c_size_single_block <= self.block_size_max + ZSTD_BLOCKHEADERSIZE);
            return Ok(c_size_single_block);
        }

        // Differs from libzstd: each partition is derived just before it is
        // compressed, where libzstd derives the next one first. Deriving
        // reads only the lengths, which compressing leaves as they are.
        let mut seq_start = 0;
        for (i, &seq_end) in partitions.iter().enumerate() {
            let last_partition = i == num_splits;
            let chunk = zstd_derive_seq_store_chunk(&self.seq_store, seq_start, seq_end as usize);
            let mut last_block_entire_src = false;
            let mut src_bytes = zstd_count_seq_store_literals_bytes(&self.seq_store, &chunk)
                + zstd_count_seq_store_match_bytes(&self.seq_store, &chunk);
            src_bytes_total += src_bytes;
            if last_partition {
                // The last partition: with the block's last literals.
                src_bytes += block_size - src_bytes_total;
                last_block_entire_src = last_block;
            }

            let c_size_chunk = self.compress_seq_store_single_block(
                &chunk,
                &mut d_rep,
                &mut c_rep,
                &mut dst[op..],
                &src[ip..ip + src_bytes],
                last_block_entire_src,
                true,
            )?;
            ip += src_bytes;
            op += c_size_chunk;
            seq_start = seq_end as usize;
            debug_assert!(c_size_chunk <= self.block_size_max + ZSTD_BLOCKHEADERSIZE);
        }
        // The encoder's and the decoder's repeat offsets may differ now: the
        // next block takes the decoder's.
        self.prev_cblock.rep = d_rep;
        Ok(op)
    }

    /// `ZSTD_compressBlock_splitBlock`: the block `istart..iend` of the
    /// window's prefix, its sequences found, as one block or several, cut
    /// where their statistics change, each with its header, into `dst`.
    /// Returns their size.
    fn compress_block_split_block(
        &mut self,
        dst: &mut [u8],
        bufs: Buffers<'_>,
        istart: usize,
        iend: usize,
        last_block: bool,
    ) -> Result<usize> {
        debug_assert!(self.applied_params.post_block_splitter == ParamSwitch::Enable);
        let src = &bufs.get(self.match_state.window.buffer)[istart..iend];
        if !self.build_seq_store(bufs, istart, iend)? {
            // Too small to compress.
            if self.prev_cblock.entropy.fse.offcode_repeat_mode == FseRepeat::Valid {
                self.prev_cblock.entropy.fse.offcode_repeat_mode = FseRepeat::Check;
            }
            return zstd_no_compress_block(dst, src, last_block);
        }
        let nb_seq = self.seq_store.sequences.len() as u32;
        self.compress_block_split_block_internal(dst, src, last_block, nb_seq)
    }

    /// `ZSTD_optimalBlockSize`: where to end the next block, perhaps before
    /// `block_size_max`, when its content changes.
    fn optimal_block_size(
        src: &[u8],
        block_size_max: usize,
        split_level: i32,
        strategy: Strategy,
        savings: i64,
    ) -> usize {
        // The split level of each strategy, from fast to btultra2.
        const SPLIT_LEVELS: [i32; 10] = [0, 0, 1, 2, 2, 3, 3, 4, 4, 4];
        let src_size = src.len();
        // Only full blocks of 128 KB are split, for now; splitting smaller
        // ones pays less.
        if src_size < 128 << 10 || block_size_max < 128 << 10 {
            return src_size.min(block_size_max);
        }
        // Not data that does not compress: splitting takes savings of 3 bytes
        // or more, so the first full block is never split.
        if savings < 3 {
            return 128 << 10;
        }
        let split_level = match split_level {
            1 => return 128 << 10,
            0 => SPLIT_LEVELS[strategy as usize],
            level => {
                debug_assert!((2..=6).contains(&level));
                level - 2
            }
        };
        zstd_split_block(&src[..128 << 10], split_level as usize)
    }

    /// `ZSTD_compress_frameChunk`: the window prefix's `start..end` into
    /// blocks, all of it.
    fn compress_frame_chunk(
        &mut self,
        dst: &mut [u8],
        bufs: Buffers<'_>,
        start: usize,
        end: usize,
        last_frame_chunk: bool,
    ) -> Result<usize> {
        let block_size_max = self.block_size_max;
        let src = bufs.get(self.match_state.window.buffer);
        let mut remaining = end - start;
        let mut ip = start;
        let mut op = 0;
        let mut dst_capacity = dst.len();
        let max_dist = 1u32 << self.applied_params.c_params.window_log;
        let mut savings = self.consumed_src_size as i64 - self.produced_csize as i64;

        if self.applied_params.f_params.checksum_flag && end > start {
            self.xxh_state.update(&src[start..end]);
        }

        while remaining > 0 {
            let block_size = Self::optimal_block_size(
                &src[ip..end],
                block_size_max,
                self.applied_params.pre_block_splitter_level,
                self.applied_params.c_params.strategy,
                savings,
            );
            let last_block = last_frame_chunk & (block_size == remaining);
            debug_assert!(block_size <= remaining);

            if dst_capacity < ZSTD_BLOCKHEADERSIZE + MIN_CBLOCK_SIZE + 1 {
                // Not enough room for a compressed block.
                return error!(DstSizeTooSmall);
            }

            // Without a dictionary, ZSTD_checkDictValidity changes nothing.
            let ms = &mut self.match_state;
            zstd_overflow_correct_if_needed(ms, &self.applied_params, ip, ip + block_size);
            ms.window.enforce_max_dist(ms.window.index(ip), max_dist);

            // Table updates resume no sooner than lowLimit.
            if ms.next_to_update < ms.window.low_limit {
                ms.next_to_update = ms.window.low_limit;
            }

            let c_size = if zstd_block_splitter_enabled(&self.applied_params) {
                // Perhaps in several blocks, their headers included.
                let c_size = self.compress_block_split_block(
                    &mut dst[op..op + dst_capacity],
                    bufs,
                    ip,
                    ip + block_size,
                    last_block,
                )?;
                debug_assert!(c_size > 0);
                c_size
            } else {
                let c_size = self.compress_block_internal(
                    &mut dst[op + ZSTD_BLOCKHEADERSIZE..op + dst_capacity],
                    bufs,
                    ip,
                    ip + block_size,
                )?;
                if c_size == 0 {
                    // The block does not compress.
                    zstd_no_compress_block(
                        &mut dst[op..op + dst_capacity],
                        &src[ip..ip + block_size],
                        last_block,
                    )?
                } else {
                    let c_block_header = if c_size == 1 {
                        u32::from(last_block)
                            + ((BlockType::Rle as u32) << 1)
                            + ((block_size as u32) << 3)
                    } else {
                        u32::from(last_block)
                            + ((BlockType::Compressed as u32) << 1)
                            + ((c_size as u32) << 3)
                    };
                    dst[op..op + 3].copy_from_slice(&c_block_header.to_le_bytes()[..3]);
                    c_size + ZSTD_BLOCKHEADERSIZE
                }
            };

            // `savings` keeps splitting from expanding data that does not
            // compress by more than libzstd's 3 bytes per full block: splitting
            // needs savings of 3 bytes or more.
            savings += block_size as i64 - c_size as i64;

            ip += block_size;
            remaining -= block_size;
            op += c_size;
            dst_capacity -= c_size;
            self.is_first_block = false;
        }

        if last_frame_chunk && op > 0 {
            self.stage = CompressionStage::Ending;
        }
        Ok(op)
    }

    /// `ZSTD_writeFrameHeader`
    fn write_frame_header(
        dst: &mut [u8],
        params: &CCtxParams,
        pledged_src_size: u64,
        dict_id: u32,
    ) -> Result<usize> {
        let dict_id_size_code_length =
            u32::from(dict_id > 0) + u32::from(dict_id >= 256) + u32::from(dict_id >= 65536);
        let dict_id_size_code = if params.f_params.no_dict_id_flag {
            0
        } else {
            dict_id_size_code_length
        };
        let checksum_flag = u32::from(params.f_params.checksum_flag);
        let window_size = 1u64 << params.c_params.window_log;
        let single_segment = params.f_params.content_size_flag && window_size >= pledged_src_size;
        let window_log_byte =
            ((params.c_params.window_log - ZSTD_WINDOWLOG_ABSOLUTEMIN) << 3) as u8;
        let fcs_code = if params.f_params.content_size_flag {
            u32::from(pledged_src_size >= 256)
                + u32::from(pledged_src_size >= 65536 + 256)
                + u32::from(pledged_src_size >= 0xFFFF_FFFF)
        } else {
            0
        };
        let frame_header_description_byte = (dict_id_size_code
            + (checksum_flag << 2)
            + (u32::from(single_segment) << 5)
            + (fcs_code << 6)) as u8;

        debug_assert!(
            !(params.f_params.content_size_flag && pledged_src_size == ZSTD_CONTENTSIZE_UNKNOWN)
        );
        if dst.len() < ZSTD_FRAMEHEADERSIZE_MAX {
            // Too small for the largest frame header.
            return error!(DstSizeTooSmall);
        }
        let mut pos = 0;
        if params.format == Format::Zstd1 {
            write_le32(dst, 0, ZSTD_MAGICNUMBER);
            pos = 4;
        }
        dst[pos] = frame_header_description_byte;
        pos += 1;
        if !single_segment {
            dst[pos] = window_log_byte;
            pos += 1;
        }
        match dict_id_size_code {
            1 => {
                dst[pos] = dict_id as u8;
                pos += 1;
            }
            2 => {
                write_le16(dst, pos, dict_id as u16);
                pos += 2;
            }
            3 => {
                write_le32(dst, pos, dict_id);
                pos += 4;
            }
            _ => {}
        }
        match fcs_code {
            0 => {
                if single_segment {
                    dst[pos] = pledged_src_size as u8;
                    pos += 1;
                }
            }
            1 => {
                write_le16(dst, pos, (pledged_src_size - 256) as u16);
                pos += 2;
            }
            2 => {
                write_le32(dst, pos, pledged_src_size as u32);
                pos += 4;
            }
            _ => {
                write_le64(dst, pos, pledged_src_size);
                pos += 8;
            }
        }
        Ok(pos)
    }

    /// `ZSTD_compressContinue_internal`, in a frame: the frame header if
    /// not written yet, then `start..end` of the buffer `which`, in blocks.
    #[allow(clippy::too_many_arguments)]
    fn compress_continue_internal(
        &mut self,
        dst: &mut [u8],
        bufs: Buffers<'_>,
        which: WindowBuffer,
        start: usize,
        end: usize,
        last_frame_chunk: bool,
    ) -> Result<usize> {
        let mut fh_size = 0;
        if self.stage == CompressionStage::Created {
            // Missing init.
            return error!(StageWrong);
        }

        if self.stage == CompressionStage::Init {
            fh_size = Self::write_frame_header(
                dst,
                &self.applied_params,
                self.pledged_src_size_plus_one.wrapping_sub(1),
                self.dict_id,
            )?;
            self.stage = CompressionStage::Ongoing;
        }

        if start == end {
            // No empty block without input.
            return Ok(fh_size);
        }

        let ms = &mut self.match_state;
        if !ms.window.update(which, start, end - start, false) {
            ms.next_to_update = ms.window.dict_limit;
        }
        if !zstd_window_in_buffers(&ms.window, &bufs) {
            return error!(SrcBufferWrong);
        }
        if self.applied_params.ldm_enable == ParamSwitch::Enable {
            let window = &mut self.ldm_state.window;
            window.update(which, start, end - start, false);
            if !zstd_window_in_buffers(window, &bufs) {
                return error!(SrcBufferWrong);
            }
        }

        let c_size =
            self.compress_frame_chunk(&mut dst[fh_size..], bufs, start, end, last_frame_chunk)?;
        self.consumed_src_size += (end - start) as u64;
        self.produced_csize += (c_size + fh_size) as u64;
        if self.pledged_src_size_plus_one != 0
            && self.consumed_src_size + 1 > self.pledged_src_size_plus_one
        {
            // More input than pledged.
            return error!(SrcSizeWrong);
        }
        Ok(c_size + fh_size)
    }

    /// `ZSTD_compressContinue_public`: `start..end` of the buffer `which`,
    /// more of the frame.
    fn compress_continue(
        &mut self,
        dst: &mut [u8],
        bufs: Buffers<'_>,
        which: WindowBuffer,
        start: usize,
        end: usize,
    ) -> Result<usize> {
        self.compress_continue_internal(dst, bufs, which, start, end, false)
    }

    /// `ZSTD_writeEpilogue`: an empty last block if needed, and the
    /// checksum.
    fn write_epilogue(&mut self, dst: &mut [u8]) -> Result<usize> {
        let mut op = 0;
        if self.stage == CompressionStage::Created {
            // Init missing.
            return error!(StageWrong);
        }

        // An empty frame.
        if self.stage == CompressionStage::Init {
            let fh_size = Self::write_frame_header(dst, &self.applied_params, 0, 0)?;
            op += fh_size;
            self.stage = CompressionStage::Ongoing;
        }

        if self.stage != CompressionStage::Ending {
            // One last empty block, marked last.
            let c_block_header24 = 1 /* last block */ + ((BlockType::Raw as u32) << 1);
            if dst.len() - op < 3 {
                return error!(DstSizeTooSmall);
            }
            dst[op..op + 3].copy_from_slice(&c_block_header24.to_le_bytes()[..3]);
            op += ZSTD_BLOCKHEADERSIZE;
        }

        if self.applied_params.f_params.checksum_flag {
            let checksum = self.xxh_state.digest() as u32;
            if dst.len() - op < 4 {
                // No room for the checksum.
                return error!(DstSizeTooSmall);
            }
            write_le32(dst, op, checksum);
            op += 4;
        }

        // Back to "created, not initialized".
        self.stage = CompressionStage::Created;
        Ok(op)
    }

    /// `ZSTD_compressEnd_public`: `start..end` of the buffer `which`, the
    /// rest of the frame, and the end of the frame.
    fn compress_end(
        &mut self,
        dst: &mut [u8],
        bufs: Buffers<'_>,
        which: WindowBuffer,
        start: usize,
        end: usize,
    ) -> Result<usize> {
        let c_size = self.compress_continue_internal(dst, bufs, which, start, end, true)?;
        let end_result = self.write_epilogue(&mut dst[c_size..])?;
        if self.pledged_src_size_plus_one != 0
            && self.pledged_src_size_plus_one != self.consumed_src_size + 1
        {
            // Not the input pledged.
            return error!(SrcSizeWrong);
        }
        Ok(c_size + end_result)
    }

    /// `ZSTD_compress_advanced_internal`, without a dictionary.
    pub(crate) fn compress_advanced_internal(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        params: &CCtxParams,
    ) -> Result<usize> {
        self.compress_begin_internal(params, src.len() as u64, false)?;
        let bufs = Buffers {
            input: src,
            in_buff: &[],
        };
        self.compress_end(dst, bufs, WindowBuffer::Input, 0, src.len())
    }

    /// `ZSTD_compressCCtx`: `src` as one frame, at `compression_level`, into
    /// `dst`. Returns the frame's size.
    ///
    /// The frame has the content size and no checksum, as libzstd's, and is
    /// byte for byte the frame libzstd 1.5.7 writes. Levels go from
    /// [`min_c_level`] to [`max_c_level`]; 0 is [`default_c_level`]. Room
    /// for [`compress_bound`] bytes is always enough. The parameters set
    /// with [`CCtx::set_parameter`] do not apply; [`CCtx::compress2`] takes
    /// them.
    ///
    /// Work in progress: the port has libzstd's strategies up to `btlazy2`
    /// so far, which are every level up to 15 for inputs over 256 KB (or of
    /// unknown size), up to 12 for inputs over 16 KB, and up to 10 for
    /// smaller ones. Other levels fail with
    /// [`ErrorCode::ParameterUnsupported`](crate::ErrorCode::ParameterUnsupported).
    pub fn compress(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        compression_level: i32,
    ) -> Result<usize> {
        let (c_params, f_params) = zstd_get_params_internal(
            compression_level,
            src.len() as u64,
            0,
            CParamMode::NoAttachDict,
        );
        debug_assert!(f_params.content_size_flag);
        let level = if compression_level == 0 {
            ZSTD_CLEVEL_DEFAULT
        } else {
            compression_level
        };
        let params = CCtxParams::new(c_params, f_params, level);
        self.compress_advanced_internal(dst, src, &params)
    }

    // -----------------------------------------------------------------------
    // Parameters

    /// `ZSTD_CCtx_setParameter`: sets a parameter for the frames that start
    /// after. Between frames any can be set; while a frame is being
    /// streamed, only the compression level and the compression parameters
    /// but the window log (or fails with [`ErrorCode::StageWrong`]).
    /// Values out of range fail with [`ErrorCode::ParameterOutOfBound`],
    /// but the level's, which are clamped.
    pub fn set_parameter(&mut self, parameter: CParameter) -> Result<()> {
        if self.stream_stage != StreamStage::Init && !zstd_is_update_authorized(parameter.kind()) {
            // Only in the init stage.
            return error!(StageWrong);
        }
        let params = &mut self.requested_params;
        let c_params = &mut self.requested_c_params;
        match parameter {
            CParameter::CompressionLevel(level) => {
                let level = level.clamp(zstd_min_clevel(), ZSTD_MAX_CLEVEL);
                params.compression_level = if level == 0 {
                    ZSTD_CLEVEL_DEFAULT
                } else {
                    level
                };
            }
            CParameter::WindowLog(value) => {
                if value != 0 {
                    bound_check(value, ZSTD_WINDOWLOG_MIN..=ZSTD_WINDOWLOG_MAX)?;
                }
                c_params.window_log = value;
            }
            CParameter::HashLog(value) => {
                if value != 0 {
                    bound_check(value, ZSTD_HASHLOG_MIN..=ZSTD_HASHLOG_MAX)?;
                }
                c_params.hash_log = value;
            }
            CParameter::ChainLog(value) => {
                if value != 0 {
                    bound_check(value, ZSTD_CHAINLOG_MIN..=ZSTD_CHAINLOG_MAX)?;
                }
                c_params.chain_log = value;
            }
            CParameter::SearchLog(value) => {
                if value != 0 {
                    bound_check(value, ZSTD_SEARCHLOG_MIN..=ZSTD_SEARCHLOG_MAX)?;
                }
                c_params.search_log = value;
            }
            CParameter::MinMatch(value) => {
                if value != 0 {
                    bound_check(value, ZSTD_MINMATCH_MIN..=ZSTD_MINMATCH_MAX)?;
                }
                c_params.min_match = value;
            }
            CParameter::TargetLength(value) => {
                bound_check(value, ZSTD_TARGETLENGTH_MIN..=ZSTD_TARGETLENGTH_MAX)?;
                c_params.target_length = value;
            }
            CParameter::Strategy(strategy) => c_params.strategy = strategy,
            CParameter::ContentSizeFlag(flag) => params.f_params.content_size_flag = flag,
            CParameter::ChecksumFlag(flag) => params.f_params.checksum_flag = flag,
            CParameter::DictIdFlag(flag) => params.f_params.no_dict_id_flag = !flag,
            CParameter::Format(format) => params.format = format,
            CParameter::LiteralCompressionMode(mode) => params.literal_compression_mode = mode,
            CParameter::SrcSizeHint(value) => {
                if value != 0 {
                    bound_check(value, ZSTD_SRCSIZEHINT_MIN..=ZSTD_SRCSIZEHINT_MAX)?;
                }
                params.src_size_hint = value;
            }
            CParameter::StableInBuffer(stable) => {
                params.in_buffer_mode = if stable {
                    BufferMode::Stable
                } else {
                    BufferMode::Buffered
                };
            }
            CParameter::StableOutBuffer(stable) => {
                params.out_buffer_mode = if stable {
                    BufferMode::Stable
                } else {
                    BufferMode::Buffered
                };
            }
            CParameter::BlockSplitterLevel(value) => {
                bound_check(value, 0..=ZSTD_BLOCKSPLITTER_LEVEL_MAX)?;
                params.pre_block_splitter_level = value as i32;
            }
            CParameter::MaxBlockSize(value) => {
                if value != 0 {
                    bound_check(value, ZSTD_BLOCKSIZE_MAX_MIN..=ZSTD_BLOCKSIZE_MAX as u32)?;
                }
                params.max_block_size = value as usize;
            }
            CParameter::UseRowMatchFinder(mode) => params.use_row_match_finder = mode,
            CParameter::SplitAfterSequences(mode) => params.post_block_splitter = mode,
            CParameter::EnableLongDistanceMatching(mode) => params.ldm_enable = mode,
            CParameter::LdmHashLog(value) => {
                if value != 0 {
                    bound_check(value, ZSTD_LDM_HASHLOG_MIN..=ZSTD_LDM_HASHLOG_MAX)?;
                }
                params.ldm.hash_log = value;
            }
            CParameter::LdmMinMatch(value) => {
                if value != 0 {
                    bound_check(value, ZSTD_LDM_MINMATCH_MIN..=ZSTD_LDM_MINMATCH_MAX)?;
                }
                params.ldm.min_match_length = value;
            }
            CParameter::LdmBucketSizeLog(value) => {
                if value != 0 {
                    bound_check(
                        value,
                        ZSTD_LDM_BUCKETSIZELOG_MIN..=ZSTD_LDM_BUCKETSIZELOG_MAX,
                    )?;
                }
                params.ldm.bucket_size_log = value;
            }
            CParameter::LdmHashRateLog(value) => {
                if value != 0 {
                    bound_check(value, ZSTD_LDM_HASHRATELOG_MIN..=ZSTD_LDM_HASHRATELOG_MAX)?;
                }
                params.ldm.hash_rate_log = value;
            }
        }
        Ok(())
    }

    /// `ZSTD_CCtx_getParameter`: the value set for a parameter, as libzstd
    /// gives it: flags are 0 or 1, the strategy and the format their
    /// number, the literal compression mode 0 (auto), 1 (on) or 2 (off),
    /// compression parameters not set 0.
    pub fn get_parameter(&self, parameter: CParameterKind) -> i32 {
        let params = &self.requested_params;
        let c_params = &self.requested_c_params;
        let buffer_mode = |mode| i32::from(mode == BufferMode::Stable);
        match parameter {
            CParameterKind::CompressionLevel => params.compression_level,
            CParameterKind::WindowLog => c_params.window_log as i32,
            CParameterKind::HashLog => c_params.hash_log as i32,
            CParameterKind::ChainLog => c_params.chain_log as i32,
            CParameterKind::SearchLog => c_params.search_log as i32,
            CParameterKind::MinMatch => c_params.min_match as i32,
            CParameterKind::TargetLength => c_params.target_length as i32,
            CParameterKind::Strategy => c_params.strategy.map_or(0, |strategy| strategy as i32),
            CParameterKind::ContentSizeFlag => i32::from(params.f_params.content_size_flag),
            CParameterKind::ChecksumFlag => i32::from(params.f_params.checksum_flag),
            CParameterKind::DictIdFlag => i32::from(!params.f_params.no_dict_id_flag),
            CParameterKind::Format => match params.format {
                Format::Zstd1 => 0,
                Format::Zstd1Magicless => 1,
            },
            CParameterKind::LiteralCompressionMode => params.literal_compression_mode as i32,
            CParameterKind::SrcSizeHint => params.src_size_hint as i32,
            CParameterKind::StableInBuffer => buffer_mode(params.in_buffer_mode),
            CParameterKind::StableOutBuffer => buffer_mode(params.out_buffer_mode),
            CParameterKind::BlockSplitterLevel => params.pre_block_splitter_level,
            CParameterKind::MaxBlockSize => params.max_block_size as i32,
            CParameterKind::UseRowMatchFinder => params.use_row_match_finder as i32,
            CParameterKind::SplitAfterSequences => params.post_block_splitter as i32,
            CParameterKind::EnableLongDistanceMatching => params.ldm_enable as i32,
            CParameterKind::LdmHashLog => params.ldm.hash_log as i32,
            CParameterKind::LdmMinMatch => params.ldm.min_match_length as i32,
            CParameterKind::LdmBucketSizeLog => params.ldm.bucket_size_log as i32,
            CParameterKind::LdmHashRateLog => params.ldm.hash_rate_log as i32,
        }
    }

    /// `ZSTD_CCtx_setPledgedSrcSize`: the size of the next frame's content,
    /// [`CONTENTSIZE_UNKNOWN`](crate::CONTENTSIZE_UNKNOWN) for not known
    /// (the default). The frame then has its size in its header, and fails
    /// with [`ErrorCode::SrcSizeWrong`] if it gets another. Only between
    /// frames (or fails with [`ErrorCode::StageWrong`]); the next frame
    /// started uses it up.
    pub fn set_pledged_src_size(&mut self, pledged_src_size: u64) -> Result<()> {
        if self.stream_stage != StreamStage::Init {
            // Not in the init stage.
            return error!(StageWrong);
        }
        self.pledged_src_size_plus_one = pledged_src_size.wrapping_add(1);
        Ok(())
    }

    /// `ZSTD_CCtx_reset`: abandons the frame being streamed (and the input
    /// taken for it), and the pledged size; or sets the parameters back to their defaults, which
    /// only works between frames (or fails with [`ErrorCode::StageWrong`]);
    /// or both.
    pub fn reset(&mut self, reset: ResetDirective) -> Result<()> {
        if matches!(
            reset,
            ResetDirective::SessionOnly | ResetDirective::SessionAndParameters
        ) {
            self.reset_session();
        }
        if matches!(
            reset,
            ResetDirective::Parameters | ResetDirective::SessionAndParameters
        ) {
            if self.stream_stage != StreamStage::Init {
                // Only in the init stage.
                return error!(StageWrong);
            }
            (self.requested_params, self.requested_c_params) = CCtxParams::requested_default();
        }
        Ok(())
    }

    /// `ZSTD_CCtx_reset(ZSTD_reset_session_only)`. Also drops the input a
    /// stable input buffer was said to give but not compressed yet:
    /// libzstd keeps it, and starts the next frame that much before its
    /// input.
    fn reset_session(&mut self) {
        self.stream_stage = StreamStage::Init;
        self.pledged_src_size_plus_one = 0;
        self.stable_in_not_consumed = 0;
    }

    // -----------------------------------------------------------------------
    // Streaming

    /// `ZSTD_compress2`: `src` as one frame, with the parameters set, into
    /// `dst`. Returns the frame's size. Abandons any frame being streamed.
    ///
    /// With the default parameters, the frame is the one [`CCtx::compress`]
    /// writes at the default level. Fails with
    /// [`ErrorCode::DstSizeTooSmall`] if the frame does not fit:
    /// [`compress_bound`] bytes always do.
    pub fn compress2(&mut self, dst: &mut [u8], src: &[u8]) -> Result<usize> {
        let original_in_buffer_mode = self.requested_params.in_buffer_mode;
        let original_out_buffer_mode = self.requested_params.out_buffer_mode;
        self.reset_session();
        // Stable input and output buffers.
        self.requested_params.in_buffer_mode = BufferMode::Stable;
        self.requested_params.out_buffer_mode = BufferMode::Stable;
        let mut o_pos = 0;
        let mut i_pos = 0;
        let result =
            self.compress_stream2_simple_args(dst, &mut o_pos, src, &mut i_pos, EndDirective::End);
        // Back to the modes set.
        self.requested_params.in_buffer_mode = original_in_buffer_mode;
        self.requested_params.out_buffer_mode = original_out_buffer_mode;

        if result? != 0 {
            // Not all written out, for lack of room.
            return error!(DstSizeTooSmall);
        }
        debug_assert_eq!(i_pos, src.len());
        Ok(o_pos)
    }

    /// `ZSTD_compressStream2`: takes input from `input.pos` on, writes
    /// output from `output.pos` on, and moves both forward. Returns how
    /// much is left to write out, at least: 0 when all is.
    ///
    /// The first call of a frame starts it, with the parameters set (and
    /// the size pledged; with [`EndDirective::End`], the size of the input).
    /// [`EndDirective::Continue`] takes input and writes out what is ready;
    /// call it as long as there is input. Then call with
    /// [`EndDirective::End`] (or [`EndDirective::Flush`]) until it returns
    /// 0: the frame is then complete (or all the input so far written out).
    /// Each frame is the one libzstd 1.5.7 writes for the same calls.
    pub fn compress_stream2(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        end_op: EndDirective,
    ) -> Result<usize> {
        if output.pos > output.dst.len() {
            // Not a valid output buffer.
            return error!(DstSizeTooSmall);
        }
        if input.pos > input.src.len() {
            // Not a valid input buffer.
            return error!(SrcSizeWrong);
        }

        // The transparent initialization stage.
        if self.stream_stage == StreamStage::Init {
            // No obligation to start from pos 0.
            let input_size = input.src.len() - input.pos;
            let total_input_size = input_size + self.stable_in_not_consumed;
            if self.requested_params.in_buffer_mode == BufferMode::Stable
                && end_op == EndDirective::Continue
                && total_input_size < ZSTD_BLOCKSIZE_MAX
            {
                // Not a block yet, and more input to come, in the same
                // buffer: wait, to start the frame knowing more.
                if self.stable_in_not_consumed != 0 {
                    if input.src.as_ptr() as usize != self.expected_in_buffer.address {
                        // Not the same input buffer.
                        return error!(StabilityConditionNotRespected);
                    }
                    if input.pos != self.expected_in_buffer.size {
                        // Its position moved.
                        return error!(StabilityConditionNotRespected);
                    }
                }
                // Say the input was taken, to show progress.
                input.pos = input.src.len();
                self.expected_in_buffer = InBufferId::of(input);
                // It was not: compression starts from there.
                self.stable_in_not_consumed += input_size;
                // At least a frame header to write.
                return Ok(zstd_frameheadersize_min(self.requested_params.format));
            }
            self.init_compress_stream2(end_op, total_input_size)?;
            self.set_buffer_expectations(output, input);
        }

        self.check_buffer_stability(output, input)?;
        self.compress_stream_generic(output, input, end_op)?;
        self.set_buffer_expectations(output, input);
        // What is left to write out.
        Ok(self.out_buff_content_size - self.out_buff_flushed_size)
    }

    /// `ZSTD_compressStream2_simpleArgs`: [`CCtx::compress_stream2`], with
    /// the buffers' positions apart.
    pub fn compress_stream2_simple_args(
        &mut self,
        dst: &mut [u8],
        dst_pos: &mut usize,
        src: &[u8],
        src_pos: &mut usize,
        end_op: EndDirective,
    ) -> Result<usize> {
        let mut output = OutBuffer { dst, pos: *dst_pos };
        let mut input = InBuffer { src, pos: *src_pos };
        let result = self.compress_stream2(&mut output, &mut input, end_op);
        *dst_pos = output.pos;
        *src_pos = input.pos;
        result
    }

    /// `ZSTD_initCStream`: abandons any frame being streamed, and sets the
    /// compression level. The other parameters stay.
    pub fn init_cstream(&mut self, compression_level: i32) -> Result<()> {
        self.reset(ResetDirective::SessionOnly)?;
        self.set_parameter(CParameter::CompressionLevel(compression_level))
    }

    /// `ZSTD_compressStream`: [`CCtx::compress_stream2`] with
    /// [`EndDirective::Continue`]. Returns how much input to give next, as a
    /// hint: what completes the block being taken.
    pub fn compress_stream(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
    ) -> Result<usize> {
        self.compress_stream2(output, input, EndDirective::Continue)?;
        Ok(self.next_input_size_hint())
    }

    /// `ZSTD_flushStream`: [`CCtx::compress_stream2`] with
    /// [`EndDirective::Flush`] and no more input. Returns how much is left
    /// to write out.
    ///
    /// With a stable input buffer, libzstd flushes from the input buffer
    /// of the last call, which the port does not keep: it fails with
    /// [`ErrorCode::StabilityConditionNotRespected`]; call
    /// [`CCtx::compress_stream2`] with that input instead.
    pub fn flush_stream(&mut self, output: &mut OutBuffer<'_>) -> Result<usize> {
        if self.applied_params.in_buffer_mode == BufferMode::Stable {
            return error!(StabilityConditionNotRespected);
        }
        let mut input = InBuffer { src: &[], pos: 0 };
        self.compress_stream2(output, &mut input, EndDirective::Flush)
    }

    /// `ZSTD_endStream`: [`CCtx::compress_stream2`] with
    /// [`EndDirective::End`] and no more input. Returns how much is left to
    /// write out, the end of the frame included: 0 when the frame is
    /// complete.
    ///
    /// With a stable input buffer, fails as [`CCtx::flush_stream`] does.
    pub fn end_stream(&mut self, output: &mut OutBuffer<'_>) -> Result<usize> {
        if self.applied_params.in_buffer_mode == BufferMode::Stable {
            return error!(StabilityConditionNotRespected);
        }
        let mut input = InBuffer { src: &[], pos: 0 };
        let remaining_to_flush = self.compress_stream2(output, &mut input, EndDirective::End)?;
        // Without workers: what is left more precisely.
        let last_block_size = if self.frame_ended {
            0
        } else {
            ZSTD_BLOCKHEADERSIZE
        };
        let checksum_size = if self.frame_ended {
            0
        } else {
            usize::from(self.applied_params.f_params.checksum_flag) * 4
        };
        Ok(remaining_to_flush + last_block_size + checksum_size)
    }

    /// `ZSTD_CCtx_init_compressStream2`: starts a frame, with the parameters
    /// set. With [`EndDirective::End`], `in_size` is its size.
    fn init_compress_stream2(&mut self, end_op: EndDirective, in_size: usize) -> Result<()> {
        let mut params = self.requested_params;
        if end_op == EndDirective::End {
            // The size, known.
            self.pledged_src_size_plus_one = in_size as u64 + 1;
        }
        let pledged_src_size = self.pledged_src_size_plus_one.wrapping_sub(1);
        params.c_params = zstd_get_cparams_from_cctx_params(
            &params,
            &self.requested_c_params,
            pledged_src_size,
            0,
            CParamMode::NoAttachDict,
        );
        // ZSTD_CCtx_init_compressStream2, in libzstd's order.
        params.post_block_splitter =
            zstd_resolve_block_splitter_mode(params.post_block_splitter, &params.c_params);
        params.ldm_enable = zstd_resolve_enable_ldm(params.ldm_enable, &params.c_params);
        params.use_row_match_finder =
            zstd_resolve_row_match_finder_mode(params.use_row_match_finder, &params.c_params);
        params.max_block_size = zstd_resolve_max_block_size(params.max_block_size);

        self.compress_begin_internal(&params, pledged_src_size, true)?;
        if self.applied_params.in_buffer_mode == BufferMode::Buffered {
            // Input a stable buffer was said to give, with the mode changed
            // since: libzstd leaves it out of the frame, and counts it in
            // the size of every later frame started with all its input.
            // The port drops it.
            self.stable_in_not_consumed = 0;
        }
        self.in_to_compress = 0;
        self.in_buff_pos = 0;
        self.in_buff_target = if self.applied_params.in_buffer_mode == BufferMode::Buffered {
            // For a small input, no automatic flush at the end of the block,
            // which would take an empty block of 3 bytes to end the frame.
            self.block_size_max + usize::from(self.block_size_max as u64 == pledged_src_size)
        } else {
            0
        };
        self.out_buff_content_size = 0;
        self.out_buff_flushed_size = 0;
        self.stream_stage = StreamStage::Load;
        self.frame_ended = false;
        Ok(())
    }

    /// `ZSTD_setBufferExpectations`: with stable buffers, what the next call
    /// must get.
    fn set_buffer_expectations(&mut self, output: &OutBuffer<'_>, input: &InBuffer<'_>) {
        if self.applied_params.in_buffer_mode == BufferMode::Stable {
            self.expected_in_buffer = InBufferId::of(input);
        }
        if self.applied_params.out_buffer_mode == BufferMode::Stable {
            self.expected_out_buffer_size = output.dst.len() - output.pos;
        }
    }

    /// `ZSTD_checkBufferStability`: with stable buffers, whether a call got
    /// what the one before left.
    fn check_buffer_stability(&self, output: &OutBuffer<'_>, input: &InBuffer<'_>) -> Result<()> {
        if self.applied_params.in_buffer_mode == BufferMode::Stable {
            let expect = self.expected_in_buffer;
            if expect.address != input.src.as_ptr() as usize || expect.pos != input.pos {
                // A stable input, but not the one expected.
                return error!(StabilityConditionNotRespected);
            }
        }
        if self.applied_params.out_buffer_mode == BufferMode::Stable
            && self.expected_out_buffer_size != output.dst.len() - output.pos
        {
            // A stable output, but not of the room expected.
            return error!(StabilityConditionNotRespected);
        }
        Ok(())
    }

    /// `ZSTD_nextInputSizeHint`: how much input completes the block being
    /// taken. With a stable input buffer, before a frame starts, it is
    /// worked out from the last frame's block size, and can wrap around as
    /// libzstd's does (which then reads as an error when within 120 of the
    /// top).
    fn next_input_size_hint(&self) -> usize {
        if self.applied_params.in_buffer_mode == BufferMode::Stable {
            return self
                .block_size_max
                .wrapping_sub(self.stable_in_not_consumed);
        }
        match self.in_buff_target - self.in_buff_pos {
            0 => self.block_size_max,
            hint => hint,
        }
    }

    /// `ZSTD_compressStream_generic`: the streaming state machine. The
    /// context's buffers are taken out of it meanwhile, for the compressor
    /// to read the input buffer while it changes the context.
    fn compress_stream_generic(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        flush_mode: EndDirective,
    ) -> Result<usize> {
        let mut in_buff = std::mem::take(&mut self.in_buff);
        let mut out_buff = std::mem::take(&mut self.out_buff);
        let result = self.compress_stream_generic_with(
            &mut in_buff,
            &mut out_buff,
            output,
            input,
            flush_mode,
        );
        self.in_buff = in_buff;
        self.out_buff = out_buff;
        result
    }

    /// `ZSTD_compressStream_generic`, with the context's buffers apart.
    /// Returns a hint of the input to give next.
    #[allow(clippy::too_many_lines)]
    fn compress_stream_generic_with(
        &mut self,
        in_buff: &mut [u8],
        out_buff: &mut [u8],
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        flush_mode: EndDirective,
    ) -> Result<usize> {
        let iend = input.src.len();
        let oend = output.dst.len();

        if self.applied_params.in_buffer_mode == BufferMode::Stable {
            // The input said to be taken, and not compressed yet, is before
            // the position. libzstd asserts it is there.
            if input.pos < self.stable_in_not_consumed {
                return error!(StabilityConditionNotRespected);
            }
            input.pos -= self.stable_in_not_consumed;
            self.stable_in_not_consumed = 0;
        }
        let mut ip = input.pos;
        let mut op = output.pos;
        let mut some_more_work = true;

        while some_more_work {
            match self.stream_stage {
                StreamStage::Init => {
                    // Call ZSTD_initCStream() first!
                    return error!(InitMissing);
                }

                StreamStage::Load => {
                    if flush_mode == EndDirective::End
                        && (zstd_compress_bound(iend - ip).is_ok_and(|bound| oend - op >= bound)
                            || self.applied_params.out_buffer_mode == BufferMode::Stable)
                        && self.in_buff_pos == 0
                    {
                        // Enough room, or leave to fail with
                        // DstSizeTooSmall: compress straight into the
                        // output.
                        let bufs = Buffers {
                            input: input.src,
                            in_buff,
                        };
                        let c_size = self.compress_end(
                            &mut output.dst[op..],
                            bufs,
                            WindowBuffer::Input,
                            ip,
                            iend,
                        )?;
                        ip = iend;
                        op += c_size;
                        self.frame_ended = true;
                        self.reset_session();
                        some_more_work = false;
                        continue;
                    }
                    if self.applied_params.in_buffer_mode == BufferMode::Buffered {
                        // Fill the input buffer.
                        if self.in_buff_target > in_buff.len() {
                            // The port checks: the buffer is another
                            // frame's, after a one-call compression.
                            return error!(StageWrong);
                        }
                        let to_load = self.in_buff_target - self.in_buff_pos;
                        let loaded = to_load.min(iend - ip);
                        in_buff[self.in_buff_pos..self.in_buff_pos + loaded]
                            .copy_from_slice(&input.src[ip..ip + loaded]);
                        self.in_buff_pos += loaded;
                        ip += loaded;
                        if flush_mode == EndDirective::Continue
                            && self.in_buff_pos < self.in_buff_target
                        {
                            // Not a full block: stop here.
                            some_more_work = false;
                            continue;
                        }
                        if flush_mode == EndDirective::Flush
                            && self.in_buff_pos == self.in_to_compress
                        {
                            // Nothing to flush.
                            some_more_work = false;
                            continue;
                        }
                    } else {
                        if flush_mode == EndDirective::Continue && iend - ip < self.block_size_max {
                            // Not a full block: stop here, and say the input
                            // was taken.
                            self.stable_in_not_consumed = iend - ip;
                            ip = iend;
                            some_more_work = false;
                            continue;
                        }
                        if flush_mode == EndDirective::Flush && ip == iend {
                            // Nothing to flush.
                            some_more_work = false;
                            continue;
                        }
                    }

                    // Compress the current block; this stage cannot stop in
                    // the middle.
                    let input_buffered = self.applied_params.in_buffer_mode == BufferMode::Buffered;
                    let o_size = oend - op;
                    let i_size = if input_buffered {
                        self.in_buff_pos - self.in_to_compress
                    } else {
                        (iend - ip).min(self.block_size_max)
                    };
                    // Into the output, to skip the flush stage, when it fits.
                    let into_output = zstd_compress_bound(i_size)
                        .is_ok_and(|bound| o_size >= bound)
                        || self.applied_params.out_buffer_mode == BufferMode::Stable;
                    let c_size;
                    {
                        let bufs = Buffers {
                            input: input.src,
                            in_buff,
                        };
                        let c_dst: &mut [u8] = if into_output {
                            &mut output.dst[op..]
                        } else {
                            &mut *out_buff
                        };
                        if input_buffered {
                            let last_block = flush_mode == EndDirective::End && ip == iend;
                            let (start, end) = (self.in_to_compress, self.in_to_compress + i_size);
                            c_size = if last_block {
                                self.compress_end(c_dst, bufs, WindowBuffer::InBuff, start, end)?
                            } else {
                                self.compress_continue(
                                    c_dst,
                                    bufs,
                                    WindowBuffer::InBuff,
                                    start,
                                    end,
                                )?
                            };
                            self.frame_ended = last_block;
                            // Prepare the next block.
                            self.in_buff_target = self.in_buff_pos + self.block_size_max;
                            if self.in_buff_target > in_buff.len() {
                                self.in_buff_pos = 0;
                                self.in_buff_target = self.block_size_max;
                            }
                            self.in_to_compress = self.in_buff_pos;
                        } else {
                            let last_block = flush_mode == EndDirective::End && ip + i_size == iend;
                            let result = if last_block {
                                self.compress_end(c_dst, bufs, WindowBuffer::Input, ip, ip + i_size)
                            } else {
                                self.compress_continue(
                                    c_dst,
                                    bufs,
                                    WindowBuffer::Input,
                                    ip,
                                    ip + i_size,
                                )
                            };
                            // The input is taken before the error check, as
                            // libzstd does.
                            ip += i_size;
                            c_size = result?;
                            self.frame_ended = last_block;
                        }
                    }
                    if into_output {
                        // Nothing to flush.
                        op += c_size;
                        if self.frame_ended {
                            // The frame is complete, in the output.
                            some_more_work = false;
                            self.reset_session();
                        }
                        continue;
                    }
                    self.out_buff_content_size = c_size;
                    self.out_buff_flushed_size = 0;
                    // On to the flush stage.
                    self.stream_stage = StreamStage::Flush;
                }

                StreamStage::Flush => {
                    debug_assert!(self.applied_params.out_buffer_mode == BufferMode::Buffered);
                    if self.out_buff_content_size > out_buff.len() {
                        // The port checks: the buffer is another frame's,
                        // after a one-call compression.
                        return error!(StageWrong);
                    }
                    let to_flush = self.out_buff_content_size - self.out_buff_flushed_size;
                    let flushed = to_flush.min(oend - op);
                    output.dst[op..op + flushed].copy_from_slice(
                        &out_buff[self.out_buff_flushed_size..self.out_buff_flushed_size + flushed],
                    );
                    op += flushed;
                    self.out_buff_flushed_size += flushed;
                    if to_flush != flushed {
                        // Not all written out, as the output is full.
                        some_more_work = false;
                        continue;
                    }
                    self.out_buff_content_size = 0;
                    self.out_buff_flushed_size = 0;
                    if self.frame_ended {
                        // The frame is complete, written out.
                        some_more_work = false;
                        self.reset_session();
                        continue;
                    }
                    self.stream_stage = StreamStage::Load;
                }
            }
        }

        input.pos = ip;
        output.pos = op;
        if self.frame_ended {
            return Ok(0);
        }
        Ok(self.next_input_size_hint())
    }
}

#[cfg(test)]
impl CCtx {
    /// How many times the indices were lowered in the last frame.
    pub(crate) fn nb_overflow_corrections(&self) -> u32 {
        self.match_state.window.nb_overflow_corrections
    }

    /// How many times the indices of long distance matching were lowered
    /// in the last frame.
    pub(crate) fn nb_ldm_overflow_corrections(&self) -> u32 {
        self.ldm_state.window.nb_overflow_corrections
    }
}

/// `ZSTD_isRLE`: whether `src` is one byte repeated.
fn zstd_is_rle(src: &[u8]) -> bool {
    src.iter().all(|&b| b == src[0])
}

impl Default for CCtx {
    fn default() -> Self {
        CCtx::new()
    }
}

/// `ZSTD_compress`: `src` as one frame, at `compression_level`, into `dst`.
/// Returns the frame's size. Each call sets up a new context; reuse a
/// [`CCtx`] to avoid that. See [`CCtx::compress`].
pub fn compress(dst: &mut [u8], src: &[u8], compression_level: i32) -> Result<usize> {
    CCtx::new().compress(dst, src, compression_level)
}

/// `ZSTD_CStreamInSize`: a good size for the input of each streaming call,
/// a block's worth.
pub fn cstream_in_size() -> usize {
    ZSTD_BLOCKSIZE_MAX
}

/// `ZSTD_CStreamOutSize`: a good size for the output of each streaming
/// call: a block, compressed, always fits.
pub fn cstream_out_size() -> usize {
    // A 32-bit checksum at the end.
    zstd_compress_bound(ZSTD_BLOCKSIZE_MAX).unwrap_or(0) + ZSTD_BLOCKHEADERSIZE + 4
}
