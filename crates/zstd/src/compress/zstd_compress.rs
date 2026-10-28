//! Port of `compress/zstd_compress.c`: so far, the entropy coding of a
//! block from its sequences and literals.

use crate::common::bits::highbit32;
use crate::common::error_private::{ErrorCode, Result, error};
use crate::common::mem::write_le16;
use crate::common::zstd_internal::{
    DEFAULT_MAX_OFF, LL_DEFAULT_NORM, LL_DEFAULT_NORM_LOG, LL_FSE_LOG, LONGNBSEQ, MAX_LL, MAX_ML,
    MAX_OFF, MAX_SEQ, ML_DEFAULT_NORM, ML_DEFAULT_NORM_LOG, ML_FSE_LOG, OF_DEFAULT_NORM,
    OF_DEFAULT_NORM_LOG, OFF_FSE_LOG, SymbolEncodingType,
};
use crate::compress::hist::{HIST_WKSP_SIZE_U32, hist_count_fast_wksp};
use crate::compress::zstd_compress_internal::{
    EntropyCTables, FseCTables, LongLengthType, SeqStore, Strategy, zstd_ll_code, zstd_min_gain,
    zstd_ml_code,
};
use crate::compress::zstd_compress_literals::zstd_compress_literals;
use crate::compress::zstd_compress_sequences::{
    DefaultPolicy, zstd_build_ctable, zstd_encode_sequences, zstd_select_encoding_type,
};

/// `ZSTD_seqToCodes`: the codes of the sequences' lengths and offsets, into
/// the store. Returns `longOffsets`, which is only ever set on 32-bit
/// machines.
pub(crate) fn zstd_seq_to_codes(seq_store: &mut SeqStore) -> bool {
    let nb_seq = seq_store.sequences.len();
    seq_store.ll_code.resize(nb_seq, 0);
    seq_store.ml_code.resize(nb_seq, 0);
    seq_store.of_code.resize(nb_seq, 0);
    for (u, seq) in seq_store.sequences.iter().enumerate() {
        let llv = u32::from(seq.lit_length);
        let of_code = highbit32(seq.off_base);
        let mlv = u32::from(seq.ml_base);
        seq_store.ll_code[u] = zstd_ll_code(llv) as u8;
        seq_store.of_code[u] = of_code as u8;
        seq_store.ml_code[u] = zstd_ml_code(mlv) as u8;
    }
    let pos = seq_store.long_length_pos as usize;
    match seq_store.long_length_type {
        LongLengthType::LiteralLength => seq_store.ll_code[pos] = MAX_LL as u8,
        LongLengthType::MatchLength => seq_store.ml_code[pos] = MAX_ML as u8,
        LongLengthType::None => {}
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
    seq_store: &mut SeqStore,
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
    zstd_seq_to_codes(seq_store);
    let seq_store = &*seq_store;
    debug_assert!(nb_seq != 0); // ZSTD_selectEncodingType() divides by nbSeq

    let mut types = [SymbolEncodingType::Basic; 3];
    let kinds = [
        // Literal lengths.
        CodeKind {
            max: MAX_LL,
            codes: &seq_store.ll_code,
            fse_log: LL_FSE_LOG,
            default_norm: &LL_DEFAULT_NORM,
            default_norm_log: LL_DEFAULT_NORM_LOG,
            default_max: MAX_LL,
        },
        // Offsets.
        CodeKind {
            max: MAX_OFF,
            codes: &seq_store.of_code,
            fse_log: OFF_FSE_LOG,
            default_norm: &OF_DEFAULT_NORM,
            default_norm_log: OF_DEFAULT_NORM_LOG,
            default_max: DEFAULT_MAX_OFF,
        },
        // Match lengths.
        CodeKind {
            max: MAX_ML,
            codes: &seq_store.ml_code,
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
/// sequences, entropy-coded, into `dst`. Returns the size, or 0 for a block
/// to store raw instead.
#[allow(clippy::too_many_arguments)]
fn zstd_entropy_compress_seq_store_internal(
    dst: &mut [u8],
    seq_store: &mut SeqStore,
    prev_entropy: &EntropyCTables,
    next_entropy: &mut EntropyCTables,
    strategy: Strategy,
    disable_literal_compression: bool,
    bmi2: bool,
) -> Result<usize> {
    let mut count = [0u32; MAX_SEQ as usize + 1];
    let mut hist_wksp = [0u32; HIST_WKSP_SIZE_U32];
    let nb_seq = seq_store.sequences.len();
    let literals = &seq_store.literals;
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
            seq_store,
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
            &seq_store.ml_code,
            &fse.offcode_ctable,
            &seq_store.of_code,
            &fse.litlength_ctable,
            &seq_store.ll_code,
            &seq_store.sequences,
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

/// `ZSTD_entropyCompressSeqStore_wExtLitBuffer`, with the store's literals:
/// the block entropy-coded, or 0 when it is better stored raw: when it does
/// not save `ZSTD_minGain` over the `block_size` bytes it holds, or does
/// not fit `dst` where a raw block would.
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
    let dst_capacity = dst.len();
    let c_size = zstd_entropy_compress_seq_store_internal(
        dst,
        seq_store,
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
