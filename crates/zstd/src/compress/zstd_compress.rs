//! Port of `compress/zstd_compress.c`: so far, the entropy coding of a
//! block from its sequences and literals.

use crate::common::bits::highbit32;
use crate::common::error_private::{ErrorCode, Result, error};
use crate::common::mem::{write_le16, write_le32, write_le64};
use crate::common::xxhash::Xxh64State;
use crate::common::zstd_internal::{
    BlockType, DEFAULT_MAX_OFF, LL_DEFAULT_NORM, LL_DEFAULT_NORM_LOG, LL_FSE_LOG, LONGNBSEQ,
    MAX_LL, MAX_ML, MAX_OFF, MAX_SEQ, MIN_CBLOCK_SIZE, ML_DEFAULT_NORM, ML_DEFAULT_NORM_LOG,
    ML_FSE_LOG, OF_DEFAULT_NORM, OF_DEFAULT_NORM_LOG, OFF_FSE_LOG, REP_START_VALUE,
    SymbolEncodingType, ZSTD_BLOCKHEADERSIZE, ZSTD_BLOCKSIZE_MAX, ZSTD_MAGICNUMBER,
    ZSTD_WINDOWLOG_ABSOLUTEMIN,
};
use crate::compress::clevels::{ZSTD_DEFAULT_CPARAMETERS, ZSTD_MAX_CLEVEL};
use crate::compress::hist::{HIST_WKSP_SIZE_U32, hist_count_fast_wksp};
use crate::compress::huf_compress::HufRepeat;
use crate::compress::zstd_compress_internal::{
    CompressedBlockState, CompressionParameters, EntropyCTables, FrameParameters, FseCTables,
    FseRepeat, LongLengthType, MatchState, ParamSwitch, SeqStore, Strategy, Window,
    ZSTD_HASHLOG_MIN, ZSTD_WINDOW_START_INDEX, ZSTD_WINDOWLOG_MAX,
    zstd_literals_compression_is_disabled, zstd_ll_code, zstd_min_gain, zstd_ml_code,
    zstd_no_compress_block,
};
use crate::compress::zstd_compress_literals::zstd_compress_literals;
use crate::compress::zstd_compress_sequences::{
    DefaultPolicy, zstd_build_ctable, zstd_encode_sequences, zstd_select_encoding_type,
};
use crate::compress::zstd_double_fast::zstd_compress_block_double_fast;
use crate::compress::zstd_fast::zstd_compress_block_fast;
use crate::compress::zstd_pre_split::zstd_split_block;

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

// ---------------------------------------------------------------------------
// Parameters

/// `ZSTD_CLEVEL_DEFAULT`: the level 0 stands for.
pub(crate) const ZSTD_CLEVEL_DEFAULT: i32 = 3;
/// `ZSTD_TARGETLENGTH_MAX`
const ZSTD_TARGETLENGTH_MAX: u32 = ZSTD_BLOCKSIZE_MAX as u32;
/// `ZSTD_CONTENTSIZE_UNKNOWN`
pub(crate) const ZSTD_CONTENTSIZE_UNKNOWN: u64 = u64::MAX;
/// `ZSTD_FRAMEHEADERSIZE_MAX`
const ZSTD_FRAMEHEADERSIZE_MAX: usize = 18;
/// `ZSTD_ROW_HASH_TAG_BITS`
const ZSTD_ROW_HASH_TAG_BITS: u32 = 8;
/// `ZSTD_CURRENT_MAX` on 64-bit machines: the largest index before libzstd
/// lowers them all.
const ZSTD_CURRENT_MAX: u32 = 3500 << 20;
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

/// `ZSTD_allocateChainTable`: whether the strategy needs a chain table (for
/// `dfast`, its short hash table).
fn zstd_allocate_chain_table(strategy: Strategy, use_row_match_finder: ParamSwitch) -> bool {
    strategy != Strategy::Fast && !zstd_row_match_finder_used(strategy, use_row_match_finder)
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

/// `ZSTD_CCtx_params`: the parameters a frame is compressed with, those the
/// port has so far.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CCtxParams {
    pub(crate) c_params: CompressionParameters,
    pub(crate) f_params: FrameParameters,
    pub(crate) compression_level: i32,
    pub(crate) literal_compression_mode: ParamSwitch,
    /// The largest block, 0 for `ZSTD_BLOCKSIZE_MAX`.
    pub(crate) max_block_size: usize,
    /// 0 for the strategy's level of block splitting, 1 for none, 2 to 6.
    pub(crate) pre_block_splitter_level: i32,
}

impl CCtxParams {
    /// `ZSTD_CCtxParams_init_internal`
    pub(crate) fn new(
        c_params: CompressionParameters,
        f_params: FrameParameters,
        compression_level: i32,
    ) -> Self {
        CCtxParams {
            c_params,
            f_params,
            compression_level,
            literal_compression_mode: ParamSwitch::Auto,
            max_block_size: 0,
            pre_block_splitter_level: 0,
        }
    }
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

/// `ZSTD_CCtx`: a compression context, reused across frames.
///
/// Create one with [`CCtx::new`] and keep it: it holds tables and buffers
/// that would otherwise be set up for every call. So far it compresses whole
/// frames in one call ([`CCtx::compress`]), without a dictionary.
pub struct CCtx {
    stage: CompressionStage,
    applied_params: CCtxParams,
    /// The tables and repeat offsets of the block before, and of the one
    /// being compressed (`blockState.prevCBlock`, `nextCBlock`).
    prev_cblock: CompressedBlockState,
    next_cblock: CompressedBlockState,
    match_state: MatchState,
    seq_store: SeqStore,
    block_size_max: usize,
    is_first_block: bool,
    pledged_src_size_plus_one: u64,
    consumed_src_size: u64,
    produced_csize: u64,
    xxh_state: Xxh64State,
    dict_id: u32,
}

impl CCtx {
    /// `ZSTD_createCCtx`
    pub fn new() -> Self {
        let (c_params, f_params) = zstd_get_params_internal(
            ZSTD_CLEVEL_DEFAULT,
            ZSTD_CONTENTSIZE_UNKNOWN,
            0,
            CParamMode::Unknown,
        );
        CCtx {
            stage: CompressionStage::Created,
            applied_params: CCtxParams::new(c_params, f_params, ZSTD_CLEVEL_DEFAULT),
            prev_cblock: CompressedBlockState {
                entropy: EntropyCTables::filled(0),
                rep: REP_START_VALUE,
            },
            next_cblock: CompressedBlockState {
                entropy: EntropyCTables::filled(0),
                rep: REP_START_VALUE,
            },
            match_state: MatchState {
                window: Window::new(0),
                hash_table: Vec::new(),
                chain_table: Vec::new(),
                next_to_update: 0,
                loaded_dict_end: 0,
                c_params,
            },
            seq_store: SeqStore::with_capacity(0, 0),
            block_size_max: 0,
            is_first_block: true,
            pledged_src_size_plus_one: 0,
            consumed_src_size: 0,
            produced_csize: 0,
            xxh_state: Xxh64State::new(0),
            dict_id: 0,
        }
    }

    /// `ZSTD_resetCCtx_internal`, for a frame of `pledged_src_size` bytes,
    /// with clean tables. The indices start again at
    /// `ZSTD_WINDOW_START_INDEX`: libzstd continues them in a context used
    /// again, which compresses the same.
    fn reset_cctx_internal(&mut self, params: &CCtxParams, pledged_src_size: u64) {
        self.is_first_block = true;
        self.applied_params = *params;
        self.applied_params.max_block_size = zstd_resolve_max_block_size(params.max_block_size);
        let c_params = self.applied_params.c_params;

        let window_size = (1u64 << c_params.window_log).min(pledged_src_size).max(1) as usize;
        let block_size = self.applied_params.max_block_size.min(window_size);
        let max_nb_seq = zstd_max_nb_seq(block_size, c_params.min_match);

        self.pledged_src_size_plus_one = pledged_src_size.wrapping_add(1);
        self.consumed_src_size = 0;
        self.produced_csize = 0;
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
        ms.window = Window::new(0);
        ms.next_to_update = ms.window.dict_limit;
        ms.loaded_dict_end = 0;
        ms.hash_table.clear();
        ms.hash_table.resize(1 << c_params.hash_log, 0);
        // ZSTD_allocateChainTable: none for fast, nor for the row match
        // finder, which the port does not have yet.
        let chain_size = if zstd_allocate_chain_table(c_params.strategy, ParamSwitch::Disable) {
            1 << c_params.chain_log
        } else {
            0
        };
        ms.chain_table.clear();
        ms.chain_table.resize(chain_size, 0);
        ms.c_params = c_params;

        self.seq_store = SeqStore::with_capacity(block_size, max_nb_seq);
    }

    /// `ZSTD_compressBegin_internal`, without a dictionary.
    fn compress_begin_internal(&mut self, params: &CCtxParams, pledged_src_size: u64) {
        self.reset_cctx_internal(params, pledged_src_size);
        self.dict_id = 0;
    }

    /// `ZSTD_buildSeqStore`: the block `src[istart..iend]`'s sequences and
    /// literals. Returns whether to compress it: blocks too small are
    /// stored raw.
    fn build_seq_store(&mut self, src: &[u8], istart: usize, iend: usize) -> Result<bool> {
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
            let curr = (istart as u32).wrapping_add(ms.window.base);
            if curr > ms.next_to_update + 384 {
                ms.next_to_update = curr - 192.min(curr - ms.next_to_update - 384);
            }
        }

        // Find and store the sequences.
        self.next_cblock.rep = self.prev_cblock.rep;
        let last_ll_size = match self.applied_params.c_params.strategy {
            Strategy::Fast => zstd_compress_block_fast(
                ms,
                &mut self.seq_store,
                &mut self.next_cblock.rep,
                src,
                istart,
                iend,
            ),
            Strategy::Dfast => zstd_compress_block_double_fast(
                ms,
                &mut self.seq_store,
                &mut self.next_cblock.rep,
                src,
                istart,
                iend,
            ),
            // The other strategies are not ported yet.
            _ => return error!(ParameterUnsupported),
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

    /// `ZSTD_compressBlock_internal`, in a frame: the block's content, into
    /// `dst` after the block header. Returns its size, 0 to store the block
    /// raw, or 1 for a block of one byte repeated.
    fn compress_block_internal(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        istart: usize,
        iend: usize,
    ) -> Result<usize> {
        // RLE blocks only pay below this compressed size.
        const RLE_MAX_LENGTH: usize = 25;
        let block = &src[istart..iend];
        let mut c_size = 0;
        if self.build_seq_store(src, istart, iend)? {
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

    /// `ZSTD_compress_frameChunk`: `src` into blocks, all of it.
    fn compress_frame_chunk(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        last_frame_chunk: bool,
    ) -> Result<usize> {
        let block_size_max = self.block_size_max;
        let mut remaining = src.len();
        let mut ip = 0;
        let mut op = 0;
        let mut dst_capacity = dst.len();
        let max_dist = 1u32 << self.applied_params.c_params.window_log;
        let mut savings = self.consumed_src_size as i64 - self.produced_csize as i64;

        if self.applied_params.f_params.checksum_flag && !src.is_empty() {
            self.xxh_state.update(src);
        }

        while remaining > 0 {
            let block_size = Self::optimal_block_size(
                &src[ip..],
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

            // Overflow correction: libzstd lowers every index when they near
            // 2^32 (ZSTD_overflowCorrectIfNeeded), past 3.5 GB of input,
            // which the port does not have yet. Without a dictionary,
            // ZSTD_checkDictValidity changes nothing.
            let ms = &mut self.match_state;
            ms.window
                .enforce_max_dist((ip as u32).wrapping_add(ms.window.base), max_dist);

            // Table updates resume no sooner than lowLimit.
            if ms.next_to_update < ms.window.low_limit {
                ms.next_to_update = ms.window.low_limit;
            }

            let c_size = {
                let c_size = self.compress_block_internal(
                    &mut dst[op + ZSTD_BLOCKHEADERSIZE..op + dst_capacity],
                    src,
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
        write_le32(dst, 0, ZSTD_MAGICNUMBER);
        let mut pos = 4;
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
    /// not written yet, then `src` in blocks. `src` is the whole input: the
    /// port's window does not follow one buffer with another yet.
    fn compress_continue_internal(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
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

        if src.is_empty() {
            // No empty block without input.
            return Ok(fh_size);
        }

        // Until the port lowers indices as libzstd does when they near 2^32
        // (ZSTD_overflowCorrectIfNeeded), it refuses inputs that would take
        // them past ZSTD_CURRENT_MAX, rather than let them wrap around.
        if src.len() as u64 > u64::from(ZSTD_CURRENT_MAX - ZSTD_WINDOW_START_INDEX) {
            return error!(SrcSizeWrong);
        }

        // ZSTD_window_update: the input does not follow anything.
        {
            let ms = &mut self.match_state;
            ms.window = Window::new(src.len());
            ms.next_to_update = ms.window.dict_limit;
        }

        let c_size = self.compress_frame_chunk(&mut dst[fh_size..], src, last_frame_chunk)?;
        self.consumed_src_size += src.len() as u64;
        self.produced_csize += (c_size + fh_size) as u64;
        if self.pledged_src_size_plus_one != 0
            && self.consumed_src_size + 1 > self.pledged_src_size_plus_one
        {
            // More input than pledged.
            return error!(SrcSizeWrong);
        }
        Ok(c_size + fh_size)
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

    /// `ZSTD_compressEnd_public`: `src`, the rest of the frame, and the end
    /// of the frame.
    fn compress_end(&mut self, dst: &mut [u8], src: &[u8]) -> Result<usize> {
        let c_size = self.compress_continue_internal(dst, src, true)?;
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
        self.compress_begin_internal(params, src.len() as u64);
        self.compress_end(dst, src)
    }

    /// `ZSTD_compressCCtx`: `src` as one frame, at `compression_level`, into
    /// `dst`. Returns the frame's size.
    ///
    /// The frame has the content size and no checksum, as libzstd's, and is
    /// byte for byte the frame libzstd 1.5.7 writes. Levels go from
    /// [`min_c_level`] to [`max_c_level`]; 0 is [`default_c_level`]. Room
    /// for [`compress_bound`] bytes is always enough.
    ///
    /// Work in progress: the port has libzstd's `fast` and `dfast`
    /// strategies so far, which are every level up to 3, and level 4 for
    /// inputs over 256 KB. Other levels fail with
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
