//! The encoder's shared types: port of the parts of
//! `compress/zstd_compress_internal.h` the port needs so far.

use crate::common::bits::highbit32;
use crate::common::fse::fse_ctable_size_u32;
use crate::common::zstd_internal::{LL_FSE_LOG, MAX_LL, MAX_ML, MAX_OFF, ML_FSE_LOG, OFF_FSE_LOG};
use crate::compress::huf_compress::{HUF_CTABLE_SIZE, HufCTable, HufRepeat};

/// `ZSTD_strategy`: how hard the match finder searches, from `Fast` (1) to
/// `Btultra2` (9).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum Strategy {
    Fast = 1,
    Dfast = 2,
    Greedy = 3,
    Lazy = 4,
    Lazy2 = 5,
    Btlazy2 = 6,
    Btopt = 7,
    Btultra = 8,
    Btultra2 = 9,
}

impl Strategy {
    /// The strategy of libzstd's number for it, 1 to 9.
    pub(crate) fn from_number(number: u32) -> Option<Strategy> {
        Some(match number {
            1 => Strategy::Fast,
            2 => Strategy::Dfast,
            3 => Strategy::Greedy,
            4 => Strategy::Lazy,
            5 => Strategy::Lazy2,
            6 => Strategy::Btlazy2,
            7 => Strategy::Btopt,
            8 => Strategy::Btultra,
            9 => Strategy::Btultra2,
            _ => return None,
        })
    }
}

/// `ZSTD_ParamSwitch_e`: a feature on, off, or left to libzstd.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ParamSwitch {
    Auto = 0,
    Enable = 1,
    Disable = 2,
}

/// `FSE_repeat`: whether a block's FSE table may be used again.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum FseRepeat {
    /// It cannot.
    None = 0,
    /// It can, once checked against the new symbols.
    Check = 1,
    /// It can, and has every symbol.
    Valid = 2,
}

/// `ZSTD_hufCTables_t`
#[derive(Clone)]
pub(crate) struct HufCTables {
    pub(crate) ctable: HufCTable,
    pub(crate) repeat_mode: HufRepeat,
}

/// The words of the offset codes' table: `FSE_CTABLE_SIZE_U32(OffFSELog, MaxOff)`.
pub(crate) const OFFCODE_CTABLE_SIZE: usize = fse_ctable_size_u32(OFF_FSE_LOG, MAX_OFF);
/// The words of the match lengths' table.
pub(crate) const MATCHLENGTH_CTABLE_SIZE: usize = fse_ctable_size_u32(ML_FSE_LOG, MAX_ML);
/// The words of the literal lengths' table.
pub(crate) const LITLENGTH_CTABLE_SIZE: usize = fse_ctable_size_u32(LL_FSE_LOG, MAX_LL);

/// `ZSTD_fseCTables_t`
#[derive(Clone)]
pub(crate) struct FseCTables {
    pub(crate) offcode_ctable: [u32; OFFCODE_CTABLE_SIZE],
    pub(crate) matchlength_ctable: [u32; MATCHLENGTH_CTABLE_SIZE],
    pub(crate) litlength_ctable: [u32; LITLENGTH_CTABLE_SIZE],
    pub(crate) offcode_repeat_mode: FseRepeat,
    pub(crate) matchlength_repeat_mode: FseRepeat,
    pub(crate) litlength_repeat_mode: FseRepeat,
}

/// `ZSTD_entropyCTables_t`: the tables a block was compressed with, which
/// the next block may use again.
#[derive(Clone)]
pub(crate) struct EntropyCTables {
    pub(crate) huf: HufCTables,
    pub(crate) fse: FseCTables,
}

impl EntropyCTables {
    /// Tables filled with `fill`, none of them to be used again. libzstd's
    /// start as whatever its workspace held; nothing reads them before a
    /// block writes them.
    pub(crate) fn filled(fill: u32) -> Box<Self> {
        Box::new(EntropyCTables {
            huf: HufCTables {
                ctable: [(u64::from(fill) << 32) | u64::from(fill); HUF_CTABLE_SIZE],
                repeat_mode: HufRepeat::None,
            },
            fse: FseCTables {
                offcode_ctable: [fill; OFFCODE_CTABLE_SIZE],
                matchlength_ctable: [fill; MATCHLENGTH_CTABLE_SIZE],
                litlength_ctable: [fill; LITLENGTH_CTABLE_SIZE],
                offcode_repeat_mode: FseRepeat::None,
                matchlength_repeat_mode: FseRepeat::None,
                litlength_repeat_mode: FseRepeat::None,
            },
        })
    }
}

/// `SeqDef`: one sequence, as the match finder stores it.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct SeqDef {
    /// The offset plus `ZSTD_REP_NUM`, or the repeat code 1, 2 or 3.
    pub(crate) off_base: u32,
    pub(crate) lit_length: u16,
    /// The match length minus `MINMATCH`.
    pub(crate) ml_base: u16,
}

/// `ZSTD_longLengthType_e`: which length of one sequence is 0x10000 more
/// than its `U16` holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum LongLengthType {
    None = 0,
    LiteralLength = 1,
    MatchLength = 2,
}

/// `SeqStore_t`: a block's sequences and literals, and the codes of the
/// sequences' lengths and offsets.
///
/// Differs from libzstd: the buffers are vectors, and the positions their
/// lengths, instead of pointers into the context's workspace.
#[derive(Clone)]
pub(crate) struct SeqStore {
    pub(crate) sequences: Vec<SeqDef>,
    pub(crate) literals: Vec<u8>,
    pub(crate) ll_code: Vec<u8>,
    pub(crate) ml_code: Vec<u8>,
    pub(crate) of_code: Vec<u8>,
    pub(crate) long_length_type: LongLengthType,
    /// The sequence with the long length.
    pub(crate) long_length_pos: u32,
}

/// `ZSTD_LLcode`: the code of a literal length.
pub(crate) fn zstd_ll_code(lit_length: u32) -> u32 {
    const LL_CODE: [u8; 64] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 16, 17, 17, 18, 18, 19, 19, 20,
        20, 20, 20, 21, 21, 21, 21, 22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 23, 23,
        24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    ];
    const LL_DELTA_CODE: u32 = 19;
    if lit_length > 63 {
        highbit32(lit_length) + LL_DELTA_CODE
    } else {
        u32::from(LL_CODE[lit_length as usize])
    }
}

/// `ZSTD_MLcode`: the code of a match length, given less `MINMATCH`.
pub(crate) fn zstd_ml_code(ml_base: u32) -> u32 {
    const ML_CODE: [u8; 128] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 32, 33, 33, 34, 34, 35, 35, 36, 36, 36, 36, 37, 37, 37, 37,
        38, 38, 38, 38, 38, 38, 38, 38, 39, 39, 39, 39, 39, 39, 39, 39, 40, 40, 40, 40, 40, 40, 40,
        40, 40, 40, 40, 40, 40, 40, 40, 40, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
        41, 41, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
        42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
    ];
    const ML_DELTA_CODE: u32 = 36;
    if ml_base > 127 {
        highbit32(ml_base) + ML_DELTA_CODE
    } else {
        u32::from(ML_CODE[ml_base as usize])
    }
}

/// `ZSTD_minGain`: how much a compressed block or literals section must
/// save to be kept.
pub(crate) fn zstd_min_gain(src_size: usize, strategy: Strategy) -> usize {
    let min_log = if strategy >= Strategy::Btultra {
        strategy as u32 - 1
    } else {
        6
    };
    (src_size >> min_log) + 2
}

/// `ZSTD_literalsCompressionIsDisabled`, from the parameters it reads.
pub(crate) fn zstd_literals_compression_is_disabled(
    literal_compression_mode: ParamSwitch,
    strategy: Strategy,
    target_length: u32,
) -> bool {
    match literal_compression_mode {
        ParamSwitch::Enable => false,
        ParamSwitch::Disable => true,
        ParamSwitch::Auto => strategy == Strategy::Fast && target_length > 0,
    }
}
