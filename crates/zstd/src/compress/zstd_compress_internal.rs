//! The encoder's shared types: port of the parts of
//! `compress/zstd_compress_internal.h` the port needs so far.

use crate::common::bits::{highbit32, nb_common_bytes};
use crate::common::error_private::{Result, error};
use crate::common::fse::fse_ctable_size_u32;
use crate::common::mem::{read_le16, read_le32, read_le64};
use crate::common::zstd_internal::ZSTD_BLOCKHEADERSIZE;
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

// ---------------------------------------------------------------------------
// Parameters

/// `ZSTD_compressionParameters`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct CompressionParameters {
    /// The largest match distance is `1 << window_log`.
    pub(crate) window_log: u32,
    /// The size of the chain or binary tree tables.
    pub(crate) chain_log: u32,
    /// The size of the hash table.
    pub(crate) hash_log: u32,
    /// The number of searches.
    pub(crate) search_log: u32,
    /// The shortest match.
    pub(crate) min_match: u32,
    /// How long a match must be to stop searching (or, for `fast`, the
    /// acceleration).
    pub(crate) target_length: u32,
    pub(crate) strategy: Strategy,
}

/// `ZSTD_frameParameters`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct FrameParameters {
    /// Write the content size in the frame header, when known.
    pub(crate) content_size_flag: bool,
    /// Write a checksum of the content at the end of the frame.
    pub(crate) checksum_flag: bool,
    /// Leave the dictionary ID out of the frame header.
    pub(crate) no_dict_id_flag: bool,
}

/// `ZSTD_WINDOWLOG_MAX` on 64-bit machines.
pub(crate) const ZSTD_WINDOWLOG_MAX: u32 = 31;
/// `ZSTD_HASHLOG_MIN`
pub(crate) const ZSTD_HASHLOG_MIN: u32 = 6;
/// `ZSTD_WINDOW_START_INDEX`: the index of the first byte a fresh context
/// sees, above 0 so that every position is valid.
pub(crate) const ZSTD_WINDOW_START_INDEX: u32 = 2;
/// `HASH_READ_SIZE`: the bytes the hashes read at a position.
pub(crate) const HASH_READ_SIZE: usize = 8;
/// `kSearchStrength`: how quickly the search speeds up over data without
/// matches.
pub(crate) const K_SEARCH_STRENGTH: u32 = 8;

/// `REPCODE1_TO_OFFBASE`
pub(crate) const REPCODE1_TO_OFFBASE: u32 = 1;

/// `OFFSET_TO_OFFBASE`
#[inline(always)]
pub(crate) fn offset_to_offbase(offset: u32) -> u32 {
    debug_assert!(offset > 0);
    offset + crate::common::zstd_internal::ZSTD_REP_NUM as u32
}

// ---------------------------------------------------------------------------
// The window and the match state

/// `ZSTD_window_t`, for input in one buffer: index `i` is byte `i - base`
/// of the buffer the window is over. Below `low_limit` no index is valid;
/// from `dict_limit` on, the prefix starts.
///
/// Differs from libzstd: positions are indices into the buffer instead of
/// pointers, so the window covers one buffer, without an older segment
/// (an `extDict`) yet.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Window {
    /// The index of the buffer's first byte.
    pub(crate) base: u32,
    /// The index after the last byte seen.
    pub(crate) next_src: u32,
    pub(crate) dict_limit: u32,
    pub(crate) low_limit: u32,
}

impl Window {
    /// `ZSTD_window_init`, then `ZSTD_window_update` with a buffer that does
    /// not follow anything: its first byte gets index
    /// `ZSTD_WINDOW_START_INDEX`.
    pub(crate) fn new(src_size: usize) -> Self {
        Window {
            base: ZSTD_WINDOW_START_INDEX,
            next_src: ZSTD_WINDOW_START_INDEX + src_size as u32,
            dict_limit: ZSTD_WINDOW_START_INDEX,
            low_limit: ZSTD_WINDOW_START_INDEX,
        }
    }

    /// `ZSTD_window_enforceMaxDist`, without a dictionary: makes indices
    /// more than `max_dist` before `block_end_idx` invalid.
    pub(crate) fn enforce_max_dist(&mut self, block_end_idx: u32, max_dist: u32) {
        if block_end_idx > max_dist {
            let new_low_limit = block_end_idx - max_dist;
            if self.low_limit < new_low_limit {
                self.low_limit = new_low_limit;
            }
            if self.dict_limit < self.low_limit {
                self.dict_limit = self.low_limit;
            }
        }
    }
}

/// `ZSTD_MatchState_t`: what the match finders keep from block to block.
pub(crate) struct MatchState {
    pub(crate) window: Window,
    pub(crate) hash_table: Vec<u32>,
    pub(crate) next_to_update: u32,
    /// The index after a loaded dictionary, or 0.
    pub(crate) loaded_dict_end: u32,
    pub(crate) c_params: CompressionParameters,
}

impl MatchState {
    /// `ZSTD_getLowestPrefixIndex`: the lowest index a match at `curr` may
    /// reach, at most `1 << window_log` back.
    #[inline(always)]
    pub(crate) fn lowest_prefix_index(&self, curr: u32, window_log: u32) -> u32 {
        let max_distance = 1u32 << window_log;
        let lowest_valid = self.window.dict_limit;
        let within_window = if curr.wrapping_sub(lowest_valid) > max_distance {
            curr - max_distance
        } else {
            lowest_valid
        };
        let is_dictionary = self.loaded_dict_end != 0;
        if is_dictionary {
            lowest_valid
        } else {
            within_window
        }
    }
}

/// `ZSTD_compressedBlockState_t`: the tables and repeat offsets a block
/// leaves for the next one.
#[derive(Clone)]
pub(crate) struct CompressedBlockState {
    pub(crate) entropy: Box<EntropyCTables>,
    pub(crate) rep: [u32; crate::common::zstd_internal::ZSTD_REP_NUM],
}

// ---------------------------------------------------------------------------
// Hashes

const PRIME4BYTES: u32 = 2_654_435_761;
const PRIME5BYTES: u64 = 889_523_592_379;
const PRIME6BYTES: u64 = 227_718_039_650_203;
const PRIME7BYTES: u64 = 58_295_818_150_454_627;
const PRIME8BYTES: u64 = 0xCF1B_BCDC_B7A5_6463;

/// `ZSTD_hashPtr`: the hash of the `mls` bytes at `at`, `h_bits` long. Reads
/// 4 bytes for `mls` 4 (or less), 8 otherwise.
#[inline(always)]
pub(crate) fn zstd_hash_ptr(src: &[u8], at: usize, h_bits: u32, mls: u32) -> usize {
    debug_assert!(h_bits <= 32);
    match mls {
        5 => zstd_hash_n::<5>(read_le64(src, at), PRIME5BYTES, h_bits),
        6 => zstd_hash_n::<6>(read_le64(src, at), PRIME6BYTES, h_bits),
        7 => zstd_hash_n::<7>(read_le64(src, at), PRIME7BYTES, h_bits),
        8 => (read_le64(src, at).wrapping_mul(PRIME8BYTES) >> (64 - h_bits)) as usize,
        // 4, and anything else
        _ => (read_le32(src, at).wrapping_mul(PRIME4BYTES) >> (32 - h_bits)) as usize,
    }
}

/// `ZSTD_hash5` to `ZSTD_hash7`: the low `N` bytes of `u`.
#[inline(always)]
fn zstd_hash_n<const N: u32>(u: u64, prime: u64, h_bits: u32) -> usize {
    ((u << (64 - 8 * N)).wrapping_mul(prime) >> (64 - h_bits)) as usize
}

/// `ZSTD_count`: how many bytes from `p_in` equal those from `p_match`,
/// stopping at `p_in_limit`. `p_match` is before `p_in`.
#[inline(always)]
pub(crate) fn zstd_count(
    src: &[u8],
    mut p_in: usize,
    mut p_match: usize,
    p_in_limit: usize,
) -> usize {
    let p_start = p_in;
    if p_in_limit >= 7 {
        let p_in_loop_limit = p_in_limit - 7;
        while p_in < p_in_loop_limit {
            let diff = read_le64(src, p_match) ^ read_le64(src, p_in);
            if diff != 0 {
                return p_in + nb_common_bytes(diff) as usize - p_start;
            }
            p_in += 8;
            p_match += 8;
        }
    }
    if p_in + 3 < p_in_limit && read_le32(src, p_match) == read_le32(src, p_in) {
        p_in += 4;
        p_match += 4;
    }
    if p_in + 1 < p_in_limit && read_le16(src, p_match) == read_le16(src, p_in) {
        p_in += 2;
        p_match += 2;
    }
    if p_in < p_in_limit && src[p_match] == src[p_in] {
        p_in += 1;
    }
    p_in - p_start
}

// ---------------------------------------------------------------------------
// Storing sequences

impl SeqStore {
    /// An empty store, for a block of up to `block_size` bytes.
    pub(crate) fn with_capacity(block_size: usize, max_nb_seq: usize) -> Self {
        SeqStore {
            sequences: Vec::with_capacity(max_nb_seq),
            literals: Vec::with_capacity(block_size),
            ll_code: Vec::with_capacity(max_nb_seq),
            ml_code: Vec::with_capacity(max_nb_seq),
            of_code: Vec::with_capacity(max_nb_seq),
            long_length_type: LongLengthType::None,
            long_length_pos: 0,
        }
    }

    /// `ZSTD_resetSeqStore`
    pub(crate) fn reset(&mut self) {
        self.sequences.clear();
        self.literals.clear();
        self.long_length_type = LongLengthType::None;
    }

    /// `ZSTD_storeSeq`: a sequence and its `lit_length` literals, at
    /// `literals` in `src`.
    #[inline(always)]
    pub(crate) fn store_seq(
        &mut self,
        src: &[u8],
        literals: usize,
        lit_length: usize,
        off_base: u32,
        match_length: usize,
    ) {
        self.literals
            .extend_from_slice(&src[literals..literals + lit_length]);
        self.store_seq_only(lit_length, off_base, match_length);
    }

    /// `ZSTD_storeSeqOnly`: a sequence, its literals already stored.
    #[inline(always)]
    pub(crate) fn store_seq_only(&mut self, lit_length: usize, off_base: u32, match_length: usize) {
        debug_assert!(lit_length <= crate::common::zstd_internal::ZSTD_BLOCKSIZE_MAX);
        if lit_length > 0xFFFF {
            // A block has at most one long length.
            debug_assert!(self.long_length_type == LongLengthType::None);
            self.long_length_type = LongLengthType::LiteralLength;
            self.long_length_pos = self.sequences.len() as u32;
        }
        debug_assert!(match_length >= crate::common::zstd_internal::MINMATCH as usize);
        let ml_base = match_length - crate::common::zstd_internal::MINMATCH as usize;
        if ml_base > 0xFFFF {
            debug_assert!(self.long_length_type == LongLengthType::None);
            self.long_length_type = LongLengthType::MatchLength;
            self.long_length_pos = self.sequences.len() as u32;
        }
        self.sequences.push(SeqDef {
            off_base,
            lit_length: lit_length as u16,
            ml_base: ml_base as u16,
        });
    }

    /// `ZSTD_storeLastLiterals`
    pub(crate) fn store_last_literals(&mut self, src: &[u8], anchor: usize, last_ll_size: usize) {
        self.literals
            .extend_from_slice(&src[anchor..anchor + last_ll_size]);
    }
}

/// `ZSTD_noCompressBlock`: `src` as a raw block, after its header.
pub(crate) fn zstd_no_compress_block(
    dst: &mut [u8],
    src: &[u8],
    last_block: bool,
) -> Result<usize> {
    let header = u32::from(last_block)
        + ((crate::common::zstd_internal::BlockType::Raw as u32) << 1)
        + ((src.len() as u32) << 3);
    if src.len() + ZSTD_BLOCKHEADERSIZE > dst.len() {
        return error!(DstSizeTooSmall);
    }
    dst[..3].copy_from_slice(&header.to_le_bytes()[..3]);
    dst[ZSTD_BLOCKHEADERSIZE..ZSTD_BLOCKHEADERSIZE + src.len()].copy_from_slice(src);
    Ok(ZSTD_BLOCKHEADERSIZE + src.len())
}
