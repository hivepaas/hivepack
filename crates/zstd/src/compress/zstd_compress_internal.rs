//! The encoder's shared types: port of the parts of
//! `compress/zstd_compress_internal.h` the port needs so far.

use crate::common::bits::{highbit32, nb_common_bytes};
use crate::common::error_private::{Result, error};
use crate::common::fse::fse_ctable_size_u32;
use crate::common::mem::{idx, read_le16, read_le32, read_le64};
use crate::common::zstd_internal::ZSTD_BLOCKHEADERSIZE;
use crate::common::zstd_internal::{LL_FSE_LOG, MAX_LL, MAX_ML, MAX_OFF, ML_FSE_LOG, OFF_FSE_LOG};
use crate::compress::huf_compress::{HUF_CTABLE_SIZE, HufCTable, HufRepeat};

/// `ZSTD_strategy`: how hard the match finder searches, from `Fast` (1) to
/// `Btultra2` (9). The port has those up to `Btlazy2` so far.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Strategy {
    /// One hash table, one candidate per position.
    Fast = 1,
    /// Two hash tables, of short and long matches.
    Dfast = 2,
    /// The first match of a hash chain or row.
    Greedy = 3,
    /// A match, or a better one at the next position.
    Lazy = 4,
    /// The same, up to two positions on.
    Lazy2 = 5,
    /// `Lazy2` over a binary tree.
    Btlazy2 = 6,
    /// The optimal parser.
    Btopt = 7,
    /// The optimal parser, counting costs more precisely.
    Btultra = 8,
    /// `Btultra`, with a first pass to gather statistics.
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

/// `ZSTD_ParamSwitch_e`: a feature on, off, or left to the library.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParamSwitch {
    /// The library's choice.
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
/// lengths (or, for the literals, `lit_len`), instead of pointers into the
/// context's workspace.
#[derive(Clone)]
pub(crate) struct SeqStore {
    pub(crate) sequences: Vec<SeqDef>,
    /// The literals, `lit_buffer[..lit_len]`, with `WILDCOPY_OVERLENGTH`
    /// bytes more for the copies in pieces of 16 that may run past them.
    lit_buffer: Vec<u8>,
    lit_len: usize,
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
/// `ZSTD_DUBT_UNSORTED_MARK`: in the binary tree of `btlazy2`, the second
/// entry of a position inserted but not sorted yet. No index is 1: they
/// start at `ZSTD_WINDOW_START_INDEX`.
pub(crate) const ZSTD_DUBT_UNSORTED_MARK: u32 = 1;
const _: () = assert!(ZSTD_DUBT_UNSORTED_MARK < ZSTD_WINDOW_START_INDEX);
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

/// Which buffer a window's segment lies in: the caller's input, or the
/// context's own input buffer when streaming with one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum WindowBuffer {
    /// None yet: the window is new.
    None,
    Input,
    InBuff,
}

/// The buffers a window's segments can lie in, for one call.
#[derive(Clone, Copy)]
pub(crate) struct Buffers<'a> {
    /// The caller's input.
    pub(crate) input: &'a [u8],
    /// The context's input buffer.
    pub(crate) in_buff: &'a [u8],
}

impl<'a> Buffers<'a> {
    /// The buffer `which` names.
    #[inline(always)]
    pub(crate) fn get(&self, which: WindowBuffer) -> &'a [u8] {
        match which {
            WindowBuffer::None => &[],
            WindowBuffer::Input => self.input,
            WindowBuffer::InBuff => self.in_buff,
        }
    }
}

/// `ZSTD_window_t`: the input seen so far, in two segments. Index `i` of
/// the prefix, from `dict_limit` on, is byte `i - base` of its buffer;
/// index `i` of the older segment (the `extDict`), from `low_limit` to
/// `dict_limit`, is byte `i - dict_base` of its buffer. Below `low_limit`
/// no index is valid.
///
/// Differs from libzstd: positions are indices into buffers instead of
/// pointers. `base` and `dict_base` are the indices of the buffers' first
/// bytes, as libzstd's pointers are the addresses of index 0; they can be
/// negative, as libzstd's can point before the buffer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Window {
    pub(crate) base: i64,
    pub(crate) dict_base: i64,
    /// The buffers the prefix and the older segment lie in.
    pub(crate) buffer: WindowBuffer,
    pub(crate) dict_buffer: WindowBuffer,
    /// The index after the last byte seen; libzstd keeps a pointer, which
    /// can be more than 4 GiB past `base`.
    pub(crate) next_src: i64,
    pub(crate) dict_limit: u32,
    pub(crate) low_limit: u32,
    pub(crate) nb_overflow_corrections: u32,
}

impl Window {
    /// `ZSTD_window_init`: empty, starting at `ZSTD_WINDOW_START_INDEX` so
    /// that every position is valid.
    pub(crate) fn new() -> Self {
        Window {
            base: 0,
            dict_base: 0,
            buffer: WindowBuffer::None,
            dict_buffer: WindowBuffer::None,
            next_src: i64::from(ZSTD_WINDOW_START_INDEX),
            dict_limit: ZSTD_WINDOW_START_INDEX,
            low_limit: ZSTD_WINDOW_START_INDEX,
            nb_overflow_corrections: 0,
        }
    }

    /// The index of byte `position` of the prefix's buffer.
    #[inline(always)]
    pub(crate) fn index(&self, position: usize) -> u32 {
        (position as i64 + self.base) as u32
    }

    /// `ZSTD_window_hasExtDict`
    pub(crate) fn has_ext_dict(&self) -> bool {
        self.low_limit < self.dict_limit
    }

    /// `ZSTD_window_update`: the window after `size` bytes at `position` of
    /// `buffer`. Returns whether they follow the bytes before. When they do
    /// not, the prefix becomes the older segment.
    pub(crate) fn update(
        &mut self,
        buffer: WindowBuffer,
        position: usize,
        size: usize,
        force_non_contiguous: bool,
    ) -> bool {
        let mut contiguous = true;
        if size == 0 {
            return contiguous;
        }
        // Do the bytes follow the ones before?
        let next_src_position = self.next_src - self.base;
        if buffer != self.buffer || position as i64 != next_src_position || force_non_contiguous {
            // Not contiguous.
            let distance_from_base = self.next_src;
            debug_assert!(distance_from_base == i64::from(distance_from_base as u32));
            self.low_limit = self.dict_limit;
            self.dict_limit = distance_from_base as u32;
            self.dict_base = self.base;
            self.dict_buffer = self.buffer;
            self.base = distance_from_base - position as i64;
            self.buffer = buffer;
            if self.dict_limit - self.low_limit < HASH_READ_SIZE as u32 {
                // An older segment too small to use.
                self.low_limit = self.dict_limit;
            }
            contiguous = false;
        }
        self.next_src = (position + size) as i64 + self.base;
        // Input over the older segment overwrites it: shrink the segment.
        if self.dict_buffer == buffer {
            let input_start = position as i64 + self.dict_base;
            let input_end = (position + size) as i64 + self.dict_base;
            if input_end > i64::from(self.low_limit) && input_start < i64::from(self.dict_limit) {
                let high_input_idx = input_end;
                let low_limit_max = if high_input_idx > i64::from(self.dict_limit) {
                    self.dict_limit
                } else {
                    high_input_idx as u32
                };
                self.low_limit = low_limit_max;
            }
        }
        contiguous
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

    /// `ZSTD_window_canOverflowCorrect`: whether the indices are large
    /// enough to lower them without losing matches.
    fn can_overflow_correct(
        &self,
        cycle_log: u32,
        max_dist: u32,
        loaded_dict_end: u32,
        curr: u32,
    ) -> bool {
        let cycle_size = 1u32 << cycle_log;
        let min_index_to_overflow_correct =
            cycle_size + max_dist.max(cycle_size) + ZSTD_WINDOW_START_INDEX;
        // Back off, so as not to spend too long correcting. If this
        // overflows, it only has to be at least the minimum.
        let adjustment = self.nb_overflow_corrections + 1;
        let adjusted_index = min_index_to_overflow_correct
            .wrapping_mul(adjustment)
            .max(min_index_to_overflow_correct);
        let index_large_enough = curr > adjusted_index;
        // Only early when the dictionary is out of the window already, not
        // to hurt the compression ratio.
        let dictionary_invalidated = curr > max_dist.wrapping_add(loaded_dict_end);
        index_large_enough && dictionary_invalidated
    }

    /// `ZSTD_window_needOverflowCorrection`: whether the indices from
    /// `src` to `src_end` (indices of the prefix) are getting too large.
    pub(crate) fn need_overflow_correction(
        &self,
        cycle_log: u32,
        max_dist: u32,
        loaded_dict_end: u32,
        src: u32,
        src_end: u32,
    ) -> bool {
        if overflow_correct_frequently()
            && self.can_overflow_correct(cycle_log, max_dist, loaded_dict_end, src)
        {
            return true;
        }
        src_end > ZSTD_CURRENT_MAX
    }

    /// `ZSTD_window_correctOverflow`: lowers the indices, keeping their low
    /// `cycle_log` bits and the last `max_dist` of history. Returns the
    /// correction, to subtract from every index stored.
    pub(crate) fn correct_overflow(&mut self, cycle_log: u32, max_dist: u32, src: u32) -> u32 {
        let cycle_size = 1u32 << cycle_log;
        let cycle_mask = cycle_size - 1;
        let curr = src;
        let current_cycle = curr & cycle_mask;
        // Keep newCurrent - maxDist >= ZSTD_WINDOW_START_INDEX.
        let current_cycle_correction = if current_cycle < ZSTD_WINDOW_START_INDEX {
            cycle_size.max(ZSTD_WINDOW_START_INDEX)
        } else {
            0
        };
        let new_current = current_cycle + current_cycle_correction + max_dist.max(cycle_size);
        let correction = curr - new_current;
        debug_assert!(max_dist & (max_dist - 1) == 0);
        debug_assert!(curr & cycle_mask == new_current & cycle_mask);
        debug_assert!(curr > new_current);

        self.base -= i64::from(correction);
        self.dict_base -= i64::from(correction);
        self.next_src -= i64::from(correction);
        if self.low_limit < correction + ZSTD_WINDOW_START_INDEX {
            self.low_limit = ZSTD_WINDOW_START_INDEX;
        } else {
            self.low_limit -= correction;
        }
        if self.dict_limit < correction + ZSTD_WINDOW_START_INDEX {
            self.dict_limit = ZSTD_WINDOW_START_INDEX;
        } else {
            self.dict_limit -= correction;
        }

        // The whole window can still be reached.
        debug_assert!(new_current >= max_dist);
        debug_assert!(new_current - max_dist >= ZSTD_WINDOW_START_INDEX);
        debug_assert!(self.low_limit <= new_current && self.dict_limit <= new_current);

        self.nb_overflow_corrections += 1;
        correction
    }
}

/// `ZSTD_CURRENT_MAX` on 64-bit machines: the largest index before the
/// indices are lowered.
pub(crate) const ZSTD_CURRENT_MAX: u32 = 3500 << 20;

#[cfg(test)]
thread_local! {
    /// `ZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY`, which libzstd sets when
    /// built for fuzzing: lower the indices as soon as possible, for the
    /// tests to reach that code.
    pub(crate) static OVERFLOW_CORRECT_FREQUENTLY: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn overflow_correct_frequently() -> bool {
    OVERFLOW_CORRECT_FREQUENTLY.with(std::cell::Cell::get)
}

#[cfg(not(test))]
#[inline(always)]
fn overflow_correct_frequently() -> bool {
    false
}

/// `ZSTD_reduceTable_internal`: lowers every index of a table by
/// `reducer_value`; those it would take below `ZSTD_WINDOW_START_INDEX`
/// become 0. With `PRESERVE_MARK`, `ZSTD_DUBT_UNSORTED_MARK` stays.
#[inline(always)]
fn zstd_reduce_table_internal<const PRESERVE_MARK: bool>(table: &mut [u32], reducer_value: u32) {
    // Indices below ZSTD_WINDOW_START_INDEX are special.
    let reducer_threshold = reducer_value + ZSTD_WINDOW_START_INDEX;
    for cell in table {
        *cell = if PRESERVE_MARK && *cell == ZSTD_DUBT_UNSORTED_MARK {
            ZSTD_DUBT_UNSORTED_MARK
        } else if *cell < reducer_threshold {
            0
        } else {
            *cell - reducer_value
        };
    }
}

/// `ZSTD_reduceTable`
pub(crate) fn zstd_reduce_table(table: &mut [u32], reducer_value: u32) {
    zstd_reduce_table_internal::<false>(table, reducer_value);
}

/// `ZSTD_reduceTable_btlazy2`: for the binary tree of `btlazy2`, whose
/// unsorted positions stay unsorted.
pub(crate) fn zstd_reduce_table_btlazy2(table: &mut [u32], reducer_value: u32) {
    zstd_reduce_table_internal::<true>(table, reducer_value);
}

/// `ZSTD_ROW_HASH_CACHE_SIZE`: how many positions ahead the row match
/// finder hashes.
pub(crate) const ZSTD_ROW_HASH_CACHE_SIZE: usize = 8;

/// `ZSTD_MatchState_t`: what the match finders keep from block to block.
pub(crate) struct MatchState {
    pub(crate) window: Window,
    /// The hash table; for the row match finder, its rows one after
    /// another.
    pub(crate) hash_table: Vec<u32>,
    /// The chain table, or for `dfast` the short hash table; empty for
    /// `fast` and the row match finder.
    pub(crate) chain_table: Vec<u32>,
    pub(crate) next_to_update: u32,
    /// The index after a loaded dictionary, or 0.
    pub(crate) loaded_dict_end: u32,
    /// `lazySkipping`: the lazy strategies, over input without matches,
    /// insert only the positions they search.
    pub(crate) lazy_skipping: bool,
    pub(crate) c_params: CompressionParameters,

    // The row match finder.
    /// `rowHashLog`: the log of the number of rows.
    pub(crate) row_hash_log: u32,
    /// `tagTable`: a byte for each entry of the hash table. The first of
    /// each row is the row's head; the others are the tags of the row's
    /// entries, the low 8 bits of their hashes.
    pub(crate) tag_table: Vec<u8>,
    /// `hashCache`: the hashes of the next positions to insert, each at
    /// its index modulo the size.
    pub(crate) hash_cache: [u32; ZSTD_ROW_HASH_CACHE_SIZE],
    /// `hashSalt`: mixed into the hashes, new at every frame.
    pub(crate) hash_salt: u64,
    /// `hashSaltEntropy`: the sum of the hashes searched, for the next
    /// salt.
    pub(crate) hash_salt_entropy: u32,
}

impl MatchState {
    /// `ZSTD_getLowestMatchIndex`: the lowest index a match at `curr` may
    /// reach, in either segment, at most `1 << window_log` back.
    #[inline(always)]
    pub(crate) fn lowest_match_index(&self, curr: u32, window_log: u32) -> u32 {
        let max_distance = 1u32 << window_log;
        let lowest_valid = self.window.low_limit;
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

/// `MEM_readLE16` on the input, its index masked with `idx`: the compiler
/// then sees that the end of the read does not overflow, which saves a
/// check.
#[inline(always)]
pub(crate) fn mem_read16(src: &[u8], at: usize) -> u16 {
    read_le16(src, idx(at))
}

/// `MEM_readLE32` on the input; see [`mem_read16`].
#[inline(always)]
pub(crate) fn mem_read32(src: &[u8], at: usize) -> u32 {
    read_le32(src, idx(at))
}

/// `MEM_readLE64` on the input; see [`mem_read16`].
#[inline(always)]
pub(crate) fn mem_read64(src: &[u8], at: usize) -> u64 {
    read_le64(src, idx(at))
}

/// `MEM_readLE32` at `at`, or `None` where the 4 bytes are not all in
/// `src`, whatever `at` is.
#[inline(always)]
pub(crate) fn mem_read32_within(src: &[u8], at: usize) -> Option<u32> {
    let bytes: [u8; 4] = src.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// `MEM_readLE64` at `at`, or `None` where the 8 bytes are not all in
/// `src`, whatever `at` is.
#[inline(always)]
pub(crate) fn mem_read64_within(src: &[u8], at: usize) -> Option<u64> {
    let bytes: [u8; 8] = src.get(at..at.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

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
    (zstd_hash_top(src, at, mls) >> (64 - h_bits)) as usize
}

/// The hash of the `mls` bytes at `at` before its shift: the hash `h_bits`
/// long is the top `h_bits` of it.
///
/// Differs from libzstd: `ZSTD_hash4` multiplies on 32 bits and shifts by
/// `32 - h_bits`. Here the 4 bytes are in the top half of a `u64`, where the
/// product has the same 32 bits, so that the hashes of every length shift by
/// `64 - h_bits`, which [`HashTable`] depends on.
#[inline(always)]
fn zstd_hash_top(src: &[u8], at: usize, mls: u32) -> u64 {
    match mls {
        5 => zstd_hash_n::<5>(mem_read64(src, at), PRIME5BYTES),
        6 => zstd_hash_n::<6>(mem_read64(src, at), PRIME6BYTES),
        7 => zstd_hash_n::<7>(mem_read64(src, at), PRIME7BYTES),
        8 => mem_read64(src, at).wrapping_mul(PRIME8BYTES),
        // 4, and anything else
        _ => (u64::from(mem_read32(src, at)) << 32).wrapping_mul(u64::from(PRIME4BYTES)),
    }
}

/// [`zstd_hash_top`] of the 8 bytes `u`, read at a position already: the
/// hash of their low `mls` bytes before its shift.
#[inline(always)]
fn zstd_hash_top_u64(u: u64, mls: u32) -> u64 {
    match mls {
        5 => zstd_hash_n::<5>(u, PRIME5BYTES),
        6 => zstd_hash_n::<6>(u, PRIME6BYTES),
        7 => zstd_hash_n::<7>(u, PRIME7BYTES),
        8 => u.wrapping_mul(PRIME8BYTES),
        // 4, and anything else: the low 4 bytes
        _ => (u << 32).wrapping_mul(u64::from(PRIME4BYTES)),
    }
}

/// `ZSTD_hash5` to `ZSTD_hash7`, before the shift: the low `N` bytes of `u`.
#[inline(always)]
fn zstd_hash_n<const N: u32>(u: u64, prime: u64) -> u64 {
    (u << (64 - 8 * N)).wrapping_mul(prime)
}

/// `ZSTD_hashPtrSalted`: [`zstd_hash_ptr`] with `salt` mixed in before the
/// shift, as a `U32`; the 4-byte hash takes the salt's low 32 bits.
///
/// The 4-byte hash is in the top half of [`zstd_hash_top`]'s `u64`, so its
/// salt goes there too: the top 32 bits are then libzstd's `U32`.
#[inline(always)]
pub(crate) fn zstd_hash_ptr_salted(src: &[u8], at: usize, h_bits: u32, mls: u32, salt: u64) -> u32 {
    debug_assert!(h_bits <= 32);
    let salt = match mls {
        5..=8 => salt,
        // 4, and anything else
        _ => u64::from(salt as u32) << 32,
    };
    ((zstd_hash_top(src, at, mls) ^ salt) >> (64 - h_bits)) as u32
}

/// A match finder's hash table of `1 << h_bits` entries, and its hashes.
///
/// Differs from libzstd: the table is cut once to the entries a hash can
/// reach, up to `u64::MAX >> shift`, `shift` being the `64 - h_bits` every
/// hash shifts by. Where the compiler sees how a hash was made, it can then
/// tell that the hash masked with `len - 1` is in bounds and that the mask
/// leaves it as it is, and drops both: indexing costs nothing. A hash kept
/// from one turn of a loop to the next may cost the mask, one `and`,
/// instead of the check.
pub(crate) struct HashTable<'a> {
    table: &'a mut [u32],
    shift: u32,
}

impl<'a> HashTable<'a> {
    /// The first `1 << h_bits` entries of `table`, which has that many.
    #[inline(always)]
    pub(crate) fn new(table: &'a mut [u32], h_bits: u32) -> Self {
        debug_assert!((1..=32).contains(&h_bits));
        let shift = 64 - h_bits;
        let table = &mut table[..=(u64::MAX >> shift) as usize];
        HashTable { table, shift }
    }

    /// `ZSTD_hashPtr`: the hash of the `mls` bytes at `at`.
    #[inline(always)]
    pub(crate) fn hash(&self, src: &[u8], at: usize, mls: u32) -> usize {
        (zstd_hash_top(src, at, mls) >> self.shift) as usize
    }

    /// [`Self::hash`] of the 8 bytes `u`, read at a position already.
    #[inline(always)]
    pub(crate) fn hash_u64(&self, u: u64, mls: u32) -> usize {
        (zstd_hash_top_u64(u, mls) >> self.shift) as usize
    }

    /// The entry of `hash`, one of the table's hashes.
    #[inline(always)]
    pub(crate) fn get(&self, hash: usize) -> u32 {
        self.table[hash & (self.table.len() - 1)]
    }

    /// Sets the entry of `hash`, one of the table's hashes.
    #[inline(always)]
    pub(crate) fn set(&mut self, hash: usize, value: u32) {
        let mask = self.table.len() - 1;
        self.table[hash & mask] = value;
    }
}

/// `ZSTD_count`: how many bytes from `p_in` equal those from `p_match`,
/// stopping at `p_in_limit`. `p_match` is before `p_in`.
#[inline(always)]
pub(crate) fn zstd_count(src: &[u8], p_in: usize, p_match: usize, p_in_limit: usize) -> usize {
    zstd_count_from(src, p_in, src, p_match, p_in_limit)
}

/// `ZSTD_count`, with the match in another buffer, `mbuf`. The match run,
/// as long as the one from `p_in` to `p_in_limit`, must be in `mbuf`.
///
/// Differs from libzstd: the first 8 bytes, where most counts end, are read
/// at the two positions, as in C; past them, the two runs are cut out of
/// their buffers once and compared 8 bytes at a time, then 4, 2 and 1, with
/// no bounds check for each read. `p_in_limit` is never past the end of
/// `src`, so taking the smaller of the two changes nothing, and lets the
/// test of the limit stand for the bounds check on `src`. Cutting the match
/// run is what needs it whole in `mbuf`, where C reads only up to the first
/// difference: every caller's match is before `p_in` in `src`, or in the
/// older segment with the count stopping at its end.
#[inline(always)]
fn zstd_count_from(
    src: &[u8],
    p_in: usize,
    mbuf: &[u8],
    p_match: usize,
    p_in_limit: usize,
) -> usize {
    let p_in_limit = p_in_limit.min(src.len());
    // Masked, so that `p_in + 8` does not overflow; see `idx`.
    let p_in = idx(p_in);
    if p_in + 8 <= p_in_limit {
        let diff = mem_read64(mbuf, p_match) ^ mem_read64(src, p_in);
        if diff != 0 {
            return nb_common_bytes(diff) as usize;
        }
        // The rest of the two runs, as long as each other.
        let input = &src[p_in + 8..p_in_limit];
        let matched = &mbuf[p_match + 8..][..input.len()];
        let (in_words, in_rest) = input.as_chunks::<8>();
        let (m_words, m_rest) = matched.as_chunks::<8>();
        for (i, (a, b)) in in_words.iter().zip(m_words).enumerate() {
            let diff = u64::from_le_bytes(*b) ^ u64::from_le_bytes(*a);
            if diff != 0 {
                return 8 + 8 * i + nb_common_bytes(diff) as usize;
            }
        }
        return 8 + 8 * in_words.len() + zstd_count_end(in_rest, m_rest);
    }
    // Under 8 bytes before the limit.
    if p_in >= p_in_limit {
        return 0;
    }
    let input = &src[p_in..p_in_limit];
    zstd_count_end(input, &mbuf[p_match..][..input.len()])
}

/// The end of `ZSTD_count`, its tests of 4, 2 and 1 bytes: how many leading
/// bytes of `input`, under 8, equal those of `matched`, which is as long.
#[inline(always)]
fn zstd_count_end(mut input: &[u8], mut matched: &[u8]) -> usize {
    debug_assert!(input.len() < 8 && matched.len() == input.len());
    let mut length = 0;
    if input.len() >= 4 && input[..4] == matched[..4] {
        length += 4;
        input = &input[4..];
        matched = &matched[4..];
    }
    if input.len() >= 2 && input[..2] == matched[..2] {
        length += 2;
        input = &input[2..];
        matched = &matched[2..];
    }
    if !input.is_empty() && input[0] == matched[0] {
        length += 1;
    }
    length
}

/// `ZSTD_count_2segments`: the length of a match at `ip` (of `src`, up to
/// `i_end`) with `match_pos` of `mbuf`, which ends at `m_end`, and goes on
/// at `i_start` of `src`: a match in the older segment may run into the
/// prefix.
#[inline(always)]
pub(crate) fn zstd_count_2segments(
    src: &[u8],
    ip: usize,
    mbuf: &[u8],
    match_pos: usize,
    i_end: usize,
    m_end: usize,
    i_start: usize,
) -> usize {
    // libzstd's `ip + (mEnd - match)` goes before `ip` for a match past the
    // segment's end, which counts nothing; so does 0.
    let v_end = (ip + m_end.saturating_sub(match_pos)).min(i_end);
    let match_length = zstd_count_from(src, ip, mbuf, match_pos, v_end);
    if match_pos + match_length != m_end {
        return match_length;
    }
    match_length + zstd_count(src, ip + match_length, i_start, i_end)
}

/// `ZSTD_index_overlap_check`: whether 4 bytes at `rep_index` lie in one
/// segment, before or from `prefix_lowest_index`.
#[inline(always)]
pub(crate) fn zstd_index_overlap_check(prefix_lowest_index: u32, rep_index: u32) -> bool {
    (prefix_lowest_index.wrapping_sub(1)).wrapping_sub(rep_index) >= 3
}

// ---------------------------------------------------------------------------
// Storing sequences

impl SeqStore {
    /// An empty store, for a block of up to `block_size` bytes.
    pub(crate) fn with_capacity(block_size: usize, max_nb_seq: usize) -> Self {
        SeqStore {
            sequences: Vec::with_capacity(max_nb_seq),
            lit_buffer: vec![0; block_size + WILDCOPY_OVERLENGTH],
            lit_len: 0,
            ll_code: Vec::with_capacity(max_nb_seq),
            ml_code: Vec::with_capacity(max_nb_seq),
            of_code: Vec::with_capacity(max_nb_seq),
            long_length_type: LongLengthType::None,
            long_length_pos: 0,
        }
    }

    /// A store of `literals` and room for `nb_seq` sequences, for tests.
    pub(crate) fn with_literals(literals: &[u8], nb_seq: usize) -> Self {
        let mut store = SeqStore::with_capacity(literals.len(), nb_seq);
        store.lit_buffer[..literals.len()].copy_from_slice(literals);
        store.lit_len = literals.len();
        store
    }

    /// The literals stored.
    #[inline(always)]
    pub(crate) fn literals(&self) -> &[u8] {
        &self.lit_buffer[..self.lit_len]
    }

    /// `ZSTD_resetSeqStore`
    pub(crate) fn reset(&mut self) {
        self.sequences.clear();
        self.lit_len = 0;
        self.long_length_type = LongLengthType::None;
    }

    /// `ZSTD_storeSeq`: a sequence and its `lit_length` literals, at
    /// `literals` in `src`.
    ///
    /// As libzstd, the literals are copied in pieces of 16 bytes when the
    /// source has 32 bytes more (libzstd counts them to the block's end,
    /// the port to its buffer's): the bytes past them land in the store's
    /// margin, where the next literals go.
    #[inline(always)]
    pub(crate) fn store_seq(
        &mut self,
        src: &[u8],
        literals: usize,
        lit_length: usize,
        off_base: u32,
        match_length: usize,
    ) {
        let lit_end = literals + lit_length;
        let op = self.lit_len;
        if lit_end + WILDCOPY_OVERLENGTH <= src.len() {
            // The common case: literals are likely short.
            copy16(&mut self.lit_buffer, op, src, literals);
            if lit_length > 16 {
                wildcopy(
                    &mut self.lit_buffer,
                    op + 16,
                    src,
                    literals + 16,
                    lit_length - 16,
                );
            }
        } else {
            // ZSTD_safecopyLiterals
            self.lit_buffer[op..op + lit_length].copy_from_slice(&src[literals..lit_end]);
        }
        self.lit_len += lit_length;
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
        let op = self.lit_len;
        self.lit_buffer[op..op + last_ll_size].copy_from_slice(&src[anchor..anchor + last_ll_size]);
        self.lit_len += last_ll_size;
    }
}

/// `WILDCOPY_OVERLENGTH`: how far past their end copies in pieces may
/// write.
pub(crate) const WILDCOPY_OVERLENGTH: usize = 32;

/// `ZSTD_copy16`
#[inline(always)]
fn copy16(dst: &mut [u8], op: usize, src: &[u8], ip: usize) {
    let (op, ip) = (idx(op), idx(ip));
    let mut piece = [0u8; 16];
    piece.copy_from_slice(&src[ip..ip + 16]);
    dst[op..op + 16].copy_from_slice(&piece);
}

/// `ZSTD_wildcopy` with `ZSTD_no_overlap`: `length` bytes and up to 32
/// more, in pieces of 16.
#[inline(always)]
fn wildcopy(dst: &mut [u8], mut op: usize, src: &[u8], mut ip: usize, length: usize) {
    let oend = op + length;
    loop {
        copy16(dst, op, src, ip);
        copy16(dst, op + 16, src, ip + 16);
        op += 32;
        ip += 32;
        if op >= oend {
            break;
        }
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
