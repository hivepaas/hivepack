//! What the LZMA encoder and decoder share: port of
//! `lzma/lzma_common.h`, and the LZMA options of `api/lzma/lzma12.h`.

/// `LZMA_LCLP_MAX`.
pub const LCLP_MAX: u32 = 4;
/// `LZMA_PB_MAX`.
pub const PB_MAX: u32 = 4;
/// `LZMA_DICT_SIZE_MIN`.
pub const DICT_SIZE_MIN: u32 = 4096;
/// `LZMA_LZMA1EXT_ALLOW_EOPM`.
pub const LZMA1EXT_ALLOW_EOPM: u32 = 0x01;

/// `lzma_options_lzma`, as the decoders read it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LzmaOptions {
    /// Dictionary size in bytes.
    pub dict_size: u32,
    /// A preset dictionary, or none.
    pub preset_dict: Option<Vec<u8>>,
    /// Number of literal context bits.
    pub lc: u32,
    /// Number of literal position bits.
    pub lp: u32,
    /// Number of position bits.
    pub pb: u32,
    /// Flags for LZMA_FILTER_LZMA1EXT.
    pub ext_flags: u32,
    /// For LZMA_FILTER_LZMA1EXT: uncompressed size (low bits).
    pub ext_size_low: u32,
    /// For LZMA_FILTER_LZMA1EXT: uncompressed size (high bits).
    pub ext_size_high: u32,
}

/// `POS_STATES_MAX`.
pub(crate) const POS_STATES_MAX: usize = 1 << PB_MAX;

/// `is_lclppb_valid`.
pub(crate) fn is_lclppb_valid(options: &LzmaOptions) -> bool {
    options.lc <= LCLP_MAX
        && options.lp <= LCLP_MAX
        && options.lc + options.lp <= LCLP_MAX
        && options.pb <= PB_MAX
}

// lzma_lzma_state.
pub(crate) const STATE_LIT_LIT: u32 = 0;
pub(crate) const STATE_SHORTREP_LIT_LIT: u32 = 3;
pub(crate) const STATE_LIT_MATCH: u32 = 7;
pub(crate) const STATE_LIT_LONGREP: u32 = 8;
pub(crate) const STATE_LIT_SHORTREP: u32 = 9;
pub(crate) const STATE_NONLIT_MATCH: u32 = 10;
pub(crate) const STATE_NONLIT_REP: u32 = 11;

/// `STATES`.
pub(crate) const STATES: usize = 12;
/// `LIT_STATES`.
pub(crate) const LIT_STATES: u32 = 7;

/// `update_literal_normal`.
#[inline(always)]
pub(crate) fn update_literal_normal(state: u32) -> u32 {
    if state <= STATE_SHORTREP_LIT_LIT {
        STATE_LIT_LIT
    } else {
        state - 3
    }
}

/// `update_literal_matched`.
#[inline(always)]
pub(crate) fn update_literal_matched(state: u32) -> u32 {
    if state <= STATE_LIT_SHORTREP {
        state - 3
    } else {
        state - 6
    }
}

/// `update_match`.
#[inline(always)]
pub(crate) fn update_match(state: u32) -> u32 {
    if state < LIT_STATES {
        STATE_LIT_MATCH
    } else {
        STATE_NONLIT_MATCH
    }
}

/// `update_long_rep`.
#[inline(always)]
pub(crate) fn update_long_rep(state: u32) -> u32 {
    if state < LIT_STATES {
        STATE_LIT_LONGREP
    } else {
        STATE_NONLIT_REP
    }
}

/// `update_short_rep`.
#[inline(always)]
pub(crate) fn update_short_rep(state: u32) -> u32 {
    if state < LIT_STATES {
        STATE_LIT_SHORTREP
    } else {
        STATE_NONLIT_REP
    }
}

/// `is_literal_state`.
#[inline(always)]
pub(crate) fn is_literal_state(state: u32) -> bool {
    state < LIT_STATES
}

/// `LITERAL_CODER_SIZE`.
pub(crate) const LITERAL_CODER_SIZE: usize = 0x300;
/// `LITERAL_CODERS_MAX`.
pub(crate) const LITERAL_CODERS_MAX: usize = 1 << LCLP_MAX;

/// `literal_mask_calc`.
pub(crate) fn literal_mask_calc(lc: u32, lp: u32) -> u32 {
    (0x100 << lp) - (0x100 >> lc)
}

/// `MATCH_LEN_MIN`.
pub(crate) const MATCH_LEN_MIN: u32 = 2;
pub(crate) const LEN_LOW_BITS: u32 = 3;
pub(crate) const LEN_LOW_SYMBOLS: u32 = 1 << LEN_LOW_BITS;
pub(crate) const LEN_MID_BITS: u32 = 3;
pub(crate) const LEN_MID_SYMBOLS: u32 = 1 << LEN_MID_BITS;
pub(crate) const LEN_HIGH_BITS: u32 = 8;
pub(crate) const LEN_HIGH_SYMBOLS: u32 = 1 << LEN_HIGH_BITS;

/// `DIST_STATES`.
pub(crate) const DIST_STATES: u32 = 4;

/// `get_dist_state`.
#[inline(always)]
pub(crate) fn get_dist_state(len: u32) -> u32 {
    if len < DIST_STATES + MATCH_LEN_MIN {
        len - MATCH_LEN_MIN
    } else {
        DIST_STATES - 1
    }
}

pub(crate) const DIST_SLOT_BITS: u32 = 6;
pub(crate) const DIST_SLOTS: u32 = 1 << DIST_SLOT_BITS;
pub(crate) const DIST_MODEL_START: u32 = 4;
pub(crate) const DIST_MODEL_END: u32 = 14;
pub(crate) const FULL_DISTANCES_BITS: u32 = DIST_MODEL_END / 2;
pub(crate) const FULL_DISTANCES: u32 = 1 << FULL_DISTANCES_BITS;
pub(crate) const ALIGN_BITS: u32 = 4;
pub(crate) const ALIGN_SIZE: u32 = 1 << ALIGN_BITS;
