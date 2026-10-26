//! Finite State Entropy: port of the decoding parts of `common/fse.h`.

use super::bitstream::BitDStream;

/// `FSE_MAX_MEMORY_USAGE`
pub(crate) const FSE_MAX_MEMORY_USAGE: u32 = 14;
/// `FSE_DEFAULT_MEMORY_USAGE`
pub(crate) const FSE_DEFAULT_MEMORY_USAGE: u32 = 13;
/// `FSE_MAX_SYMBOL_VALUE`
pub(crate) const FSE_MAX_SYMBOL_VALUE: u32 = 255;
/// `FSE_MAX_TABLELOG`
pub(crate) const FSE_MAX_TABLELOG: u32 = FSE_MAX_MEMORY_USAGE - 2;
/// `FSE_MAX_TABLESIZE`
pub(crate) const FSE_MAX_TABLESIZE: usize = 1 << FSE_MAX_TABLELOG;
/// `FSE_DEFAULT_TABLELOG`
pub(crate) const FSE_DEFAULT_TABLELOG: u32 = FSE_DEFAULT_MEMORY_USAGE - 2;
/// `FSE_MIN_TABLELOG`
pub(crate) const FSE_MIN_TABLELOG: u32 = 5;
/// `FSE_TABLELOG_ABSOLUTE_MAX`
pub(crate) const FSE_TABLELOG_ABSOLUTE_MAX: u32 = 15;

/// `FSE_TABLESTEP`
pub(crate) const fn fse_tablestep(table_size: u32) -> u32 {
    (table_size >> 1) + (table_size >> 3) + 3
}

/// `FSE_DTABLE_SIZE_U32`
pub(crate) const fn fse_dtable_size_u32(max_table_log: u32) -> usize {
    1 + (1 << max_table_log)
}

/// `FSE_BUILD_DTABLE_WKSP_SIZE`, in bytes.
pub(crate) const fn fse_build_dtable_wksp_size(max_table_log: u32, max_symbol_value: u32) -> usize {
    2 * (max_symbol_value as usize + 1) + (1 << max_table_log) + 8
}

/// `FSE_BUILD_DTABLE_WKSP_SIZE_U32`
pub(crate) const fn fse_build_dtable_wksp_size_u32(
    max_table_log: u32,
    max_symbol_value: u32,
) -> usize {
    fse_build_dtable_wksp_size(max_table_log, max_symbol_value).div_ceil(4)
}

/// `FSE_DECOMPRESS_WKSP_SIZE_U32`
pub(crate) const fn fse_decompress_wksp_size_u32(
    max_table_log: u32,
    max_symbol_value: u32,
) -> usize {
    fse_dtable_size_u32(max_table_log)
        + 1
        + fse_build_dtable_wksp_size_u32(max_table_log, max_symbol_value)
        + (FSE_MAX_SYMBOL_VALUE as usize + 1) * 2 / 4 // the counts, in U32
        + 1
}

/// `FSE_DECOMPRESS_WKSP_SIZE`, in bytes.
pub(crate) const fn fse_decompress_wksp_size(max_table_log: u32, max_symbol_value: u32) -> usize {
    fse_decompress_wksp_size_u32(max_table_log, max_symbol_value) * 4
}

/// `FSE_decode_t`: one cell of a decoding table.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct FseDecode {
    pub(crate) new_state: u16,
    pub(crate) symbol: u8,
    pub(crate) nb_bits: u8,
}

/// `FSE_DTable`: the header (`FSE_DTableHeader`) and room for `N` cells,
/// the table of a `tableLog` of at most `log2(N)`.
///
/// Differs from libzstd: the cells are typed instead of living in a `U32`
/// array after the header.
#[derive(Clone)]
pub(crate) struct FseDTable<const N: usize> {
    pub(crate) table_log: u16,
    pub(crate) fast_mode: bool,
    pub(crate) table: [FseDecode; N],
}

impl<const N: usize> Default for FseDTable<N> {
    fn default() -> Self {
        FseDTable {
            table_log: 0,
            fast_mode: false,
            table: [FseDecode::default(); N],
        }
    }
}

/// `FSE_DState_t`. The table is passed to each call instead of being kept
/// in the state.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FseDState {
    pub(crate) state: usize,
}

impl FseDState {
    /// `FSE_initDState`
    #[inline(always)]
    pub(crate) fn new<const N: usize>(bit_d: &mut BitDStream<'_>, dt: &FseDTable<N>) -> Self {
        let state = bit_d.read_bits(u32::from(dt.table_log)) as usize;
        bit_d.reload();
        FseDState { state }
    }

    /// `FSE_peekSymbol`
    #[inline(always)]
    pub(crate) fn peek_symbol<const N: usize>(&self, dt: &FseDTable<N>) -> u8 {
        dt.table[self.state].symbol
    }

    /// `FSE_updateState`
    #[inline(always)]
    pub(crate) fn update_state<const N: usize>(
        &mut self,
        dt: &FseDTable<N>,
        bit_d: &mut BitDStream<'_>,
    ) {
        let d_info = dt.table[self.state];
        let low_bits = bit_d.read_bits(u32::from(d_info.nb_bits));
        self.state = usize::from(d_info.new_state) + low_bits as usize;
    }

    /// `FSE_decodeSymbol`
    #[inline(always)]
    pub(crate) fn decode_symbol<const N: usize>(
        &mut self,
        dt: &FseDTable<N>,
        bit_d: &mut BitDStream<'_>,
    ) -> u8 {
        let d_info = dt.table[self.state];
        let low_bits = bit_d.read_bits(u32::from(d_info.nb_bits));
        self.state = usize::from(d_info.new_state) + low_bits as usize;
        d_info.symbol
    }

    /// `FSE_decodeSymbolFast`: only when no symbol has a probability over
    /// 50%, so that every cell reads at least one bit.
    #[inline(always)]
    pub(crate) fn decode_symbol_fast<const N: usize>(
        &mut self,
        dt: &FseDTable<N>,
        bit_d: &mut BitDStream<'_>,
    ) -> u8 {
        let d_info = dt.table[self.state];
        let low_bits = bit_d.read_bits_fast(u32::from(d_info.nb_bits));
        self.state = usize::from(d_info.new_state) + low_bits as usize;
        d_info.symbol
    }

    /// `FSE_endOfDState`
    #[inline(always)]
    pub(crate) fn end_of_dstate(&self) -> bool {
        self.state == 0
    }
}
