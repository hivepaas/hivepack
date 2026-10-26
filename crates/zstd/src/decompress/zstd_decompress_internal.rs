//! The decoder's types and constants: port of
//! `decompress/zstd_decompress_internal.h`.
//!
//! `ZSTD_DCtx` holds pointers into buffers it does not own: the previous
//! output (`prefixStart`, `virtualStart`, `dictEnd`) and the literals
//! (`litPtr`, `litBuffer`, `litBufferEnd`), which may be in the output, in its
//! own extra buffer, or in the input. The port keeps indices instead, with a
//! tag saying which buffer each one is in, and passes the buffers to the
//! functions that use them.

use crate::common::fse_decompress::FseBuildDTableWksp;
use crate::common::zstd_internal::{
    LL_FSE_LOG, MAX_LL, MAX_ML, MAX_OFF, ML_FSE_LOG, OFF_FSE_LOG, REP_START_VALUE,
    ZSTD_BLOCKSIZE_MAX, ZSTD_REP_NUM,
};
use crate::decompress::huf_decompress::{HufDTable, HufDecompressWksp};

/// `LL_base`
pub(crate) const LL_BASE: [u32; MAX_LL as usize + 1] = [
    0, 1, 2, 3, 4, 5, 6, 7, //
    8, 9, 10, 11, 12, 13, 14, 15, //
    16, 18, 20, 22, 24, 28, 32, 40, //
    48, 64, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, //
    0x2000, 0x4000, 0x8000, 0x10000,
];

/// `OF_base`
pub(crate) const OF_BASE: [u32; MAX_OFF as usize + 1] = [
    0, 1, 1, 5, 0xD, 0x1D, 0x3D, 0x7D, //
    0xFD, 0x1FD, 0x3FD, 0x7FD, 0xFFD, 0x1FFD, 0x3FFD, 0x7FFD, //
    0xFFFD, 0x1FFFD, 0x3FFFD, 0x7FFFD, 0xFFFFD, 0x1FFFFD, 0x3FFFFD, 0x7FFFFD, //
    0xFFFFFD, 0x1FFFFFD, 0x3FFFFFD, 0x7FFFFFD, 0xFFFFFFD, 0x1FFFFFFD, 0x3FFFFFFD, 0x7FFFFFFD,
];

/// `OF_bits`
pub(crate) const OF_BITS: [u8; MAX_OFF as usize + 1] = [
    0, 1, 2, 3, 4, 5, 6, 7, //
    8, 9, 10, 11, 12, 13, 14, 15, //
    16, 17, 18, 19, 20, 21, 22, 23, //
    24, 25, 26, 27, 28, 29, 30, 31,
];

/// `ML_base`
pub(crate) const ML_BASE: [u32; MAX_ML as usize + 1] = [
    3, 4, 5, 6, 7, 8, 9, 10, //
    11, 12, 13, 14, 15, 16, 17, 18, //
    19, 20, 21, 22, 23, 24, 25, 26, //
    27, 28, 29, 30, 31, 32, 33, 34, //
    35, 37, 39, 41, 43, 47, 51, 59, //
    67, 83, 99, 0x83, 0x103, 0x203, 0x403, 0x803, //
    0x1003, 0x2003, 0x4003, 0x8003, 0x10003,
];

/// `ZSTD_seqSymbol`: one cell of a sequence decoding table.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct SeqSymbol {
    pub(crate) next_state: u16,
    pub(crate) nb_additional_bits: u8,
    pub(crate) nb_bits: u8,
    pub(crate) base_value: u32,
}

/// A cell, in the order libzstd writes them in its tables.
pub(crate) const fn sym(
    next_state: u16,
    nb_additional_bits: u8,
    nb_bits: u8,
    base_value: u32,
) -> SeqSymbol {
    SeqSymbol {
        next_state,
        nb_additional_bits,
        nb_bits,
        base_value,
    }
}

/// A sequence decoding table of up to `N` cells, with its header
/// (`ZSTD_seqSymbol_header`).
#[derive(Clone)]
pub(crate) struct SeqDTable<const N: usize> {
    pub(crate) fast_mode: bool,
    pub(crate) table_log: u32,
    pub(crate) cells: [SeqSymbol; N],
}

impl<const N: usize> Default for SeqDTable<N> {
    fn default() -> Self {
        SeqDTable {
            fast_mode: false,
            table_log: 0,
            cells: [SeqSymbol::default(); N],
        }
    }
}

/// The literal-length table: `SEQSYMBOL_TABLE_SIZE(LLFSELog)` less the header.
pub(crate) const LL_TABLE_CELLS: usize = 1 << LL_FSE_LOG;
/// The offset table.
pub(crate) const OF_TABLE_CELLS: usize = 1 << OFF_FSE_LOG;
/// The match-length table.
pub(crate) const ML_TABLE_CELLS: usize = 1 << ML_FSE_LOG;

/// `ZSTD_entropyDTables_t`
pub(crate) struct EntropyDTables {
    pub(crate) ll_table: SeqDTable<LL_TABLE_CELLS>,
    pub(crate) of_table: SeqDTable<OF_TABLE_CELLS>,
    pub(crate) ml_table: SeqDTable<ML_TABLE_CELLS>,
    pub(crate) huf_table: HufDTable,
    pub(crate) rep: [u32; ZSTD_REP_NUM],
    pub(crate) workspace: FseBuildDTableWksp,
}

/// `ZSTD_HUFFDTABLE_CAPACITY_LOG`
pub(crate) const ZSTD_HUFFDTABLE_CAPACITY_LOG: u32 = 12;

impl Default for EntropyDTables {
    fn default() -> Self {
        EntropyDTables {
            ll_table: SeqDTable::default(),
            of_table: SeqDTable::default(),
            ml_table: SeqDTable::default(),
            huf_table: HufDTable::new(ZSTD_HUFFDTABLE_CAPACITY_LOG),
            rep: REP_START_VALUE,
            workspace: FseBuildDTableWksp::default(),
        }
    }
}

/// Which table one of libzstd's `LLTptr`, `OFTptr`, `MLTptr` or `HUFptr`
/// points to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TableRef {
    /// The predefined table for the default distribution.
    Default,
    /// The context's own table, in `entropy`.
    Own,
}

/// `ZSTD_DECODER_INTERNAL_BUFFER`
pub(crate) const ZSTD_DECODER_INTERNAL_BUFFER: usize = 1 << 16;
/// `ZSTD_LBMIN`
const ZSTD_LBMIN: usize = 64;
/// `ZSTD_LBMAX`
const ZSTD_LBMAX: usize = 128 << 10;
/// `ZSTD_LITBUFFEREXTRASIZE`: the extra buffer that holds literals when the
/// output has no room for them.
pub(crate) const ZSTD_LITBUFFEREXTRASIZE: usize = if ZSTD_DECODER_INTERNAL_BUFFER < ZSTD_LBMIN {
    ZSTD_LBMIN
} else if ZSTD_DECODER_INTERNAL_BUFFER > ZSTD_LBMAX {
    ZSTD_LBMAX
} else {
    ZSTD_DECODER_INTERNAL_BUFFER
};

/// `WILDCOPY_OVERLENGTH`: how far libzstd's copies may run past their end.
/// The port copies exact lengths, but keeps the margins libzstd keeps, since
/// they decide where literals go and which checks apply.
pub(crate) const WILDCOPY_OVERLENGTH: usize = 32;

/// `ZSTD_litLocation_e`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum LitLocation {
    /// Entirely in the extra buffer (or, for stored literals, in the input).
    NotInDst,
    /// Entirely in the output, after where this block's output ends.
    InDst,
    /// Split between the end of this block's output and the extra buffer.
    Split,
}

/// The buffer a literal position is in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum LitBuf {
    /// The output.
    Out,
    /// `litExtraBuffer`.
    Extra,
    /// The block's input: stored literals referenced where they are.
    Src,
}

/// A position in one of the literal buffers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct LitPos {
    pub(crate) buf: LitBuf,
    pub(crate) pos: usize,
}

impl LitPos {
    pub(crate) const fn new(buf: LitBuf, pos: usize) -> Self {
        LitPos { buf, pos }
    }
}

/// The older segment of the window, libzstd's "extDict": the dictionary's
/// content, or output from before a discontinuity. libzstd describes it by
/// `virtualStart` and `dictEnd`; its length is `prefixStart - virtualStart`.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ExtDict<'a> {
    None,
    /// A buffer of its own.
    Separate(&'a [u8]),
}

impl ExtDict<'_> {
    pub(crate) fn len(&self) -> usize {
        match self {
            ExtDict::None => 0,
            ExtDict::Separate(content) => content.len(),
        }
    }
}

/// The part of `ZSTD_DCtx` that block decoding uses. The frame and
/// streaming state comes with that part of the port.
pub(crate) struct DCtx {
    pub(crate) ll_tptr: TableRef,
    pub(crate) ml_tptr: TableRef,
    pub(crate) of_tptr: TableRef,
    pub(crate) huf_ptr: TableRef,
    pub(crate) entropy: EntropyDTables,
    /// `workspace`: for building Huffman tables.
    pub(crate) workspace: HufDecompressWksp,
    /// `fParams.blockSizeMax`, used when decompressing a frame.
    pub(crate) block_size_max: usize,
    pub(crate) lit_entropy: bool,
    pub(crate) fse_entropy: bool,
    pub(crate) lit_ptr: LitPos,
    pub(crate) lit_size: usize,
    pub(crate) is_frame_decompression: bool,
    pub(crate) ddict_is_cold: bool,
    /// `disableHufAsm`: has no effect in the port, which has no assembly.
    pub(crate) disable_huf_asm: bool,
    pub(crate) lit_buffer: LitPos,
    pub(crate) lit_buffer_end: LitPos,
    pub(crate) lit_buffer_location: LitLocation,
    pub(crate) lit_extra_buffer: Box<[u8]>,
}

impl DCtx {
    pub(crate) fn new() -> Self {
        DCtx {
            ll_tptr: TableRef::Own,
            ml_tptr: TableRef::Own,
            of_tptr: TableRef::Own,
            huf_ptr: TableRef::Own,
            entropy: EntropyDTables::default(),
            workspace: HufDecompressWksp::default(),
            block_size_max: ZSTD_BLOCKSIZE_MAX,
            lit_entropy: false,
            fse_entropy: false,
            lit_ptr: LitPos::new(LitBuf::Extra, 0),
            lit_size: 0,
            is_frame_decompression: false,
            ddict_is_cold: false,
            disable_huf_asm: false,
            lit_buffer: LitPos::new(LitBuf::Extra, 0),
            lit_buffer_end: LitPos::new(LitBuf::Extra, 0),
            lit_buffer_location: LitLocation::NotInDst,
            lit_extra_buffer: vec![0; ZSTD_LITBUFFEREXTRASIZE + WILDCOPY_OVERLENGTH]
                .into_boxed_slice(),
        }
    }

    /// The entropy part of `ZSTD_decompressBegin`: no tables from earlier
    /// blocks, and the starting repeat offsets.
    pub(crate) fn reset_entropy(&mut self) {
        // libzstd sets only the descriptor; the cells are rebuilt before use.
        self.entropy.huf_table.desc = HufDTable::new_desc(ZSTD_HUFFDTABLE_CAPACITY_LOG);
        self.lit_entropy = false;
        self.fse_entropy = false;
        self.entropy.rep = REP_START_VALUE;
        self.ll_tptr = TableRef::Own;
        self.ml_tptr = TableRef::Own;
        self.of_tptr = TableRef::Own;
        self.huf_ptr = TableRef::Own;
    }
}
