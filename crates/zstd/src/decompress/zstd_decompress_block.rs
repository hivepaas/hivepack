//! Decoding blocks: port of `decompress/zstd_decompress_block.c`.
//!
//! A compressed block holds a literals section (stored, RLE, or Huffman
//! coded) and a sequences section: FSE-coded (literal length, match length,
//! offset) triples that rebuild the block from the literals and the window.
//!
//! Where libzstd copies with `ZSTD_wildcopy`, which may write up to 32 bytes
//! past the end of a copy, the port copies the exact length, with the same
//! result: the extra bytes libzstd writes always land where later writes go,
//! on literals already read, or past the decoded output. libzstd keeps
//! literals in the output buffer when it has room (`ZSTD_in_dst`,
//! `ZSTD_split`), and the port puts them in the same place, since corrupted
//! input can make the output run over them; the checks libzstd makes there
//! are ported too.

use crate::common::bits::highbit32;
use crate::common::bitstream::BitDStream;
use crate::common::entropy_common::fse_read_ncount;
use crate::common::error_private::{Error, ErrorCode, Result, error};
use crate::common::fse::fse_tablestep;
use crate::common::fse_decompress::FseBuildDTableWksp;
use crate::common::huf::{HUF_FLAGS_BMI2, HUF_FLAGS_DISABLE_ASM};
use crate::common::mem::{read_le16, read_le24, read_le32};
use crate::common::zstd_internal::{
    BlockType, LL_BITS, LL_DEFAULT_NORM_LOG, LL_FSE_LOG, LONGNBSEQ, MAX_LL, MAX_ML, MAX_OFF,
    MAX_SEQ, MIN_CBLOCK_SIZE, MIN_LITERALS_FOR_4_STREAMS, MIN_SEQUENCES_SIZE, ML_BITS,
    ML_DEFAULT_NORM_LOG, ML_FSE_LOG, OF_DEFAULT_NORM_LOG, OFF_FSE_LOG, SymbolEncodingType,
    ZSTD_BLOCKHEADERSIZE, ZSTD_BLOCKSIZE_MAX, ZSTD_REP_NUM,
};
use crate::decompress::huf_decompress::{
    huf_decompress1x_using_dtable, huf_decompress1x1_dctx_wksp, huf_decompress4x_huf_only_wksp,
    huf_decompress4x_using_dtable,
};
use crate::decompress::zstd_decompress_internal::{
    DCtx, EntropyDTables, ExtDict, LL_BASE, LitBuf, LitLocation, LitPos, ML_BASE, OF_BASE, OF_BITS,
    SeqDTable, SeqSymbol, TableRef, WILDCOPY_OVERLENGTH, ZSTD_LITBUFFEREXTRASIZE, sym,
};

/// How often each path ran, so the tests can check they reach all of them:
/// literals in the extra buffer, in the input, in the output, split; then
/// the plain, split and prefetching sequence loops.
#[cfg(test)]
pub(crate) static PATH_RUNS: [std::sync::atomic::AtomicUsize; 7] =
    [const { std::sync::atomic::AtomicUsize::new(0) }; 7];

#[cfg(test)]
fn count_path(which: usize) {
    PATH_RUNS[which].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(not(test))]
#[inline(always)]
fn count_path(_which: usize) {}

// Makes every block use the prefetching sequence loop, as libzstd does after
// loading a dictionary or with a history over 16 MiB, which the block tests
// cannot reach. Valid input decodes the same with every loop.
#[cfg(test)]
thread_local! {
    pub(crate) static FORCE_LONG_LOOP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn force_long_loop() -> bool {
    FORCE_LONG_LOOP.with(std::cell::Cell::get)
}

#[cfg(not(test))]
#[inline(always)]
fn force_long_loop() -> bool {
    false
}

// ---------------------------------------------------------------------------
// Block headers
// ---------------------------------------------------------------------------

/// `ZSTD_blockSizeMax`
fn block_size_max(dctx: &DCtx) -> usize {
    let block_size_max = if dctx.is_frame_decompression {
        dctx.f_params.block_size_max as usize
    } else {
        ZSTD_BLOCKSIZE_MAX
    };
    debug_assert!(block_size_max <= ZSTD_BLOCKSIZE_MAX);
    block_size_max
}

/// `blockProperties_t`
#[derive(Clone, Copy, Debug)]
pub(crate) struct BlockProperties {
    pub(crate) block_type: BlockType,
    pub(crate) last_block: bool,
    /// Only meaningful for RLE blocks: the size they decode to.
    pub(crate) orig_size: u32,
}

/// `ZSTD_getcBlockSize`: reads a block header. Returns the size of the
/// block's content: 1 for RLE blocks.
pub(crate) fn get_c_block_size(src: &[u8], bp: &mut BlockProperties) -> Result<usize> {
    if src.len() < ZSTD_BLOCKHEADERSIZE {
        return error!(SrcSizeWrong);
    }
    let c_block_header = read_le24(src, 0);
    let c_size = c_block_header >> 3;
    bp.last_block = c_block_header & 1 != 0;
    bp.block_type = match (c_block_header >> 1) & 3 {
        0 => BlockType::Raw,
        1 => BlockType::Rle,
        2 => BlockType::Compressed,
        _ => BlockType::Reserved,
    };
    bp.orig_size = c_size;
    if bp.block_type == BlockType::Rle {
        return Ok(1);
    }
    if bp.block_type == BlockType::Reserved {
        return error!(CorruptionDetected);
    }
    Ok(c_size as usize)
}

// ---------------------------------------------------------------------------
// Literals
// ---------------------------------------------------------------------------

/// `ZSTD_allocateLiteralsBuffer`: where this block's literals go. `dst` is
/// where the block's output starts in the output buffer.
fn allocate_literals_buffer(
    dctx: &mut DCtx,
    dst: usize,
    dst_capacity: usize,
    lit_size: usize,
    streaming: bool,
    expected_write_size: usize,
    split_immediately: bool,
) {
    let block_size_max = block_size_max(dctx);
    debug_assert!(lit_size <= block_size_max);
    debug_assert!(expected_write_size <= block_size_max);
    if !streaming
        && dst_capacity > block_size_max + WILDCOPY_OVERLENGTH + lit_size + WILDCOPY_OVERLENGTH
    {
        // Not streaming, so there is no window to protect: put the
        // literals after where this block's output can reach.
        dctx.lit_buffer = LitPos::new(LitBuf::Out, dst + block_size_max + WILDCOPY_OVERLENGTH);
        dctx.lit_buffer_end = LitPos::new(LitBuf::Out, dctx.lit_buffer.pos + lit_size);
        dctx.lit_buffer_location = LitLocation::InDst;
    } else if lit_size <= ZSTD_LITBUFFEREXTRASIZE {
        // They fit in the extra buffer: no need to split them.
        dctx.lit_buffer = LitPos::new(LitBuf::Extra, 0);
        dctx.lit_buffer_end = LitPos::new(LitBuf::Extra, lit_size);
        dctx.lit_buffer_location = LitLocation::NotInDst;
    } else {
        debug_assert!(block_size_max > ZSTD_LITBUFFEREXTRASIZE);
        // Split: the tail in the extra buffer, the rest at the end of this
        // block's output, with WILDCOPY_OVERLENGTH bytes of room. This never
        // reaches past the block's maximum size, which would overwrite the
        // window when streaming.
        if split_immediately {
            let start = dst + expected_write_size - lit_size + ZSTD_LITBUFFEREXTRASIZE
                - WILDCOPY_OVERLENGTH;
            dctx.lit_buffer = LitPos::new(LitBuf::Out, start);
            dctx.lit_buffer_end =
                LitPos::new(LitBuf::Out, start + lit_size - ZSTD_LITBUFFEREXTRASIZE);
        } else {
            // All in the output while Huffman decoding; part moves to the
            // extra buffer afterwards.
            dctx.lit_buffer = LitPos::new(LitBuf::Out, dst + expected_write_size - lit_size);
            dctx.lit_buffer_end = LitPos::new(LitBuf::Out, dst + expected_write_size);
        }
        dctx.lit_buffer_location = LitLocation::Split;
        debug_assert!(dctx.lit_buffer_end.pos <= dst + expected_write_size);
    }
}

/// The literal buffer `pos` is in, as a mutable slice of `len` bytes.
fn lit_buffer_mut<'a>(
    out: &'a mut [u8],
    extra: &'a mut [u8],
    pos: LitPos,
    len: usize,
) -> &'a mut [u8] {
    match pos.buf {
        LitBuf::Out => &mut out[pos.pos..pos.pos + len],
        LitBuf::Extra | LitBuf::Src => &mut extra[pos.pos..pos.pos + len],
    }
}

/// `ZSTD_decodeLiteralsBlock`: reads the literals section at the start of
/// `src`, a compressed block. Returns its size.
fn decode_literals_block(
    dctx: &mut DCtx,
    src: &[u8],
    out: &mut [u8],
    dst: usize,
    dst_capacity: usize,
    streaming: bool,
    dict: Option<&EntropyDTables>,
) -> Result<usize> {
    let src_size = src.len();
    if src_size < MIN_CBLOCK_SIZE {
        return error!(CorruptionDetected);
    }
    let istart = src;
    let lit_enc_type = match istart[0] & 3 {
        0 => SymbolEncodingType::Basic,
        1 => SymbolEncodingType::Rle,
        2 => SymbolEncodingType::Compressed,
        _ => SymbolEncodingType::Repeat,
    };
    let block_size_max = block_size_max(dctx);

    match lit_enc_type {
        SymbolEncodingType::Repeat | SymbolEncodingType::Compressed => {
            if lit_enc_type == SymbolEncodingType::Repeat && !dctx.lit_entropy {
                return error!(DictionaryCorrupted);
            }
            if src_size < 5 {
                // Up to 5 bytes are read for the header below.
                return error!(CorruptionDetected);
            }
            let lhl_code = (istart[0] >> 2) & 3;
            let lhc = read_le32(istart, 0);
            let expected_write_size = block_size_max.min(dst_capacity);
            // libzstd passes these on; they do not change what decoding does.
            let flags = HUF_FLAGS_BMI2
                | if dctx.disable_huf_asm {
                    HUF_FLAGS_DISABLE_ASM
                } else {
                    0
                };
            let (single_stream, lh_size, lit_size, lit_c_size) = match lhl_code {
                // 2 - 2 - 10 - 10
                0 | 1 => (
                    lhl_code == 0,
                    3,
                    ((lhc >> 4) & 0x3FF) as usize,
                    ((lhc >> 14) & 0x3FF) as usize,
                ),
                // 2 - 2 - 14 - 14
                2 => (
                    false,
                    4,
                    ((lhc >> 4) & 0x3FFF) as usize,
                    (lhc >> 18) as usize,
                ),
                // 2 - 2 - 18 - 18
                _ => (
                    false,
                    5,
                    ((lhc >> 4) & 0x3FFFF) as usize,
                    (lhc >> 22) as usize + (usize::from(istart[4]) << 10),
                ),
            };
            // libzstd also refuses literals when dst is NULL; the port's
            // output always exists, and an empty one fails below.
            if lit_size > block_size_max {
                return error!(CorruptionDetected);
            }
            if !single_stream && lit_size < MIN_LITERALS_FOR_4_STREAMS {
                return error!(LiteralsHeaderWrong);
            }
            if lit_c_size + lh_size > src_size {
                return error!(CorruptionDetected);
            }
            if expected_write_size < lit_size {
                return error!(DstSizeTooSmall);
            }
            allocate_literals_buffer(
                dctx,
                dst,
                dst_capacity,
                lit_size,
                streaming,
                expected_write_size,
                false,
            );

            let c_src = &istart[lh_size..lh_size + lit_c_size];
            let lit_buffer = dctx.lit_buffer;
            let huf_success = {
                let lits = lit_buffer_mut(out, &mut dctx.lit_extra_buffer, lit_buffer, lit_size);
                if lit_enc_type == SymbolEncodingType::Repeat {
                    let huf_table = match (dctx.huf_ptr, dict) {
                        (TableRef::Dict, Some(dict)) => &dict.huf_table,
                        _ => &dctx.entropy.huf_table,
                    };
                    if single_stream {
                        huf_decompress1x_using_dtable(lits, c_src, huf_table, flags)
                    } else {
                        debug_assert!(lit_size >= MIN_LITERALS_FOR_4_STREAMS);
                        huf_decompress4x_using_dtable(lits, c_src, huf_table, flags)
                    }
                } else if single_stream {
                    huf_decompress1x1_dctx_wksp(
                        &mut dctx.entropy.huf_table,
                        lits,
                        c_src,
                        &mut dctx.workspace,
                        flags,
                    )
                } else {
                    huf_decompress4x_huf_only_wksp(
                        &mut dctx.entropy.huf_table,
                        lits,
                        c_src,
                        &mut dctx.workspace,
                        flags,
                    )
                }
            };
            if dctx.lit_buffer_location == LitLocation::Split {
                // Move the tail to the extra buffer, and the rest up to leave
                // WILDCOPY_OVERLENGTH bytes before the extra buffer's part.
                debug_assert!(lit_size > ZSTD_LITBUFFEREXTRASIZE);
                let end = dctx.lit_buffer_end.pos;
                dctx.lit_extra_buffer[..ZSTD_LITBUFFEREXTRASIZE]
                    .copy_from_slice(&out[end - ZSTD_LITBUFFEREXTRASIZE..end]);
                let start = dctx.lit_buffer.pos;
                out.copy_within(
                    start..start + lit_size - ZSTD_LITBUFFEREXTRASIZE,
                    start + ZSTD_LITBUFFEREXTRASIZE - WILDCOPY_OVERLENGTH,
                );
                dctx.lit_buffer.pos += ZSTD_LITBUFFEREXTRASIZE - WILDCOPY_OVERLENGTH;
                dctx.lit_buffer_end.pos -= WILDCOPY_OVERLENGTH;
                debug_assert!(dctx.lit_buffer_end.pos <= dst + block_size_max);
            }

            if huf_success.is_err() {
                return error!(CorruptionDetected);
            }

            dctx.lit_ptr = dctx.lit_buffer;
            dctx.lit_size = lit_size;
            dctx.lit_entropy = true;
            if lit_enc_type == SymbolEncodingType::Compressed {
                dctx.huf_ptr = TableRef::Own;
            }
            Ok(lit_c_size + lh_size)
        }

        SymbolEncodingType::Basic => {
            let lhl_code = (istart[0] >> 2) & 3;
            let expected_write_size = block_size_max.min(dst_capacity);
            let (lh_size, lit_size) = match lhl_code {
                0 | 2 => (1, usize::from(istart[0] >> 3)),
                1 => (2, usize::from(read_le16(istart, 0) >> 4)),
                _ => {
                    if src_size < 3 {
                        return error!(CorruptionDetected);
                    }
                    (3, (read_le24(istart, 0) >> 4) as usize)
                }
            };

            if lit_size > block_size_max {
                return error!(CorruptionDetected);
            }
            if expected_write_size < lit_size {
                return error!(DstSizeTooSmall);
            }
            allocate_literals_buffer(
                dctx,
                dst,
                dst_capacity,
                lit_size,
                streaming,
                expected_write_size,
                true,
            );
            if lh_size + lit_size + WILDCOPY_OVERLENGTH > src_size {
                // Referencing the input would let copies read past it.
                if lit_size + lh_size > src_size {
                    return error!(CorruptionDetected);
                }
                let lits = &istart[lh_size..lh_size + lit_size];
                let lit_buffer = dctx.lit_buffer;
                if dctx.lit_buffer_location == LitLocation::Split {
                    let first = lit_size - ZSTD_LITBUFFEREXTRASIZE;
                    out[lit_buffer.pos..lit_buffer.pos + first].copy_from_slice(&lits[..first]);
                    dctx.lit_extra_buffer[..ZSTD_LITBUFFEREXTRASIZE]
                        .copy_from_slice(&lits[first..]);
                } else {
                    lit_buffer_mut(out, &mut dctx.lit_extra_buffer, lit_buffer, lit_size)
                        .copy_from_slice(lits);
                }
                dctx.lit_ptr = dctx.lit_buffer;
                dctx.lit_size = lit_size;
                return Ok(lh_size + lit_size);
            }
            // Reference the literals where they are, in the input.
            dctx.lit_ptr = LitPos::new(LitBuf::Src, lh_size);
            dctx.lit_size = lit_size;
            dctx.lit_buffer_end = LitPos::new(LitBuf::Src, lh_size + lit_size);
            dctx.lit_buffer_location = LitLocation::NotInDst;
            Ok(lh_size + lit_size)
        }

        SymbolEncodingType::Rle => {
            let lhl_code = (istart[0] >> 2) & 3;
            let expected_write_size = block_size_max.min(dst_capacity);
            let (lh_size, lit_size) = match lhl_code {
                0 | 2 => (1, usize::from(istart[0] >> 3)),
                1 => {
                    if src_size < 3 {
                        return error!(CorruptionDetected);
                    }
                    (2, usize::from(read_le16(istart, 0) >> 4))
                }
                _ => {
                    if src_size < 4 {
                        return error!(CorruptionDetected);
                    }
                    (3, (read_le24(istart, 0) >> 4) as usize)
                }
            };
            if lit_size > block_size_max {
                return error!(CorruptionDetected);
            }
            if expected_write_size < lit_size {
                return error!(DstSizeTooSmall);
            }
            allocate_literals_buffer(
                dctx,
                dst,
                dst_capacity,
                lit_size,
                streaming,
                expected_write_size,
                true,
            );
            let value = istart[lh_size];
            let lit_buffer = dctx.lit_buffer;
            if dctx.lit_buffer_location == LitLocation::Split {
                let first = lit_size - ZSTD_LITBUFFEREXTRASIZE;
                out[lit_buffer.pos..lit_buffer.pos + first].fill(value);
                dctx.lit_extra_buffer[..ZSTD_LITBUFFEREXTRASIZE].fill(value);
            } else {
                lit_buffer_mut(out, &mut dctx.lit_extra_buffer, lit_buffer, lit_size).fill(value);
            }
            dctx.lit_ptr = dctx.lit_buffer;
            dctx.lit_size = lit_size;
            Ok(lh_size + 1)
        }
    }
}

// ---------------------------------------------------------------------------
// Sequence tables
// ---------------------------------------------------------------------------

/// `LL_defaultDTable`: the table for the default distribution, with a log of 6
/// (its header in libzstd: fast mode, and that log).
pub(crate) const LL_DEFAULT_DTABLE: [SeqSymbol; 64] = [
    sym(0, 0, 4, 0),
    sym(16, 0, 4, 0),
    sym(32, 0, 5, 1),
    sym(0, 0, 5, 3),
    sym(0, 0, 5, 4),
    sym(0, 0, 5, 6),
    sym(0, 0, 5, 7),
    sym(0, 0, 5, 9),
    sym(0, 0, 5, 10),
    sym(0, 0, 5, 12),
    sym(0, 0, 6, 14),
    sym(0, 1, 5, 16),
    sym(0, 1, 5, 20),
    sym(0, 1, 5, 22),
    sym(0, 2, 5, 28),
    sym(0, 3, 5, 32),
    sym(0, 4, 5, 48),
    sym(32, 6, 5, 64),
    sym(0, 7, 5, 128),
    sym(0, 8, 6, 256),
    sym(0, 10, 6, 1024),
    sym(0, 12, 6, 4096),
    sym(32, 0, 4, 0),
    sym(0, 0, 4, 1),
    sym(0, 0, 5, 2),
    sym(32, 0, 5, 4),
    sym(0, 0, 5, 5),
    sym(32, 0, 5, 7),
    sym(0, 0, 5, 8),
    sym(32, 0, 5, 10),
    sym(0, 0, 5, 11),
    sym(0, 0, 6, 13),
    sym(32, 1, 5, 16),
    sym(0, 1, 5, 18),
    sym(32, 1, 5, 22),
    sym(0, 2, 5, 24),
    sym(32, 3, 5, 32),
    sym(0, 3, 5, 40),
    sym(0, 6, 4, 64),
    sym(16, 6, 4, 64),
    sym(32, 7, 5, 128),
    sym(0, 9, 6, 512),
    sym(0, 11, 6, 2048),
    sym(48, 0, 4, 0),
    sym(16, 0, 4, 1),
    sym(32, 0, 5, 2),
    sym(32, 0, 5, 3),
    sym(32, 0, 5, 5),
    sym(32, 0, 5, 6),
    sym(32, 0, 5, 8),
    sym(32, 0, 5, 9),
    sym(32, 0, 5, 11),
    sym(32, 0, 5, 12),
    sym(0, 0, 6, 15),
    sym(32, 1, 5, 18),
    sym(32, 1, 5, 20),
    sym(32, 2, 5, 24),
    sym(32, 2, 5, 28),
    sym(32, 3, 5, 40),
    sym(32, 4, 5, 48),
    sym(0, 16, 6, 65536),
    sym(0, 15, 6, 32768),
    sym(0, 14, 6, 16384),
    sym(0, 13, 6, 8192),
];

/// `OF_defaultDTable`: the table for the default distribution, with a log of 5
/// (its header in libzstd: fast mode, and that log).
pub(crate) const OF_DEFAULT_DTABLE: [SeqSymbol; 32] = [
    sym(0, 0, 5, 0),
    sym(0, 6, 4, 61),
    sym(0, 9, 5, 509),
    sym(0, 15, 5, 32765),
    sym(0, 21, 5, 2097149),
    sym(0, 3, 5, 5),
    sym(0, 7, 4, 125),
    sym(0, 12, 5, 4093),
    sym(0, 18, 5, 262141),
    sym(0, 23, 5, 8388605),
    sym(0, 5, 5, 29),
    sym(0, 8, 4, 253),
    sym(0, 14, 5, 16381),
    sym(0, 20, 5, 1048573),
    sym(0, 2, 5, 1),
    sym(16, 7, 4, 125),
    sym(0, 11, 5, 2045),
    sym(0, 17, 5, 131069),
    sym(0, 22, 5, 4194301),
    sym(0, 4, 5, 13),
    sym(16, 8, 4, 253),
    sym(0, 13, 5, 8189),
    sym(0, 19, 5, 524285),
    sym(0, 1, 5, 1),
    sym(16, 6, 4, 61),
    sym(0, 10, 5, 1021),
    sym(0, 16, 5, 65533),
    sym(0, 28, 5, 268435453),
    sym(0, 27, 5, 134217725),
    sym(0, 26, 5, 67108861),
    sym(0, 25, 5, 33554429),
    sym(0, 24, 5, 16777213),
];

/// `ML_defaultDTable`: the table for the default distribution, with a log of 6
/// (its header in libzstd: fast mode, and that log).
pub(crate) const ML_DEFAULT_DTABLE: [SeqSymbol; 64] = [
    sym(0, 0, 6, 3),
    sym(0, 0, 4, 4),
    sym(32, 0, 5, 5),
    sym(0, 0, 5, 6),
    sym(0, 0, 5, 8),
    sym(0, 0, 5, 9),
    sym(0, 0, 5, 11),
    sym(0, 0, 6, 13),
    sym(0, 0, 6, 16),
    sym(0, 0, 6, 19),
    sym(0, 0, 6, 22),
    sym(0, 0, 6, 25),
    sym(0, 0, 6, 28),
    sym(0, 0, 6, 31),
    sym(0, 0, 6, 34),
    sym(0, 1, 6, 37),
    sym(0, 1, 6, 41),
    sym(0, 2, 6, 47),
    sym(0, 3, 6, 59),
    sym(0, 4, 6, 83),
    sym(0, 7, 6, 131),
    sym(0, 9, 6, 515),
    sym(16, 0, 4, 4),
    sym(0, 0, 4, 5),
    sym(32, 0, 5, 6),
    sym(0, 0, 5, 7),
    sym(32, 0, 5, 9),
    sym(0, 0, 5, 10),
    sym(0, 0, 6, 12),
    sym(0, 0, 6, 15),
    sym(0, 0, 6, 18),
    sym(0, 0, 6, 21),
    sym(0, 0, 6, 24),
    sym(0, 0, 6, 27),
    sym(0, 0, 6, 30),
    sym(0, 0, 6, 33),
    sym(0, 1, 6, 35),
    sym(0, 1, 6, 39),
    sym(0, 2, 6, 43),
    sym(0, 3, 6, 51),
    sym(0, 4, 6, 67),
    sym(0, 5, 6, 99),
    sym(0, 8, 6, 259),
    sym(32, 0, 4, 4),
    sym(48, 0, 4, 4),
    sym(16, 0, 4, 5),
    sym(32, 0, 5, 7),
    sym(32, 0, 5, 8),
    sym(32, 0, 5, 10),
    sym(32, 0, 5, 11),
    sym(0, 0, 6, 14),
    sym(0, 0, 6, 17),
    sym(0, 0, 6, 20),
    sym(0, 0, 6, 23),
    sym(0, 0, 6, 26),
    sym(0, 0, 6, 29),
    sym(0, 0, 6, 32),
    sym(0, 16, 6, 65539),
    sym(0, 15, 6, 32771),
    sym(0, 14, 6, 16387),
    sym(0, 13, 6, 8195),
    sym(0, 12, 6, 4099),
    sym(0, 11, 6, 2051),
    sym(0, 10, 6, 1027),
];
/// `ZSTD_buildSeqTable_rle`: a table of one cell, for an RLE-coded field.
fn build_seq_table_rle<const N: usize>(dt: &mut SeqDTable<N>, base_value: u32, nb_add_bits: u8) {
    dt.table_log = 0;
    dt.fast_mode = false;
    dt.cells[0] = SeqSymbol {
        nb_bits: 0,
        next_state: 0,
        nb_additional_bits: nb_add_bits,
        base_value,
    };
}

/// `ZSTD_buildFSETable`: the decoding table of one field (literal lengths,
/// match lengths or offsets). Cannot fail: `normalized_counter` comes from
/// [`fse_read_ncount`], with `table_log` checked.
pub(crate) fn build_fse_table<const N: usize>(
    dt: &mut SeqDTable<N>,
    normalized_counter: &[i16],
    max_symbol_value: u32,
    base_value: &[u32],
    nb_additional_bits: &[u8],
    table_log: u32,
    wksp: &mut FseBuildDTableWksp,
) {
    let max_sv1 = max_symbol_value as usize + 1;
    let table_size = 1u32 << table_log;
    let mut high_threshold = table_size - 1;
    debug_assert!(max_symbol_value <= MAX_SEQ);
    debug_assert!(table_size as usize <= N);

    let table_decode = &mut dt.cells;
    // `symbolNext` and `spread` share libzstd's workspace; the port's FSE
    // workspace has room for both.
    let symbol_next = &mut wksp.symbol_next;

    // Init, lay down low-probability symbols.
    {
        dt.table_log = table_log;
        dt.fast_mode = true;
        let large_limit = (1i32 << (table_log - 1)) as i16;
        for s in 0..max_sv1 {
            if normalized_counter[s] == -1 {
                table_decode[high_threshold as usize].base_value = s as u32;
                high_threshold = high_threshold.wrapping_sub(1);
                symbol_next[s] = 1;
            } else {
                if normalized_counter[s] >= large_limit {
                    dt.fast_mode = false;
                }
                debug_assert!(normalized_counter[s] >= 0);
                symbol_next[s] = normalized_counter[s] as u16;
            }
        }
    }

    // Spread symbols.
    if high_threshold == table_size - 1 {
        let table_mask = (table_size - 1) as usize;
        let step = fse_tablestep(table_size) as usize;
        // Lay down the symbols in order, eight bytes at a time; the spread
        // buffer has 8 bytes to spare.
        {
            let spread = &mut wksp.spread;
            let mut pos = 0usize;
            for s in 0..max_sv1 {
                let n = i32::from(normalized_counter[s]);
                spread[pos..pos + 8].fill(s as u8);
                let mut i = 8;
                while i < n {
                    spread[pos + i as usize..pos + i as usize + 8].fill(s as u8);
                    i += 8;
                }
                pos += n as usize;
            }
        }
        // Spread those positions across the table, two at a time.
        let mut position = 0usize;
        let mut s = 0usize;
        while s < table_size as usize {
            for u in 0..2 {
                let u_position = (position + u * step) & table_mask;
                table_decode[u_position].base_value = u32::from(wksp.spread[s + u]);
            }
            position = (position + 2 * step) & table_mask;
            s += 2;
        }
        debug_assert!(position == 0);
    } else {
        let table_mask = table_size - 1;
        let step = fse_tablestep(table_size);
        let mut position: u32 = 0;
        for s in 0..max_sv1 {
            let n = i32::from(normalized_counter[s]);
            for _ in 0..n {
                table_decode[position as usize].base_value = s as u32;
                position = (position + step) & table_mask;
                while position > high_threshold {
                    // The low-probability area.
                    position = (position + step) & table_mask;
                }
            }
        }
        debug_assert!(position == 0);
    }

    // Build the decoding table.
    for u in 0..table_size as usize {
        let symbol = table_decode[u].base_value as usize;
        let next_state = u32::from(symbol_next[symbol]);
        symbol_next[symbol] = symbol_next[symbol].wrapping_add(1);
        let nb_bits = (table_log - highbit32(next_state)) as u8;
        table_decode[u].nb_bits = nb_bits;
        table_decode[u].next_state = ((next_state << nb_bits) - table_size) as u16;
        table_decode[u].nb_additional_bits = nb_additional_bits[symbol];
        table_decode[u].base_value = base_value[symbol];
    }
}

/// `ZSTD_buildSeqTable`: sets up the table of one field as its encoding type
/// says. Returns the size read from `src`.
#[allow(clippy::too_many_arguments)]
fn build_seq_table<const N: usize>(
    dtable_space: &mut SeqDTable<N>,
    dtable_ptr: &mut TableRef,
    encoding: SymbolEncodingType,
    max: u32,
    max_log: u32,
    src: &[u8],
    base_value: &[u32],
    nb_additional_bits: &[u8],
    flag_repeat_table: bool,
    wksp: &mut FseBuildDTableWksp,
) -> Result<usize> {
    match encoding {
        SymbolEncodingType::Rle => {
            if src.is_empty() {
                return error!(SrcSizeWrong);
            }
            if u32::from(src[0]) > max {
                return error!(CorruptionDetected);
            }
            let symbol = usize::from(src[0]);
            build_seq_table_rle(dtable_space, base_value[symbol], nb_additional_bits[symbol]);
            *dtable_ptr = TableRef::Own;
            Ok(1)
        }
        SymbolEncodingType::Basic => {
            *dtable_ptr = TableRef::Default;
            Ok(0)
        }
        SymbolEncodingType::Repeat => {
            if !flag_repeat_table {
                return error!(CorruptionDetected);
            }
            // libzstd prefetches the table here when it is cold.
            Ok(0)
        }
        SymbolEncodingType::Compressed => {
            let mut table_log = 0u32;
            let mut max = max;
            let mut norm = [0i16; MAX_SEQ as usize + 1];
            let header_size = match fse_read_ncount(&mut norm, &mut max, &mut table_log, src) {
                Ok(size) => size,
                Err(_) => return error!(CorruptionDetected),
            };
            if table_log > max_log {
                return error!(CorruptionDetected);
            }
            build_fse_table(
                dtable_space,
                &norm,
                max,
                base_value,
                nb_additional_bits,
                table_log,
                wksp,
            );
            *dtable_ptr = TableRef::Own;
            Ok(header_size)
        }
    }
}

fn encoding_type(bits: u8) -> SymbolEncodingType {
    match bits & 3 {
        0 => SymbolEncodingType::Basic,
        1 => SymbolEncodingType::Rle,
        2 => SymbolEncodingType::Compressed,
        _ => SymbolEncodingType::Repeat,
    }
}

/// `ZSTD_decodeSeqHeaders`: reads the number of sequences and sets up the
/// three tables. Returns the size of the headers.
pub(crate) fn decode_seq_headers(
    dctx: &mut DCtx,
    nb_seq_ptr: &mut usize,
    src: &[u8],
) -> Result<usize> {
    let iend = src.len();
    let mut ip = 0usize;

    if src.len() < MIN_SEQUENCES_SIZE {
        return error!(SrcSizeWrong);
    }

    // SeqHead
    let mut nb_seq = usize::from(src[ip]);
    ip += 1;
    if nb_seq > 0x7F {
        if nb_seq == 0xFF {
            if ip + 2 > iend {
                return error!(SrcSizeWrong);
            }
            nb_seq = usize::from(read_le16(src, ip)) + LONGNBSEQ;
            ip += 2;
        } else {
            if ip >= iend {
                return error!(SrcSizeWrong);
            }
            nb_seq = ((nb_seq - 0x80) << 8) + usize::from(src[ip]);
            ip += 1;
        }
    }
    *nb_seq_ptr = nb_seq;

    if nb_seq == 0 {
        // No sequences: the section ends here.
        if ip != iend {
            return error!(CorruptionDetected);
        }
        return Ok(ip);
    }

    // FSE table descriptors: at least 1 byte for the encoding types.
    if ip + 1 > iend {
        return error!(SrcSizeWrong);
    }
    if src[ip] & 3 != 0 {
        // The reserved field must be zero.
        return error!(CorruptionDetected);
    }
    let ll_type = encoding_type(src[ip] >> 6);
    let of_type = encoding_type(src[ip] >> 4);
    let ml_type = encoding_type(src[ip] >> 2);
    ip += 1;

    // Every failure here is reported as corruption.
    let corrupt = |_: Error| Error::from(ErrorCode::CorruptionDetected);
    let llh_size = build_seq_table(
        &mut dctx.entropy.ll_table,
        &mut dctx.ll_tptr,
        ll_type,
        MAX_LL,
        LL_FSE_LOG,
        &src[ip..],
        &LL_BASE,
        &LL_BITS,
        dctx.fse_entropy,
        &mut dctx.entropy.workspace,
    )
    .map_err(corrupt)?;
    ip += llh_size;

    let ofh_size = build_seq_table(
        &mut dctx.entropy.of_table,
        &mut dctx.of_tptr,
        of_type,
        MAX_OFF,
        OFF_FSE_LOG,
        &src[ip..],
        &OF_BASE,
        &OF_BITS,
        dctx.fse_entropy,
        &mut dctx.entropy.workspace,
    )
    .map_err(corrupt)?;
    ip += ofh_size;

    let mlh_size = build_seq_table(
        &mut dctx.entropy.ml_table,
        &mut dctx.ml_tptr,
        ml_type,
        MAX_ML,
        ML_FSE_LOG,
        &src[ip..],
        &ML_BASE,
        &ML_BITS,
        dctx.fse_entropy,
        &mut dctx.entropy.workspace,
    )
    .map_err(corrupt)?;
    ip += mlh_size;

    Ok(ip)
}

/// A table that `LLTptr`, `OFTptr` or `MLTptr` points to: its cells and log.
#[derive(Clone, Copy)]
struct SeqTableView<'a> {
    cells: &'a [SeqSymbol],
    table_log: u32,
}

fn seq_table<'a, const N: usize>(
    which: TableRef,
    own: &'a SeqDTable<N>,
    dict: Option<&'a SeqDTable<N>>,
    default: &'a [SeqSymbol],
    default_log: u32,
) -> SeqTableView<'a> {
    let table = match which {
        TableRef::Default => {
            return SeqTableView {
                cells: default,
                table_log: default_log,
            };
        }
        TableRef::Own => own,
        // Only set while a dictionary is in use, which the caller passes.
        TableRef::Dict => dict.unwrap_or(own),
    };
    SeqTableView {
        cells: &table.cells,
        table_log: table.table_log,
    }
}

// ---------------------------------------------------------------------------
// Sequences
// ---------------------------------------------------------------------------

/// `seq_t`
#[derive(Clone, Copy, Default, Debug)]
struct Seq {
    lit_length: usize,
    match_length: usize,
    offset: usize,
}

/// `seqState_t`, with the three FSE states (`ZSTD_fseState`) as just the
/// state; the tables are passed alongside.
struct SeqState<'a> {
    d_stream: BitDStream<'a>,
    state_ll: usize,
    state_offb: usize,
    state_ml: usize,
    prev_offset: [usize; ZSTD_REP_NUM],
}

/// The three tables the sequences are decoded with.
#[derive(Clone, Copy)]
struct SeqTables<'a> {
    ll: SeqTableView<'a>,
    of: SeqTableView<'a>,
    ml: SeqTableView<'a>,
}

/// `ZSTD_initFseState`
fn init_fse_state(bit_d: &mut BitDStream<'_>, table: SeqTableView<'_>) -> usize {
    let state = bit_d.read_bits(table.table_log) as usize;
    bit_d.reload();
    state
}

/// `STREAM_ACCUMULATOR_MIN_64`
const STREAM_ACCUMULATOR_MIN_64: u32 = 57;

/// `ZSTD_decodeSequence`, for a 64-bit register: offsets never need a refill
/// in the middle (the `longOffsets` case of 32-bit machines).
#[inline(always)]
fn decode_sequence(seq_state: &mut SeqState<'_>, tables: SeqTables<'_>, is_last_seq: bool) -> Seq {
    let ll_d_info = tables.ll.cells[seq_state.state_ll];
    let ml_d_info = tables.ml.cells[seq_state.state_ml];
    let of_d_info = tables.of.cells[seq_state.state_offb];
    let mut seq = Seq {
        match_length: ml_d_info.base_value as usize,
        lit_length: ll_d_info.base_value as usize,
        offset: 0,
    };
    let of_base = of_d_info.base_value as usize;
    let ll_bits = u32::from(ll_d_info.nb_additional_bits);
    let ml_bits = u32::from(ml_d_info.nb_additional_bits);
    let of_bits = u32::from(of_d_info.nb_additional_bits);
    let total_bits = ll_bits + ml_bits + of_bits;
    let d = &mut seq_state.d_stream;
    let prev = &mut seq_state.prev_offset;

    // The offset.
    {
        let offset;
        if of_bits > 1 {
            // At most ZSTD_WINDOWLOG_MAX - 1 bits.
            offset = of_base + d.read_bits_fast(of_bits) as usize;
            prev[2] = prev[1];
            prev[1] = prev[0];
            prev[0] = offset;
        } else {
            let ll0 = usize::from(ll_d_info.base_value == 0);
            if of_bits == 0 {
                offset = prev[ll0];
                prev[1] = prev[1 - ll0];
                prev[0] = offset;
            } else {
                let code = of_base + ll0 + d.read_bits_fast(1) as usize;
                let mut temp = if code == 3 {
                    prev[0].wrapping_sub(1)
                } else {
                    prev[code]
                };
                // 0 is not valid: the input is corrupted. Make it -1, which
                // the copy rejects.
                temp = temp.wrapping_sub(usize::from(temp == 0));
                if code != 1 {
                    prev[2] = prev[1];
                }
                prev[1] = prev[0];
                prev[0] = temp;
                offset = temp;
            }
        }
        seq.offset = offset;
    }

    if ml_bits > 0 {
        seq.match_length += d.read_bits_fast(ml_bits) as usize;
    }
    if total_bits >= STREAM_ACCUMULATOR_MIN_64 - (LL_FSE_LOG + ML_FSE_LOG + OFF_FSE_LOG) {
        d.reload();
    }
    // There are now enough bits for the rest.
    if ll_bits > 0 {
        seq.lit_length += d.read_bits_fast(ll_bits) as usize;
    }

    if !is_last_seq {
        // The last sequence does not move the states.
        seq_state.state_ll =
            usize::from(ll_d_info.next_state) + d.read_bits(u32::from(ll_d_info.nb_bits)) as usize;
        seq_state.state_ml =
            usize::from(ml_d_info.next_state) + d.read_bits(u32::from(ml_d_info.nb_bits)) as usize;
        seq_state.state_offb =
            usize::from(of_d_info.next_state) + d.read_bits(u32::from(of_d_info.nb_bits)) as usize;
        d.reload();
    }

    seq
}

/// Where a sequence's literals are read from.
#[derive(Clone, Copy)]
enum Lits<'a> {
    /// The output buffer itself (`ZSTD_in_dst`, and the first part of
    /// `ZSTD_split`).
    Out,
    /// The extra buffer, or the block's input.
    Buf(&'a [u8]),
}

/// Copies `len` literals from `lit_pos` to `op`. Within the output, the copy
/// behaves as `memmove`, as libzstd's copies do there.
#[inline(always)]
fn copy_literals(out: &mut [u8], op: usize, lits: Lits<'_>, lit_pos: usize, len: usize) {
    match lits {
        Lits::Out => out.copy_within(lit_pos..lit_pos + len, op),
        Lits::Buf(buf) => out[op..op + len].copy_from_slice(&buf[lit_pos..lit_pos + len]),
    }
}

/// Copies a match of `length` bytes from `offset` bytes back, byte by byte
/// as LZ77 means it: when the match overlaps its own output, the copied
/// bytes repeat. This is what libzstd's copies produce.
#[inline(always)]
fn copy_match(out: &mut [u8], op: usize, offset: usize, length: usize) {
    if offset == 0 {
        // Valid sequences never have it (see decode_sequence); libzstd would
        // copy the bytes onto themselves, which changes nothing.
        return;
    }
    let src = op - offset;
    if offset >= length {
        out.copy_within(src..src + length, op);
        return;
    }
    // The output repeats every `offset` bytes, so it also repeats every
    // multiple of that; copy from as far back as has been written, which
    // doubles the step each time.
    let mut copied = 0;
    while copied < length {
        let period = (offset + copied) / offset * offset;
        let n = (length - copied).min(period);
        out.copy_within(op + copied - period..op + copied - period + n, op + copied);
        copied += n;
    }
}

/// Copies `len` bytes from position `at` of the older segment of the window.
/// Within the output, the copy behaves as `memmove`, as libzstd's does.
#[inline(always)]
fn copy_from_ext(out: &mut [u8], op: usize, ext: ExtDict<'_>, at: usize, len: usize) {
    match ext {
        ExtDict::None => debug_assert!(len == 0),
        ExtDict::Separate(content) => out[op..op + len].copy_from_slice(&content[at..at + len]),
        ExtDict::InOut { start, .. } => out.copy_within(start + at..start + at + len, op),
    }
}

/// The match part of `ZSTD_execSequence` and its variants: copies the match
/// of `seq` to `o_lit_end`, from the older segment, the prefix, or both.
#[inline(always)]
fn copy_sequence_match(
    out: &mut [u8],
    o_lit_end: usize,
    seq: Seq,
    prefix_start: usize,
    ext: ExtDict<'_>,
) -> Result<()> {
    let mut op = o_lit_end;
    let mut match_length = seq.match_length;
    if seq.offset > o_lit_end - prefix_start {
        // The offset goes past the prefix, into the older segment.
        let ext_len = ext.len();
        if seq.offset > o_lit_end - prefix_start + ext_len {
            return error!(CorruptionDetected);
        }
        // dictEnd - (prefixStart - match)
        let at = ext_len - (seq.offset - (o_lit_end - prefix_start));
        if at + match_length <= ext_len {
            copy_from_ext(out, op, ext, at, match_length);
            return Ok(());
        }
        // It spans the older segment and the prefix.
        let length1 = ext_len - at;
        copy_from_ext(out, op, ext, at, length1);
        op += length1;
        match_length -= length1;
        // The rest starts at prefixStart.
        copy_match(out, op, op - prefix_start, match_length);
        return Ok(());
    }
    copy_match(out, op, seq.offset, match_length);
    Ok(())
}

/// `ZSTD_execSequenceEnd`: a sequence near the end of the output, or one
/// whose literals run past their buffer; checks bounds carefully.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn exec_sequence_end(
    out: &mut [u8],
    op: usize,
    oend: usize,
    seq: Seq,
    lits: Lits<'_>,
    lit_ptr: &mut usize,
    lit_limit: usize,
    prefix_start: usize,
    ext: ExtDict<'_>,
) -> Result<usize> {
    let o_lit_end = op + seq.lit_length;
    let sequence_length = seq.lit_length + seq.match_length;

    if sequence_length > oend - op {
        // The last match must fit in the output.
        return error!(DstSizeTooSmall);
    }
    if seq.lit_length > lit_limit - *lit_ptr {
        // Reading past the literals.
        return error!(CorruptionDetected);
    }

    copy_literals(out, op, lits, *lit_ptr, seq.lit_length);
    *lit_ptr += seq.lit_length;
    copy_sequence_match(out, o_lit_end, seq, prefix_start, ext)?;
    Ok(sequence_length)
}

/// `ZSTD_execSequence`: writes one sequence's literals and match at `op`.
/// Returns its length.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn exec_sequence(
    out: &mut [u8],
    op: usize,
    oend: usize,
    seq: Seq,
    lits: Lits<'_>,
    lit_ptr: &mut usize,
    lit_limit: usize,
    prefix_start: usize,
    ext: ExtDict<'_>,
) -> Result<usize> {
    let o_lit_end = op + seq.lit_length;
    let sequence_length = seq.lit_length + seq.match_length;
    let o_match_end = op + sequence_length;
    let i_lit_end = *lit_ptr + seq.lit_length;

    // Edge cases go the slow way: reading past the literals, or a match
    // ending within WILDCOPY_OVERLENGTH of the end (`oMatchEnd > oend_w`).
    if i_lit_end > lit_limit || o_match_end + WILDCOPY_OVERLENGTH > oend {
        return exec_sequence_end(
            out,
            op,
            oend,
            seq,
            lits,
            lit_ptr,
            lit_limit,
            prefix_start,
            ext,
        );
    }

    copy_literals(out, op, lits, *lit_ptr, seq.lit_length);
    *lit_ptr = i_lit_end;
    copy_sequence_match(out, o_lit_end, seq, prefix_start, ext)?;
    Ok(sequence_length)
}

/// `ZSTD_execSequenceEndSplitLitBuffer`: like [`exec_sequence_end`], while
/// the literals are still in the output, ahead of it.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn exec_sequence_end_split_lit_buffer(
    out: &mut [u8],
    op: usize,
    oend: usize,
    seq: Seq,
    lit_ptr: &mut usize,
    lit_limit: usize,
    prefix_start: usize,
    ext: ExtDict<'_>,
) -> Result<usize> {
    let o_lit_end = op + seq.lit_length;
    let sequence_length = seq.lit_length + seq.match_length;

    if sequence_length > oend - op {
        return error!(DstSizeTooSmall);
    }
    if seq.lit_length > lit_limit - *lit_ptr {
        return error!(CorruptionDetected);
    }

    // The output must not have caught up with the literals it copies.
    if op > *lit_ptr && op < *lit_ptr + seq.lit_length {
        return error!(DstSizeTooSmall);
    }
    // ZSTD_safecopyDstBeforeSrc: a forward copy within the output.
    out.copy_within(*lit_ptr..*lit_ptr + seq.lit_length, op);
    *lit_ptr += seq.lit_length;
    copy_sequence_match(out, o_lit_end, seq, prefix_start, ext)?;
    Ok(sequence_length)
}

/// `ZSTD_execSequenceSplitLitBuffer`: like [`exec_sequence`], while the
/// literals are still in the output: the fast path must also end
/// WILDCOPY_OVERLENGTH bytes before this sequence's literals end
/// (`oend_w`).
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn exec_sequence_split_lit_buffer(
    out: &mut [u8],
    op: usize,
    oend: usize,
    seq: Seq,
    lit_ptr: &mut usize,
    lit_limit: usize,
    prefix_start: usize,
    ext: ExtDict<'_>,
) -> Result<usize> {
    let o_lit_end = op + seq.lit_length;
    let sequence_length = seq.lit_length + seq.match_length;
    let o_match_end = op + sequence_length;
    let i_lit_end = *lit_ptr + seq.lit_length;

    // oend_w is litPtr + litLength - WILDCOPY_OVERLENGTH.
    if i_lit_end > lit_limit || o_match_end + WILDCOPY_OVERLENGTH > i_lit_end {
        return exec_sequence_end_split_lit_buffer(
            out,
            op,
            oend,
            seq,
            lit_ptr,
            lit_limit,
            prefix_start,
            ext,
        );
    }

    copy_literals(out, op, Lits::Out, *lit_ptr, seq.lit_length);
    *lit_ptr = i_lit_end;
    copy_sequence_match(out, o_lit_end, seq, prefix_start, ext)?;
    Ok(sequence_length)
}

// ---------------------------------------------------------------------------
// Decoding all of a block's sequences
// ---------------------------------------------------------------------------

/// The output of a block, and the window before it.
pub(crate) struct BlockOut<'o, 'e> {
    /// The buffer the block is decoded into.
    pub(crate) out: &'o mut [u8],
    /// Where this block's output starts.
    pub(crate) dst: usize,
    /// How many bytes this block may write from `dst`.
    pub(crate) dst_capacity: usize,
    /// libzstd's `prefixStart`: where the current segment of the window
    /// starts, in `out`.
    pub(crate) prefix_start: usize,
    /// The older segment of the window.
    pub(crate) ext: ExtDict<'e>,
    /// The tables of the dictionary in use, for [`TableRef::Dict`].
    pub(crate) dict: Option<&'e EntropyDTables>,
}

/// The three tables `dctx` points to. A macro rather than a function, so
/// that it borrows only the fields it reads.
macro_rules! dctx_tables {
    ($dctx:expr, $dict:expr) => {
        SeqTables {
            ll: seq_table(
                $dctx.ll_tptr,
                &$dctx.entropy.ll_table,
                $dict.map(|d: &EntropyDTables| &d.ll_table),
                &LL_DEFAULT_DTABLE,
                LL_DEFAULT_NORM_LOG,
            ),
            of: seq_table(
                $dctx.of_tptr,
                &$dctx.entropy.of_table,
                $dict.map(|d: &EntropyDTables| &d.of_table),
                &OF_DEFAULT_DTABLE,
                OF_DEFAULT_NORM_LOG,
            ),
            ml: seq_table(
                $dctx.ml_tptr,
                &$dctx.entropy.ml_table,
                $dict.map(|d: &EntropyDTables| &d.ml_table),
                &ML_DEFAULT_DTABLE,
                ML_DEFAULT_NORM_LOG,
            ),
        }
    };
}

/// The start of `ZSTD_decompressSequences_body` and its variants: the
/// bitstream and the three states.
fn init_seq_state<'a>(
    rep: &[u32; ZSTD_REP_NUM],
    tables: SeqTables<'_>,
    seq_src: &'a [u8],
) -> Result<SeqState<'a>> {
    let Ok(mut d_stream) = BitDStream::new(seq_src) else {
        return error!(CorruptionDetected);
    };
    let state_ll = init_fse_state(&mut d_stream, tables.ll);
    let state_offb = init_fse_state(&mut d_stream, tables.of);
    let state_ml = init_fse_state(&mut d_stream, tables.ml);
    Ok(SeqState {
        d_stream,
        state_ll,
        state_offb,
        state_ml,
        prev_offset: rep.map(|rep| rep as usize),
    })
}

/// Saves the repeat offsets for the next block. libzstd keeps them as
/// `U32`.
fn save_reps(rep: &mut [u32; ZSTD_REP_NUM], prev_offset: &[usize; ZSTD_REP_NUM]) {
    for (rep, &prev) in rep.iter_mut().zip(prev_offset) {
        *rep = prev as u32;
    }
}

/// The literal buffer a literal position refers to.
fn lits_at<'a>(pos: LitPos, extra: &'a [u8], block_src: &'a [u8]) -> Lits<'a> {
    match pos.buf {
        LitBuf::Out => Lits::Out,
        LitBuf::Extra => Lits::Buf(extra),
        LitBuf::Src => Lits::Buf(block_src),
    }
}

/// `ZSTD_decompressSequences_body`: for literals that are not split.
fn decompress_sequences_body(
    dctx: &mut DCtx,
    bo: &mut BlockOut<'_, '_>,
    seq_src: &[u8],
    nb_seq: usize,
    block_src: &[u8],
) -> Result<usize> {
    let ostart = bo.dst;
    let oend = if dctx.lit_buffer_location == LitLocation::NotInDst {
        ostart + bo.dst_capacity
    } else {
        dctx.lit_buffer.pos
    };
    let mut op = ostart;
    let mut lit_ptr = dctx.lit_ptr.pos;
    let lit_end = lit_ptr + dctx.lit_size;
    let lits = lits_at(dctx.lit_ptr, &dctx.lit_extra_buffer, block_src);
    let out = &mut *bo.out;

    // Regenerate the sequences.
    if nb_seq > 0 {
        dctx.fse_entropy = true;
        let tables = dctx_tables!(dctx, bo.dict);
        let mut seq_state = init_seq_state(&dctx.entropy.rep, tables, seq_src)?;
        for remaining in (1..=nb_seq).rev() {
            let sequence = decode_sequence(&mut seq_state, tables, remaining == 1);
            let one_seq_size = exec_sequence(
                out,
                op,
                oend,
                sequence,
                lits,
                &mut lit_ptr,
                lit_end,
                bo.prefix_start,
                bo.ext,
            )?;
            op += one_seq_size;
        }

        // The bitstream must end exactly here.
        if !seq_state.d_stream.end_of_dstream() {
            return error!(CorruptionDetected);
        }
        let prev_offset = seq_state.prev_offset;
        save_reps(&mut dctx.entropy.rep, &prev_offset);
    }

    // The last literals.
    let last_ll_size = lit_end - lit_ptr;
    if last_ll_size > oend - op {
        return error!(DstSizeTooSmall);
    }
    copy_literals(out, op, lits, lit_ptr, last_ll_size);
    op += last_ll_size;

    Ok(op - ostart)
}

/// `ZSTD_decompressSequences_bodySplitLitBuffer`: for literals split between
/// the output and the extra buffer.
fn decompress_sequences_body_split_lit_buffer(
    dctx: &mut DCtx,
    bo: &mut BlockOut<'_, '_>,
    seq_src: &[u8],
    mut nb_seq: usize,
) -> Result<usize> {
    let ostart = bo.dst;
    let oend = ostart + bo.dst_capacity;
    let mut op = ostart;
    debug_assert!(dctx.lit_ptr.buf == LitBuf::Out);
    let mut lit_ptr = dctx.lit_ptr.pos;
    let mut lit_buffer_end = dctx.lit_buffer_end.pos;
    let (prefix_start, ext) = (bo.prefix_start, bo.ext);
    let out = &mut *bo.out;
    let mut location = dctx.lit_buffer_location;

    if nb_seq > 0 {
        dctx.fse_entropy = true;
        let tables = dctx_tables!(dctx, bo.dict);
        let mut seq_state = init_seq_state(&dctx.entropy.rep, tables, seq_src)?;

        // Decode without overrunning where the literals in the output begin.
        let mut sequence = Seq::default();
        while nb_seq > 0 {
            sequence = decode_sequence(&mut seq_state, tables, nb_seq == 1);
            if lit_ptr + sequence.lit_length > dctx.lit_buffer_end.pos {
                break;
            }
            let one_seq_size = exec_sequence_split_lit_buffer(
                out,
                op,
                oend,
                sequence,
                &mut lit_ptr,
                lit_buffer_end,
                prefix_start,
                ext,
            )?;
            op += one_seq_size;
            nb_seq -= 1;
        }

        // The rest of the sequences read their literals from the extra
        // buffer: copy what remains in the output, and switch.
        if nb_seq > 0 {
            let leftover_lit = dctx.lit_buffer_end.pos - lit_ptr;
            if leftover_lit > 0 {
                if leftover_lit > oend - op {
                    return error!(DstSizeTooSmall);
                }
                // ZSTD_safecopyDstBeforeSrc
                out.copy_within(lit_ptr..lit_ptr + leftover_lit, op);
                sequence.lit_length -= leftover_lit;
                op += leftover_lit;
            }
            lit_ptr = 0;
            lit_buffer_end = ZSTD_LITBUFFEREXTRASIZE;
            location = LitLocation::NotInDst;
            let extra = Lits::Buf(&dctx.lit_extra_buffer);
            let one_seq_size = exec_sequence(
                out,
                op,
                oend,
                sequence,
                extra,
                &mut lit_ptr,
                lit_buffer_end,
                prefix_start,
                ext,
            )?;
            op += one_seq_size;
            nb_seq -= 1;
        }

        // The remaining literals are in the extra buffer.
        let extra = Lits::Buf(&dctx.lit_extra_buffer);
        while nb_seq > 0 {
            let sequence = decode_sequence(&mut seq_state, tables, nb_seq == 1);
            let one_seq_size = exec_sequence(
                out,
                op,
                oend,
                sequence,
                extra,
                &mut lit_ptr,
                lit_buffer_end,
                prefix_start,
                ext,
            )?;
            op += one_seq_size;
            nb_seq -= 1;
        }

        // The bitstream must end exactly here.
        if nb_seq > 0 {
            return error!(CorruptionDetected);
        }
        if !seq_state.d_stream.end_of_dstream() {
            dctx.lit_buffer_location = location;
            return error!(CorruptionDetected);
        }
        let prev_offset = seq_state.prev_offset;
        save_reps(&mut dctx.entropy.rep, &prev_offset);
    }

    // The last literals.
    if location == LitLocation::Split {
        // The split was not reached: first the part in the output.
        let last_ll_size = lit_buffer_end - lit_ptr;
        if last_ll_size > oend - op {
            return error!(DstSizeTooSmall);
        }
        out.copy_within(lit_ptr..lit_ptr + last_ll_size, op);
        op += last_ll_size;
        lit_ptr = 0;
        lit_buffer_end = ZSTD_LITBUFFEREXTRASIZE;
        location = LitLocation::NotInDst;
    }
    dctx.lit_buffer_location = location;
    // Then the extra buffer.
    let last_ll_size = lit_buffer_end - lit_ptr;
    if last_ll_size > oend - op {
        return error!(DstSizeTooSmall);
    }
    out[op..op + last_ll_size]
        .copy_from_slice(&dctx.lit_extra_buffer[lit_ptr..lit_ptr + last_ll_size]);
    op += last_ll_size;

    Ok(op - ostart)
}

/// `STORED_SEQS`: how many sequences the prefetching decoder decodes ahead.
const STORED_SEQS: usize = 8;
const STORED_SEQS_MASK: usize = STORED_SEQS - 1;
const ADVANCED_SEQS: usize = STORED_SEQS;

/// `ZSTD_decompressSequencesLong_body`: decodes sequences ahead of executing
/// them, so libzstd can prefetch their matches. The port does not prefetch;
/// it keeps the order of work, which decides which error a corrupted block
/// reports.
fn decompress_sequences_long_body(
    dctx: &mut DCtx,
    bo: &mut BlockOut<'_, '_>,
    seq_src: &[u8],
    nb_seq: usize,
    block_src: &[u8],
) -> Result<usize> {
    let ostart = bo.dst;
    let oend = if dctx.lit_buffer_location == LitLocation::InDst {
        dctx.lit_buffer.pos
    } else {
        ostart + bo.dst_capacity
    };
    let mut op = ostart;
    let mut lit_ptr = dctx.lit_ptr;
    let mut lit_buffer_end = dctx.lit_buffer_end.pos;
    let (prefix_start, ext) = (bo.prefix_start, bo.ext);
    let out = &mut *bo.out;

    if nb_seq > 0 {
        let mut sequences = [Seq::default(); STORED_SEQS];
        let seq_advance = nb_seq.min(ADVANCED_SEQS);
        dctx.fse_entropy = true;
        let tables = dctx_tables!(dctx, bo.dict);
        let mut seq_state = init_seq_state(&dctx.entropy.rep, tables, seq_src)?;

        // Prepare in advance.
        let mut seq_nb = 0;
        while seq_nb < seq_advance {
            sequences[seq_nb] = decode_sequence(&mut seq_state, tables, seq_nb == nb_seq - 1);
            seq_nb += 1;
        }

        // Executes one queued sequence, switching from the output's part of
        // split literals to the extra buffer when it reaches the split.
        let split_end = dctx.lit_buffer_end.pos;
        let extra: &[u8] = &dctx.lit_extra_buffer;
        let mut location = dctx.lit_buffer_location;
        let mut run = |sequence: &mut Seq,
                       op: &mut usize,
                       lit_ptr: &mut LitPos,
                       lit_buffer_end: &mut usize,
                       location: &mut LitLocation|
         -> Result<()> {
            if *location == LitLocation::Split && lit_ptr.pos + sequence.lit_length > split_end {
                // The literals reach the split point: empty the first part
                // and move on to the extra buffer.
                let leftover_lit = split_end - lit_ptr.pos;
                if leftover_lit > 0 {
                    if leftover_lit > oend - *op {
                        return error!(DstSizeTooSmall);
                    }
                    out.copy_within(lit_ptr.pos..lit_ptr.pos + leftover_lit, *op);
                    sequence.lit_length -= leftover_lit;
                    *op += leftover_lit;
                }
                *lit_ptr = LitPos::new(LitBuf::Extra, 0);
                *lit_buffer_end = ZSTD_LITBUFFEREXTRASIZE;
                *location = LitLocation::NotInDst;
                *op += exec_sequence(
                    out,
                    *op,
                    oend,
                    *sequence,
                    Lits::Buf(extra),
                    &mut lit_ptr.pos,
                    *lit_buffer_end,
                    prefix_start,
                    ext,
                )?;
            } else if *location == LitLocation::Split {
                *op += exec_sequence_split_lit_buffer(
                    out,
                    *op,
                    oend,
                    *sequence,
                    &mut lit_ptr.pos,
                    *lit_buffer_end,
                    prefix_start,
                    ext,
                )?;
            } else {
                let lits = lits_at(*lit_ptr, extra, block_src);
                *op += exec_sequence(
                    out,
                    *op,
                    oend,
                    *sequence,
                    lits,
                    &mut lit_ptr.pos,
                    *lit_buffer_end,
                    prefix_start,
                    ext,
                )?;
            }
            Ok(())
        };

        // Decode one, execute the one decoded ADVANCED_SEQS earlier.
        while seq_nb < nb_seq {
            let sequence = decode_sequence(&mut seq_state, tables, seq_nb == nb_seq - 1);
            let mut queued = sequences[(seq_nb - ADVANCED_SEQS) & STORED_SEQS_MASK];
            run(
                &mut queued,
                &mut op,
                &mut lit_ptr,
                &mut lit_buffer_end,
                &mut location,
            )?;
            sequences[seq_nb & STORED_SEQS_MASK] = sequence;
            seq_nb += 1;
        }
        if !seq_state.d_stream.end_of_dstream() {
            return error!(CorruptionDetected);
        }

        // Finish the queue.
        seq_nb -= seq_advance;
        while seq_nb < nb_seq {
            let mut queued = sequences[seq_nb & STORED_SEQS_MASK];
            run(
                &mut queued,
                &mut op,
                &mut lit_ptr,
                &mut lit_buffer_end,
                &mut location,
            )?;
            seq_nb += 1;
        }

        dctx.lit_buffer_location = location;
        let prev_offset = seq_state.prev_offset;
        save_reps(&mut dctx.entropy.rep, &prev_offset);
    }

    // The last literals.
    if dctx.lit_buffer_location == LitLocation::Split {
        // First empty the part in the output, then the extra buffer.
        let last_ll_size = lit_buffer_end - lit_ptr.pos;
        if last_ll_size > oend - op {
            return error!(DstSizeTooSmall);
        }
        out.copy_within(lit_ptr.pos..lit_ptr.pos + last_ll_size, op);
        op += last_ll_size;
        lit_ptr = LitPos::new(LitBuf::Extra, 0);
        lit_buffer_end = ZSTD_LITBUFFEREXTRASIZE;
    }
    let last_ll_size = lit_buffer_end - lit_ptr.pos;
    if last_ll_size > oend - op {
        return error!(DstSizeTooSmall);
    }
    let lits = lits_at(lit_ptr, &dctx.lit_extra_buffer, block_src);
    copy_literals(out, op, lits, lit_ptr.pos, last_ll_size);
    op += last_ll_size;

    Ok(op - ostart)
}

/// `ZSTD_OffsetInfo`
struct OffsetInfo {
    long_offset_share: u32,
    max_nb_additional_bits: u32,
}

/// `ZSTD_getOffsetInfo`: the share of long offsets (over 2^23) in the offset
/// table, scaled to a table of `OffFSELog`, and the largest number of extra
/// bits.
fn get_offset_info(of_table: SeqTableView<'_>, nb_seq: usize) -> OffsetInfo {
    let mut info = OffsetInfo {
        long_offset_share: 0,
        max_nb_additional_bits: 0,
    };
    // With no sequences the table is not set up, and both are 0.
    if nb_seq != 0 {
        let table_log = of_table.table_log;
        let max = 1usize << table_log;
        for cell in &of_table.cells[..max] {
            info.max_nb_additional_bits = info
                .max_nb_additional_bits
                .max(u32::from(cell.nb_additional_bits));
            if cell.nb_additional_bits > 22 {
                info.long_offset_share += 1;
            }
        }
        debug_assert!(table_log <= OFF_FSE_LOG);
        info.long_offset_share <<= OFF_FSE_LOG - table_log;
    }
    info
}

/// `ZSTD_decompressBlock_internal`: decodes the compressed block `src` to
/// `bo.dst`. Returns the size it decoded to.
pub(crate) fn decompress_block_internal(
    dctx: &mut DCtx,
    bo: &mut BlockOut<'_, '_>,
    src: &[u8],
    streaming: bool,
) -> Result<usize> {
    // The format allows a compressed block exactly as large as
    // blockSizeMax (libzstd before 1.5.4 refused it).
    if src.len() > block_size_max(dctx) {
        return error!(SrcSizeWrong);
    }

    // The literals section.
    let lit_c_size = decode_literals_block(
        dctx,
        src,
        bo.out,
        bo.dst,
        bo.dst_capacity,
        streaming,
        bo.dict,
    )?;
    let ip = lit_c_size;

    count_path(match (dctx.lit_buffer_location, dctx.lit_ptr.buf) {
        (LitLocation::NotInDst, LitBuf::Src) => 1,
        (LitLocation::NotInDst, _) => 0,
        (LitLocation::InDst, _) => 2,
        (LitLocation::Split, _) => 3,
    });

    // The tables.
    let block_size_max = bo.dst_capacity.min(block_size_max(dctx));
    // ZSTD_totalHistorySize(dst + blockSizeMax, virtualStart)
    let total_history_size = bo.dst + block_size_max - bo.prefix_start + bo.ext.len();
    // Long offsets need a refill in the middle only with a 32-bit register.
    let mut use_prefetch_decoder = dctx.ddict_is_cold;
    let mut nb_seq = 0usize;
    let seq_h_size = decode_seq_headers(dctx, &mut nb_seq, &src[ip..])?;
    let ip = ip + seq_h_size;

    // libzstd also refuses a NULL dst here, and one at the very end of the
    // address space.
    if bo.dst_capacity == 0 && nb_seq > 0 {
        return error!(DstSizeTooSmall);
    }

    if !use_prefetch_decoder && total_history_size > (1 << 24) && nb_seq > 8 {
        let tables = dctx_tables!(dctx, bo.dict);
        let info = get_offset_info(tables.of, nb_seq);
        // A heuristic: 2.73% of long offsets.
        let min_share = 7;
        use_prefetch_decoder = info.long_offset_share >= min_share;
        let _ = info.max_nb_additional_bits;
    }

    dctx.ddict_is_cold = false;

    if use_prefetch_decoder || force_long_loop() {
        count_path(6);
        return decompress_sequences_long_body(dctx, bo, &src[ip..], nb_seq, src);
    }
    if dctx.lit_buffer_location == LitLocation::Split {
        count_path(5);
        decompress_sequences_body_split_lit_buffer(dctx, bo, &src[ip..], nb_seq)
    } else {
        count_path(4);
        decompress_sequences_body(dctx, bo, &src[ip..], nb_seq, src)
    }
}

/// `ZSTD_decompressBlock`, for a block that continues the previous ones:
/// the output so far is the prefix, from position 0 of `out`.
///
/// libzstd's version also notices when `dst` does not follow the previous
/// output (`ZSTD_checkContinuity`); callers of the port's say where the
/// window is through [`BlockOut`].
pub(crate) fn decompress_block(
    dctx: &mut DCtx,
    bo: &mut BlockOut<'_, '_>,
    src: &[u8],
) -> Result<usize> {
    dctx.is_frame_decompression = false;
    decompress_block_internal(dctx, bo, src, false)
}
