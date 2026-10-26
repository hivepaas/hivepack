//! Decoding frames: port of the one-call half of
//! `decompress/zstd_decompress.c` (streaming comes later).
//!
//! libzstd decodes into a caller's buffer that may overlap the input
//! ("in-place" decompression). The port takes an output slice and an input
//! slice, which cannot overlap, so that case does not arise.

use std::sync::Arc;

use crate::common::entropy_common::fse_read_ncount;
use crate::common::error_private::{Error, ErrorCode, Result, error};
use crate::common::mem::{read_le16, read_le32, read_le64};
use crate::common::xxhash::{Xxh64State, xxh64};
use crate::common::zstd_internal::{
    BlockType, LL_BITS, LL_FSE_LOG, MAX_LL, MAX_ML, MAX_OFF, ML_BITS, ML_FSE_LOG, OFF_FSE_LOG,
    ZSTD_BLOCKHEADERSIZE, ZSTD_BLOCKSIZE_MAX, ZSTD_DID_FIELD_SIZE, ZSTD_FCS_FIELD_SIZE,
    ZSTD_FRAMEIDSIZE, ZSTD_MAGIC_DICTIONARY, ZSTD_MAGIC_SKIPPABLE_MASK, ZSTD_MAGIC_SKIPPABLE_START,
    ZSTD_MAGICNUMBER, ZSTD_WINDOWLOG_ABSOLUTEMIN,
};
use crate::decompress::huf_decompress::{HufReadDTableX2Workspace, huf_read_dtable_x2_wksp};
use crate::decompress::zstd_ddict::{DDict, DictContentType};
use crate::decompress::zstd_decompress_block::{
    BlockOut, BlockProperties, build_fse_table, decompress_block_internal, get_c_block_size,
};
use crate::decompress::zstd_decompress_internal::{
    CONTENTSIZE_UNKNOWN, DCtx, DDictHashSet, DictUses, EntropyDTables, ExtDict, Format,
    FrameHeader, FrameType, LL_BASE, ML_BASE, OF_BASE, OF_BITS, TableRef,
    ZSTD_MAXWINDOWSIZE_DEFAULT, ZSTD_WINDOWLOG_LIMIT_DEFAULT,
};

/// `ZSTD_SKIPPABLEHEADERSIZE`
pub const SKIPPABLE_HEADER_SIZE: usize = 8;
/// `ZSTD_WINDOWLOG_MAX` for a 64-bit machine. libzstd lowers it to 30 on
/// 32-bit machines; the port keeps 31 everywhere.
pub const WINDOWLOG_MAX: u32 = 31;
/// `ZSTD_BLOCKSIZE_MAX_MIN`: the smallest maximum block size allowed.
pub const BLOCKSIZE_MAX_MIN: u32 = 1 << 10;
/// `ZSTD_FRAMEHEADERSIZE_MAX`
pub const FRAMEHEADER_SIZE_MAX: usize = 18;

/// `ZSTD_FRAMEHEADERSIZE_PREFIX`: what it takes to know the header's size.
const fn frame_header_size_prefix(format: Format) -> usize {
    match format {
        Format::Zstd1 => 5,
        Format::Zstd1Magicless => 1,
    }
}

/// `ZSTD_FRAMEHEADERSIZE_MIN`
const fn frame_header_size_min(format: Format) -> usize {
    match format {
        Format::Zstd1 => 6,
        Format::Zstd1Magicless => 2,
    }
}

/// `ZSTD_startingInputLength`
const fn starting_input_length(format: Format) -> usize {
    frame_header_size_prefix(format)
}

/// The address of a position in a buffer: what libzstd compares its
/// pointers against. Never dereferenced.
fn address(buffer: &[u8], pos: usize) -> usize {
    (buffer.as_ptr() as usize).wrapping_add(pos)
}

// ---------------------------------------------------------------------------
// The DDict hash set
// ---------------------------------------------------------------------------

/// `DDICT_HASHSET_MAX_LOAD_FACTOR_COUNT_MULT` and `_SIZE_MULT`: the table
/// grows once `count * 4 / size * 3` is not 0, that is from a quarter full
/// (the integer division makes it so, not the 0.75 libzstd describes).
const DDICT_HASHSET_MAX_LOAD_FACTOR_COUNT_MULT: usize = 4;
const DDICT_HASHSET_MAX_LOAD_FACTOR_SIZE_MULT: usize = 3;
const DDICT_HASHSET_TABLE_BASE_SIZE: usize = 64;
const DDICT_HASHSET_RESIZE_FACTOR: usize = 2;

impl DDictHashSet {
    /// `ZSTD_createDDictHashSet`
    pub(crate) fn new() -> DDictHashSet {
        DDictHashSet {
            table: vec![None; DDICT_HASHSET_TABLE_BASE_SIZE],
            count: 0,
        }
    }

    /// `ZSTD_DDictHashSet_getIndex`: where the search for `dict_id` starts.
    ///
    /// Differs from libzstd: the ID is hashed as little-endian bytes.
    /// libzstd hashes them in the machine's order, so on big-endian
    /// machines its IDs land in other slots.
    fn get_index(&self, dict_id: u32) -> usize {
        let hash = xxh64(&dict_id.to_le_bytes(), 0);
        (hash & (self.table.len() as u64 - 1)) as usize
    }

    /// `ZSTD_DDictHashSet_emplaceDDict`: adds `ddict` without growing the
    /// table, replacing one of the same ID.
    ///
    /// Differs from libzstd: the search wraps from the last slot to the
    /// first, as libzstd's development branch does since commit c6f91a4.
    /// libzstd 1.5.7 steps from the last slot to one past the table.
    fn emplace(&mut self, ddict: Arc<DDict>) -> Result<()> {
        let dict_id = ddict.dict_id;
        let mut idx = self.get_index(dict_id);
        let idx_range_mask = self.table.len() - 1;
        if self.count == self.table.len() {
            // The set is full.
            return error!(Generic);
        }
        while let Some(entry) = &self.table[idx] {
            if entry.dict_id == dict_id {
                self.table[idx] = Some(ddict);
                return Ok(());
            }
            idx = (idx + 1) & idx_range_mask;
        }
        self.table[idx] = Some(ddict);
        self.count += 1;
        Ok(())
    }

    /// `ZSTD_DDictHashSet_expand`: doubles the table and places every
    /// DDict again.
    fn expand(&mut self) -> Result<()> {
        let new_table_size = self.table.len() * DDICT_HASHSET_RESIZE_FACTOR;
        let old_table = std::mem::replace(&mut self.table, vec![None; new_table_size]);
        self.count = 0;
        for ddict in old_table.into_iter().flatten() {
            self.emplace(ddict)?;
        }
        Ok(())
    }

    /// `ZSTD_DDictHashSet_getDDict`: the DDict of ID `dict_id`, if any.
    ///
    /// As in libzstd, the search stops at the first DDict of ID 0, taken
    /// for an empty slot: a raw-content DDict found there is what comes
    /// back, whatever ID was asked for. The search wraps around as in
    /// [`DDictHashSet::emplace`].
    pub(crate) fn get(&self, dict_id: u32) -> Option<&Arc<DDict>> {
        let mut idx = self.get_index(dict_id);
        let idx_range_mask = self.table.len() - 1;
        loop {
            let curr_dict_id = self.table[idx].as_ref().map_or(0, |ddict| ddict.dict_id);
            if curr_dict_id == dict_id || curr_dict_id == 0 {
                break;
            }
            idx = (idx + 1) & idx_range_mask;
        }
        self.table[idx].as_ref()
    }

    /// `ZSTD_DDictHashSet_addDDict`: adds `ddict`, growing the table first
    /// if it is loaded enough.
    pub(crate) fn add(&mut self, ddict: Arc<DDict>) -> Result<()> {
        if self.count * DDICT_HASHSET_MAX_LOAD_FACTOR_COUNT_MULT / self.table.len()
            * DDICT_HASHSET_MAX_LOAD_FACTOR_SIZE_MULT
            != 0
        {
            self.expand()?;
        }
        self.emplace(ddict)
    }
}

// ---------------------------------------------------------------------------
// Frame headers
// ---------------------------------------------------------------------------

/// `ZSTD_isFrame`: whether `buffer` starts with a frame's magic number,
/// skippable or not (legacy frames are not supported).
pub fn is_frame(buffer: &[u8]) -> bool {
    if buffer.len() < ZSTD_FRAMEIDSIZE {
        return false;
    }
    let magic = read_le32(buffer, 0);
    magic == ZSTD_MAGICNUMBER || (magic & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START
}

/// `ZSTD_isSkippableFrame`
pub fn is_skippable_frame(buffer: &[u8]) -> bool {
    buffer.len() >= ZSTD_FRAMEIDSIZE
        && (read_le32(buffer, 0) & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START
}

/// `ZSTD_frameHeaderSize_internal`
fn frame_header_size_internal(src: &[u8], format: Format) -> Result<usize> {
    let min_input_size = starting_input_length(format);
    if src.len() < min_input_size {
        return error!(SrcSizeWrong);
    }
    let fhd = src[min_input_size - 1];
    let dict_id = usize::from(fhd & 3);
    let single_segment = (fhd >> 5) & 1 != 0;
    let fcs_id = usize::from(fhd >> 6);
    Ok(min_input_size
        + usize::from(!single_segment)
        + ZSTD_DID_FIELD_SIZE[dict_id]
        + ZSTD_FCS_FIELD_SIZE[fcs_id]
        + usize::from(single_segment && fcs_id == 0))
}

/// `ZSTD_frameHeaderSize`: the size of the frame header at the start of
/// `src`, which needs 5 bytes.
pub fn frame_header_size(src: &[u8]) -> Result<usize> {
    frame_header_size_internal(src, Format::Zstd1)
}

/// What [`get_frame_header`] found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameHeaderState {
    /// The whole header.
    Complete(FrameHeader),
    /// The input stops before the header ends: this many bytes are needed.
    NeedsInput(usize),
}

/// `ZSTD_getFrameHeader_advanced`
pub fn get_frame_header_advanced(src: &[u8], format: Format) -> Result<FrameHeaderState> {
    let ip = src;
    let src_size = src.len();
    let min_input_size = starting_input_length(format);

    if src_size < min_input_size {
        if src_size > 0 && format != Format::Zstd1Magicless {
            // Check that what there is could be a supported magic number,
            // to fail early if it cannot.
            let to_copy = src_size.min(4);
            let mut hbuf = ZSTD_MAGICNUMBER.to_le_bytes();
            hbuf[..to_copy].copy_from_slice(&src[..to_copy]);
            if u32::from_le_bytes(hbuf) != ZSTD_MAGICNUMBER {
                // Not a zstd frame: maybe a skippable one.
                let mut hbuf = ZSTD_MAGIC_SKIPPABLE_START.to_le_bytes();
                hbuf[..to_copy].copy_from_slice(&src[..to_copy]);
                if (u32::from_le_bytes(hbuf) & ZSTD_MAGIC_SKIPPABLE_MASK)
                    != ZSTD_MAGIC_SKIPPABLE_START
                {
                    return error!(PrefixUnknown);
                }
            }
        }
        return Ok(FrameHeaderState::NeedsInput(min_input_size));
    }

    let mut zfh = FrameHeader::default();
    if format != Format::Zstd1Magicless && read_le32(src, 0) != ZSTD_MAGICNUMBER {
        if (read_le32(src, 0) & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START {
            // A skippable frame.
            if src_size < SKIPPABLE_HEADER_SIZE {
                // The magic number and the frame length.
                return Ok(FrameHeaderState::NeedsInput(SKIPPABLE_HEADER_SIZE));
            }
            zfh.frame_type = FrameType::Skippable;
            zfh.dict_id = read_le32(src, 0) - ZSTD_MAGIC_SKIPPABLE_START;
            zfh.header_size = SKIPPABLE_HEADER_SIZE as u32;
            zfh.frame_content_size = u64::from(read_le32(src, ZSTD_FRAMEIDSIZE));
            return Ok(FrameHeaderState::Complete(zfh));
        }
        return error!(PrefixUnknown);
    }

    // Enough input to read the whole header?
    let fh_size = frame_header_size_internal(src, format)?;
    if src_size < fh_size {
        return Ok(FrameHeaderState::NeedsInput(fh_size));
    }
    zfh.header_size = fh_size as u32;

    let fhd_byte = ip[min_input_size - 1];
    let mut pos = min_input_size;
    let dict_id_size_code = fhd_byte & 3;
    let checksum_flag = (fhd_byte >> 2) & 1 != 0;
    let single_segment = (fhd_byte >> 5) & 1 != 0;
    let fcs_id = fhd_byte >> 6;
    let mut window_size: u64 = 0;
    let mut dict_id: u32 = 0;
    let mut frame_content_size = CONTENTSIZE_UNKNOWN;
    if fhd_byte & 0x08 != 0 {
        // Reserved bits, which must be zero.
        return error!(FrameParameterUnsupported);
    }

    if !single_segment {
        let wl_byte = ip[pos];
        pos += 1;
        let window_log = u32::from(wl_byte >> 3) + ZSTD_WINDOWLOG_ABSOLUTEMIN;
        if window_log > WINDOWLOG_MAX {
            return error!(FrameParameterWindowTooLarge);
        }
        window_size = 1u64 << window_log;
        window_size += (window_size >> 3) * u64::from(wl_byte & 7);
    }
    match dict_id_size_code {
        0 => {}
        1 => {
            dict_id = u32::from(ip[pos]);
            pos += 1;
        }
        2 => {
            dict_id = u32::from(read_le16(ip, pos));
            pos += 2;
        }
        _ => {
            dict_id = read_le32(ip, pos);
            pos += 4;
        }
    }
    match fcs_id {
        0 => {
            if single_segment {
                frame_content_size = u64::from(ip[pos]);
            }
        }
        1 => frame_content_size = u64::from(read_le16(ip, pos)) + 256,
        2 => frame_content_size = u64::from(read_le32(ip, pos)),
        _ => frame_content_size = read_le64(ip, pos),
    }
    if single_segment {
        window_size = frame_content_size;
    }

    zfh.frame_type = FrameType::Frame;
    zfh.frame_content_size = frame_content_size;
    zfh.window_size = window_size;
    zfh.block_size_max = window_size.min(ZSTD_BLOCKSIZE_MAX as u64) as u32;
    zfh.dict_id = dict_id;
    zfh.checksum_flag = checksum_flag;
    Ok(FrameHeaderState::Complete(zfh))
}

/// `ZSTD_getFrameHeader`: reads the frame header at the start of `src`.
/// It does not consume input, only reads it.
pub fn get_frame_header(src: &[u8]) -> Result<FrameHeaderState> {
    get_frame_header_advanced(src, Format::Zstd1)
}

/// The result of [`get_frame_content_size`] and [`find_decompressed_size`]:
/// libzstd's `ZSTD_CONTENTSIZE_UNKNOWN` and `ZSTD_CONTENTSIZE_ERROR`, or a
/// size.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ContentSize {
    Known(u64),
    /// The frame does not say.
    Unknown,
    /// Not a frame, or too short to tell.
    Error,
}

impl ContentSize {
    /// How libzstd returns it: the size, or one of its two special values.
    fn from_raw(size: u64) -> ContentSize {
        match size {
            CONTENTSIZE_UNKNOWN => ContentSize::Unknown,
            CONTENTSIZE_ERROR => ContentSize::Error,
            size => ContentSize::Known(size),
        }
    }
}

/// `ZSTD_CONTENTSIZE_ERROR`
const CONTENTSIZE_ERROR: u64 = u64::MAX - 1;

/// `ZSTD_getFrameContentSize` as libzstd returns it.
fn get_frame_content_size_raw(src: &[u8]) -> u64 {
    match get_frame_header(src) {
        Ok(FrameHeaderState::Complete(zfh)) if zfh.frame_type == FrameType::Skippable => 0,
        Ok(FrameHeaderState::Complete(zfh)) => zfh.frame_content_size,
        _ => CONTENTSIZE_ERROR,
    }
}

/// `ZSTD_getFrameContentSize`: the content size of the frame at the start
/// of `src`, as its header gives it.
pub fn get_frame_content_size(src: &[u8]) -> ContentSize {
    ContentSize::from_raw(get_frame_content_size_raw(src))
}

/// `readSkippableFrameSize`
fn read_skippable_frame_size(src: &[u8]) -> Result<usize> {
    if src.len() < SKIPPABLE_HEADER_SIZE {
        return error!(SrcSizeWrong);
    }
    let size_u32 = read_le32(src, ZSTD_FRAMEIDSIZE);
    if size_u32.wrapping_add(SKIPPABLE_HEADER_SIZE as u32) < size_u32 {
        return error!(FrameParameterUnsupported);
    }
    let skippable_size = SKIPPABLE_HEADER_SIZE + size_u32 as usize;
    if skippable_size > src.len() {
        return error!(SrcSizeWrong);
    }
    Ok(skippable_size)
}

/// `ZSTD_readSkippableFrame`: copies the content of the skippable frame at
/// the start of `src` to `dst`. Returns its size, and the magic number's
/// variant (0 to 15).
pub fn read_skippable_frame(dst: &mut [u8], src: &[u8]) -> Result<(usize, u32)> {
    if src.len() < SKIPPABLE_HEADER_SIZE {
        return error!(SrcSizeWrong);
    }
    let magic_number = read_le32(src, 0);
    let skippable_frame_size = read_skippable_frame_size(src);
    // libzstd checks the frame size after the magic number, whatever the
    // size's error.
    if !is_skippable_frame(src) {
        return error!(FrameParameterUnsupported);
    }
    let skippable_frame_size = match skippable_frame_size {
        Ok(size) => size,
        // libzstd subtracts the header size from the error code and goes on;
        // the only error left possible here is a size past the input.
        Err(_) => return error!(SrcSizeWrong),
    };
    let skippable_content_size = skippable_frame_size - SKIPPABLE_HEADER_SIZE;
    if skippable_content_size > dst.len() {
        return error!(DstSizeTooSmall);
    }
    dst[..skippable_content_size]
        .copy_from_slice(&src[SKIPPABLE_HEADER_SIZE..skippable_frame_size]);
    Ok((
        skippable_content_size,
        magic_number - ZSTD_MAGIC_SKIPPABLE_START,
    ))
}

/// `ZSTD_findDecompressedSize`: the total content size of the frames in
/// `src`, which must hold whole frames and nothing else.
pub fn find_decompressed_size(src: &[u8]) -> ContentSize {
    let mut src = src;
    let mut total_dst_size: u64 = 0;

    while src.len() >= starting_input_length(Format::Zstd1) {
        let magic_number = read_le32(src, 0);

        if (magic_number & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START {
            let Ok(skippable_size) = read_skippable_frame_size(src) else {
                return ContentSize::Error;
            };
            src = &src[skippable_size..];
            continue;
        }

        let fcs = get_frame_content_size_raw(src);
        if fcs >= CONTENTSIZE_ERROR {
            return ContentSize::from_raw(fcs);
        }
        let Some(total) = total_dst_size.checked_add(fcs) else {
            return ContentSize::Error;
        };
        total_dst_size = total;

        // Skip to the next frame.
        let Ok(frame_src_size) = find_frame_compressed_size(src) else {
            return ContentSize::Error;
        };
        src = &src[frame_src_size..];
    }

    if !src.is_empty() {
        return ContentSize::Error;
    }
    ContentSize::Known(total_dst_size)
}

/// `ZSTD_frameSizeInfo`
struct FrameSizeInfo {
    nb_blocks: usize,
    compressed_size: usize,
    decompressed_bound: u64,
}

/// `ZSTD_findFrameSizeInfo`: walks the frame at the start of `src`.
fn find_frame_size_info(src: &[u8], format: Format) -> Result<FrameSizeInfo> {
    if format == Format::Zstd1
        && src.len() >= SKIPPABLE_HEADER_SIZE
        && (read_le32(src, 0) & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START
    {
        return Ok(FrameSizeInfo {
            nb_blocks: 0,
            compressed_size: read_skippable_frame_size(src)?,
            decompressed_bound: 0,
        });
    }

    let mut ip = 0usize;
    let mut remaining_size = src.len();
    let mut nb_blocks = 0usize;

    // The frame header.
    let zfh = match get_frame_header_advanced(src, format)? {
        FrameHeaderState::Complete(zfh) => zfh,
        FrameHeaderState::NeedsInput(_) => return error!(SrcSizeWrong),
    };
    ip += zfh.header_size as usize;
    remaining_size -= zfh.header_size as usize;

    // Each block.
    loop {
        let mut block_properties = BlockProperties {
            block_type: BlockType::Raw,
            last_block: false,
            orig_size: 0,
        };
        let c_block_size = get_c_block_size(&src[ip..], &mut block_properties)?;
        if ZSTD_BLOCKHEADERSIZE + c_block_size > remaining_size {
            return error!(SrcSizeWrong);
        }
        ip += ZSTD_BLOCKHEADERSIZE + c_block_size;
        remaining_size -= ZSTD_BLOCKHEADERSIZE + c_block_size;
        nb_blocks += 1;
        if block_properties.last_block {
            break;
        }
    }

    // The checksum.
    if zfh.checksum_flag {
        if remaining_size < 4 {
            return error!(SrcSizeWrong);
        }
        ip += 4;
    }

    let decompressed_bound = if zfh.frame_content_size != CONTENTSIZE_UNKNOWN {
        zfh.frame_content_size
    } else {
        (nb_blocks as u64).wrapping_mul(u64::from(zfh.block_size_max))
    };
    Ok(FrameSizeInfo {
        nb_blocks,
        compressed_size: ip,
        decompressed_bound,
    })
}

/// `ZSTD_findFrameCompressedSize`: the size of the frame (or skippable
/// frame) at the start of `src`.
pub fn find_frame_compressed_size(src: &[u8]) -> Result<usize> {
    find_frame_size_info(src, Format::Zstd1).map(|info| info.compressed_size)
}

/// `ZSTD_decompressBound`: an upper bound on what the frames in `src`
/// decode to, `None` if they are not valid.
pub fn decompress_bound(src: &[u8]) -> Option<u64> {
    let mut src = src;
    let mut bound: u64 = 0;
    while !src.is_empty() {
        let info = find_frame_size_info(src, Format::Zstd1).ok()?;
        if info.decompressed_bound == CONTENTSIZE_ERROR {
            return None;
        }
        src = &src[info.compressed_size..];
        bound = bound.wrapping_add(info.decompressed_bound);
    }
    Some(bound)
}

/// `ZSTD_getDictID_fromDict`: the ID of a zstd dictionary, 0 for raw
/// content.
pub fn get_dict_id_from_dict(dict: &[u8]) -> u32 {
    if dict.len() < 8 || read_le32(dict, 0) != ZSTD_MAGIC_DICTIONARY {
        return 0;
    }
    read_le32(dict, ZSTD_FRAMEIDSIZE)
}

/// `ZSTD_getDictID_fromFrame`: the ID of the dictionary the frame needs, 0
/// if it needs none, does not say, or cannot be read.
pub fn get_dict_id_from_frame(src: &[u8]) -> u32 {
    match get_frame_header(src) {
        Ok(FrameHeaderState::Complete(zfh)) => zfh.dict_id,
        Ok(FrameHeaderState::NeedsInput(_)) => 0,
        Err(_) => 0,
    }
}

// ---------------------------------------------------------------------------
// Dictionaries
// ---------------------------------------------------------------------------

/// `ZSTD_loadDEntropy`: reads the entropy tables of the zstd dictionary
/// `dict`. Returns the size of that part.
pub(crate) fn load_d_entropy(entropy: &mut EntropyDTables, dict: &[u8]) -> Result<usize> {
    let dict_end = dict.len();
    if dict.len() <= 8 {
        return error!(DictionaryCorrupted);
    }
    debug_assert!(read_le32(dict, 0) == ZSTD_MAGIC_DICTIONARY);
    // Skip the header: magic number and ID.
    let mut dict_ptr = 8usize;

    {
        // libzstd uses the FSE tables as the workspace here.
        let mut workspace = Box::new(HufReadDTableX2Workspace::default());
        let Ok(h_size) =
            huf_read_dtable_x2_wksp(&mut entropy.huf_table, &dict[dict_ptr..], &mut workspace)
        else {
            return error!(DictionaryCorrupted);
        };
        dict_ptr += h_size;
    }

    {
        let mut offcode_ncount = [0i16; MAX_OFF as usize + 1];
        let mut offcode_max_value = MAX_OFF;
        let mut offcode_log = 0;
        let Ok(offcode_header_size) = fse_read_ncount(
            &mut offcode_ncount,
            &mut offcode_max_value,
            &mut offcode_log,
            &dict[dict_ptr..],
        ) else {
            return error!(DictionaryCorrupted);
        };
        if offcode_max_value > MAX_OFF || offcode_log > OFF_FSE_LOG {
            return error!(DictionaryCorrupted);
        }
        build_fse_table(
            &mut entropy.of_table,
            &offcode_ncount,
            offcode_max_value,
            &OF_BASE,
            &OF_BITS,
            offcode_log,
            &mut entropy.workspace,
        );
        dict_ptr += offcode_header_size;
    }

    {
        let mut matchlength_ncount = [0i16; MAX_ML as usize + 1];
        let mut matchlength_max_value = MAX_ML;
        let mut matchlength_log = 0;
        let Ok(matchlength_header_size) = fse_read_ncount(
            &mut matchlength_ncount,
            &mut matchlength_max_value,
            &mut matchlength_log,
            &dict[dict_ptr..],
        ) else {
            return error!(DictionaryCorrupted);
        };
        if matchlength_max_value > MAX_ML || matchlength_log > ML_FSE_LOG {
            return error!(DictionaryCorrupted);
        }
        build_fse_table(
            &mut entropy.ml_table,
            &matchlength_ncount,
            matchlength_max_value,
            &ML_BASE,
            &ML_BITS,
            matchlength_log,
            &mut entropy.workspace,
        );
        dict_ptr += matchlength_header_size;
    }

    {
        let mut litlength_ncount = [0i16; MAX_LL as usize + 1];
        let mut litlength_max_value = MAX_LL;
        let mut litlength_log = 0;
        let Ok(litlength_header_size) = fse_read_ncount(
            &mut litlength_ncount,
            &mut litlength_max_value,
            &mut litlength_log,
            &dict[dict_ptr..],
        ) else {
            return error!(DictionaryCorrupted);
        };
        if litlength_max_value > MAX_LL || litlength_log > LL_FSE_LOG {
            return error!(DictionaryCorrupted);
        }
        build_fse_table(
            &mut entropy.ll_table,
            &litlength_ncount,
            litlength_max_value,
            &LL_BASE,
            &LL_BITS,
            litlength_log,
            &mut entropy.workspace,
        );
        dict_ptr += litlength_header_size;
    }

    if dict_ptr + 12 > dict_end {
        return error!(DictionaryCorrupted);
    }
    let dict_content_size = dict_end - (dict_ptr + 12);
    for i in 0..3 {
        let rep = read_le32(dict, dict_ptr);
        dict_ptr += 4;
        if rep == 0 || rep as usize > dict_content_size {
            return error!(DictionaryCorrupted);
        }
        entropy.rep[i] = rep;
    }

    Ok(dict_ptr)
}

/// The window a frame starts with, besides its own output: the content of
/// the dictionary in use, and its tables when it has some.
#[derive(Clone, Copy)]
struct FrameDict<'d> {
    content: ExtDict<'d>,
    entropy: Option<&'d EntropyDTables>,
}

impl FrameDict<'_> {
    const NONE: FrameDict<'static> = FrameDict {
        content: ExtDict::None,
        entropy: None,
    };
}

impl DCtx {
    /// `ZSTD_decompressBegin`: gets ready for a new frame.
    pub(crate) fn decompress_begin(&mut self) {
        self.processed_c_size = 0;
        self.decoded_size = 0;
        self.previous_dst_end = 0;
        self.dict_end = 0;
        self.reset_entropy();
        self.dict_id = 0;
        self.is_frame_decompression = true;
    }

    /// `ZSTD_refDictContent`, for the pointer bookkeeping: the window will
    /// be `content`.
    fn ref_dict_content(&mut self, content: &[u8]) {
        self.dict_end = self.previous_dst_end;
        self.previous_dst_end = address(content, content.len());
    }

    /// `ZSTD_decompress_insertDictionary`: loads `dict`'s tables, if it is a
    /// zstd dictionary, and returns its content.
    fn insert_dictionary<'d>(&mut self, dict: &'d [u8]) -> Result<&'d [u8]> {
        if dict.len() < 8 || read_le32(dict, 0) != ZSTD_MAGIC_DICTIONARY {
            // Raw content.
            self.ref_dict_content(dict);
            return Ok(dict);
        }
        self.dict_id = read_le32(dict, ZSTD_FRAMEIDSIZE);

        // The entropy tables.
        let Ok(e_size) = load_d_entropy(&mut self.entropy, dict) else {
            return error!(DictionaryCorrupted);
        };
        let content = &dict[e_size..];
        self.lit_entropy = true;
        self.fse_entropy = true;

        // The rest is content.
        self.ref_dict_content(content);
        Ok(content)
    }

    /// `ZSTD_decompressBegin_usingDict`
    fn decompress_begin_using_dict<'d>(&mut self, dict: Option<&'d [u8]>) -> Result<FrameDict<'d>> {
        self.decompress_begin();
        let Some(dict) = dict.filter(|d| !d.is_empty()) else {
            return Ok(FrameDict::NONE);
        };
        match self.insert_dictionary(dict) {
            Ok(content) => Ok(FrameDict {
                content: ExtDict::Separate(content),
                entropy: None,
            }),
            Err(_) => error!(DictionaryCorrupted),
        }
    }

    /// `ZSTD_decompressBegin_usingDDict`
    fn decompress_begin_using_ddict<'d>(&mut self, ddict: Option<&'d DDict>) -> FrameDict<'d> {
        if let Some(ddict) = ddict {
            // A dictionary other than the one just used is presumably not in
            // the processor's cache: the first block then prefetches.
            self.ddict_is_cold = self.dict_end != address(&ddict.content, ddict.content.len());
        }
        self.decompress_begin();
        match ddict {
            // A missing DDict means no dictionary.
            None => FrameDict::NONE,
            Some(ddict) => {
                self.copy_ddict_parameters(ddict);
                FrameDict {
                    content: ExtDict::Separate(&ddict.content),
                    entropy: ddict.entropy_present.then_some(&*ddict.entropy),
                }
            }
        }
    }

    /// `ZSTD_copyDDictParameters`
    fn copy_ddict_parameters(&mut self, ddict: &DDict) {
        self.dict_id = ddict.dict_id;
        self.dict_end = address(&ddict.content, ddict.content.len());
        self.previous_dst_end = self.dict_end;
        if ddict.entropy_present {
            self.lit_entropy = true;
            self.fse_entropy = true;
            self.ll_tptr = TableRef::Dict;
            self.ml_tptr = TableRef::Dict;
            self.of_tptr = TableRef::Dict;
            self.huf_ptr = TableRef::Dict;
            self.entropy.rep = ddict.entropy.rep;
        } else {
            self.lit_entropy = false;
            self.fse_entropy = false;
        }
    }

    /// `ZSTD_checkContinuity`, for the pointer bookkeeping: a frame's output
    /// never continues the previous segment, which becomes the older one.
    fn check_continuity(&mut self, dst: &[u8], pos: usize, dst_size: usize) {
        let dst_address = address(dst, pos);
        if dst_address != self.previous_dst_end && dst_size > 0 {
            self.dict_end = self.previous_dst_end;
            self.previous_dst_end = dst_address;
        }
    }

    /// `ZSTD_DCtx_selectFrameDDict`: with several dictionaries referenced,
    /// switches to the one the frame names.
    ///
    /// As in libzstd, when called for a one-call decompression this changes
    /// the dictionary later frames use, not the one already set up for this
    /// frame.
    ///
    /// Differs from libzstd: libzstd frees a dictionary loaded with
    /// `ZSTD_DCtx_loadDictionary` (or a prefix) here, while this frame and
    /// the rest of the call still read it: a use-after-free in 1.5.7, still
    /// in its development branch in October 2026. The port keeps it alive,
    /// and decodes as libzstd would if the freed memory were intact.
    fn select_frame_ddict(&mut self) {
        if self.ddict.is_some()
            && let Some(frame_ddict) = self
                .ddict_set
                .as_ref()
                .and_then(|set| set.get(self.f_params.dict_id))
        {
            let frame_ddict = frame_ddict.clone();
            self.clear_dict();
            self.dict_id = self.f_params.dict_id;
            self.ddict = Some(frame_ddict);
            self.dict_uses = DictUses::Indefinitely;
        }
    }

    /// `ZSTD_decodeFrameHeader`: reads the header, whose size is known.
    fn decode_frame_header(&mut self, src: &[u8]) -> Result<()> {
        match get_frame_header_advanced(src, self.format)? {
            FrameHeaderState::NeedsInput(_) => return error!(SrcSizeWrong),
            FrameHeaderState::Complete(zfh) => self.f_params = zfh,
        }

        // With several dictionaries, use the one the frame names.
        if self.ref_multiple_ddicts && self.ddict_set.is_some() {
            self.select_frame_ddict();
        }

        if self.f_params.dict_id != 0 && self.dict_id != self.f_params.dict_id {
            return error!(DictionaryWrong);
        }
        self.validate_checksum = self.f_params.checksum_flag && !self.force_ignore_checksum;
        if self.validate_checksum {
            self.xxh_state = Xxh64State::new(0);
        }
        self.processed_c_size += src.len() as u64;
        Ok(())
    }

    /// `ZSTD_decompressFrame`: decodes the frame at the start of `src` to
    /// `dst[op_start..]`. Returns the size it decoded to and the size of the
    /// frame.
    fn decompress_frame(
        &mut self,
        dst: &mut [u8],
        op_start: usize,
        src: &[u8],
        dict: FrameDict<'_>,
    ) -> Result<(usize, usize)> {
        let mut ip = 0usize;
        let oend = dst.len();
        let mut op = op_start;
        let mut remaining_src_size = src.len();

        if remaining_src_size < frame_header_size_min(self.format) + ZSTD_BLOCKHEADERSIZE {
            return error!(SrcSizeWrong);
        }

        // The frame header.
        {
            let frame_header_size = frame_header_size_internal(
                &src[..frame_header_size_prefix(self.format)],
                self.format,
            )?;
            if remaining_src_size < frame_header_size + ZSTD_BLOCKHEADERSIZE {
                return error!(SrcSizeWrong);
            }
            self.decode_frame_header(&src[..frame_header_size])?;
            ip += frame_header_size;
            remaining_src_size -= frame_header_size;
        }

        // A smaller maximum block size, if set.
        self.block_size_max = self.f_params.block_size_max as usize;
        if self.max_block_size_param != 0 {
            self.block_size_max = self.block_size_max.min(self.max_block_size_param as usize);
            self.f_params.block_size_max = self.block_size_max as u32;
        }

        // Each block.
        loop {
            let mut block_properties = BlockProperties {
                block_type: BlockType::Raw,
                last_block: false,
                orig_size: 0,
            };
            let c_block_size =
                get_c_block_size(&src[ip..ip + remaining_src_size], &mut block_properties)?;

            ip += ZSTD_BLOCKHEADERSIZE;
            remaining_src_size -= ZSTD_BLOCKHEADERSIZE;
            if c_block_size > remaining_src_size {
                return error!(SrcSizeWrong);
            }
            let block = &src[ip..ip + c_block_size];

            let decoded_size = match block_properties.block_type {
                BlockType::Compressed => {
                    debug_assert!(self.is_frame_decompression);
                    let mut bo = BlockOut {
                        out: &mut *dst,
                        dst: op,
                        dst_capacity: oend - op,
                        prefix_start: op_start,
                        ext: dict.content,
                        dict: dict.entropy,
                    };
                    decompress_block_internal(self, &mut bo, block, false)?
                }
                BlockType::Raw => {
                    // ZSTD_copyRawBlock
                    if c_block_size > oend - op {
                        return error!(DstSizeTooSmall);
                    }
                    dst[op..op + c_block_size].copy_from_slice(block);
                    c_block_size
                }
                BlockType::Rle => {
                    // ZSTD_setRleBlock
                    let regen_size = block_properties.orig_size as usize;
                    if regen_size > oend - op {
                        return error!(DstSizeTooSmall);
                    }
                    dst[op..op + regen_size].fill(block[0]);
                    regen_size
                }
                BlockType::Reserved => return error!(CorruptionDetected),
            };
            if self.validate_checksum {
                self.xxh_state.update(&dst[op..op + decoded_size]);
            }
            op += decoded_size;
            ip += c_block_size;
            remaining_src_size -= c_block_size;
            if block_properties.last_block {
                break;
            }
        }

        if self.f_params.frame_content_size != CONTENTSIZE_UNKNOWN
            && (op - op_start) as u64 != self.f_params.frame_content_size
        {
            return error!(CorruptionDetected);
        }
        if self.f_params.checksum_flag {
            // The frame content checksum.
            if remaining_src_size < 4 {
                return error!(ChecksumWrong);
            }
            if !self.force_ignore_checksum {
                let check_calc = self.xxh_state.digest() as u32;
                let check_read = read_le32(src, ip);
                if check_read != check_calc {
                    return error!(ChecksumWrong);
                }
            }
            ip += 4;
        }
        Ok((op - op_start, ip))
    }

    /// `ZSTD_decompressMultiFrame`: decodes every frame in `src`, with `dict`
    /// or `ddict` (not both).
    fn decompress_multi_frame(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        dict: Option<&[u8]>,
        ddict: Option<&DDict>,
    ) -> Result<usize> {
        let mut src_pos = 0usize;
        let mut op = 0usize;
        let mut more_than_1_frame = false;
        debug_assert!(dict.is_none() || ddict.is_none());

        while src.len() - src_pos >= starting_input_length(self.format) {
            let frame_src = &src[src_pos..];
            if self.format == Format::Zstd1 && frame_src.len() >= 4 {
                let magic_number = read_le32(frame_src, 0);
                if (magic_number & ZSTD_MAGIC_SKIPPABLE_MASK) == ZSTD_MAGIC_SKIPPABLE_START {
                    // A skippable frame: skip it.
                    let skippable_size = read_skippable_frame_size(frame_src)?;
                    src_pos += skippable_size;
                    continue;
                }
            }

            let frame_dict = if ddict.is_some() {
                self.decompress_begin_using_ddict(ddict)
            } else {
                // With no dictionary too.
                self.decompress_begin_using_dict(dict)?
            };
            self.check_continuity(dst, op, dst.len() - op);

            match self.decompress_frame(dst, op, frame_src, frame_dict) {
                Err(error) if error.code() == ErrorCode::PrefixUnknown && more_than_1_frame => {
                    // After a frame, bytes that are not a frame more likely
                    // mean the input size is wrong.
                    return error!(SrcSizeWrong);
                }
                Err(error) => return Err(error),
                Ok((decoded, consumed)) => {
                    op += decoded;
                    src_pos += consumed;
                }
            }
            more_than_1_frame = true;
        }

        if src_pos != src.len() {
            // Input left over.
            return error!(SrcSizeWrong);
        }
        Ok(op)
    }

    /// `ZSTD_getDDict`: the dictionary for the next frame.
    fn get_ddict(&mut self) -> Option<Arc<DDict>> {
        match self.dict_uses {
            DictUses::DontUse => {
                self.clear_dict();
                None
            }
            DictUses::Indefinitely => self.ddict.clone(),
            DictUses::Once => {
                self.dict_uses = DictUses::DontUse;
                self.ddict.clone()
            }
        }
    }

    /// `ZSTD_clearDict`
    fn clear_dict(&mut self) {
        self.ddict = None;
        self.dict_uses = DictUses::DontUse;
    }

    /// `ZSTD_decompressDCtx`: decodes the frames in `src` to `dst`, with the
    /// dictionary loaded or referenced, if any. Returns the size decoded.
    ///
    /// `src` must hold whole frames (and skippable frames), and nothing else.
    pub fn decompress(&mut self, dst: &mut [u8], src: &[u8]) -> Result<usize> {
        let ddict = self.get_ddict();
        self.decompress_multi_frame(dst, src, None, ddict.as_deref())
    }

    /// `ZSTD_decompress_usingDict`: decodes with `dict`, a zstd dictionary
    /// or raw content, read anew for each frame.
    pub fn decompress_using_dict(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        dict: &[u8],
    ) -> Result<usize> {
        self.decompress_multi_frame(dst, src, Some(dict), None)
    }

    /// `ZSTD_decompress_usingDDict`: decodes with a dictionary prepared
    /// once.
    pub fn decompress_using_ddict(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        ddict: &DDict,
    ) -> Result<usize> {
        self.decompress_multi_frame(dst, src, None, Some(ddict))
    }

    /// `ZSTD_DCtx_loadDictionary_advanced`, by copy: the dictionary for the
    /// frames that follow.
    pub fn load_dictionary_advanced(
        &mut self,
        dict: &[u8],
        content_type: DictContentType,
    ) -> Result<()> {
        self.clear_dict();
        if !dict.is_empty() {
            // libzstd reports any failure here as an allocation failure.
            let Ok(ddict) = DDict::with_content_type(dict, content_type) else {
                return error!(MemoryAllocation);
            };
            self.ddict = Some(Arc::new(ddict));
            self.dict_uses = DictUses::Indefinitely;
        }
        Ok(())
    }

    /// `ZSTD_DCtx_loadDictionary`: the dictionary for the frames that
    /// follow, copied in. An empty one means none.
    pub fn load_dictionary(&mut self, dict: &[u8]) -> Result<()> {
        self.load_dictionary_advanced(dict, DictContentType::Auto)
    }

    /// `ZSTD_DCtx_refPrefix`: raw content to use as the window for the next
    /// frame only. libzstd references it; the port copies it.
    pub fn ref_prefix(&mut self, prefix: &[u8]) -> Result<()> {
        self.load_dictionary_advanced(prefix, DictContentType::RawContent)?;
        self.dict_uses = DictUses::Once;
        Ok(())
    }

    /// `ZSTD_DCtx_refDDict`: the dictionary for the frames that follow, or
    /// none. With [`DParameter::RefMultipleDDicts`] on, each one referenced
    /// is kept, and a frame uses the one it names.
    pub fn ref_ddict(&mut self, ddict: Option<Arc<DDict>>) -> Result<()> {
        self.clear_dict();
        if let Some(ddict) = ddict {
            self.ddict = Some(ddict.clone());
            self.dict_uses = DictUses::Indefinitely;
            if self.ref_multiple_ddicts {
                self.ddict_set
                    .get_or_insert_with(DDictHashSet::new)
                    .add(ddict)?;
            }
        }
        Ok(())
    }

    /// `ZSTD_DCtx_setMaxWindowSize`: the largest window the context accepts
    /// when streaming.
    pub fn set_max_window_size(&mut self, max_window_size: usize) -> Result<()> {
        let min = 1usize << ZSTD_WINDOWLOG_ABSOLUTEMIN;
        let max = 1usize << WINDOWLOG_MAX;
        if max_window_size < min || max_window_size > max {
            return error!(ParameterOutOfBound);
        }
        self.max_window_size = max_window_size;
        Ok(())
    }

    /// `ZSTD_DCtx_setParameter`
    pub fn set_parameter(&mut self, parameter: DParameter) -> Result<()> {
        match parameter {
            DParameter::WindowLogMax(value) => {
                let value = if value == 0 {
                    ZSTD_WINDOWLOG_LIMIT_DEFAULT
                } else {
                    value
                };
                if !(ZSTD_WINDOWLOG_ABSOLUTEMIN..=WINDOWLOG_MAX).contains(&value) {
                    return error!(ParameterOutOfBound);
                }
                self.max_window_size = 1 << value;
            }
            DParameter::Format(format) => self.format = format,
            DParameter::StableOutBuffer(stable) => self.stable_out_buffer = stable,
            DParameter::ForceIgnoreChecksum(ignore) => self.force_ignore_checksum = ignore,
            DParameter::RefMultipleDDicts(multiple) => self.ref_multiple_ddicts = multiple,
            DParameter::DisableHuffmanAssembly(disable) => self.disable_huf_asm = disable,
            DParameter::MaxBlockSize(value) => {
                if value != 0 && !(BLOCKSIZE_MAX_MIN..=ZSTD_BLOCKSIZE_MAX as u32).contains(&value) {
                    return error!(ParameterOutOfBound);
                }
                self.max_block_size_param = value;
            }
        }
        Ok(())
    }

    /// `ZSTD_DCtx_getParameter`, as libzstd's integer value.
    pub fn get_parameter(&self, parameter: DParameterKind) -> i32 {
        match parameter {
            DParameterKind::WindowLogMax => {
                (usize::BITS - 1 - self.max_window_size.leading_zeros()) as i32
            }
            DParameterKind::Format => match self.format {
                Format::Zstd1 => 0,
                Format::Zstd1Magicless => 1,
            },
            DParameterKind::StableOutBuffer => i32::from(self.stable_out_buffer),
            DParameterKind::ForceIgnoreChecksum => i32::from(self.force_ignore_checksum),
            DParameterKind::RefMultipleDDicts => i32::from(self.ref_multiple_ddicts),
            DParameterKind::DisableHuffmanAssembly => i32::from(self.disable_huf_asm),
            DParameterKind::MaxBlockSize => self.max_block_size_param as i32,
        }
    }

    /// `ZSTD_DCtx_reset`
    pub fn reset(&mut self, reset: ResetDirective) -> Result<()> {
        if matches!(
            reset,
            ResetDirective::SessionOnly | ResetDirective::SessionAndParameters
        ) {
            self.is_frame_decompression = true;
        }
        if matches!(
            reset,
            ResetDirective::Parameters | ResetDirective::SessionAndParameters
        ) {
            self.clear_dict();
            // ZSTD_DCtx_resetParameters
            self.format = Format::Zstd1;
            self.max_window_size = ZSTD_MAXWINDOWSIZE_DEFAULT;
            self.stable_out_buffer = false;
            self.force_ignore_checksum = false;
            self.ref_multiple_ddicts = false;
            self.disable_huf_asm = false;
            self.max_block_size_param = 0;
        }
        Ok(())
    }
}

/// `ZSTD_dParameter`, with its value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DParameter {
    /// The largest window to accept when streaming, as a power of 2; 0 for
    /// the default, 27 (128 MiB). One-call decompression is bounded by its
    /// output instead.
    WindowLogMax(u32),
    /// Frames with or without the magic number.
    Format(Format),
    /// When streaming, the output buffer stays the same between calls.
    StableOutBuffer(bool),
    /// Do not check checksums.
    ForceIgnoreChecksum(bool),
    /// Keep every dictionary referenced with [`DCtx::ref_ddict`], and use
    /// the one each frame names.
    RefMultipleDDicts(bool),
    /// libzstd's switch for its assembly Huffman loop. The port has none; it
    /// is accepted and changes nothing.
    DisableHuffmanAssembly(bool),
    /// A smaller maximum block size, 1 KiB to 128 KiB; 0 for none.
    MaxBlockSize(u32),
}

/// A `ZSTD_dParameter`, for [`DCtx::get_parameter`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DParameterKind {
    WindowLogMax,
    Format,
    StableOutBuffer,
    ForceIgnoreChecksum,
    RefMultipleDDicts,
    DisableHuffmanAssembly,
    MaxBlockSize,
}

/// `ZSTD_ResetDirective`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResetDirective {
    /// Abandon the current frame; keep the parameters and dictionary.
    SessionOnly,
    /// Reset the parameters and drop the dictionary.
    Parameters,
    SessionAndParameters,
}

/// `ZSTD_decompress`: decodes the frames in `src` to `dst`, which must be
/// large enough for all of them. Returns the size decoded.
///
/// [`find_decompressed_size`] or [`get_frame_content_size`] tell how large,
/// when the frames say. Each call sets up a new context; reuse a [`DCtx`]
/// to avoid that.
pub fn decompress(dst: &mut [u8], src: &[u8]) -> Result<usize> {
    DCtx::new().decompress(dst, src)
}

impl From<Error> for std::io::Error {
    fn from(error: Error) -> Self {
        std::io::Error::other(error)
    }
}
