//! Blocks: port of `common/block_header_decoder.c`, `common/block_util.c`
//! and `common/block_decoder.c`, with `lzma_block` of `api/lzma/block.h`.

use crate::check::{CHECK_ID_MAX, CHECK_SIZE_MAX, Check, CheckState, crc32};
use crate::common::{Action, NextCoder, Ret, VLI_MAX, VLI_UNKNOWN, bufcpy, read32le, vli_is_valid};
use crate::filter::{Filter, filter_flags_decode, raw_decoder_init};
use crate::vli;

/// `LZMA_BLOCK_HEADER_SIZE_MIN`.
pub(crate) const BLOCK_HEADER_SIZE_MIN: u32 = 8;
/// `LZMA_BLOCK_HEADER_SIZE_MAX`.
pub(crate) const BLOCK_HEADER_SIZE_MAX: u32 = 1024;

/// `UNPADDED_SIZE_MIN`.
pub(crate) const UNPADDED_SIZE_MIN: u64 = 5;
/// `UNPADDED_SIZE_MAX`.
pub(crate) const UNPADDED_SIZE_MAX: u64 = VLI_MAX & !3;

/// `lzma_block_header_size_decode`.
pub(crate) fn header_size_decode(b: u8) -> u32 {
    (u32::from(b) + 1) * 4
}

/// `vli_ceil4`.
pub(crate) fn vli_ceil4(vli: u64) -> u64 {
    (vli + 3) & !3
}

/// `lzma_block`: the options of a Block, as its header gives them and as
/// decoding it fills them in.
#[derive(Clone, Debug)]
pub(crate) struct Block {
    pub(crate) version: u32,
    pub(crate) header_size: u32,
    pub(crate) check: Check,
    pub(crate) compressed_size: u64,
    pub(crate) uncompressed_size: u64,
    pub(crate) filters: Vec<Filter>,
    pub(crate) raw_check: [u8; CHECK_SIZE_MAX],
    pub(crate) ignore_check: bool,
}

impl Block {
    pub(crate) fn new() -> Block {
        Block {
            version: 0,
            header_size: 0,
            check: Check::NONE,
            compressed_size: VLI_UNKNOWN,
            uncompressed_size: VLI_UNKNOWN,
            filters: Vec::new(),
            raw_check: [0; CHECK_SIZE_MAX],
            ignore_check: false,
        }
    }

    /// `lzma_block_header_decode`: the Block Header in `input`, whose size
    /// `header_size` already has.
    pub(crate) fn header_decode(&mut self, input: &[u8]) -> Ret {
        // Initialize the filter options array. This way the caller can
        // safely free() the options even if an error occurs in this
        // function.
        self.filters.clear();

        // Versions 0 and 1 are supported. If a newer version was specified,
        // we need to downgrade it.
        if self.version > 1 {
            self.version = 1;
        }

        // This isn't a Block Header option but since the decompressor will
        // read it if version >= 1, it's better to initialize it here than
        // to expect the caller to do it since in almost all cases this
        // should be false.
        self.ignore_check = false;

        // Validate Block Header Size and Check type. The caller must have
        // already set these, so it is a programming error if this test
        // fails.
        if header_size_decode(input[0]) != self.header_size || self.check.0 > CHECK_ID_MAX {
            return Ret::ProgError;
        }

        // Exclude the CRC32 field.
        let in_size = self.header_size as usize - 4;

        // Verify CRC32
        if crc32(&input[..in_size], 0) != read32le(&input[in_size..]) {
            return Ret::DataError;
        }

        // Check for unsupported flags.
        if input[1] & 0x3C != 0 {
            return Ret::OptionsError;
        }

        // Start after the Block Header Size and Block Flags fields.
        let header = &input[..in_size];
        let mut in_pos = 2;

        // Compressed Size
        if input[1] & 0x40 != 0 {
            match vli::decode_single(&mut self.compressed_size, header, &mut in_pos) {
                Ret::Ok => {}
                ret => return ret,
            }

            // Validate Compressed Size. This checks that it isn't zero and
            // that the total size of the Block is a valid VLI.
            if self.unpadded_size() == 0 {
                return Ret::DataError;
            }
        } else {
            self.compressed_size = VLI_UNKNOWN;
        }

        // Uncompressed Size
        if input[1] & 0x80 != 0 {
            match vli::decode_single(&mut self.uncompressed_size, header, &mut in_pos) {
                Ret::Ok => {}
                ret => return ret,
            }
        } else {
            self.uncompressed_size = VLI_UNKNOWN;
        }

        // Filter Flags
        let filter_count = usize::from(input[1] & 3) + 1;
        for _ in 0..filter_count {
            match filter_flags_decode(header, &mut in_pos) {
                Ok(filter) => self.filters.push(filter),
                Err(ret) => {
                    self.filters.clear();
                    return ret;
                }
            }
        }

        // Padding
        while in_pos < in_size {
            let byte = input[in_pos];
            in_pos += 1;
            if byte != 0x00 {
                self.filters.clear();
                // Possibly some new field present so use
                // LZMA_OPTIONS_ERROR instead of LZMA_DATA_ERROR.
                return Ret::OptionsError;
            }
        }
        Ret::Ok
    }

    /// `lzma_block_unpadded_size`: 0 for invalid options, LZMA_VLI_UNKNOWN
    /// while the compressed size is not known.
    pub(crate) fn unpadded_size(&self) -> u64 {
        // Validate the values that we are interested in i.e. all but
        // Uncompressed Size and the filters.
        if self.version > 1
            || self.header_size < BLOCK_HEADER_SIZE_MIN
            || self.header_size > BLOCK_HEADER_SIZE_MAX
            || self.header_size & 3 != 0
            || !vli_is_valid(self.compressed_size)
            || self.compressed_size == 0
            || self.check.0 > CHECK_ID_MAX
        {
            return 0;
        }

        // If Compressed Size is unknown, return that we cannot know size of
        // the Block either.
        if self.compressed_size == VLI_UNKNOWN {
            return VLI_UNKNOWN;
        }

        // Calculate Unpadded Size and validate it.
        let unpadded_size =
            self.compressed_size + u64::from(self.header_size) + u64::from(self.check.size());
        if unpadded_size > UNPADDED_SIZE_MAX {
            return 0;
        }
        unpadded_size
    }
}

/// The sequence of the Block decoder.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sequence {
    Code,
    Padding,
    Check,
}

/// `lzma_block_coder` of `block_decoder.c`.
pub(crate) struct BlockDecoder {
    sequence: Sequence,
    /// The filters.
    next: Box<dyn NextCoder>,
    /// Decoding options; the sizes are filled in once the Block ends, as
    /// liblzma fills in the application's `lzma_block`.
    pub(crate) block: Block,
    /// Compressed Size calculated while decoding.
    compressed_size: u64,
    /// Uncompressed Size calculated while decoding.
    uncompressed_size: u64,
    /// Maximum allowed Compressed Size; this takes into account the size of
    /// the Block Header and Check fields when Compressed Size is unknown.
    compressed_limit: u64,
    /// Maximum allowed Uncompressed Size.
    uncompressed_limit: u64,
    /// Position when reading the Check field.
    check_pos: usize,
    /// Check of the uncompressed data.
    check: CheckState,
    /// True if the integrity check won't be calculated and verified.
    ignore_check: bool,
}

/// `is_size_valid`.
fn is_size_valid(size: u64, reference: u64) -> bool {
    reference == VLI_UNKNOWN || reference == size
}

impl BlockDecoder {
    /// `lzma_block_decoder_init`.
    pub(crate) fn new(block: Block) -> Result<BlockDecoder, Ret> {
        // Validate the options. lzma_block_unpadded_size() does that for us
        // except for Uncompressed Size and filters. Filters are validated
        // by the raw decoder.
        if block.unpadded_size() == 0 || !vli_is_valid(block.uncompressed_size) {
            return Err(Ret::ProgError);
        }

        // Basic initializations
        let compressed_limit = if block.compressed_size == VLI_UNKNOWN {
            (VLI_MAX & !3) - u64::from(block.header_size) - u64::from(block.check.size())
        } else {
            block.compressed_size
        };
        let uncompressed_limit = if block.uncompressed_size == VLI_UNKNOWN {
            VLI_MAX
        } else {
            block.uncompressed_size
        };

        // If the Check ID is not supported, we will just skip it.
        let check = CheckState::new(block.check);
        let ignore_check = if block.version >= 1 {
            block.ignore_check
        } else {
            false
        };

        // Initialize the filter chain.
        let next = raw_decoder_init(&block.filters)?;
        Ok(BlockDecoder {
            sequence: Sequence::Code,
            next,
            block,
            compressed_size: 0,
            uncompressed_size: 0,
            compressed_limit,
            uncompressed_limit,
            check_pos: 0,
            check,
            ignore_check,
        })
    }
}

impl NextCoder for BlockDecoder {
    /// `block_decode`.
    fn code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret {
        if self.sequence == Sequence::Code {
            // Limit the amount of input and output space that we give to
            // the raw decoder based on the information we have (or don't
            // have) from Block Header.
            let in_start = *in_pos;
            let out_start = *out_pos;
            let in_stop = *in_pos
                + ((input.len() - *in_pos) as u64).min(self.compressed_limit - self.compressed_size)
                    as usize;
            let out_stop = *out_pos
                + ((output.len() - *out_pos) as u64)
                    .min(self.uncompressed_limit - self.uncompressed_size)
                    as usize;

            let ret = self.next.code(
                &input[..in_stop],
                in_pos,
                &mut output[..out_stop],
                out_pos,
                action,
            );

            let in_used = *in_pos - in_start;
            let out_used = *out_pos - out_start;

            // Because we have limited the input and output sizes, we know
            // that these cannot grow too big or overflow.
            self.compressed_size += in_used as u64;
            self.uncompressed_size += out_used as u64;

            if ret == Ret::Ok {
                let comp_done = self.compressed_size == self.block.compressed_size;
                let uncomp_done = self.uncompressed_size == self.block.uncompressed_size;

                // If both input and output amounts match the sizes in Block
                // Header but we still got LZMA_OK instead of
                // LZMA_STREAM_END, the file is broken.
                if comp_done && uncomp_done {
                    return Ret::DataError;
                }

                // If the decoder has consumed all the input that it needs
                // but it still couldn't fill the output buffer or return
                // LZMA_STREAM_END, the file is broken.
                if comp_done && *out_pos < output.len() {
                    return Ret::DataError;
                }

                // If the decoder has produced all the output but it still
                // didn't return LZMA_STREAM_END or consume more input
                // (for example, detecting an end of payload marker may need
                // more input but produce no output) the file is broken.
                if uncomp_done && *in_pos < input.len() {
                    return Ret::DataError;
                }
            }

            // Don't waste time updating the integrity check if it will be
            // ignored. Also skip it if no new output was produced.
            if !self.ignore_check && out_used > 0 {
                self.check
                    .update(self.block.check, &output[out_start..out_start + out_used]);
            }

            if ret != Ret::StreamEnd {
                return ret;
            }

            // Compressed and Uncompressed Sizes are now at their final
            // values. Verify that they match the values given to us.
            if !is_size_valid(self.compressed_size, self.block.compressed_size)
                || !is_size_valid(self.uncompressed_size, self.block.uncompressed_size)
            {
                return Ret::DataError;
            }

            // Copy the values into coder->block. The caller may use this
            // information to construct Index.
            self.block.compressed_size = self.compressed_size;
            self.block.uncompressed_size = self.uncompressed_size;

            self.sequence = Sequence::Padding;
        }

        if self.sequence == Sequence::Padding {
            // Compressed Data is padded to a multiple of four bytes.
            while self.compressed_size & 3 != 0 {
                if *in_pos >= input.len() {
                    return Ret::Ok;
                }

                // We use compressed_size here just get the Padding right.
                // The actual Compressed Size was stored to coder->block
                // already, and won't be modified by us anymore.
                self.compressed_size += 1;

                let byte = input[*in_pos];
                *in_pos += 1;
                if byte != 0x00 {
                    return Ret::DataError;
                }
            }

            if self.block.check == Check::NONE {
                return Ret::StreamEnd;
            }

            if !self.ignore_check {
                self.check.finish(self.block.check);
            }

            self.sequence = Sequence::Check;
        }

        // Sequence::Check
        let check_size = self.block.check.size() as usize;
        bufcpy(
            input,
            in_pos,
            &mut self.block.raw_check[..check_size],
            &mut self.check_pos,
        );
        if self.check_pos < check_size {
            return Ret::Ok;
        }

        // Validate the Check only if we support it. coder->check.buffer
        // may be uninitialized when the Check ID is not supported.
        if !self.ignore_check
            && self.block.check.is_supported()
            && self.block.raw_check[..check_size] != self.check.buffer[..check_size]
        {
            return Ret::DataError;
        }
        Ret::StreamEnd
    }
}
