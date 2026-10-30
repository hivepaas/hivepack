//! Filters and filter chains: port of the decoding parts of
//! `common/filter_common.c`, `common/filter_decoder.c` and
//! `common/filter_flags_decoder.c`, with the filter IDs of
//! `api/lzma/lzma12.h`.

use crate::common::{FILTER_RESERVED_START, MEMUSAGE_BASE, NextCoder, Ret, VLI_UNKNOWN};
use crate::lz_decoder::{Lz, LzCoder};
use crate::lz_encoder::{LzEnc, LzEncCoder};
use crate::lzma_common::{LZMA1EXT_ALLOW_EOPM, LzmaOptions, is_lclppb_valid};
use crate::lzma_decoder::{self, LzmaDecoder};
use crate::lzma_encoder::{self, LzmaEncoder};
use crate::lzma2_decoder::{self, Lzma2Decoder};
use crate::lzma2_encoder::{self, Lzma2Encoder};
use crate::vli;

/// `LZMA_FILTER_LZMA1`.
pub const FILTER_LZMA1: u64 = 0x4000_0000_0000_0001;
/// `LZMA_FILTER_LZMA1EXT`.
pub const FILTER_LZMA1EXT: u64 = 0x4000_0000_0000_0002;
/// `LZMA_FILTER_LZMA2`.
pub const FILTER_LZMA2: u64 = 0x21;

/// `LZMA_FILTERS_MAX`.
pub const FILTERS_MAX: usize = 4;

/// `lzma_filter`: a filter of a chain, its ID and its options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    /// The Filter ID, such as [`FILTER_LZMA2`].
    pub id: u64,
    /// The options, for the filters that have them.
    pub options: Option<LzmaOptions>,
}

/// An entry of the `features` table of `filter_common.c`, for the filters
/// the port has.
struct Feature {
    id: u64,
    /// true if it is OK to use this filter as non-last filter in the
    /// chain.
    non_last_ok: bool,
    /// true if it is OK to use this filter as the last filter in the
    /// chain.
    last_ok: bool,
    /// true if the filter may change the size of the data (that is, the
    /// amount of encoded output can be different than the amount of
    /// uncompressed input).
    changes_size: bool,
}

/// `features`.
const FEATURES: [Feature; 3] = [
    Feature {
        id: FILTER_LZMA1,
        non_last_ok: false,
        last_ok: true,
        changes_size: true,
    },
    Feature {
        id: FILTER_LZMA1EXT,
        non_last_ok: false,
        last_ok: true,
        changes_size: true,
    },
    Feature {
        id: FILTER_LZMA2,
        non_last_ok: false,
        last_ok: true,
        changes_size: true,
    },
];

/// `lzma_validate_chain`: the number of filters in a valid chain.
pub(crate) fn validate_chain(filters: &[Filter]) -> Result<usize, Ret> {
    // There must be at least one filter.
    if filters.is_empty() {
        return Err(Ret::ProgError);
    }

    // Number of non-last filters that may change the size of the data
    // significantly (that is, more than 1-2 % or so).
    let mut changes_size_count = 0;

    // True if it is OK to add a new filter after the current filter.
    let mut non_last_ok = true;

    // True if the last filter in the given chain is actually usable as the
    // last filter. Only filters that support embedding End of Payload
    // Marker can be used as the last filter in the chain.
    let mut last_ok = false;

    for filter in filters {
        // Don't allow too many filters, and look for the filter.
        let Some(feature) = FEATURES.iter().find(|f| f.id == filter.id) else {
            return Err(Ret::OptionsError);
        };

        // If the previous filter in the chain cannot be a non-last filter,
        // the chain is invalid.
        if !non_last_ok {
            return Err(Ret::OptionsError);
        }

        non_last_ok = feature.non_last_ok;
        last_ok = feature.last_ok;
        changes_size_count += usize::from(feature.changes_size);
    }

    // There must be 1-4 filters. The last filter must be usable as the last
    // filter in the chain. A maximum of three filters are allowed to change
    // the size of the data.
    if filters.len() > FILTERS_MAX || !last_ok || changes_size_count > 3 {
        return Err(Ret::OptionsError);
    }
    Ok(filters.len())
}

/// `lzma_filter_decoder_is_supported`.
pub fn decoder_is_supported(id: u64) -> bool {
    matches!(id, FILTER_LZMA1 | FILTER_LZMA1EXT | FILTER_LZMA2)
}

/// The options of an LZMA filter, or `LZMA_PROG_ERROR` as liblzma gives
/// for a filter without them.
fn lzma_options(filter: &Filter) -> Result<&LzmaOptions, Ret> {
    filter.options.as_ref().ok_or(Ret::ProgError)
}

/// The decoder of one filter, `init` of the decoders' table: the LZMA
/// decoders' `lzma_lzma_decoder_init` and `lzma_lzma2_decoder_init`.
pub(crate) fn filter_init(
    filter: &Filter,
    next: Option<Box<dyn NextCoder>>,
) -> Result<Box<dyn NextCoder>, Ret> {
    let options = lzma_options(filter)?;
    match filter.id {
        FILTER_LZMA1 | FILTER_LZMA1EXT => {
            // `lzma_decoder_init`.
            if !is_lclppb_valid(options) {
                return Err(Ret::ProgError);
            }
            let mut uncomp_size = VLI_UNKNOWN;
            let mut allow_eopm = true;
            if filter.id == FILTER_LZMA1EXT {
                // Only one flag is supported.
                if options.ext_flags & !LZMA1EXT_ALLOW_EOPM != 0 {
                    return Err(Ret::OptionsError);
                }
                uncomp_size =
                    u64::from(options.ext_size_low) + (u64::from(options.ext_size_high) << 32);
                allow_eopm =
                    options.ext_flags & LZMA1EXT_ALLOW_EOPM != 0 || uncomp_size == VLI_UNKNOWN;
            }
            let (mut lzma, lz_options) = LzmaDecoder::create(options);
            lzma.reset(options);
            lzma.set_uncompressed(uncomp_size, allow_eopm);
            let coder = LzCoder::new(Lz::Lzma(Box::new(lzma)), &lz_options, next)?;
            Ok(Box::new(coder))
        }
        FILTER_LZMA2 => {
            let (lzma2, lz_options) = Lzma2Decoder::new(options);
            let coder = LzCoder::new(Lz::Lzma2(Box::new(lzma2)), &lz_options, next)?;
            Ok(Box::new(coder))
        }
        _ => Err(Ret::OptionsError),
    }
}

/// `lzma_raw_decoder_init`: the chain of decoders for `filters`, the
/// first filter's decoder reading from the next one's.
pub(crate) fn raw_decoder_init(filters: &[Filter]) -> Result<Box<dyn NextCoder>, Ret> {
    let count = validate_chain(filters)?;

    // Every filter must have a decoder.
    for filter in &filters[..count] {
        if !decoder_is_supported(filter.id) {
            return Err(Ret::OptionsError);
        }
    }

    // `lzma_next_filter_init`, from the last filter to the first.
    let mut next = None;
    for filter in filters[..count].iter().rev() {
        next = Some(filter_init(filter, next)?);
    }
    next.ok_or(Ret::ProgError)
}

/// `memusage` of the decoders' table.
fn filter_memusage(filter: &Filter) -> u64 {
    let Some(options) = filter.options.as_ref() else {
        return u64::MAX;
    };
    match filter.id {
        FILTER_LZMA1 | FILTER_LZMA1EXT => lzma_decoder::decoder_memusage(options),
        FILTER_LZMA2 => lzma2_decoder::decoder_memusage(options),
        _ => u64::MAX,
    }
}

/// `lzma_raw_decoder_memusage`: `u64::MAX` for an invalid chain.
pub fn raw_decoder_memusage(filters: &[Filter]) -> u64 {
    if validate_chain(filters).is_err() {
        return u64::MAX;
    }
    let mut total: u64 = 0;
    for filter in filters {
        if !decoder_is_supported(filter.id) {
            // Unsupported Filter ID
            return u64::MAX;
        }
        let usage = filter_memusage(filter);
        if usage == u64::MAX {
            // Invalid options
            return u64::MAX;
        }
        total += usage;
    }
    total + MEMUSAGE_BASE
}

/// `lzma_properties_decode`: the options of `id` from its properties.
pub(crate) fn properties_decode(id: u64, props: &[u8]) -> Result<Option<LzmaOptions>, Ret> {
    match id {
        FILTER_LZMA1 | FILTER_LZMA1EXT => lzma_decoder::props_decode(props).map(Some),
        FILTER_LZMA2 => lzma2_decoder::props_decode(props).map(Some),
        _ => Err(Ret::OptionsError),
    }
}

/// `lzma_filter_flags_decode`: a filter of a Block Header.
pub(crate) fn filter_flags_decode(input: &[u8], in_pos: &mut usize) -> Result<Filter, Ret> {
    // Filter ID
    let mut id = 0;
    match vli::decode_single(&mut id, input, in_pos) {
        Ret::Ok => {}
        ret => return Err(ret),
    }
    if id >= FILTER_RESERVED_START {
        return Err(Ret::DataError);
    }

    // Size of Properties
    let mut props_size = 0;
    match vli::decode_single(&mut props_size, input, in_pos) {
        Ret::Ok => {}
        ret => return Err(ret),
    }

    // Filter Properties
    if ((input.len() - *in_pos) as u64) < props_size {
        return Err(Ret::DataError);
    }
    let props = &input[*in_pos..*in_pos + props_size as usize];
    let options = properties_decode(id, props);
    *in_pos += props_size as usize;
    Ok(Filter {
        id,
        options: options?,
    })
}

// filter_encoder.c

/// `lzma_filter_encoder_is_supported`.
pub fn encoder_is_supported(id: u64) -> bool {
    matches!(id, FILTER_LZMA1 | FILTER_LZMA1EXT | FILTER_LZMA2)
}

/// The `init` of an encoder in `encoders[]`: the LZMA1 or LZMA2 encoder of
/// `filter`, the LZ encoder around it.
fn encoder_filter_init(filter: &Filter) -> Result<Box<dyn NextCoder>, Ret> {
    // lzma_encoder_init() and lzma2_encoder_init().
    let options = lzma_options(filter)?;
    let (lz, lz_options) = match filter.id {
        FILTER_LZMA1 | FILTER_LZMA1EXT => {
            let (lzma, lz_options) = LzmaEncoder::create(filter.id, options)?;
            (LzEnc::Lzma(Box::new(lzma)), lz_options)
        }
        FILTER_LZMA2 => {
            let (lzma2, lz_options) = Lzma2Encoder::new(options)?;
            (LzEnc::Lzma2(Box::new(lzma2)), lz_options)
        }
        _ => return Err(Ret::OptionsError),
    };
    Ok(Box::new(LzEncCoder::new(lz, &lz_options)?))
}

/// `lzma_raw_encoder_init`: the encoders of a filter chain.
///
/// Differs from liblzma, without a difference to see: liblzma reverses
/// the chain for its encoders, LZMA last in the chain and first to run;
/// with LZMA1 and LZMA2 only, the chain is the one filter.
pub(crate) fn raw_encoder_init(filters: &[Filter]) -> Result<Box<dyn NextCoder>, Ret> {
    // Do some basic validation and get the number of filters.
    let count = validate_chain(filters)?;

    for filter in &filters[..count] {
        if !encoder_is_supported(filter.id) {
            return Err(Ret::OptionsError);
        }
    }

    encoder_filter_init(&filters[0])
}

/// The `memusage` of an encoder in `encoders[]`.
fn encoder_memusage(filter: &Filter) -> u64 {
    // liblzma reads the options without checking for NULL.
    let Some(options) = filter.options.as_ref() else {
        return u64::MAX;
    };
    match filter.id {
        FILTER_LZMA1 | FILTER_LZMA1EXT => lzma_encoder::encoder_memusage(options),
        FILTER_LZMA2 => lzma2_encoder::lzma2_encoder_memusage(options),
        _ => u64::MAX,
    }
}

/// `lzma_raw_encoder_memusage`: the memory the encoders of a chain need,
/// or u64::MAX if the chain is invalid or not supported.
pub fn raw_encoder_memusage(filters: &[Filter]) -> u64 {
    // The chain has to have at least one filter.
    if validate_chain(filters).is_err() {
        return u64::MAX;
    }

    let mut total: u64 = 0;
    for filter in filters {
        if !encoder_is_supported(filter.id) {
            return u64::MAX; // Unsupported Filter ID
        }

        // Call the filter-specific memory usage calculation function.
        let usage = encoder_memusage(filter);
        if usage == u64::MAX {
            return u64::MAX; // Invalid options
        }

        total += usage;
    }

    // Add some fixed amount of extra. It's to compensate memory usage of
    // Stream, Block etc. coders, malloc() overhead, stack etc.
    total + MEMUSAGE_BASE
}

/// `lzma_properties_size`.
pub(crate) fn properties_size(filter: &Filter) -> Result<u32, Ret> {
    match filter.id {
        FILTER_LZMA1 | FILTER_LZMA1EXT => Ok(5),
        FILTER_LZMA2 => Ok(1),
        // Unknown filter - if the Filter ID is a proper VLI, return
        // LZMA_OPTIONS_ERROR instead of LZMA_PROG_ERROR, because it's
        // possible that we just don't have support compiled in for the
        // requested filter.
        id if id <= crate::common::VLI_MAX => Err(Ret::OptionsError),
        _ => Err(Ret::ProgError),
    }
}

/// `lzma_properties_encode`.
pub(crate) fn properties_encode(filter: &Filter, props: &mut [u8]) -> Ret {
    let Some(options) = filter.options.as_ref() else {
        return Ret::ProgError;
    };
    match filter.id {
        FILTER_LZMA1 | FILTER_LZMA1EXT => lzma_encoder::props_encode(options, props),
        FILTER_LZMA2 => lzma2_encoder::lzma2_props_encode(options, props),
        _ => Ret::ProgError,
    }
}

// filter_flags_encoder.c

/// `lzma_filter_flags_size`.
pub(crate) fn filter_flags_size(filter: &Filter) -> Result<u32, Ret> {
    if filter.id >= FILTER_RESERVED_START {
        return Err(Ret::ProgError);
    }

    let size = properties_size(filter)?;
    Ok(size + vli::size(filter.id) + vli::size(u64::from(size)))
}

/// `lzma_filter_flags_encode`.
pub(crate) fn filter_flags_encode(filter: &Filter, out: &mut [u8], out_pos: &mut usize) -> Ret {
    // Filter ID
    if filter.id >= FILTER_RESERVED_START {
        return Ret::ProgError;
    }

    let ret = vli::encode_single(filter.id, out, out_pos);
    if ret != Ret::Ok {
        return ret;
    }

    // Size of Properties
    let props_size = match properties_size(filter) {
        Ok(size) => size,
        Err(ret) => return ret,
    };
    let ret = vli::encode_single(u64::from(props_size), out, out_pos);
    if ret != Ret::Ok {
        return ret;
    }

    // Filter Properties
    if out.len() - *out_pos < props_size as usize {
        return Ret::ProgError;
    }

    let ret = properties_encode(filter, &mut out[*out_pos..]);
    if ret != Ret::Ok {
        return ret;
    }

    *out_pos += props_size as usize;

    Ret::Ok
}

/// `lzma_filters_copy`: a copy of the chain, or LZMA_OPTIONS_ERROR for more
/// than four filters, or options of a filter this build does not know.
pub(crate) fn filters_copy(filters: &[Filter]) -> Result<Vec<Filter>, Ret> {
    for (i, filter) in filters.iter().enumerate() {
        if i == FILTERS_MAX {
            return Err(Ret::OptionsError);
        }

        if filter.options.is_some() && !FEATURES.iter().any(|f| f.id == filter.id) {
            return Err(Ret::OptionsError);
        }
    }
    Ok(filters.to_vec())
}
