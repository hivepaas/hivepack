//! Variable-length integers: port of `common/vli_decoder.c` and
//! `common/vli_size.c`.

use crate::common::{Ret, VLI_BYTES_MAX, VLI_MAX};

/// `lzma_vli_decode` in single-call mode (`vli_pos == NULL`): the whole
/// integer must be in `input`, or the result is `LZMA_DATA_ERROR`.
pub(crate) fn decode_single(vli: &mut u64, input: &[u8], in_pos: &mut usize) -> Ret {
    let mut vli_pos = 0;
    *vli = 0;
    if *in_pos >= input.len() {
        return Ret::DataError;
    }
    match decode_bytes(vli, &mut vli_pos, input, in_pos) {
        // Single-call returns LZMA_OK where multi-call says
        // LZMA_STREAM_END, and the input ending first is an error.
        Ret::StreamEnd => Ret::Ok,
        Ret::Ok => Ret::DataError,
        ret => ret,
    }
}

/// `lzma_vli_decode` in multi-call mode: the integer so far and how many
/// of its bytes were read, kept from one call to the next;
/// `LZMA_STREAM_END` once it is complete.
pub(crate) fn decode(vli: &mut u64, vli_pos: &mut usize, input: &[u8], in_pos: &mut usize) -> Ret {
    // Initialize *vli when starting to decode a new integer.
    if *vli_pos == 0 {
        *vli = 0;
    }

    // Validate the arguments.
    if *vli_pos >= VLI_BYTES_MAX || (*vli >> (*vli_pos * 7)) != 0 {
        return Ret::ProgError;
    }

    if *in_pos >= input.len() {
        return Ret::BufError;
    }
    decode_bytes(vli, vli_pos, input, in_pos)
}

/// The loop of `lzma_vli_decode`, in multi-call terms.
fn decode_bytes(vli: &mut u64, vli_pos: &mut usize, input: &[u8], in_pos: &mut usize) -> Ret {
    loop {
        // Read the next byte. Use a temporary variable so that we can
        // update *in_pos immediately.
        let byte = input[*in_pos];
        *in_pos += 1;

        // Add the newly read byte to *vli.
        *vli += u64::from(byte & 0x7F) << (*vli_pos * 7);
        *vli_pos += 1;

        // Check if this is the last byte of a multibyte integer.
        if byte & 0x80 == 0 {
            // We don't allow using variable-length integers as padding
            // i.e. the encoding must use the most the compact form.
            if byte == 0x00 && *vli_pos > 1 {
                return Ret::DataError;
            }
            return Ret::StreamEnd;
        }

        // There is at least one more byte coming. If we have already read
        // maximum number of bytes, the integer is considered corrupt.
        if *vli_pos == VLI_BYTES_MAX {
            return Ret::DataError;
        }

        if *in_pos >= input.len() {
            return Ret::Ok;
        }
    }
}

/// `lzma_vli_size`: the bytes `vli` takes encoded, or 0 if it is out of
/// range.
pub(crate) fn size(mut vli: u64) -> u32 {
    if vli > VLI_MAX {
        return 0;
    }
    let mut i = 0;
    loop {
        vli >>= 7;
        i += 1;
        if vli == 0 {
            break;
        }
    }
    i
}
