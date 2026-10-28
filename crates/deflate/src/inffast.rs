//! The fast decoding loop: port of `inffast.{h,c}`.

use crate::inflate::{InflateState, Mode};

/// Decodes literal, length and distance codes and writes literals and match
/// bytes until either not enough input or output is available, an
/// end-of-block is encountered, or a data error is encountered. When large
/// enough input and output buffers are supplied to inflate(), for example,
/// a 16K input buffer and a 64K output buffer, more than 95% of the
/// inflate execution time is spent in this routine.
///
/// Entry assumptions:
/// - `state.mode` is `Len`;
/// - at least 6 bytes of input are left at `*next_in`;
/// - at least 258 bytes of output space are left at `*next_out`;
/// - `start` is the output space inflate() had when it was called, so that
///   the output written in this call starts at `*next_out - (start -
///   left)`;
/// - `state.bits < 8`.
///
/// On return, `state.mode` is one of `Len` (not enough input or output),
/// `Type` (end of block) or `Bad` (with `*msg` set). The bytes of the bit
/// buffer that were not used are given back to the input.
///
/// Port of `inflate_fast`, `inffast.c` (without `INFLATE_STRICT` and
/// `INFLATE_ALLOW_INVALID_DISTANCE_TOOFAR_ARRR`, as zlib is built by
/// default). Differs from zlib: positions are indices into `input`,
/// `output` and the window rather than pointers.
pub(crate) fn inflate_fast(
    state: &mut InflateState,
    input: &[u8],
    next_in: &mut usize,
    output: &mut [u8],
    next_out: &mut usize,
    start: usize,
    msg: &mut Option<&'static str>,
) {
    // copy state to local variables
    let mut inp = *next_in; // local strm->next_in
    let last = inp + (input.len() - inp - 5); // have enough input while in < last
    let mut out = *next_out; // local strm->next_out
    let beg = out - (start - (output.len() - out)); // inflate()'s initial strm->next_out
    let end = out + (output.len() - out - 257); // while out < end, enough space available
    let wsize = state.wsize; // window size or zero if not using window
    let whave = state.whave; // valid bytes in the window
    let wnext = state.wnext; // window write index
    let mut hold = state.hold; // local strm->hold
    let mut bits = state.bits; // local strm->bits
    let lmask = (1u64 << state.lenbits) - 1; // mask for first level of length codes
    let dmask = (1u64 << state.distbits) - 1; // mask for first level of distance codes
    let sane = state.sane;
    let mut mode = None; // the mode to leave in, when not Len

    {
        let window = &state.window[..];
        let lcode = state.table(state.lencode); // local strm->lencode
        let dcode = state.table(state.distcode); // local strm->distcode

        // decode literals and length/distances until end-of-block or not
        // enough input data or output space
        'outer: loop {
            if bits < 15 {
                hold += u64::from(input[inp]) << bits;
                inp += 1;
                bits += 8;
                hold += u64::from(input[inp]) << bits;
                inp += 1;
                bits += 8;
            }
            let mut here = lcode[(hold & lmask) as usize];
            // dolen:
            loop {
                let op = u32::from(here.bits);
                hold >>= op;
                bits -= op;
                let mut op = u32::from(here.op);
                if op == 0 {
                    // literal
                    output[out] = here.val as u8;
                    out += 1;
                } else if op & 16 != 0 {
                    // length base
                    let mut len = u32::from(here.val);
                    op &= 15; // number of extra bits
                    if op != 0 {
                        if bits < op {
                            hold += u64::from(input[inp]) << bits;
                            inp += 1;
                            bits += 8;
                        }
                        len += (hold as u32) & ((1u32 << op) - 1);
                        hold >>= op;
                        bits -= op;
                    }
                    if bits < 15 {
                        hold += u64::from(input[inp]) << bits;
                        inp += 1;
                        bits += 8;
                        hold += u64::from(input[inp]) << bits;
                        inp += 1;
                        bits += 8;
                    }
                    here = dcode[(hold & dmask) as usize];
                    // dodist:
                    loop {
                        let op = u32::from(here.bits);
                        hold >>= op;
                        bits -= op;
                        let mut op = u32::from(here.op);
                        if op & 16 != 0 {
                            // distance base
                            let mut dist = u32::from(here.val);
                            op &= 15; // number of extra bits
                            if bits < op {
                                hold += u64::from(input[inp]) << bits;
                                inp += 1;
                                bits += 8;
                                if bits < op {
                                    hold += u64::from(input[inp]) << bits;
                                    inp += 1;
                                    bits += 8;
                                }
                            }
                            dist += (hold as u32) & ((1u32 << op) - 1);
                            hold >>= op;
                            bits -= op;
                            let dist = dist as usize;
                            let mut len = len as usize;
                            let op = out - beg; // max distance in output
                            if dist > op {
                                // see if copy from window
                                let mut op = dist - op; // distance back in window
                                if op > whave && sane {
                                    *msg = Some("invalid distance too far back");
                                    mode = Some(Mode::Bad);
                                    break 'outer;
                                }
                                // Where the rest of the copy comes from: the
                                // window at `from`, or the output if
                                // `from_window` is false.
                                let mut from;
                                let mut from_window = true;
                                if wnext == 0 {
                                    // very common case
                                    from = wsize - op;
                                    if op < len {
                                        // some from window
                                        len -= op;
                                        output[out..out + op]
                                            .copy_from_slice(&window[from..from + op]);
                                        out += op;
                                        from = out - dist; // rest from output
                                        from_window = false;
                                    }
                                } else if wnext < op {
                                    // wrap around window
                                    from = wsize + wnext - op;
                                    op -= wnext;
                                    if op < len {
                                        // some from end of window
                                        len -= op;
                                        output[out..out + op]
                                            .copy_from_slice(&window[from..from + op]);
                                        out += op;
                                        from = 0;
                                        if wnext < len {
                                            // some from start of window
                                            let op = wnext;
                                            len -= op;
                                            output[out..out + op].copy_from_slice(&window[..op]);
                                            out += op;
                                            from = out - dist; // rest from output
                                            from_window = false;
                                        }
                                    }
                                } else {
                                    // contiguous in window
                                    from = wnext - op;
                                    if op < len {
                                        // some from window
                                        len -= op;
                                        output[out..out + op]
                                            .copy_from_slice(&window[from..from + op]);
                                        out += op;
                                        from = out - dist; // rest from output
                                        from_window = false;
                                    }
                                }
                                if from_window {
                                    output[out..out + len]
                                        .copy_from_slice(&window[from..from + len]);
                                    out += len;
                                } else {
                                    copy_from_output(output, &mut out, from, len);
                                }
                            } else {
                                // copy direct from output
                                let from = out - dist;
                                copy_from_output(output, &mut out, from, len);
                            }
                        } else if op & 64 == 0 {
                            // 2nd level distance code
                            here =
                                dcode[usize::from(here.val) + (hold & ((1u64 << op) - 1)) as usize];
                            continue;
                        } else {
                            *msg = Some("invalid distance code");
                            mode = Some(Mode::Bad);
                            break 'outer;
                        }
                        break;
                    }
                } else if op & 64 == 0 {
                    // 2nd level length code
                    here = lcode[usize::from(here.val) + (hold & ((1u64 << op) - 1)) as usize];
                    continue;
                } else if op & 32 != 0 {
                    // end-of-block
                    mode = Some(Mode::Type);
                    break 'outer;
                } else {
                    *msg = Some("invalid literal/length code");
                    mode = Some(Mode::Bad);
                    break 'outer;
                }
                break;
            }
            if !(inp < last && out < end) {
                break;
            }
        }
    }

    // return unused bytes (on entry, bits < 8, so in won't go too far back)
    let len = bits >> 3;
    inp -= len as usize;
    bits -= len << 3;
    hold &= (1u64 << bits) - 1;

    // update state and return
    *next_in = inp;
    *next_out = out;
    state.hold = hold;
    state.bits = bits;
    if let Some(mode) = mode {
        state.mode = mode;
    }
}

/// Copies `len` bytes (at least three) from `from`, earlier in `output`, to
/// `*out`, a byte at a time so that the copy repeats when they overlap.
///
/// Differs from zlib: zlib copies three bytes per loop, with the same
/// result.
#[inline(always)]
fn copy_from_output(output: &mut [u8], out: &mut usize, from: usize, len: usize) {
    for i in 0..len {
        output[*out + i] = output[from + i];
    }
    *out += len;
}
