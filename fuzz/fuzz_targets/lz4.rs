//! hivepack-lz4 against liblz4. A panic or a difference is a bug.
//!
//! The first byte chooses what is done with the rest, after eight bytes
//! that seed the sizes:
//!
//! - 0 mod 4: the rest is a block, decoded by both with
//!   `LZ4_decompress_safe` into an output of a size from the seed, first
//!   filled the same way. Both must succeed or fail together, with the same
//!   size, and leave the same bytes in all of the output, past what they
//!   decoded too.
//! - 1 mod 4: the rest is a frame, read by the lz4 crate's `Decoder` and by
//!   the same loop over the port's context, in reads of sizes from the
//!   seed. Every read must agree: the same bytes, or both an error.
//! - 2 mod 4: the rest is a block, decoded by the port partially, with a
//!   dictionary, after a prefix, or in a stream, which the lz4 crate cannot
//!   do: no panic (`tests/oracle.rs` compares them with liblz4).
//! - 3 mod 4: the rest is read by the port's `Decoder`, in reads of sizes
//!   from the seed: no panic.

#![no_main]

use std::io::Read;

use hivepack_lz4::block;
use hivepack_lz4::frame::{DecompressOptions, DecompressionContext, InBuffer, OutBuffer};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let Some((seed, data)) = rest.split_first_chunk::<8>() else { return };
    let mut rng = u64::from_le_bytes(*seed) | 1;
    let mut next = move |n: usize| {
        rng ^= rng >> 12;
        rng ^= rng << 25;
        rng ^= rng >> 27;
        (rng.wrapping_mul(0x2545_f491_4f6c_dd1d) % n as u64) as usize
    };
    match mode % 4 {
        0 => block_safe(data, &mut next),
        1 => frame(data, &mut next),
        2 => block_other(data, &mut next),
        _ => reader(data, &mut next),
    }
});

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 7 + 3) & 255) as u8).collect()
}

fn output_size(next: &mut impl FnMut(usize) -> usize, len: usize) -> usize {
    match next(4) {
        0 => next(100),
        1 => next(len * 4 + 100),
        2 => len * 255,
        _ => next(1 << 20),
    }
    .min(4 << 20)
}

fn block_safe(src: &[u8], next: &mut impl FnMut(usize) -> usize) {
    let capacity = output_size(next, src.len());
    let mut c_out = pattern(capacity);
    let mut p_out = pattern(capacity);
    let want = lz4::block::decompress_to_buffer(src, Some(capacity as i32), &mut c_out).ok();
    let got = block::decompress_safe(src, &mut p_out).ok();
    assert_eq!(got, want, "result");
    assert!(p_out == c_out, "output");
}

fn block_other(src: &[u8], next: &mut impl FnMut(usize) -> usize) {
    let capacity = output_size(next, src.len());
    let dict_len = [0, 1, 100, 65535, 65536, 70_000][next(6)];
    let dict: Vec<u8> = (0..dict_len).map(|i| (i % 251) as u8).collect();
    let target = next(capacity + 1);

    let mut out = vec![0; capacity];
    let _ = block::decompress_safe_using_dict(src, &mut out, &dict);
    let _ = block::decompress_safe_partial_using_dict(src, &mut out, target, &dict);
    let _ = block::decompress_safe_partial(src, &mut out, target);
    let mut buffer = dict.clone();
    buffer.resize(dict_len + capacity, 0);
    let _ = block::decompress_safe_with_prefix(src, &mut buffer, dict_len);
    let _ = block::decompress_safe_partial_with_prefix(src, &mut buffer, dict_len, target);

    // The same block, again and again, in a stream.
    let mut stream = block::StreamDecode::new();
    stream.set_dict(&dict);
    for _ in 0..1 + next(4) {
        let _ = stream.decompress_safe_continue(src, &mut out);
    }
}

/// The lz4 crate's `Decoder::read`, over the port's context: the same
/// calls, so that each read can be compared.
struct PortDecoder<'a> {
    dctx: DecompressionContext,
    src: &'a [u8],
    at: usize,
    buf: Vec<u8>,
    pos: usize,
    len: usize,
    next: usize,
}

impl PortDecoder<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        if self.next == 0 || buf.is_empty() {
            return Ok(0);
        }
        let mut dst_offset = 0;
        while dst_offset == 0 {
            if self.pos >= self.len {
                let need = self.buf.len().min(self.next);
                let n = need.min(self.src.len() - self.at);
                self.buf[..n].copy_from_slice(&self.src[self.at..self.at + n]);
                self.at += n;
                self.len = n;
                self.pos = 0;
                self.next -= self.len;
            }
            while dst_offset < buf.len() && (self.pos < self.len || self.len == 0) {
                let mut input = InBuffer::new(&self.buf[self.pos..self.len]);
                let mut output = OutBuffer::new(&mut buf[dst_offset..]);
                let len = self
                    .dctx
                    .decompress(&mut output, &mut input, DecompressOptions::default())
                    .map_err(|_| ())?;
                self.pos += input.pos;
                dst_offset += output.pos;
                if output.pos == 0 && input.pos == 0 {
                    return Ok(dst_offset);
                }
                if len == 0 {
                    self.next = 0;
                    return Ok(dst_offset);
                } else if self.next < len {
                    self.next = len;
                }
            }
        }
        Ok(dst_offset)
    }
}

fn frame(src: &[u8], next: &mut impl FnMut(usize) -> usize) {
    let Ok(mut c) = lz4::Decoder::new(src) else { return };
    let mut port = PortDecoder {
        dctx: DecompressionContext::new(),
        src,
        at: 0,
        buf: vec![0; 32 * 1024],
        pos: 32 * 1024,
        len: 32 * 1024,
        next: 11,
    };
    let mut c_buf = vec![0; 1 << 20];
    let mut p_buf = vec![0; 1 << 20];
    for _ in 0..10_000 {
        let size = [1, 7, 100, 4096, 65536, 1 << 20][next(6)];
        let want = c.read(&mut c_buf[..size]);
        let got = port.read(&mut p_buf[..size]);
        match (want, got) {
            (Ok(c_n), Ok(p_n)) => {
                assert_eq!(p_n, c_n, "read size");
                assert!(p_buf[..p_n] == c_buf[..c_n], "read bytes");
                if c_n == 0 {
                    return;
                }
            }
            (Err(_), Err(())) => return,
            (want, got) => panic!("liblz4 {want:?}, port {got:?}"),
        }
    }
}

fn reader(src: &[u8], next: &mut impl FnMut(usize) -> usize) {
    let mut decoder = hivepack_lz4::Decoder::new(src);
    let mut buf = vec![0; 1 << 16];
    for _ in 0..100_000 {
        let size = 1 + next(buf.len());
        match decoder.read(&mut buf[..size]) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}
