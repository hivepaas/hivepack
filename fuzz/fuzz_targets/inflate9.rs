//! Decodes the input as a Deflate64 stream with hivepack-deflate's
//! `InflateBack9`, all given at the start and in pieces, and checks that
//! both agree: the same result and message, the same input used, and the
//! same output in the same calls. A panic or a difference is a bug. zlib's
//! `contrib/infback9`, which the port follows, is not in libz-sys:
//! `crates/deflate/tests/deflate64.rs` compares the two through the oracle.
//!
//! The first eight bytes seed the piece sizes, and the rest is the stream.

#![no_main]

use hivepack_deflate::{Back9, BackIn, BackOut, InflateBack9};
use libfuzzer_sys::fuzz_target;

/// The input after the first piece, in pieces of random sizes.
struct Pieces<'a> {
    stream: &'a [u8],
    given: usize,
    rng: u64,
}

impl BackIn for Pieces<'_> {
    fn input(&mut self) -> &[u8] {
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        let left = self.stream.len() - self.given;
        let size = (self.rng.wrapping_mul(0x2545_f491_4f6c_dd1d) % 300) as usize;
        let size = size.clamp(1, left.max(1)).min(left);
        let start = self.given;
        self.given += size;
        &self.stream[start..start + size]
    }
}

/// Each call's output.
struct Calls(Vec<Vec<u8>>);

impl BackOut for Calls {
    fn output(&mut self, data: &[u8]) -> bool {
        self.0.push(data.to_vec());
        false
    }
}

/// The result, the message, and the input used: given less what is unused,
/// or `None` if the input ran out.
fn outcome(back: &Back9, decoder: &InflateBack9, given: usize) -> (String, Option<usize>) {
    let result = format!("{:?} {:?}", back.result, decoder.msg());
    (result, back.unused.map(|unused| given - unused))
}

fuzz_target!(|data: &[u8]| {
    let Some((seed, stream)) = data.split_first_chunk::<8>() else { return };
    let rng = u64::from_le_bytes(*seed) | 1;

    let mut whole = Pieces { stream, given: stream.len(), rng };
    let mut whole_out = Calls(Vec::new());
    let mut decoder = InflateBack9::new();
    let back = decoder.inflate_back9(stream, &mut whole, &mut whole_out);
    let want = outcome(&back, &decoder, whole.given);

    let first = (rng % 64) as usize % (stream.len() + 1);
    let mut pieces = Pieces { stream, given: first, rng };
    let mut pieces_out = Calls(Vec::new());
    let back = decoder.inflate_back9(&stream[..first], &mut pieces, &mut pieces_out);
    let got = outcome(&back, &decoder, pieces.given);

    assert_eq!(got, want);
    assert!(pieces_out.0 == whole_out.0, "different output");
});
