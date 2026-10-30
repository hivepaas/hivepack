//! The block compressor against liblz4 1.10.0 through the lz4 crate, on
//! every machine CI tests: the same blocks, byte for byte.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use hivepack_lz4::block;
use support::{Rng, c_compress_block, input};

#[test]
fn blocks_are_liblz4s() {
    let mut rng = Rng(0x5eed_1230);
    for round in 0..600 {
        let len = match round % 5 {
            0 => rng.below(40) as usize,
            1 => rng.below(2000) as usize,
            2 => 60_000 + rng.below(10_000) as usize,
            3 => rng.below(300_000) as usize,
            _ => rng.below(3_000_000) as usize,
        };
        let data = input(&mut rng, len);
        // 0 is LZ4_compress_default; negative values are accelerations.
        let level = match rng.below(3) {
            0 => 0,
            1 => -(1 + rng.below(10) as i32),
            _ => -(1 + rng.below(70_000) as i32),
        };
        let want = c_compress_block(&data, level);
        let mut got = vec![0; block::compress_bound(len)];
        let n = block::compress_fast(&data, &mut got, if level == 0 { 1 } else { -level });
        assert_eq!(n, want.len(), "round {round}, {len} bytes, level {level}");
        assert!(
            got[..n] == want[..],
            "round {round}, {len} bytes, level {level}"
        );

        let mut back = vec![0; len];
        assert_eq!(block::decompress_safe(&got[..n], &mut back), Ok(len));
        assert!(back == data);
    }
}
