//! Compresses the input with the port and with libzstd, in one call, at a
//! level the first byte picks among those the port has, and checks that the
//! frames are the same, byte for byte, and that the port decodes its frame
//! back. A panic or a difference is a bug.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zstd::zstd_safe;

fuzz_target!(|input: &[u8]| {
    let Some((&pick, src)) = input.split_first() else {
        return;
    };
    let level = [-100, -5, -1, 1, 2, 3][usize::from(pick) % 6];
    let capacity = hivepack_zstd::compress_bound(src.len()).unwrap_or(0);
    let mut c_out = vec![0u8; capacity];
    let mut p_out = vec![0u8; capacity];
    let want = zstd_safe::compress(&mut c_out[..], src, level).map(|n| &c_out[..n]);
    let got = hivepack_zstd::compress(&mut p_out, src, level).map(|n| &p_out[..n]);
    match (got, want) {
        (Ok(got), Ok(want)) => {
            assert!(got == want, "level {level}: the frames differ");
            let mut back = vec![0u8; src.len()];
            let size = hivepack_zstd::decompress(&mut back, got).expect("the frame decodes");
            assert!(back[..size] == *src, "level {level}: does not decode back");
        }
        (got, want) => panic!(
            "level {level}: port {:?}, libzstd {:?}",
            got.map(<[u8]>::len),
            want.map(<[u8]>::len)
        ),
    }
});
