//! Compresses the input with the port and with libzstd, in one call, at a
//! level the first byte picks, and checks that the frames are the same,
//! byte for byte, and that the port decodes its frame back. With a bit of
//! the first byte set, the blocks are split after their sequences
//! (`ZSTD_c_splitAfterSequences`), through `compress2`. With another, a
//! dictionary from the start of the input, raw content or behind the
//! dictionary magic number (a zstd dictionary to read, if it can be), in
//! `ZSTD_compress_usingDict`, or as a `CDict` in `ZSTD_compress_usingCDict`
//! (but where libzstd attaches it, which the port does not do yet). A
//! panic or a difference is a bug.

#![no_main]

use hivepack_zstd::{CCtx, CDict, CParameter as P, DCtx, ErrorCode, ParamSwitch};
use libfuzzer_sys::fuzz_target;
use zstd::zstd_safe::{self, CParameter as C};

/// `ZSTD_compress_usingDict` or `ZSTD_compress_usingCDict` with a dictionary
/// from the start of `src`, its size picked by its first byte.
fn with_dictionary(pick: u8, level: i32, src: &[u8]) {
    let Some((&size, src)) = src.split_first().filter(|(_, src)| !src.is_empty()) else {
        return;
    };
    // At least a byte: a CDict made for an empty dictionary takes the
    // level's tables for an input of unknown size, up to 640 MB at the
    // strongest levels, on each side.
    let dict_len = (usize::from(size) * src.len() / 255).max(1).min(src.len());
    // A copy apart, that cannot end where the input starts in memory, as
    // libzstd would then take it as part of the input's segment.
    let mut dict = Vec::with_capacity(dict_len + 8 + 64);
    if pick & 0x40 != 0 {
        dict.extend_from_slice(&0xEC30_A437u32.to_le_bytes());
    }
    dict.extend_from_slice(&src[..dict_len]);
    let src = &src[dict_len..];
    let capacity = hivepack_zstd::compress_bound(src.len()).unwrap_or(0);
    let mut c_out = vec![0u8; capacity];
    let mut p_out = vec![0u8; capacity];
    let mut c = zstd_safe::CCtx::create();
    let mut p = CCtx::new();
    let (want, got) = if pick & 0x80 == 0 {
        (
            c.compress_using_dict(&mut c_out[..], src, &dict, level)
                .map(|n| &c_out[..n]),
            p.compress_using_dict(&mut p_out, src, &dict, level)
                .map(|n| &p_out[..n]),
        )
    } else {
        let c_cdict = zstd_safe::CDict::try_create(&dict, level);
        let p_cdict = CDict::new(&dict, level);
        let (Some(c_cdict), Ok(p_cdict)) = (&c_cdict, &p_cdict) else {
            assert!(
                c_cdict.is_none() && p_cdict.is_err(),
                "level {level}: one makes a CDict, the other not: {p_cdict:?}"
            );
            return;
        };
        let got = p.compress_using_cdict(&mut p_out, src, p_cdict);
        if got
            .as_ref()
            .is_err_and(|error| error.code() == ErrorCode::ParameterUnsupported)
        {
            // libzstd attaches the CDict, which the port does not do yet.
            return;
        }
        (
            c.compress_using_cdict(&mut c_out[..], src, c_cdict)
                .map(|n| &c_out[..n]),
            got.map(|n| &p_out[..n]),
        )
    };
    match (got, want) {
        (Ok(got), Ok(want)) => {
            assert!(
                got == want,
                "level {level}, with a dictionary: the frames differ"
            );
            let mut back = vec![0u8; src.len()];
            let size = DCtx::new()
                .decompress_using_dict(&mut back, got, &dict)
                .expect("the frame decodes");
            assert!(back[..size] == *src, "level {level}: does not decode back");
        }
        (Err(got), Err(want)) => assert!(
            got.code().message() == zstd_safe::get_error_name(want),
            "level {level}, with a dictionary: port {got}, libzstd {}",
            zstd_safe::get_error_name(want)
        ),
        (got, want) => panic!(
            "level {level}, with a dictionary: port {:?}, libzstd {:?}",
            got.map(<[u8]>::len),
            want.map(<[u8]>::len)
        ),
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&pick, src)) = input.split_first() else {
        return;
    };
    let level = [-100, -5, -1, 1, 2, 3, 4, 5, 6, 7, 8, 10, 13, 16, 19, 22][usize::from(pick) % 16];
    if pick & 0x20 != 0 {
        with_dictionary(pick, level, src);
        return;
    }
    let split = pick & 0x10 != 0;
    let capacity = hivepack_zstd::compress_bound(src.len()).unwrap_or(0);
    let mut c_out = vec![0u8; capacity];
    let mut p_out = vec![0u8; capacity];
    let (want, got) = if split {
        let mut c = zstd_safe::CCtx::create();
        let mut p = CCtx::new();
        for (pp, cp) in [
            (P::CompressionLevel(level), C::CompressionLevel(level)),
            (
                P::SplitAfterSequences(ParamSwitch::Enable),
                C::UseBlockSplitter(zstd_safe::ParamSwitch::Enable),
            ),
        ] {
            assert!(c.set_parameter(cp).is_ok() && p.set_parameter(pp).is_ok());
        }
        (
            c.compress2(&mut c_out[..], src).map(|n| &c_out[..n]),
            p.compress2(&mut p_out, src).map(|n| &p_out[..n]),
        )
    } else {
        (
            zstd_safe::compress(&mut c_out[..], src, level).map(|n| &c_out[..n]),
            hivepack_zstd::compress(&mut p_out, src, level).map(|n| &p_out[..n]),
        )
    };
    match (got, want) {
        (Ok(got), Ok(want)) => {
            assert!(
                got == want,
                "level {level}, split {split}: the frames differ"
            );
            let mut back = vec![0u8; src.len()];
            let size = hivepack_zstd::decompress(&mut back, got).expect("the frame decodes");
            assert!(back[..size] == *src, "level {level}: does not decode back");
        }
        (got, want) => panic!(
            "level {level}, split {split}: port {:?}, libzstd {:?}",
            got.map(<[u8]>::len),
            want.map(<[u8]>::len)
        ),
    }
});
