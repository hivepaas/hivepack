//! Compresses the input with the port and with libzstd, in one call, at a
//! level the first byte picks, and checks that the frames are the same,
//! byte for byte, and that the port decodes its frame back; a strategy the
//! port does not have yet it refuses. With a bit of the first byte set, the
//! blocks are split after their sequences (`ZSTD_c_splitAfterSequences`),
//! through `compress2`. A panic or a difference is a bug.

#![no_main]

use hivepack_zstd::{CCtx, CParameter as P, ParamSwitch};
use libfuzzer_sys::fuzz_target;
use zstd::zstd_safe::{self, CParameter as C};

fuzz_target!(|input: &[u8]| {
    let Some((&pick, src)) = input.split_first() else {
        return;
    };
    let level = [-100, -5, -1, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13, 16, 19][usize::from(pick) % 16];
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
        // A strategy the port does not have yet.
        (Err(error), Ok(_)) if error.code() == hivepack_zstd::ErrorCode::ParameterUnsupported => {}
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
