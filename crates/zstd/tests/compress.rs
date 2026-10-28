//! Compresses every file of the test data with the port and with libzstd
//! 1.5.7, through the same one-call API (`ZSTD_compressCCtx`), and compares
//! the frames byte for byte; then decodes the port's frame back with the
//! port.
//!
//! At every level; those whose strategy the port does not have yet, it
//! refuses with `ParameterUnsupported`, and they are skipped.

#![allow(clippy::expect_used, clippy::panic)]

mod support;

use hivepack_zstd::{CCtx, ErrorCode};
use support::{Kind, Problems, Set};

const LEVELS: [i32; 14] = [-5, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13];

fn sets() -> Vec<Set> {
    support::manifest()
        .sets
        .into_iter()
        .filter(|set| set.present())
        // Benchmark inputs are too large for the tests; sources and tools
        // are not data.
        .filter(|set| !matches!(set.kind, Kind::Bench | Kind::Source | Kind::Tool))
        .collect()
}

/// Compresses `data` with both, compares, and decodes back.
fn compare(problems: &mut Problems, cctx: &mut CCtx, name: &str, data: &[u8], level: i32) -> bool {
    let want = zstd::bulk::compress(data, level).expect("libzstd compresses");
    let mut got = vec![0u8; hivepack_zstd::compress_bound(data.len()).expect("a bound")];
    let size = match cctx.compress(&mut got, data, level) {
        Ok(size) => size,
        // A strategy the port does not have yet.
        Err(error) if error.code() == ErrorCode::ParameterUnsupported => return false,
        Err(error) => {
            problems.add(format!("{name} at level {level}: {error}"));
            return false;
        }
    };
    if got[..size] != want[..] {
        let at = got[..size]
            .iter()
            .zip(&want)
            .position(|(a, b)| a != b)
            .unwrap_or(size.min(want.len()));
        problems.add(format!(
            "{name} at level {level}: {size} bytes, libzstd {}, first difference at {at}",
            want.len()
        ));
        return true;
    }
    let mut back = vec![0u8; data.len()];
    match hivepack_zstd::decompress(&mut back, &got[..size]) {
        Ok(n) if back[..n] == *data => {}
        other => problems.add(format!(
            "{name} at level {level}: does not decode back ({:?})",
            other.map(|_| ())
        )),
    }
    true
}

#[test]
fn every_test_file_compresses_as_libzstd_compresses_it() {
    let mut problems = Problems::default();
    let mut cctx = CCtx::new();
    let mut count = 0;
    for set in sets() {
        for (i, file) in set.list().iter().enumerate() {
            let data = set.read(file);
            let name = format!("{}/{}", set.name, file.display());
            // Two levels per file, all of them across the files.
            for level in [LEVELS[i % LEVELS.len()], LEVELS[(i + 3) % LEVELS.len()]] {
                count += usize::from(compare(&mut problems, &mut cctx, &name, &data, level));
            }
        }
    }
    eprintln!("compared {count} frames");
    // The committed sets alone have more than 300 files.
    assert!(count > 500);
    problems.check();
}

#[test]
fn small_inputs_compress_as_libzstd_compresses_them() {
    // Every size up to 300 bytes, of one byte repeated and of text, where
    // blocks are raw, RLE, or too small to compress.
    let mut problems = Problems::default();
    let mut cctx = CCtx::new();
    let text = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod \
        tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis \
        nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute \
        irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla.";
    for len in 0..=300 {
        for level in LEVELS {
            let data = vec![b'a'; len];
            compare(&mut problems, &mut cctx, &format!("{len} a"), &data, level);
            let data: Vec<u8> = text.iter().copied().cycle().take(len).collect();
            compare(
                &mut problems,
                &mut cctx,
                &format!("{len} of text"),
                &data,
                level,
            );
        }
    }
    problems.check();
}

#[test]
fn compression_fails_as_libzstd_fails() {
    let data: Vec<u8> = (0..20_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let mut cctx = CCtx::new();
    for capacity in [0, 1, 5, 17, 18, 21, 100, 1000] {
        let mut want = vec![0u8; capacity];
        let want = zstd::zstd_safe::compress(&mut want[..], &data, 1)
            .map_err(|code| zstd::zstd_safe::get_error_name(code).to_string());
        let mut got = vec![0u8; capacity];
        let got = cctx
            .compress(&mut got, &data, 1)
            .map_err(|error| error.code().message().to_string());
        assert_eq!(got, want, "room for {capacity} bytes");
    }
    // Levels beyond the bounds are clamped, as libzstd clamps them.
    for level in [i32::MIN, -1_000_000, 1_000_000] {
        let mut want = vec![0u8; 1 << 16];
        let want =
            zstd::zstd_safe::compress(&mut want[..], &data, level).map(|n| want[..n].to_vec());
        let mut got = vec![0u8; 1 << 16];
        let got = cctx
            .compress(&mut got, &data, level)
            .map(|n| got[..n].to_vec());
        match (got, want) {
            (Ok(got), Ok(want)) => assert_eq!(got, want, "level {level}"),
            (Err(error), _) if error.code() == ErrorCode::ParameterUnsupported => {}
            (got, want) => panic!("level {level}: port {got:?}, libzstd {want:?}"),
        }
    }
    assert_eq!(hivepack_zstd::default_c_level(), 3);
    assert_eq!(hivepack_zstd::max_c_level(), zstd::zstd_safe::max_c_level());
    assert_eq!(hivepack_zstd::min_c_level(), zstd::zstd_safe::min_c_level());
}
