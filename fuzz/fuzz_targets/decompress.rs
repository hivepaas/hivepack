//! Decodes the input with the port and with libzstd, in one call, and checks
//! that they agree: the same output, or the same error. A panic, a
//! difference, or (with the `unsafe-fast` feature, under the sanitizer) an
//! access out of bounds is a bug.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zstd::zstd_safe;

/// Room for the output; frames that need more fail the same way in both.
const CAPACITY: usize = 1 << 20;

fuzz_target!(|src: &[u8]| {
    let mut c_out = vec![0u8; CAPACITY];
    let mut p_out = vec![0u8; CAPACITY];
    let want = zstd_safe::DCtx::create()
        .decompress(&mut c_out[..], src)
        .map(|n| &c_out[..n])
        .map_err(zstd_safe::get_error_name);
    let got = hivepack_zstd::decompress(&mut p_out, src)
        .map(|n| &p_out[..n])
        .map_err(|error| error.code().message());
    assert!(
        want == got,
        "libzstd {:?}, port {:?}",
        summary(&want),
        summary(&got)
    );
});

fn summary(result: &Result<&[u8], &str>) -> String {
    match result {
        Ok(out) => format!("{} bytes", out.len()),
        Err(name) => format!("error {name}"),
    }
}
