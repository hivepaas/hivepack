//! Random bytes for encrypting: port of `zip_random_unix.c`'s
//! `zip_secure_random`, which reads `/dev/urandom`.
//!
//! Differs from libzip: the caller can give the bytes
//! ([`Archive::set_random_source`]), and must where the system is not Unix
//! (libzip asks Windows' and Apple's own functions, which need `unsafe`
//! code). A short read of `/dev/urandom` is read on, where libzip fails.

use std::sync::Arc;

use crate::open::Archive;

/// Where the random bytes encrypting takes come from: it fills the buffer
/// it is given, or fails. WinZip AES takes a salt of 8 to 16 bytes for
/// each entry, ZipCrypto 11 bytes for its header.
pub type RandomSource = Arc<dyn Fn(&mut [u8]) -> std::io::Result<()> + Send + Sync>;

/// `zip_secure_random`: fills `buffer` from `source`, or from the system
/// without one; `false` if it cannot.
pub(crate) fn secure_random(source: Option<&RandomSource>, buffer: &mut [u8]) -> bool {
    match source {
        Some(source) => source(buffer).is_ok(),
        None => system_random(buffer),
    }
}

#[cfg(unix)]
fn system_random(buffer: &mut [u8]) -> bool {
    use std::io::Read;
    match std::fs::File::open("/dev/urandom") {
        Ok(mut file) => file.read_exact(buffer).is_ok(),
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn system_random(_buffer: &mut [u8]) -> bool {
    false
}

impl<R> Archive<R> {
    /// Sets where the random bytes come from that encrypting entries takes
    /// when the archive is written: `source`, or with `None` the system
    /// (`/dev/urandom`), as libzip's `zip_secure_random` reads it. Where
    /// the system is not Unix, encrypting fails with
    /// [`ErrorCode::Internal`](crate::ErrorCode::Internal) unless a source
    /// is given.
    pub fn set_random_source(&mut self, source: Option<RandomSource>) {
        self.random = source;
    }
}
