//! Clearing secrets once they are used, as libzip does with
//! `_zip_crypto_clear` and BearSSL leaves to its callers.
//!
//! Best effort: safe Rust has no volatile write, so the compiler could
//! still leave out zeroing memory that is not read again; `black_box`
//! asks it not to.

use std::hint::black_box;

/// Overwrites `values` with zeros.
pub(crate) fn clear<T: Copy + Default>(values: &mut [T]) {
    values.fill(T::default());
    black_box(values);
}
