//! Constant-time helpers: `NOT`, `MUX`, `EQ` and `GT` from
//! `inner.h`, and `br_ccopy` from `codec/ccopy.c`. A condition is a
//! `u32` that is 0 or 1, never a `bool`, so that no branch depends on it.

/// `NOT`: 1 for 0, 0 for 1.
pub(crate) fn not(ctl: u32) -> u32 {
    ctl ^ 1
}

/// `MUX`: `x` if `ctl` is 1, `y` if it is 0.
pub(crate) fn mux(ctl: u32, x: u32, y: u32) -> u32 {
    y ^ (ctl.wrapping_neg() & (x ^ y))
}

/// `EQ`: 1 if `x == y`, 0 otherwise.
pub(crate) fn eq(x: u32, y: u32) -> u32 {
    let q = x ^ y;
    not((q | q.wrapping_neg()) >> 31)
}

/// `GT`: 1 if `x > y`, 0 otherwise.
pub(crate) fn gt(x: u32, y: u32) -> u32 {
    let z = y.wrapping_sub(x);
    (z ^ ((x ^ y) & (x ^ z))) >> 31
}

/// `br_ccopy`: copies `src` to `dst` if `ctl` is 1, leaves `dst` as it is
/// if it is 0, in the same time either way. BearSSL copies bytes; the
/// callers here copy words, so this does too.
pub(crate) fn ccopy(ctl: u32, dst: &mut [u32], src: &[u32]) {
    for (d, &s) in dst.iter_mut().zip(src) {
        *d = mux(ctl, s, *d);
    }
}

/// Whether `a` and `b` hold the same bytes, in a time that depends on
/// their lengths but not on their contents: for comparing an
/// authentication tag or a MAC with the one computed. Two slices of
/// different lengths are not equal.
///
/// BearSSL has no such function in its interface; it leaves the
/// comparison to the caller, and compares tags this way inside its SSL
/// engine.
pub fn equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u32;
    for (&x, &y) in a.iter().zip(b) {
        diff |= u32::from(x ^ y);
    }
    std::hint::black_box(eq(diff, 0)) == 1
}
