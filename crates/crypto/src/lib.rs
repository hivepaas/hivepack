//! AES, SHA-1, HMAC and PBKDF2 in safe Rust, ported from
//! [BearSSL](https://bearssl.org) 0.6: what ZIP's encryption needs.
//! hivepack-zip builds WinZip AES on them, as libzip builds it on OpenSSL,
//! GnuTLS or the system's library. ZipCrypto needs only CRC-32.
//!
//! - [`Aes`] is BearSSL's `aes_ct64`: AES-128, AES-192 and AES-256,
//!   bitsliced, four blocks at a time. No table is indexed with secret
//!   data, so the time it takes depends neither on the key nor on the data.
//!   It only encrypts: WinZip AES runs AES in counter mode, both ways.
//! - [`Sha1`] and [`Hmac`] are BearSSL's `sha1.c` and `hmac.c`.
//! - [`pbkdf2_hmac_sha1`] follows RFC 8018, as BearSSL has no PBKDF2.
//!
//! Secrets are overwritten when the values that hold them are dropped, as
//! libzip clears them with `_zip_crypto_clear`. That is best effort: safe
//! Rust has no volatile write, and the compiler could leave out the
//! zeroing of memory that is not read again.
//!
//! The rules the port follows, and how it is checked against nettle, are
//! in the repository: `docs/crypto.md` and `docs/safety.md`.
//!
//! ```
//! use hivepack_crypto::{Aes, Hmac, HmacKey, Sha1, pbkdf2_hmac_sha1};
//!
//! // FIPS-197, appendix C.1.
//! let key: Vec<u8> = (0..16).collect();
//! let aes = Aes::new(&key).expect("a 16-byte key");
//! let mut block = *b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
//! aes.encrypt_block(&mut block);
//! assert_eq!(block[..4], [0x69, 0xc4, 0xe0, 0xd8]);
//!
//! let mut sha1 = Sha1::new();
//! sha1.update(b"abc");
//! assert_eq!(sha1.out()[..4], [0xa9, 0x99, 0x3e, 0x36]);
//!
//! // RFC 2202, test case 2.
//! let mut hmac = Hmac::new(&HmacKey::new(b"Jefe"));
//! hmac.update(b"what do ya want for nothing?");
//! assert_eq!(hmac.out()[..4], [0xef, 0xfc, 0xdf, 0x6a]);
//!
//! // RFC 6070, the second test.
//! let mut derived = [0; 20];
//! pbkdf2_hmac_sha1(b"password", b"salt", 2, &mut derived);
//! assert_eq!(derived[..4], [0xea, 0x6c, 0x01, 0x4d]);
//! ```

mod aes_ct64;
mod aes_ct64_ctr;
mod aes_ct64_enc;
mod clear;
mod hmac;
mod pbkdf2;
mod sha1;

pub use aes_ct64_ctr::{AES_BLOCK_LENGTH, Aes};
pub use hmac::{Hmac, HmacKey};
pub use pbkdf2::pbkdf2_hmac_sha1;
pub use sha1::{SHA1_LENGTH, Sha1};

/// The BearSSL release this crate follows.
pub const UPSTREAM_VERSION: &str = "0.6";
