# hivepack-crypto

AES, SHA-1, HMAC and PBKDF2 in safe Rust, ported from [BearSSL](https://bearssl.org) 0.6: what ZIP's encryption needs.

> **Status:** AES-128, AES-192 and AES-256 encryption, and decryption in CBC mode (constant-time, BearSSL's `aes_ct64`), SHA-1, HMAC-SHA1 and PBKDF2-HMAC-SHA1, checked against the published vectors, BearSSL's own tests and nettle. `hivepack-zip` encrypts and decrypts WinZip AES with it, and `hivepack-7z` decrypts 7zAES. This crate is not on crates.io.

```rust
use hivepack_crypto::{Aes, Hmac, HmacKey, pbkdf2_hmac_sha1};

// A WinZip AES-256 key: 32 bytes for AES, 32 for HMAC, 2 to check the password.
let mut derived = [0; 66];
pbkdf2_hmac_sha1(b"password", &[0x5a; 16], 1000, &mut derived);
let aes = Aes::new(&derived[..32]).expect("a 32-byte key");
let mut block = [0; 16];
aes.encrypt_block(&mut block);
let mut hmac = Hmac::new(&HmacKey::new(&derived[32..64]));
hmac.update(&block);
let mac = hmac.out();
```

The goals:

- **No unsafe code.** The crate forbids it; see [docs/safety.md](../../docs/safety.md).
- **Constant time.** AES indexes no table with secret data, as BearSSL's `aes_ct64` does not.
- **Only what is needed.** AES encrypts for ZIP, as WinZip AES runs it in counter mode both ways, and decrypts in CBC mode for 7z.

How the port follows BearSSL, how it is checked, and its speed are in [docs/crypto.md](../../docs/crypto.md).

## License

The MIT license, the license of the code it is ported from. See [LICENSE](LICENSE). Copyright (c) 2016 Thomas Pornin, and (c) 2026 HivePaaS.
