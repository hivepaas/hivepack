# Porting BearSSL's AES, SHA-1 and HMAC

`hivepack-crypto` has what ZIP's encryption needs, in safe Rust: AES, SHA-1, HMAC-SHA1 and PBKDF2-HMAC-SHA1. WinZip AES, step 4 of [zip.md](zip.md), derives its keys with PBKDF2, encrypts with AES in counter mode and authenticates with HMAC-SHA1; ZipCrypto needs only CRC-32, which `hivepack-deflate` has. libzip takes these from OpenSSL, GnuTLS, CommonCrypto or Windows (`zip_crypto_*.c`); hivepack takes them from this crate.

## The source

The port follows [BearSSL](https://bearssl.org) **0.6** (August 2018, the latest release as of October 2026; `bearssl-0.6.tar.gz`, SHA-256 `6705bba1714961b41a728dfc5debbe348d2966c117649392f8c8139efc83ff14`). `hivepack_crypto::UPSTREAM_VERSION` names it. BearSSL is under the MIT license, small, and written so that its code runs in constant time; nettle, which the tests compare with, is under the LGPL, so its code is not ported.

| BearSSL | Port | What |
|---|---|---|
| `src/symcipher/aes_ct64.c` | `aes_ct64.rs` | the S-box, as Boyar and Peralta's circuit; the bitsliced representation; the key schedule |
| `src/symcipher/aes_ct64_enc.c` | `aes_ct64_enc.rs` | the rounds |
| `src/symcipher/aes_ct64_ctr.c` | `aes_ct64_ctr.rs` (`Aes`) | four blocks encrypted at once, without the counter |
| `src/hash/sha1.c` | `sha1.rs` (`Sha1`) | SHA-1 |
| `src/mac/hmac.c` | `hmac.rs` (`HmacKey`, `Hmac`) | HMAC, with SHA-1 |
| (none) | `pbkdf2.rs` (`pbkdf2_hmac_sha1`) | PBKDF2, from RFC 8018, section 5.2 |

The rules are those of [porting.md](porting.md): a module for each C file, the C name in each doc comment, and `Differs from BearSSL:` comments where the port departs. The differences:

- **AES without its modes.** BearSSL offers AES with CBC, CTR, CCM and GCM. WinZip AES uses a counter of its own (libzip increments the first eight bytes, little-endian), so `Aes` encrypts blocks, one or four at a time, and the caller XORs them into the data. Only encryption: a counter mode decrypts by encrypting.
- **The subkeys stay expanded.** BearSSL keeps them compressed and expands them at each call; `Aes` expands them once.
- **SHA-1 only in HMAC**, and the whole 20-byte output; libzip cuts it to 10 bytes itself.
- **A key of the wrong length** is `None`, where BearSSL's key schedule returns 0 rounds.

`aes_ct64` is BearSSL's constant-time AES for 64-bit machines: four blocks at a time are spread over eight 64-bit words, so that the S-box is a circuit of logical operations. No table is indexed with secret data, and the time taken depends neither on the key nor on the data. SHA-1 has no branches or indexing on its data either.

## Clearing secrets

libzip clears keys and contexts with `_zip_crypto_clear` when it frees them. The port overwrites keys, key schedules, HMAC keys and hash states when they are dropped, and the intermediate key material in the key schedule, HMAC and PBKDF2; not the data or the per-block temporaries, which BearSSL does not clear either. It is best effort: safe Rust has no volatile write, so the zeroing is followed by `std::hint::black_box`, which asks the compiler to keep it but does not promise to.

## Random numbers

The crate gives none. WinZip AES needs a random salt for each entry and ZipCrypto eleven random bytes for its twelve-byte header; libzip reads them from the system (`zip_random_unix.c` reads `/dev/urandom`). `hivepack-zip` will read `/dev/urandom` with the standard library on Unix, in safe Rust, and take them from the caller elsewhere; an application can use `getrandom` for that, which libraries here do not depend on (see [safety.md](safety.md)).

## How it is shown

- **`tests/vectors.rs`**: the published vectors. AES from FIPS-197 (appendix C) and NIST SP 800-38A (F.1, ECB, four blocks with each key length); SHA-1 from FIPS 180 (the empty message, `abc`, 448 and 896 bits, a million `a`); HMAC-SHA1 from RFC 2202; PBKDF2-HMAC-SHA1 from RFC 6070 (the 16,777,216-round vector is `#[ignore]`d).
- **`tests/bearssl.rs`**: BearSSL's own tests from `test/test_crypto.c` for what the port has: the 387 AES known answers (FIPS-197 and NIST's `ECBVarTxt128`, `192` and `256` files), each block encrypted alone and as each of four, and the Monte Carlo test of AES encryption with each key length (100 keys of 1,000 encryptions).
- **`tests/oracle.rs`**: comparison with [nettle](https://www.lysator.liu.se/~nisse/nettle/) 3.10.2, the library libzip's GnuTLS backend takes AES and PBKDF2 from, through `tools/nettle-oracle`, a small C program built from nettle's release by `scripts/testdata.py` (its tarball is signed by nettle's author, Niels Möller). AES with every key length, some keys of other lengths, and up to nine blocks; SHA-1 and HMAC-SHA1 on lengths around SHA-1's 64-byte blocks and the 55-byte limit of its padding, with keys up to past a block, and the port given its data in pieces of random sizes; PBKDF2 with 1 to 40 and 1,000 rounds, outputs of 1 to 100 bytes and the 34, 50 and 66 that WinZip AES derives, and salts of 8, 12 and 16 bytes among others. The inputs are random bytes, zeros, ones and single bits. 6,000 requests are compared with nettle where the oracle is built (Linux and macOS in CI), and `testdata/oracle/crypto.txt` replays 800 everywhere else, including Windows, 32-bit and big-endian machines.

## Speed

AMD Ryzen 9 9950X (x86-64, Linux), October 2026, 64 MiB at a time, release build:

| | Port | BearSSL (C, `gcc -O2`) | nettle (C, no assembly) |
|---|---|---|---|
| AES-128 | 351 MB/s | 326 MB/s (`aes_ct64`, CTR) | 672 MB/s |
| AES-256 | 246 MB/s | 235 MB/s | 442 MB/s |
| SHA-1, HMAC-SHA1 | 730 MB/s | 377 MB/s | 1,401 MB/s |
| PBKDF2, 1,000 rounds, 66 bytes (a WinZip AES-256 key) | 0.76 ms | | 0.45 ms |

nettle's AES looks bytes up in tables indexed with the key and the data, which is faster and whose time depends on them; the port keeps BearSSL's constant-time code. nettle's SHA-1 computes its message schedule as it goes, in 16 words, where BearSSL's computes all 80 first. Neither matters much for ZIP: decompression and the reads are the slower parts, and AES-NI or SHA instructions would need `unsafe` code (see [safety.md](safety.md)).

## Following new releases

BearSSL has had no release since 0.6. Changes to the ported files in its repository are ported when one comes.

## Licenses

The port is derived from BearSSL, under the MIT license (Copyright (c) 2016 Thomas Pornin). `hivepack-crypto` is under the MIT license, with BearSSL's notice in its [LICENSE](../crates/crypto/LICENSE). nettle is under the LGPL-3.0-or-later or GPL-2.0-or-later; only the test oracle is built with it, from its sources downloaded by `scripts/testdata.py`, and nothing in the repository is derived from it.
