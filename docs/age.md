# Porting age

`hivepack-age` decrypts files of [age](https://age-encryption.org), the encryption tool and format by Filippo Valsorda, in safe Rust. age files are often archives: `tar | zstd | age > backup.tar.zst.age`. An application reads the decrypted stream as it would read the file underneath.

## The source

The port follows **age v1.3.2** (`filippo.io/age`, the reference implementation, in Go; tag `v1.3.2`, module sum `h1:r6RSZLFSMm6rzKepZ7ZAYkKCu14f3/Me8c7uKYh7C8c=`), the latest release as of October 2026. `hivepack_age::UPSTREAM_VERSION` names it. The format is specified by C2SP (`c2sp.org/age`); where the specification leaves a choice, such as the limits on a header, the port does what age does.

Each Go file ported is a module, its functions keep their names in snake case, and each doc comment names the Go original, as [porting.md](porting.md) asks of the other ports. Only the decrypting half is ported.

| age | Port | What |
|---|---|---|
| `age.go` | `age.rs` (`decrypt`, `Decryptor`, `Identity`, `FileKey`) | the header's stanzas unwrapped by the identities, native ones first; the header's MAC; the payload's nonce |
| `primitives.go` | `primitives.rs` | ChaCha20-Poly1305 with a zero nonce, the header's MAC, the payload's key |
| `internal/format/format.go` | `format.rs` (`Stanza`) | the header: intro, stanzas, closing line, with age's limits (2 MiB, 1,024 stanzas, 128 arguments); what the MAC is computed over |
| `internal/stream/stream.go` | `stream.rs` | the payload: STREAM over ChaCha20-Poly1305, 64 KiB chunks, the last marked in the nonce |
| `armor/armor.go` | `armor.rs` (`ArmoredReader`) | the ASCII armor |
| `scrypt.go` | `scrypt.rs` (`ScryptIdentity`) | passphrases, and the limit on their work factor |
| `x25519.go` | `x25519.rs` (`X25519Identity`) | X25519 keys, `AGE-SECRET-KEY-1…` |
| `internal/bech32/bech32.go` | `bech32.rs` | the keys' encoding |
| `parse.go` | `parse.rs` (`parse_identities`) | files of keys, as `age-keygen` writes them |
| `decrypt` in `cmd/age/age.go` | `lib.rs` (`decrypt_file`) | what `age --decrypt` does first: armor told apart from a binary file by its first line, after up to 1 KiB of white space; files whose intro PowerShell's redirection mangled refused |
| Go's `encoding/base64`, `Strict()` | `base64.rs` | strict base64, without padding in headers and with it in the armor |

The cryptography is `hivepack-crypto`'s ([crypto.md](crypto.md)): HKDF-SHA256, HMAC-SHA256, ChaCha20-Poly1305, X25519 and scrypt, ported from BearSSL or written from their RFCs, in place of Go's standard library and `golang.org/x/crypto`. MACs and tags are compared in constant time.

## What differs

- **Errors are a type.** age's errors are Go values that its tests tell apart by type (`*format.ParseError`, `*age.NoIdentityMatchError`, `*armor.Error`) or by message (`bad header MAC`). Here they are `Error`'s variants, which match the outcomes C2SP's vectors name: `Header`, `NoMatch`, `HeaderMac`, `Armor` and `Payload`, plus `Io`. The messages are age's, near enough: Go's `%q` is Rust's `{:?}`, and base64's errors do not give the position. An identity's `unwrap` returns `UnwrapError::Incorrect` where age wraps `ErrIncorrectIdentity`, and `UnwrapError::Invalid` for its other errors, which end the decryption as a header failure.
- **Errors travel inside `io::Error`.** The armor's and the payload's errors are found while reading, through `io::Read`; they come as `io::Error`s of kind `InvalidData` that hold the `Error`, and `Error::from` takes it back out. A reader that failed returns its error again at every later read, as age's do.
- **Lines are read whole.** age peeks at three bytes for the header's closing line before reading a stanza; the port reads the next line and looks at its start, which cannot be confused, as a stanza starts with `->` and the closing line with `---`. The armor reader reads lines of at most 4 KiB, where age reads them whole whatever their length; a longer line fails as age would fail it, as too long or as not the first line.
- **No panics.** `SetMaxWorkFactor` with a value out of 1 to 30 brings it into the range, where age panics; a chunk counter that wraps around, after 2^88 chunks, is an error.
- **Post-quantum identities** (`AGE-SECRET-KEY-PQ-1…`, `mlkem768x25519` stanzas, age 1.3) are recognised in key files and refused as not supported yet; a file encrypted to one fails with `NoMatch`, whose `stanza_types` say so.
- **Not ported:** encrypting, `DecryptReaderAt` (random access), plugins (`age-plugin-*`, which age runs as programs), SSH keys (`agessh`, next), the hybrid post-quantum recipients, and `age-inspect`.

## Bounded resources

What the port allocates is bounded before it reads a file, as age bounds it: the header to 2 MiB, 1,024 stanzas and 128 arguments each; the payload to one chunk of 64 KiB at a time; a key file to 16 MiB and lines of 64 KiB. A passphrase's work factor is the exception that age sets for the caller to choose: 2^22 by default, which is 4 GiB of memory and about 5 seconds on a Ryzen 9 9950X. A file asking for more fails at once, without the work. An application that opens files from strangers, as an archiver does, should lower it with `ScryptIdentity::set_max_work_factor`: age's own default when encrypting is 2^18 (256 MiB, 0.3 s), and each step up doubles the time and the memory. scrypt's memory is allocated with `try_reserve_exact`, so a machine without it gets an error rather than an abort.

## How it is shown

- **`tests/cctv.rs`**: C2SP's CCTV test vectors for age (`c2sp.org/CCTV/age` at commit 4448f2097b2d, the module age v1.3.2 tests with), fetched by `scripts/testdata.py` from Go's module proxy into the `cctv-age` set. Each vector is a file with the outcome it must have, and the SHA-256 of all the plaintext given out, even when the payload fails later. As age's `testkit_test.go` does, an armored vector goes through the armor reader; then the vector goes through `decrypt_file` too, which must agree, except that a file with garbage before its armor is not taken for armored and fails as a header. All 128 vectors with X25519 keys and passphrases pass; the 19 with post-quantum keys are skipped.
- **`tests/oracle.rs`**: comparison with age itself, through `tools/age-oracle`, the Go program of [crypto.md](crypto.md), now built with age v1.3.2 too. age encrypts payloads of 0 to 200,000 bytes, around the 64 KiB chunks, to one to four X25519 keys or to a passphrase with a work factor of 2^1 to 2^4, armored or not. Three files in four are then damaged one of a dozen ways: a bit flipped anywhere or in the header, cut anywhere or at a chunk's end, bytes added, removed or inserted, CRLF line ends, a letter's case changed, a header line said twice or left out, the header of another file to the same recipients, white space or garbage before it. Both decrypt it with the right and wrong keys, the right and wrong passphrases, and work factors allowed or not, the port reading in pieces of random sizes; the outcome and the length and SHA-256 of the plaintext given out must be the same. 600 files are compared where the oracle is built (Linux and macOS in CI), all six outcomes among them, and `testdata/oracle/age.txt` replays 300 small ones everywhere else.
- **Fuzzing**: the `age` target decrypts any input with CCTV's usual X25519 key and the passphrase `password` (work factors up to 2^4), which many of the recorded files use, so that its corpus, seeded with them in CI, gets past the header. It reads each file twice, in pieces of different sizes; both reads must give the same plaintext and end the same way, and a panic is a bug.
- **Unit tests**: base64 with RFC 4648's vectors and the strict cases, Bech32 with BIP 173's.

## Following new releases

A new release of age is compared with the port's files, and its changes to them are ported; the CCTV module it tests with is the one the vectors come from.

## Next

1. **SSH keys**: `ssh-ed25519` stanzas (`agessh/agessh.go`), with OpenSSH's private keys, including those protected by a passphrase (bcrypt_pbkdf and Blowfish, from `golang.org/x/crypto`); and key files that are themselves age files (`cmd/age/parse.go`).
2. Later: `ssh-rsa`; the post-quantum recipients, once ML-KEM is ported; encrypting.

## Licenses

The port is derived from age, under the BSD-3-Clause license (Copyright 2019 The age Authors, 2019 Google LLC, 2022 Filippo Valsorda); `hivepack-age` is under the same license, with age's notice in its [LICENSE](../crates/age/LICENSE). The CCTV vectors are under 0BSD, CC0-1.0 or the Unlicense, to the user's choice; they are fetched, not committed. `tools/age-oracle` is built with age and `golang.org/x/crypto`, both BSD-3-Clause, and only the tests run it.
