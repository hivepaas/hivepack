# hivepack-age

Decrypting [age](https://age-encryption.org) files in safe Rust, ported from age v1.3.2, the reference implementation in Go (`filippo.io/age`).

> **Status:** decrypts files encrypted with a passphrase, to X25519 keys (`AGE-SECRET-KEY-1…`) or to SSH Ed25519 keys, with or without a passphrase, armored or not, with age's outcomes on C2SP's test vectors and on files age encrypts. SSH RSA keys, post-quantum keys, plugins and encrypting are not ported yet. This crate is not on crates.io.

```rust
use std::io::Read;
use hivepack_age::{Identity, ScryptIdentity, decrypt_file};

let file = std::fs::File::open("backup.tar.zst.age")?;
let passphrase = ScryptIdentity::new(b"correct horse battery staple")?;
let mut plaintext = decrypt_file(file, &[&passphrase as &dyn Identity])?;
let mut data = Vec::new();
plaintext.read_to_end(&mut data)?;
```

With keys from a file that `age-keygen` wrote:

```rust
let keys = hivepack_age::parse_identities(std::fs::File::open("keys.txt")?)?;
let identities: Vec<&dyn Identity> = keys.iter().map(|k| k.as_ref() as &dyn Identity).collect();
let plaintext = decrypt_file(file, &identities)?;
```

With what `age -i` takes: a file of keys, one encrypted with age, or an SSH private key. A passphrase is asked for only when one is needed: an SSH key's when a stanza is for that key, an encrypted file of keys' when one of its keys is first tried.

```rust
use std::sync::Arc;
use hivepack_age::{PassphraseFor, PassphrasePrompt, parse_identities_file};

let prompt: PassphrasePrompt = Arc::new(|what: PassphraseFor| ask_the_person(what));
let keys = parse_identities_file(std::fs::File::open("/home/me/.ssh/id_ed25519")?, prompt)?;
```

`decrypt_file` reads a file as `age --decrypt` does: armored (`-----BEGIN AGE ENCRYPTED FILE-----`) or binary, told apart by its first line. The header is checked before it returns; the payload is decrypted as it is read, 64 KiB at a time, each chunk authenticated before any of it is given out. A file cut short or changed fails when the damage is reached, with what was read before it authentic but incomplete.

`Error` says why a file did not decrypt: `Header` (malformed, or a stanza that asks for too much work), `NoMatch` (no identity fits; its `stanza_types` say what kind of key the file needs), `HeaderMac`, `Armor`, `Payload` or `Io`. A passphrase's work factor is limited to 2^22 by default (4 GiB of memory, as age); `ScryptIdentity::set_max_work_factor` lowers it.

How the port follows age, and how it is checked, is in [docs/age.md](../../docs/age.md).

## Speed

Against age v1.3.2, the reference implementation in Go, with `tools/age-bench`. Above 1× the port is faster.

| | hivepack-age / age |
|---|---|
| Passphrase, scrypt | 1.02–1.28× |
| X25519 and ssh-ed25519 | 2.23–2.35× |
| Files of 4 KiB | 2.02× |
| A big file in ASCII armor | 1.29× |
| A big file's payload | 0.40× |
| Parsing age keys | 2.19× |

**Measured on:** AMD Ryzen 9 9950X (16 cores, x86-64), 45 GiB of memory, Ubuntu 26.04 with Linux 7.0 and the `powersave` governor, rustc 1.99.1 in the workspace's release profile, Go 1.27.2 with age v1.3.2, in October 2026. The data is the Silesia corpus cut to 64 MiB, in memory, the best of five rounds taken in turn. Both read the same bytes. Go's ChaCha20-Poly1305 is AVX2 assembly, which is the big file's gap. More is in [docs/age.md](../../docs/age.md#the-speed).

## License

BSD-3-Clause, as age is (see [LICENSE](LICENSE)).
