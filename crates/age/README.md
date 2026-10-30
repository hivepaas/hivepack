# hivepack-age

Decrypting [age](https://age-encryption.org) files in safe Rust, ported from age v1.3.2, the reference implementation in Go (`filippo.io/age`).

> **Status:** decrypts files encrypted with a passphrase or to X25519 keys (`AGE-SECRET-KEY-1…`), armored or not, with age's outcomes on C2SP's test vectors and on files age encrypts. SSH keys, post-quantum keys, plugins and encrypting are not ported yet. This crate is not on crates.io.

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

`decrypt_file` reads a file as `age --decrypt` does: armored (`-----BEGIN AGE ENCRYPTED FILE-----`) or binary, told apart by its first line. The header is checked before it returns; the payload is decrypted as it is read, 64 KiB at a time, each chunk authenticated before any of it is given out. A file cut short or changed fails when the damage is reached, with what was read before it authentic but incomplete.

`Error` says why a file did not decrypt: `Header` (malformed, or a stanza that asks for too much work), `NoMatch` (no identity fits; its `stanza_types` say what kind of key the file needs), `HeaderMac`, `Armor`, `Payload` or `Io`. A passphrase's work factor is limited to 2^22 by default (4 GiB of memory, as age); `ScryptIdentity::set_max_work_factor` lowers it.

How the port follows age, and how it is checked, is in [docs/age.md](../../docs/age.md).

## License

BSD-3-Clause, as age is (see [LICENSE](LICENSE)).
