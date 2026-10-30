//! Decrypting a file: port of `age.go`, the decrypting half.

use std::io::{self, BufRead, Read};

use hivepack_crypto::equal;

use crate::error::{Error, NoIdentityMatch};
use crate::format::{self, Header, Stanza};
use crate::primitives::{header_mac, stream_key};
use crate::stream::DecryptReader;

/// `fileKeySize`.
pub(crate) const FILE_KEY_SIZE: usize = 16;

/// `streamNonceSize`.
const STREAM_NONCE_SIZE: usize = 16;

/// The key a file's payload is derived from, which each recipient stanza
/// wraps. It is overwritten when it is dropped (best effort).
#[derive(Clone, PartialEq, Eq)]
pub struct FileKey(pub(crate) [u8; FILE_KEY_SIZE]);

impl FileKey {
    /// The key's bytes.
    pub fn as_bytes(&self) -> &[u8; FILE_KEY_SIZE] {
        &self.0
    }
}

impl Drop for FileKey {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&mut self.0);
    }
}

/// Shows nothing of the key.
impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileKey(..)")
    }
}

/// Why an identity did not unwrap the file key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnwrapError {
    /// The stanzas are not for this identity, or the passphrase is wrong:
    /// `ErrIncorrectIdentity`, with what age adds to it. The next identity
    /// is tried.
    Incorrect(String),
    /// A stanza for this identity is malformed, or asks for too much work:
    /// the file fails with [`Error::Header`] without trying the others.
    Invalid(String),
}

/// A key that can unwrap a file key: `Identity`.
pub trait Identity {
    /// `Unwrap`: the file key, from one of the header's stanzas.
    fn unwrap(&self, stanzas: &[Stanza]) -> Result<FileKey, UnwrapError>;

    /// Whether this is one of age's own identities (X25519 or scrypt
    /// here), which `Decrypt` tries before the others: they are quick,
    /// and need nothing from the person.
    fn is_native(&self) -> bool {
        false
    }
}

/// `ErrIncorrectIdentity`'s message.
pub(crate) const INCORRECT_IDENTITY: &str = "incorrect identity for recipient block";

/// `multiUnwrap`: the first stanza `unwrap` takes, skipping those that are
/// not for it.
pub(crate) fn multi_unwrap(
    unwrap: impl Fn(&Stanza) -> Result<FileKey, UnwrapError>,
    stanzas: &[Stanza],
) -> Result<FileKey, UnwrapError> {
    for s in stanzas {
        match unwrap(s) {
            Err(UnwrapError::Incorrect(_)) => continue,
            result => return result,
        }
    }
    Err(UnwrapError::Incorrect(INCORRECT_IDENTITY.into()))
}

/// `decryptHdr`: the file key, from the first identity that unwraps it,
/// checked against the header's MAC.
fn decrypt_hdr(hdr: &Header, identities: &[&dyn Identity]) -> Result<FileKey, Error> {
    if identities.is_empty() {
        return Err(Error::Header("no identities specified".into()));
    }
    let mut identities = identities.to_vec();
    identities.sort_by_key(|i| !i.is_native());

    let mut no_match = NoIdentityMatch {
        errors: Vec::new(),
        stanza_types: hdr.recipients.iter().map(|s| s.kind.clone()).collect(),
    };
    let mut file_key = None;
    for id in identities {
        match id.unwrap(&hdr.recipients) {
            Ok(key) => {
                file_key = Some(key);
                break;
            }
            Err(UnwrapError::Incorrect(message)) => no_match.errors.push(message),
            Err(UnwrapError::Invalid(message)) => return Err(Error::Header(message)),
        }
    }
    let Some(file_key) = file_key else {
        return Err(Error::NoMatch(no_match));
    };

    if !equal(&header_mac(&file_key.0, hdr), &hdr.mac) {
        return Err(Error::HeaderMac);
    }
    Ok(file_key)
}

/// `Decrypt`: the plaintext of the age file `src`, with the first of
/// `identities` that matches one of its recipient stanzas.
///
/// The header is read and checked before this returns; the payload is
/// decrypted as it is read, a chunk of 64 KiB at a time, each chunk
/// authenticated before any of it is given out. A payload that is cut
/// short, changed or goes on after its end fails when that is reached:
/// what was read before it is authentic, but not all there is.
///
/// `src` is an armored file's [`ArmoredReader`](crate::ArmoredReader), or
/// a binary file as it is; [`decrypt_file`](crate::decrypt_file) tells the
/// two apart.
pub fn decrypt<R: BufRead>(
    mut src: R,
    identities: &[&dyn Identity],
) -> Result<Decryptor<R>, Error> {
    let hdr = format::parse(&mut src).map_err(|e| match e {
        Error::Header(message) => Error::Header(format!("failed to read header: {message}")),
        other => other,
    })?;

    let file_key = decrypt_hdr(&hdr, identities)?;

    let mut nonce = [0u8; STREAM_NONCE_SIZE];
    let mut n = 0;
    while n < STREAM_NONCE_SIZE {
        match src.read(&mut nonce[n..]) {
            Ok(0) => {
                let message = if n == 0 { "EOF" } else { "unexpected EOF" };
                return Err(Error::Header(format!("failed to read nonce: {message}")));
            }
            Ok(read) => n += read,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }

    Ok(Decryptor {
        stanza_types: hdr.recipients.iter().map(|s| s.kind.clone()).collect(),
        reader: DecryptReader::new(stream_key(&file_key.0, &nonce), src),
    })
}

/// The plaintext of an age file, as it is read: what [`decrypt`] and
/// [`decrypt_file`](crate::decrypt_file) return.
///
/// A payload that fails gives an `io::Error` of kind `InvalidData`, which
/// `Error::from` turns back into an [`Error::Payload`] (or an
/// [`Error::Armor`]).
#[derive(Debug)]
pub struct Decryptor<R> {
    stanza_types: Vec<String>,
    reader: DecryptReader<R>,
}

impl<R> Decryptor<R> {
    /// The types of the header's recipient stanzas, such as `X25519`.
    pub fn stanza_types(&self) -> &[String] {
        &self.stanza_types
    }
}

impl<R: Read> Read for Decryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}
