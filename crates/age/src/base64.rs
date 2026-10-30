//! Base64 (RFC 4648, section 4) as age uses it from Go's `encoding/base64`:
//! `RawStdEncoding.Strict()` in headers, without padding, and
//! `StdEncoding.Strict()` in the armor, with it. Strict means the unused
//! bits of the last character must be zero, so that each string decodes
//! from one encoding only.
//!
//! Go's decoder skips `\r` and `\n`; age refuses both before decoding, so
//! here they are invalid characters like any other.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn value(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// Decodes `input`, padded with `=` to a multiple of four characters if
/// `padded`, without padding otherwise. `None` if it is not the strict
/// encoding of anything.
pub(crate) fn decode(input: &[u8], padded: bool) -> Option<Vec<u8>> {
    decode_with(input, padded, true)
}

/// `StdEncoding.Decode`, as Go's PEM decoder calls it: padded, not
/// strict (the last character's unused bits may be anything), and with
/// the CR and LF it skips.
pub(crate) fn decode_lenient(input: &[u8]) -> Option<Vec<u8>> {
    let data: Vec<u8> = input
        .iter()
        .copied()
        .filter(|&c| c != b'\r' && c != b'\n')
        .collect();
    decode_with(&data, true, false)
}

fn decode_with(input: &[u8], padded: bool, strict: bool) -> Option<Vec<u8>> {
    let mut data = input;
    if padded {
        if !data.len().is_multiple_of(4) {
            return None;
        }
        // At most two `=`, at the end.
        let pad = data
            .iter()
            .rev()
            .take(2)
            .take_while(|&&c| c == b'=')
            .count();
        data = &data[..data.len() - pad];
        if pad > 0 && data.len() % 4 + pad != 4 {
            return None;
        }
    }
    if data.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(data.len() / 4 * 3 + 2);
    let (quads, rest) = data.as_chunks::<4>();
    for quad in quads {
        let mut n = 0;
        for &c in quad {
            n = n << 6 | value(c)?;
        }
        out.extend_from_slice(&n.to_be_bytes()[1..]);
    }
    match *rest {
        [] => {}
        [a, b] => {
            let (a, b) = (value(a)?, value(b)?);
            if strict && b & 0x0F != 0 {
                return None;
            }
            out.push((a << 2 | b >> 4) as u8);
        }
        [a, b, c] => {
            let (a, b, c) = (value(a)?, value(b)?, value(c)?);
            if strict && c & 0x03 != 0 {
                return None;
            }
            let n = a << 12 | b << 6 | c;
            out.push((n >> 10) as u8);
            out.push((n >> 2) as u8);
        }
        _ => return None,
    }
    Some(out)
}

/// Encodes `data`, without padding (`RawStdEncoding`).
pub(crate) fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let mut n = 0u32;
        for (i, &byte) in chunk.iter().enumerate() {
            n |= u32::from(byte) << (16 - 8 * i);
        }
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 0x3F) as usize]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_rfc_4648_vectors_strictly() {
        let vectors: [(&str, &str); 7] = [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, raw) in vectors {
            assert_eq!(encode(plain.as_bytes()), raw);
            assert_eq!(
                decode(raw.as_bytes(), false).as_deref(),
                Some(plain.as_bytes())
            );
            let padded = format!("{raw}{}", "=".repeat((4 - raw.len() % 4) % 4));
            assert_eq!(
                decode(padded.as_bytes(), true).as_deref(),
                Some(plain.as_bytes())
            );
            if padded != raw {
                assert_eq!(decode(padded.as_bytes(), false), None, "{padded}");
                assert_eq!(decode(raw.as_bytes(), true), None, "{raw}");
            }
        }
        // Bits past the data, which Strict refuses, and Go's PEM does not.
        assert_eq!(decode_lenient(b"Zh=="), decode_lenient(b"Zg=="));
        assert_eq!(decode_lenient(b"Zm9v\r\nYg=="), Some(b"foob".to_vec()));
        assert_eq!(decode_lenient(b"Zg"), None);
        assert_eq!(decode(b"Zh", false), None);
        assert_eq!(decode(b"Zm9", false), None);
        assert_eq!(decode(b"Zh==", true), None);
        // Bad lengths, padding in the wrong place, other characters.
        for bad in [
            "Z", "Zm9vY", "Z===", "Zg=", "=Zg=", "Zg==Zg==", "Zm9v\n", "Zm-v", "Zm_v",
        ] {
            assert_eq!(decode(bad.as_bytes(), true), None, "{bad}");
            assert_eq!(decode(bad.as_bytes(), false), None, "{bad}");
        }
    }
}
