//! What a stream is, from its first bytes: a layer to take off (age, or a
//! compressor), a container (tar, ZIP, an ISO 9660 image), or plain data.

/// A layer over the data: encryption or compression.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Layer {
    /// age, binary or armored.
    Age,
    /// Zstandard: frames, skippable ones among them.
    Zstd,
    /// LZ4's frames, skippable ones among them, or its legacy format.
    Lz4,
    /// .xz.
    Xz,
    /// .lz (lzip).
    Lzip,
    /// .lzma (LZMA_Alone), which has no magic: told by its name only.
    Lzma,
    /// gzip.
    Gzip,
    /// bzip2.
    Bzip2,
}

/// What is under the layers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Container {
    /// A tar archive.
    Tar,
    /// A ZIP archive, which is read by random access: in a layer, it must
    /// be taken out to a file first.
    Zip,
    /// An ISO 9660 image (`.iso`), which `hivepack-iso` reads in order, in
    /// a layer too (`.iso.xz`).
    Iso,
    /// Data: one file, compressed or encrypted (`notes.txt.zst`).
    Data,
}

/// What [`detect`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detected {
    Layer(Layer),
    Container(Container),
}

/// How much of a stream [`detect`] looks at: a tar header block, or an
/// armored age file's 1 KiB of white space and its first line.
pub const HEAD_LEN: usize = 1024 + 34 + 512;

/// How much of a stream [`detect`] looks at to tell an ISO 9660 image, when
/// its first [`HEAD_LEN`] bytes are data: its system area and its first
/// volume descriptor.
pub const ISO_HEAD_LEN: usize = ISO_DESCRIPTORS + 2048;

/// Where an ISO 9660 image's volume descriptors start, after its 32 KiB
/// system area (which a bootable image fills with a boot sector, or a
/// partition table to be written to a USB stick).
const ISO_DESCRIPTORS: usize = 16 * 2048;

const AGE_INTRO: &[u8] = b"age-encryption.org/";
const AGE_ARMOR: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";
const ZSTD_MAGIC: &[u8] = &[0x28, 0xB5, 0x2F, 0xFD];
const LZ4_MAGIC: &[u8] = &[0x04, 0x22, 0x4D, 0x18];
const LZ4_LEGACY_MAGIC: &[u8] = &[0x02, 0x21, 0x4C, 0x18];

/// Whether `head` starts with a skippable frame's magic, 0x184D2A50 to
/// 0x184D2A5F, little-endian: zstd's and LZ4's, which share them.
pub(crate) fn is_skippable(head: &[u8]) -> bool {
    head.len() >= 4 && head[0] & 0xF0 == 0x50 && head[1..4] == [0x2A, 0x4D, 0x18]
}

/// What comes after the skippable frames that start `head`, as far as it
/// goes: nothing if one goes on past its end.
fn past_skippable(head: &[u8]) -> &[u8] {
    let mut rest = head;
    while is_skippable(rest) {
        let Some(size) = rest.get(4..8) else {
            return &[];
        };
        let size = u32::from_le_bytes([size[0], size[1], size[2], size[3]]) as usize;
        match rest.get(8 + size..) {
            Some(after) => rest = after,
            None => return &[],
        }
    }
    rest
}

/// Whether `head` is a tar header block: USTAR's or GNU's magic, or a
/// checksum that adds up, as V7 has nothing else.
fn is_tar(head: &[u8]) -> bool {
    let Some(block) = head.get(..512) else {
        return false;
    };
    if &block[257..262] == b"ustar" {
        return true;
    }
    let field = &block[148..156];
    let digits: Vec<u8> = field
        .iter()
        .copied()
        .filter(|&c| c != b' ' && c != 0)
        .collect();
    if digits.is_empty() || !digits.iter().all(|c| (b'0'..=b'7').contains(c)) {
        return false;
    }
    let Ok(value) = i64::from_str_radix(std::str::from_utf8(&digits).unwrap_or("x"), 8) else {
        return false;
    };
    let (mut unsigned, mut signed) = (0i64, 0i64);
    for (i, &c) in block.iter().enumerate() {
        let c = if (148..156).contains(&i) { b' ' } else { c };
        unsigned += i64::from(c);
        signed += i64::from(c as i8);
    }
    // A block of zeros sums to 256 with its checksum field as spaces;
    // a value written for it is still not a header.
    value != 0 && (value == unsigned || value == signed) && block[..100].iter().any(|&c| c != 0)
}

/// Whether `head` has an ISO 9660 volume descriptor where the first one
/// is: a type (0 to 3, or 255 for the set's end), "CD001" and version 1,
/// as `file` and libarchive look for. An image with UDF beside ISO 9660
/// (Windows' and most DVDs') has it too; one with UDF alone does not.
fn is_iso(head: &[u8]) -> bool {
    let Some(vd) = head.get(ISO_DESCRIPTORS..ISO_DESCRIPTORS + 7) else {
        return false;
    };
    matches!(vd[0], 0..=3 | 255) && &vd[1..6] == b"CD001" && vd[6] == 1
}

/// What `head`, the first [`HEAD_LEN`] bytes of a stream (fewer if it is
/// shorter), or [`ISO_HEAD_LEN`] to tell an ISO 9660 image, is. `name`, the file's name if the stream is the file's, tells
/// `.lzma`, which has no magic.
pub fn detect(head: &[u8], name: Option<&str>) -> Detected {
    let starts = |magic: &[u8]| head.starts_with(magic);
    if starts(AGE_INTRO) {
        return Detected::Layer(Layer::Age);
    }
    // An armored age file: its first line after white space.
    let text = head
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .map_or(&head[head.len()..], |i| &head[i..]);
    if head.len() - text.len() <= 1024 && text.starts_with(AGE_ARMOR) {
        return Detected::Layer(Layer::Age);
    }
    if starts(ZSTD_MAGIC) {
        return Detected::Layer(Layer::Zstd);
    }
    if starts(LZ4_MAGIC) || starts(LZ4_LEGACY_MAGIC) {
        return Detected::Layer(Layer::Lz4);
    }
    // Skippable frames, zstd's or LZ4's: the frame after them tells. zstd
    // when it is past what `head` holds.
    if is_skippable(head) {
        let next = past_skippable(head);
        if next.starts_with(LZ4_MAGIC) || next.starts_with(LZ4_LEGACY_MAGIC) {
            return Detected::Layer(Layer::Lz4);
        }
        return Detected::Layer(Layer::Zstd);
    }
    if starts(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        return Detected::Layer(Layer::Xz);
    }
    if starts(b"LZIP") {
        return Detected::Layer(Layer::Lzip);
    }
    if starts(&[0x1F, 0x8B]) {
        return Detected::Layer(Layer::Gzip);
    }
    if head.len() >= 4 && starts(b"BZh") && (b'1'..=b'9').contains(&head[3]) {
        return Detected::Layer(Layer::Bzip2);
    }
    if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") || starts(b"PK\x07\x08") {
        return Detected::Container(Container::Zip);
    }
    if is_tar(head) {
        return Detected::Container(Container::Tar);
    }
    // After what starts the stream: an image's system area is anything.
    if is_iso(head) {
        return Detected::Container(Container::Iso);
    }
    if name.is_some_and(|n| n.to_ascii_lowercase().ends_with(".lzma")) {
        return Detected::Layer(Layer::Lzma);
    }
    Detected::Container(Container::Data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(head: &[u8]) -> Detected {
        detect(head, None)
    }

    /// A tar header block: `magic` at 257, the checksum summed as tar
    /// does, or `checksum` when it is given.
    fn tar_block(name: &[u8], magic: &[u8], checksum: Option<&[u8]>) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[..name.len()].copy_from_slice(name);
        b[100..108].copy_from_slice(b"0000644\0");
        b[124..136].copy_from_slice(b"00000000005\0");
        b[257..257 + magic.len()].copy_from_slice(magic);
        b[148..156].fill(b' ');
        let sum: u32 = b.iter().map(|&c| u32::from(c)).sum();
        let field = format!("{sum:06o}\0 ");
        b[148..156].copy_from_slice(checksum.unwrap_or(field.as_bytes()));
        b
    }

    #[test]
    fn layers_by_their_magic() {
        let cases: &[(&[u8], Layer)] = &[
            (b"age-encryption.org/v1\n-> X25519", Layer::Age),
            (&[0x28, 0xB5, 0x2F, 0xFD, 0x04], Layer::Zstd),
            (&[0x50, 0x2A, 0x4D, 0x18, 0, 0, 0, 0], Layer::Zstd),
            (&[0x5F, 0x2A, 0x4D, 0x18, 0, 0, 0, 0], Layer::Zstd),
            (&[0x04, 0x22, 0x4D, 0x18, 0x64], Layer::Lz4),
            (&[0x02, 0x21, 0x4C, 0x18, 0x10], Layer::Lz4),
            (b"\xFD7zXZ\0\0\x04", Layer::Xz),
            (b"LZIP\x01\x14", Layer::Lzip),
            (&[0x1F, 0x8B, 0x08], Layer::Gzip),
            (b"BZh91AY&SY", Layer::Bzip2),
        ];
        for &(head, want) in cases {
            assert_eq!(layer(head), Detected::Layer(want), "{head:?}");
        }
        // Near misses are data.
        for head in [
            &b"BZh0"[..],
            b"BZh",
            b"\xFD7zXZ",
            b"LZI",
            b"\x1F",
            b"\x60\x2A\x4D\x18",
        ] {
            assert_eq!(
                layer(head),
                Detected::Container(Container::Data),
                "{head:?}"
            );
        }
    }

    #[test]
    fn skippable_frames_are_zstd_s_or_lz4_s() {
        let skip = |size: u32| {
            let mut frame = vec![0x53, 0x2A, 0x4D, 0x18];
            frame.extend(size.to_le_bytes());
            frame.extend(vec![9; size as usize]);
            frame
        };
        let mut head = [skip(3), skip(0), LZ4_MAGIC.to_vec()].concat();
        assert_eq!(layer(&head), Detected::Layer(Layer::Lz4));
        head = [skip(10), LZ4_LEGACY_MAGIC.to_vec()].concat();
        assert_eq!(layer(&head), Detected::Layer(Layer::Lz4));
        head = [skip(10), ZSTD_MAGIC.to_vec()].concat();
        assert_eq!(layer(&head), Detected::Layer(Layer::Zstd));
        // What comes after is past the head, or nothing: zstd.
        head = [skip(HEAD_LEN as u32), LZ4_MAGIC.to_vec()].concat();
        assert_eq!(layer(&head[..HEAD_LEN]), Detected::Layer(Layer::Zstd));
        for head in [&skip(4)[..], &skip(4)[..6], &[0x50, 0x2A, 0x4D, 0x18]] {
            assert_eq!(layer(head), Detected::Layer(Layer::Zstd));
        }
    }

    #[test]
    fn armored_age_after_white_space() {
        let mut head = b" \r\n\t".repeat(256);
        head.extend(AGE_ARMOR);
        head.extend(b"\nYWdl");
        assert_eq!(layer(&head), Detected::Layer(Layer::Age));
        // Past 1 KiB of it, age does not look further.
        head.insert(0, b' ');
        assert_eq!(layer(&head), Detected::Container(Container::Data));
        assert_eq!(
            layer(&AGE_ARMOR[..20]),
            Detected::Container(Container::Data)
        );
    }

    #[test]
    fn containers() {
        for head in [
            &b"PK\x03\x04\x14\0"[..],
            b"PK\x05\x06\0\0",
            b"PK\x07\x08PK\x03\x04",
        ] {
            assert_eq!(layer(head), Detected::Container(Container::Zip));
        }
        // USTAR and GNU tar by their magic, V7 by its checksum, signed or
        // not.
        let ustar = tar_block(b"a.txt", b"ustar\x0000", None);
        assert_eq!(layer(&ustar), Detected::Container(Container::Tar));
        let gnu = tar_block(b"a.txt", b"ustar  \0", None);
        assert_eq!(layer(&gnu), Detected::Container(Container::Tar));
        let v7 = tar_block(b"a.txt", b"", None);
        assert_eq!(layer(&v7), Detected::Container(Container::Tar));
        let mut high = tar_block("é.txt".as_bytes(), b"", None);
        let signed: i64 = high
            .iter()
            .enumerate()
            .map(|(i, &c)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    i64::from(c as i8)
                }
            })
            .sum();
        high[148..156].copy_from_slice(format!("{signed:06o}\0 ").as_bytes());
        assert_eq!(layer(&high), Detected::Container(Container::Tar));
        // A wrong checksum, no name, zeros, or less than a block: data.
        let wrong = tar_block(b"a.txt", b"", Some(b"0000001\0"));
        let unnamed = tar_block(b"", b"", None);
        for head in [&wrong[..], &unnamed, &[0; 512], &v7[..511], b""] {
            assert_eq!(layer(head), Detected::Container(Container::Data));
        }
    }

    #[test]
    fn iso_by_its_first_volume_descriptor() {
        let mut image = vec![0u8; ISO_HEAD_LEN];
        image[ISO_DESCRIPTORS..ISO_DESCRIPTORS + 7].copy_from_slice(b"\x01CD001\x01");
        assert_eq!(layer(&image), Detected::Container(Container::Iso));
        // A boot record first, or the set's end; a boot sector or a
        // partition table in the system area.
        for kind in [0, 2, 3, 255] {
            image[ISO_DESCRIPTORS] = kind;
            assert_eq!(layer(&image), Detected::Container(Container::Iso));
        }
        image[..2].copy_from_slice(&[0x33, 0xed]);
        image[510..512].copy_from_slice(&[0x55, 0xaa]);
        assert_eq!(layer(&image), Detected::Container(Container::Iso));
        // What starts the stream comes first.
        image[..3].copy_from_slice(&[0x1F, 0x8B, 0x08]);
        assert_eq!(layer(&image), Detected::Layer(Layer::Gzip));
        image[..3].fill(0);
        // Another type, version or identifier (UDF alone has BEA01), or too
        // short (the first HEAD_LEN bytes alone): data.
        for (at, byte) in [(0, 4), (0, 254), (6, 2), (1, b'B')] {
            let mut other = image.clone();
            other[ISO_DESCRIPTORS + at] = byte;
            assert_eq!(layer(&other), Detected::Container(Container::Data));
        }
        for len in [ISO_DESCRIPTORS + 6, HEAD_LEN] {
            assert_eq!(layer(&image[..len]), Detected::Container(Container::Data));
        }
    }

    #[test]
    fn lzma_by_its_name_only() {
        let head = [0x5D, 0, 0, 0x10, 0, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(layer(&head), Detected::Container(Container::Data));
        for name in ["notes.lzma", "BACKUP.TAR.LZMA"] {
            assert_eq!(detect(&head, Some(name)), Detected::Layer(Layer::Lzma));
        }
        // Magic bytes come first.
        assert_eq!(
            detect(b"\x1F\x8B\x08", Some("x.lzma")),
            Detected::Layer(Layer::Gzip)
        );
    }
}
