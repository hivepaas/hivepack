//! The image the `udf` and `extract_udf` targets read, which the input
//! describes sparsely, so that a few kilobytes reach the anchors at sector
//! 256 and past: its first byte picks the sector size (512 to 4096) and
//! more, its next three the number of sectors (up to 2^16), then come
//! sectors, each its number (32 bits), how many bytes it has (16 bits) and
//! those, the rest zeros. Absent sectors are zeros, and later ones replace
//! earlier ones. `tools/udf-images/seed.py` writes images so.

use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom};

/// The image the input describes.
pub struct Sparse<'a> {
    /// Its sector size.
    pub sector_size: u64,
    len: u64,
    sectors: BTreeMap<u64, &'a [u8]>,
    pos: u64,
}

impl<'a> Sparse<'a> {
    pub fn new(data: &'a [u8]) -> Option<Sparse<'a>> {
        let (&head, rest) = data.split_first()?;
        let sector_size = 512u64 << (head & 3);
        let count = u64::from(*rest.first()?) | u64::from(*rest.get(1)?) << 8 | u64::from(*rest.get(2)?) << 16;
        let count = count.min(1 << 16);
        let mut sectors = BTreeMap::new();
        let mut rest = &rest[3..];
        while rest.len() >= 6 {
            let n = u64::from(u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]));
            let len = usize::from(u16::from_le_bytes([rest[4], rest[5]])).min(sector_size as usize);
            let take = rest.len().min(6 + len);
            sectors.insert(n, &rest[6..take]);
            rest = &rest[take..];
        }
        Some(Sparse { sector_size, len: count * sector_size, sectors, pos: 0 })
    }
}

impl Read for Sparse<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }
        let sector = self.pos / self.sector_size;
        let at = (self.pos % self.sector_size) as usize;
        let n = buf.len().min((self.sector_size as usize) - at).min((self.len - self.pos) as usize);
        let data = self.sectors.get(&sector).copied().unwrap_or(&[]);
        let have = data.len().saturating_sub(at).min(n);
        buf[..have].copy_from_slice(&data[at..at + have]);
        buf[have..n].fill(0);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Sparse<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::End(d) => self.len.saturating_add_signed(d),
            SeekFrom::Current(d) => self.pos.saturating_add_signed(d),
        };
        Ok(self.pos)
    }
}

