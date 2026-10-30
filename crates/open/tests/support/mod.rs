//! What the tests share: age's oracle program, built with Go by
//! `scripts/testdata.py`, a seeded generator, the text forms of the
//! requests and answers, and tar archives in the reference compressors.

// Test helpers: a broken oracle should stop the test.
#![allow(dead_code, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

pub fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The oracle program, running.
pub struct Oracle {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Oracle {
    /// The oracle `name` (`age-oracle`) built by `scripts/testdata.py`,
    /// or `None` with a note when it has not been built. CI lists the
    /// `generated` group in `HIVEPACK_TESTDATA_REQUIRED` where it builds the
    /// oracles, and then a missing oracle fails the test.
    pub fn spawn(name: &str) -> Option<Oracle> {
        let cache = std::env::var_os("HIVEPACK_TESTDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| repository().join("target/testdata"));
        let folder = cache.join(name);
        if !folder.join(".complete").exists() {
            let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
            assert!(
                !required.split(',').any(|g| g == "all" || g == "generated"),
                "the oracle is missing: run `python3 scripts/testdata.py fetch --group generated`"
            );
            eprintln!(
                "skipping: the oracle is not built (scripts/testdata.py fetch --group generated)"
            );
            return None;
        }
        let mut child = Command::new(folder.join("oracle"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the oracle starts");
        let input = child.stdin.take().expect("stdin");
        let output = BufReader::new(child.stdout.take().expect("stdout"));
        Some(Oracle {
            child,
            input,
            output,
        })
    }

    pub fn ask(&mut self, request: &str) -> String {
        writeln!(self.input, "{request}").expect("request sent");
        self.input.flush().expect("request sent");
        let mut line = String::new();
        self.output.read_line(&mut line).expect("answer read");
        let line = line.trim_end().to_string();
        assert!(
            line != "bad" && !line.is_empty() && !line.ends_with(" bad"),
            "the oracle answered {line:?} to {request:.200}"
        );
        line
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".into();
    }
    let mut text = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

pub fn unhex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// xorshift64*, so that failures can be replayed.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    pub fn pick<T: Copy>(&mut self, values: &[T]) -> T {
        values[self.below(values.len() as u64) as usize]
    }
}

/// A tar header block for a file or directory, with its checksum.
fn tar_header(name: &str, typeflag: u8, size: usize) -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[..name.len()].copy_from_slice(name.as_bytes());
    let mode = if typeflag == b'5' { 0o755 } else { 0o644 };
    b[100..108].copy_from_slice(format!("{mode:07o}\0").as_bytes());
    b[108..116].copy_from_slice(b"0001750\0");
    b[116..124].copy_from_slice(b"0001750\0");
    b[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    b[136..148].copy_from_slice(b"13761326400\0");
    b[156] = typeflag;
    b[257..265].copy_from_slice(b"ustar\x0000");
    b[148..156].fill(b' ');
    let sum: u32 = b.iter().map(|&c| u32::from(c)).sum();
    b[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    b
}

/// A tar archive of files (and, for names ending with `/`, directories).
pub fn tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in entries {
        let typeflag = if name.ends_with('/') { b'5' } else { b'0' };
        out.extend(tar_header(name, typeflag, data.len()));
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.extend([0u8; 1024]);
    out
}

/// The archive most tests open: a directory, a small file and one of
/// 100 KB, more than a read takes.
pub fn sample_tar() -> Vec<u8> {
    let mut rng = Rng(0x7a2_0001);
    let big: Vec<u8> = (0..100_000)
        .map(|i| {
            if rng.below(4) == 0 {
                rng.next() as u8
            } else {
                (i % 251) as u8
            }
        })
        .collect();
    tar(&[
        ("docs/", b""),
        ("docs/notes.txt", b"Hello from inside the layers.\n"),
        ("docs/data.bin", &big),
    ])
}

/// The same, with a file of 3 KB: small enough to keep as text.
pub fn small_tar() -> Vec<u8> {
    let data: Vec<u8> = (0..3000u32).map(|i| (i * i % 251) as u8).collect();
    tar(&[
        ("docs/", b""),
        ("docs/notes.txt", b"Hello from inside the layers.\n"),
        ("docs/data.bin", &data),
    ])
}

pub fn zstd(data: &[u8]) -> Vec<u8> {
    zstd::encode_all(data, 3).expect("zstd")
}

pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).expect("gzip");
    e.finish().expect("gzip")
}

pub fn bzip2(data: &[u8]) -> Vec<u8> {
    let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    e.write_all(data).expect("bzip2");
    e.finish().expect("bzip2")
}

fn lzma_stream(stream: liblzma::stream::Stream, data: &[u8]) -> Vec<u8> {
    let mut e = liblzma::write::XzEncoder::new_stream(Vec::new(), stream);
    e.write_all(data).expect("liblzma");
    e.finish().expect("liblzma")
}

pub fn xz(data: &[u8]) -> Vec<u8> {
    xz_preset(data, 6)
}

pub fn xz_preset(data: &[u8], preset: u32) -> Vec<u8> {
    let stream = liblzma::stream::Stream::new_easy_encoder(preset, liblzma::stream::Check::Crc64)
        .expect("xz");
    lzma_stream(stream, data)
}

/// .lzma, LZMA_Alone.
pub fn lzma(data: &[u8]) -> Vec<u8> {
    let options = liblzma::stream::LzmaOptions::new_preset(6).expect("preset");
    let stream = liblzma::stream::Stream::new_lzma_encoder(&options).expect("lzma");
    lzma_stream(stream, data)
}

/// A .lz member, as lzip writes one: liblzma has no lzip encoder, but its
/// raw LZMA1 encoder writes the stream lzip's header and trailer go around,
/// with lzip's properties (lc 3, lp 0, pb 2) and its end marker.
pub fn lzip(data: &[u8]) -> Vec<u8> {
    let mut options = liblzma::stream::LzmaOptions::new_preset(6).expect("preset");
    options
        .dict_size(1 << 20)
        .literal_context_bits(3)
        .literal_position_bits(0)
        .position_bits(2);
    let mut filters = liblzma::stream::Filters::new();
    filters.lzma1(&options);
    let stream = liblzma::stream::Stream::new_raw_encoder(&filters).expect("lzma1");
    // Version 1, a dictionary of 2^20 bytes.
    let mut member = b"LZIP\x01\x14".to_vec();
    member.extend(lzma_stream(stream, data));
    let mut crc = flate2::Crc::new();
    crc.update(data);
    member.extend(crc.sum().to_le_bytes());
    member.extend((data.len() as u64).to_le_bytes());
    let size = member.len() as u64 + 8;
    member.extend(size.to_le_bytes());
    member
}

/// A folder in the system's temporary one, removed when dropped.
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new() -> Scratch {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "hivepack-open-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("scratch folder");
        Scratch(path)
    }

    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
