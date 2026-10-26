//! Times zstd implementations on the same inputs: compression at each level,
//! and decompression of what libzstd wrote.
//!
//! ```text
//! cargo run --release -p zstd-bench -- [--levels 1,3,19] [--rounds 3] [--seconds 0.5] PATH...
//! ```
//!
//! Each PATH is a file, or a folder whose files are each an input. Rounds take
//! turns between implementations, so a noisy machine slows them all alike.
//! Speeds are the range over rounds in MB/s of uncompressed data (10^6 bytes
//! per second), and the output is a Markdown table.
//!
//! hivepack-zstd only decompresses so far; its compression column is empty.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use zstd::zstd_safe::{self, CCtx, DCtx};

type Result<T> = std::result::Result<T, String>;

trait Codec {
    fn name(&self) -> String;
    /// Whether [`Codec::compress`] works yet.
    fn compresses(&self) -> bool {
        true
    }
    fn compress(&mut self, level: i32, input: &[u8], output: &mut Vec<u8>) -> Result<()>;
    /// Decompresses `input`, whose content is `size` bytes long.
    fn decompress(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()>;
}

/// libzstd through the `zstd` crate, reusing one context of each kind as
/// `zstd -b` does.
struct Libzstd {
    compressor: CCtx<'static>,
    decompressor: DCtx<'static>,
}

fn error_name(code: usize) -> String {
    zstd_safe::get_error_name(code).to_string()
}

impl Codec for Libzstd {
    fn name(&self) -> String {
        // zstd-sys assembles libzstd's Huffman decoding loop only for x86-64
        // outside Windows; everywhere else libzstd runs its C loop.
        let asm = cfg!(all(target_arch = "x86_64", not(windows)));
        format!(
            "libzstd {}{}",
            zstd_safe::version_string(),
            if asm { "" } else { " (no asm)" }
        )
    }

    fn compress(&mut self, level: i32, input: &[u8], output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        output.reserve(zstd_safe::compress_bound(input.len()));
        self.compressor
            .compress(output, input, level)
            .map(drop)
            .map_err(error_name)
    }

    fn decompress(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()> {
        output.clear();
        output.reserve(size);
        self.decompressor
            .decompress(output, input)
            .map(drop)
            .map_err(error_name)
    }
}

/// The port: decompression only, for now.
struct Hivepack {
    dctx: hivepack_zstd::DCtx,
}

impl Codec for Hivepack {
    fn name(&self) -> String {
        "hivepack-zstd".into()
    }

    fn compresses(&self) -> bool {
        false
    }

    fn compress(&mut self, _level: i32, _input: &[u8], _output: &mut Vec<u8>) -> Result<()> {
        Err("hivepack-zstd does not compress yet".into())
    }

    fn decompress(&mut self, input: &[u8], size: usize, output: &mut Vec<u8>) -> Result<()> {
        output.resize(size, 0);
        let decoded = self
            .dctx
            .decompress(output, input)
            .map_err(|e| e.to_string())?;
        output.truncate(decoded);
        Ok(())
    }
}

struct Options {
    levels: Vec<i32>,
    rounds: usize,
    budget: Duration,
    paths: Vec<PathBuf>,
}

fn parse(args: impl Iterator<Item = String>) -> Result<Options> {
    let mut options = Options {
        levels: vec![1, 3, 9, 19],
        rounds: 3,
        budget: Duration::from_millis(500),
        paths: Vec::new(),
    };
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--levels" => {
                options.levels = value()?
                    .split(',')
                    .map(|l| l.parse().map_err(|_| format!("bad level {l:?}")))
                    .collect::<Result<_>>()?;
            }
            "--rounds" => options.rounds = value()?.parse().map_err(|_| "bad --rounds")?,
            "--seconds" => {
                let seconds: f64 = value()?.parse().map_err(|_| "bad --seconds")?;
                options.budget =
                    Duration::try_from_secs_f64(seconds).map_err(|_| "bad --seconds")?;
            }
            "-h" | "--help" => {
                return Err(
                    "usage: zstd-bench [--levels 1,3,19] [--rounds N] [--seconds S] PATH...".into(),
                );
            }
            _ if arg.starts_with("--") => return Err(format!("unknown option {arg}")),
            _ => options.paths.push(PathBuf::from(arg)),
        }
    }
    if options.paths.is_empty() || options.rounds == 0 {
        return Err("give at least one input file or folder, and at least one round".into());
    }
    Ok(options)
}

/// Every input file under `paths`, sorted within each folder.
fn inputs(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    for path in paths {
        if path.is_dir() {
            let mut files: Vec<PathBuf> = std::fs::read_dir(path)
                .map_err(|e| format!("{}: {e}", path.display()))?
                .filter_map(|entry| entry.ok().map(|e| e.path()))
                .filter(|p| p.is_file())
                // Hidden files, such as the `.complete` mark of a fetched set.
                .filter(|p| {
                    !p.file_name()
                        .is_some_and(|n| n.as_encoded_bytes().starts_with(b"."))
                })
                .collect();
            files.sort();
            found.extend(files);
        } else {
            found.push(path.clone());
        }
    }
    Ok(found)
}

/// Seconds per run of `op`, repeated for at least `budget` after a warm-up.
fn time(budget: Duration, mut op: impl FnMut() -> Result<()>) -> Result<f64> {
    op()?;
    let start = Instant::now();
    let mut runs = 0u32;
    loop {
        op()?;
        runs += 1;
        if start.elapsed() >= budget {
            return Ok(start.elapsed().as_secs_f64() / f64::from(runs));
        }
    }
}

struct Range(f64, f64);

impl Range {
    fn add(range: Option<Range>, value: f64) -> Option<Range> {
        Some(match range {
            None => Range(value, value),
            Some(Range(low, high)) => Range(low.min(value), high.max(value)),
        })
    }
}

impl std::fmt::Display for Range {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.round() == self.1.round() {
            write!(f, "{:.0}", self.0)
        } else {
            write!(f, "{:.0}–{:.0}", self.0, self.1)
        }
    }
}

fn bench(options: &Options, codecs: &mut [Box<dyn Codec>], input: &Path) -> Result<()> {
    let data = std::fs::read(input).map_err(|e| format!("{}: {e}", input.display()))?;
    let name = input.file_name().map_or_else(
        || input.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let megabytes = data.len() as f64 / 1e6;
    let mut compressed = Vec::new();
    let mut scratch = Vec::new();
    for &level in &options.levels {
        // libzstd's output is what every decoder reads.
        codecs[0].compress(level, &data, &mut compressed)?;
        let ratio = data.len() as f64 / compressed.len().max(1) as f64;
        let mut compress: Vec<Option<Range>> = codecs.iter().map(|_| None).collect();
        let mut decompress: Vec<Option<Range>> = codecs.iter().map(|_| None).collect();
        for _ in 0..options.rounds {
            for (i, codec) in codecs.iter_mut().enumerate() {
                if codec.compresses() {
                    let seconds = time(options.budget, || {
                        codec.compress(level, &data, &mut scratch)
                    })?;
                    compress[i] = Range::add(compress[i].take(), megabytes / seconds);
                }
                let seconds = time(options.budget, || {
                    codec.decompress(&compressed, data.len(), &mut scratch)
                })?;
                if scratch != data {
                    return Err(format!(
                        "{}: {name} level {level} does not round trip",
                        codec.name()
                    ));
                }
                decompress[i] = Range::add(decompress[i].take(), megabytes / seconds);
            }
        }
        let cells: Vec<String> = compress
            .iter()
            .zip(&decompress)
            .map(|(c, d)| {
                let show = |r: &Option<Range>| {
                    r.as_ref()
                        .map_or_else(|| "–".to_string(), |r| r.to_string())
                };
                format!("{} | {}", show(c), show(d))
            })
            .collect();
        println!(
            "| {name} | {:.1} | {level} | {ratio:.3} | {} |",
            megabytes,
            cells.join(" | ")
        );
    }
    Ok(())
}

fn run() -> Result<()> {
    let options = parse(std::env::args().skip(1))?;
    let mut codecs: Vec<Box<dyn Codec>> = vec![
        Box::new(Libzstd {
            compressor: CCtx::create(),
            decompressor: DCtx::create(),
        }),
        Box::new(Hivepack {
            dctx: hivepack_zstd::DCtx::new(),
        }),
    ];
    let header: Vec<String> = codecs
        .iter()
        .map(|c| format!("{0} compress | {0} decompress", c.name()))
        .collect();
    println!("| input | MB | level | ratio | {} |", header.join(" | "));
    println!("|---|---|---|---|{}", "---|".repeat(2 * codecs.len()));
    for input in inputs(&options.paths)? {
        bench(&options, &mut codecs, &input)?;
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("zstd-bench: {error}");
            ExitCode::FAILURE
        }
    }
}
