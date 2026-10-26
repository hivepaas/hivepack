//! Comparison with libzstd's internal functions.
//!
//! `tools/zstd-oracle` is a small C program, built with libzstd 1.5.7's
//! sources by `scripts/testdata.py`. It answers requests such as
//! `ncount 255 <hex>` by calling the C function, one line per request.
//! [`answer`] answers the same requests with the port, in the same format,
//! so the two can be compared as text.
//!
//! Two kinds of test use it:
//! - With the oracle built, thousands of generated requests are compared
//!   with libzstd directly. Valid inputs come from libzstd's own encoder
//!   (`mkncount`, `mkhuf`), then are mutated; random bytes cover the rest.
//! - Everywhere, including where the oracle cannot be built (Windows, and
//!   the emulated i686 and s390x jobs), `testdata/oracle/common.txt` replays
//!   answers libzstd gave earlier. `cargo test record_oracle_answers --
//!   --ignored` rewrites that file.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use crate::common::bitstream::BitDStream;
use crate::common::entropy_common::{
    HUF_READ_STATS_WORKSPACE_SIZE, fse_read_ncount, huf_read_stats_wksp,
};
use crate::common::error_private::Error;
use crate::common::fse::{
    FSE_MAX_SYMBOL_VALUE, FSE_MAX_TABLELOG, FseDTable, fse_build_dtable_wksp_size_u32,
    fse_decompress_wksp_size_u32,
};
use crate::common::fse_decompress::{
    FseBuildDTableWksp, FseDecompressWksp, fse_build_dtable_internal, fse_decompress_wksp,
};
use crate::common::huf::HUF_TABLELOG_MAX;
use crate::common::xxhash::xxh64;
use crate::decompress::huf_decompress::{
    HufDTable, HufReadDTableX1Workspace, HufReadDTableX2Workspace, huf_read_dtable_x1_wksp,
    huf_read_dtable_x2_wksp,
};

/// The largest workspace the oracle gives `FSE_decompress_wksp_bmi2`.
const FSE_DECOMPRESS_MAX_WKSP: usize =
    fse_decompress_wksp_size_u32(FSE_MAX_TABLELOG, FSE_MAX_SYMBOL_VALUE) * 4;

fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/common.txt")
}

/// The oracle program, running.
pub(crate) struct Oracle {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Oracle {
    /// The oracle built by `scripts/testdata.py`, or `None` with a note when
    /// it has not been built. CI lists the `generated` group in
    /// `HIVEPACK_TESTDATA_REQUIRED` where it builds the oracle, and then a
    /// missing oracle fails the test.
    pub(crate) fn spawn() -> Option<Oracle> {
        let cache = std::env::var_os("HIVEPACK_TESTDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| repository().join("target/testdata"));
        let folder = cache.join("zstd-oracle");
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

    pub(crate) fn ask(&mut self, request: &str) -> String {
        writeln!(self.input, "{request}").expect("request sent");
        self.input.flush().expect("request sent");
        let mut line = String::new();
        self.output.read_line(&mut line).expect("answer read");
        let line = line.trim_end().to_string();
        assert!(
            line != "bad" && !line.is_empty(),
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

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".into();
    }
    let mut text = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn unhex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

fn list<T: std::fmt::Display>(values: impl IntoIterator<Item = T>) -> String {
    let text: Vec<String> = values.into_iter().map(|v| v.to_string()).collect();
    if text.is_empty() {
        "-".into()
    } else {
        text.join(",")
    }
}

fn unlist(text: &str) -> Vec<i64> {
    if text == "-" {
        return Vec::new();
    }
    text.split(',')
        .map(|v| v.parse().expect("number"))
        .collect()
}

fn failed(error: Error) -> String {
    format!("err {}", error.code().number())
}

/// The port's answer to an oracle request, in the oracle's format.
pub(crate) fn answer(request: &str) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    match words[..] {
        ["ncount", max_sv, src] => {
            let mut counts = [0i16; FSE_MAX_SYMBOL_VALUE as usize + 1];
            let mut max_sv: u32 = max_sv.parse().expect("maxSV");
            let mut table_log = 0;
            match fse_read_ncount(&mut counts, &mut max_sv, &mut table_log, &unhex(src)) {
                Ok(size) => format!(
                    "ok {size} {max_sv} {table_log} {}",
                    list(&counts[..=max_sv as usize])
                ),
                Err(error) => failed(error),
            }
        }
        ["fsedtable", max_sv, table_log, counts] => {
            let counts: Vec<i16> = unlist(counts).into_iter().map(|c| c as i16).collect();
            let table_log: u32 = table_log.parse().expect("tableLog");
            let mut dt = Box::new(FseDTable::<4096>::default());
            let mut wksp = Box::new(FseBuildDTableWksp::default());
            let wksp_size =
                fse_build_dtable_wksp_size_u32(FSE_MAX_TABLELOG, FSE_MAX_SYMBOL_VALUE) * 4;
            match fse_build_dtable_internal(
                &mut dt,
                &counts,
                max_sv.parse().expect("maxSV"),
                table_log,
                &mut wksp,
                wksp_size,
            ) {
                Ok(()) => {
                    let mut text = format!("ok {} {}", dt.table_log, u8::from(dt.fast_mode));
                    for cell in &dt.table[..1 << table_log] {
                        let _ =
                            write!(text, " {}:{}:{}", cell.new_state, cell.symbol, cell.nb_bits);
                    }
                    text
                }
                Err(error) => failed(error),
            }
        }
        ["fsedecompress", max_log, wksp_size, capacity, src] => {
            let mut output = vec![0u8; capacity.parse().expect("capacity")];
            let mut wksp = Box::new(FseDecompressWksp::<4096>::default());
            match fse_decompress_wksp(
                &mut output,
                &unhex(src),
                max_log.parse().expect("maxLog"),
                &mut wksp,
                wksp_size.parse().expect("wkspSize"),
            ) {
                Ok(size) => format!("ok {size} {}", hex(&output[..size])),
                Err(error) => failed(error),
            }
        }
        ["readstats", src] => {
            let mut weights = [0u8; 256];
            let mut rank_stats = [0u32; HUF_TABLELOG_MAX as usize + 1];
            let (mut nb_symbols, mut table_log) = (0, 0);
            let mut wksp = Box::new(FseDecompressWksp::<64>::default());
            match huf_read_stats_wksp(
                &mut weights,
                &mut rank_stats,
                &mut nb_symbols,
                &mut table_log,
                &unhex(src),
                &mut wksp,
            ) {
                Ok(size) => format!(
                    "ok {size} {nb_symbols} {table_log} {} {}",
                    list(&weights[..nb_symbols as usize]),
                    list(rank_stats)
                ),
                Err(error) => failed(error),
            }
        }
        ["hufx1", src] => {
            let mut dtable = Box::new(HufDTable::new(12));
            let mut wksp = Box::new(HufReadDTableX1Workspace::default());
            match huf_read_dtable_x1_wksp(&mut dtable, &unhex(src), &mut wksp) {
                Ok(size) => {
                    let mut text = format!("ok {size} {}", dtable.desc.table_log);
                    for cell in &dtable.x1[..1 << dtable.desc.table_log] {
                        let _ = write!(text, " {}:{}", cell.nb_bits, cell.byte);
                    }
                    text
                }
                Err(error) => failed(error),
            }
        }
        ["hufx2", src] => {
            let mut dtable = Box::new(HufDTable::new(12));
            let mut wksp = Box::new(HufReadDTableX2Workspace::default());
            match huf_read_dtable_x2_wksp(&mut dtable, &unhex(src), &mut wksp) {
                Ok(size) => {
                    let mut text = format!("ok {size} {}", dtable.desc.table_log);
                    for cell in &dtable.x2[..1 << dtable.desc.table_log] {
                        let _ = write!(text, " {}:{}:{}", cell.sequence, cell.nb_bits, cell.length);
                    }
                    text
                }
                Err(error) => failed(error),
            }
        }
        ["bits", fast, src, reads] => {
            let src = unhex(src);
            match BitDStream::new(&src) {
                Ok(mut bit_d) => {
                    let mut text = String::from("ok");
                    for nb_bits in unlist(reads) {
                        let nb_bits = nb_bits as u32;
                        let value = if fast == "1" {
                            bit_d.read_bits_fast(nb_bits)
                        } else {
                            bit_d.read_bits(nb_bits)
                        };
                        let status = bit_d.reload();
                        let _ = write!(text, " {value}/{}", status as u8);
                    }
                    let _ = write!(text, " end:{}", u8::from(bit_d.end_of_dstream()));
                    text
                }
                Err(error) => failed(error),
            }
        }
        ["xxh64", seed, src] => format!(
            "ok {:016x}",
            xxh64(&unhex(src), seed.parse().expect("seed"))
        ),
        _ => panic!("unknown request {request:.200}"),
    }
}

/// Small, fast and reproducible: SplitMix64.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Rng(seed)
    }

    pub(crate) fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number in `low..=high`.
    pub(crate) fn range(&mut self, low: u64, high: u64) -> u64 {
        low + self.next() % (high - low + 1)
    }

    pub(crate) fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }

    /// Symbol counts as real data tends to have them: a few frequent
    /// symbols, many rare ones, some absent.
    pub(crate) fn histogram(&mut self, symbols: usize) -> Vec<u64> {
        let mut counts: Vec<u64> = (0..symbols)
            .map(|_| match self.range(0, 9) {
                0 | 1 => 0,
                2..=5 => self.range(1, 8),
                6..=8 => self.range(1, 300),
                _ => self.range(1, 20_000),
            })
            .collect();
        // At least two symbols present, and the last one too, so that the
        // largest symbol is the one named.
        counts[0] = counts[0].max(1);
        let last = symbols - 1;
        counts[last] = counts[last].max(1);
        counts
    }
}

/// A copy of `bytes` with one bit flipped, a byte changed, or cut short.
fn mutate(rng: &mut Rng, bytes: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    if bytes.is_empty() {
        return bytes;
    }
    match rng.range(0, 2) {
        0 => {
            let at = rng.range(0, bytes.len() as u64 - 1) as usize;
            bytes[at] ^= 1 << rng.range(0, 7);
        }
        1 => {
            let at = rng.range(0, bytes.len() as u64 - 1) as usize;
            bytes[at] = rng.next() as u8;
        }
        _ => {
            bytes.truncate(rng.range(0, bytes.len() as u64 - 1) as usize);
        }
    }
    bytes
}

/// Valid table descriptions from libzstd's own encoder.
fn made(oracle: &mut Oracle, request: &str) -> Option<Vec<u8>> {
    let reply = oracle.ask(request);
    reply.strip_prefix("ok ").map(unhex)
}

/// Requests for every command, `per_command` of each kind.
pub(crate) fn requests(oracle: &mut Oracle, rng: &mut Rng, per_command: usize) -> Vec<String> {
    let mut requests = Vec::new();

    // FSE table descriptions: valid, mutated and random.
    let mut valid_counts = Vec::new();
    for i in 0..per_command {
        let max_sv_choices = [255u64, 52, 35, 31, 28, 12];
        match i % 4 {
            0 => {
                let len = rng.range(0, 24) as usize;
                let src = rng.bytes(len);
                let max_sv = max_sv_choices[rng.range(0, 5) as usize];
                requests.push(format!("ncount {max_sv} {}", hex(&src)));
            }
            _ => {
                let symbols = if rng.range(0, 3) == 0 {
                    rng.range(2, 256)
                } else {
                    rng.range(2, 53)
                } as usize;
                let table_log = rng.range(5, 12);
                let request = format!("mkncount {table_log} {}", list(rng.histogram(symbols)));
                let Some(header) = made(oracle, &request) else {
                    continue;
                };
                let max_sv = if rng.range(0, 4) == 0 {
                    symbols as u64 - 2
                } else {
                    255
                };
                let src = if i % 4 == 3 {
                    mutate(rng, &header)
                } else {
                    header
                };
                let request = format!("ncount {max_sv} {}", hex(&src));
                let reply = oracle.ask(&request);
                if let Some(ok) = reply.strip_prefix("ok ") {
                    valid_counts.push(ok.to_string());
                }
                requests.push(request);
            }
        }
    }

    // FSE decoding tables, for the counts that were read.
    for ok in valid_counts.iter().take(per_command) {
        let [_, max_sv, table_log, counts] = ok.split(' ').collect::<Vec<_>>()[..] else {
            continue;
        };
        requests.push(format!("fsedtable {max_sv} {table_log} {counts}"));
    }

    // Huffman tree descriptions: valid, mutated and random; and the
    // FSE-compressed weights inside them.
    for i in 0..per_command {
        let tree = if i % 5 == 0 {
            let len = rng.range(0, 40) as usize;
            rng.bytes(len)
        } else {
            let symbols = if rng.range(0, 2) == 0 {
                rng.range(2, 256)
            } else {
                rng.range(2, 40)
            } as usize;
            let counts = rng.histogram(symbols);
            // HUF_minTableLog: libzstd never asks for shorter codes.
            let cardinality = counts.iter().filter(|&&c| c > 0).count() as u32;
            let min_table_log = u64::from(31 - cardinality.leading_zeros() + 1);
            let max_nb_bits = rng.range(min_table_log.max(6), 12);
            let request = format!("mkhuf {max_nb_bits} {}", list(counts));
            let Some(tree) = made(oracle, &request) else {
                continue;
            };
            if i % 5 == 4 { mutate(rng, &tree) } else { tree }
        };
        let tree_hex = hex(&tree);
        requests.push(format!("readstats {tree_hex}"));
        requests.push(format!("hufx1 {tree_hex}"));
        requests.push(format!("hufx2 {tree_hex}"));
        if let Some(&size) = tree.first()
            && size < 128
            && tree.len() > 1
        {
            let payload = &tree[1..tree.len().min(1 + usize::from(size))];
            let (max_log, wksp, capacity) = match rng.range(0, 3) {
                0 => (6, HUF_READ_STATS_WORKSPACE_SIZE, 255),
                1 => (rng.range(5, 12), FSE_DECOMPRESS_MAX_WKSP, 255),
                2 => (6, HUF_READ_STATS_WORKSPACE_SIZE, rng.range(0, 40) as usize),
                _ => (
                    rng.range(0, 12),
                    rng.range(0, FSE_DECOMPRESS_MAX_WKSP as u64) as usize,
                    255,
                ),
            };
            requests.push(format!(
                "fsedecompress {max_log} {wksp} {capacity} {}",
                hex(payload)
            ));
        }
    }

    // Bitstreams, read in random steps.
    for i in 0..per_command {
        let len = rng.range(if i % 10 == 0 { 0 } else { 1 }, 24) as usize;
        let mut src = rng.bytes(len);
        if let Some(last) = src.last_mut() {
            // The last byte holds the end mark; without one the stream is
            // refused, differently below and above 8 bytes.
            if i % 8 == 1 {
                *last = 0
            } else {
                *last |= 1 << rng.range(0, 7)
            }
        }
        let fast = rng.range(0, 1);
        let reads: Vec<u64> = (0..rng.range(1, 24)).map(|_| rng.range(fast, 31)).collect();
        requests.push(format!("bits {fast} {} {}", hex(&src), list(reads)));
    }

    // XXH64.
    for i in 0..per_command {
        let len = if i % 20 == 0 {
            rng.range(0, 3000)
        } else {
            rng.range(0, 100)
        } as usize;
        let seed = match rng.range(0, 2) {
            0 => 0,
            1 => rng.range(0, 1000),
            _ => rng.next(),
        };
        let src = rng.bytes(len);
        requests.push(format!("xxh64 {seed} {}", hex(&src)));
    }

    requests
}

/// Requests made from zstd's fuzzing corpora for the same functions, when
/// they have been fetched (`scripts/testdata.py fetch --group fuzz`). The
/// corpora's inputs are made for libzstd's own fuzzers; here they are just
/// bytes to read, which is all the comparison needs.
fn corpus_requests() -> Vec<String> {
    let cache = std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository().join("target/testdata"));
    let mut requests = Vec::new();
    let mut read = |set: &str, make: &dyn Fn(&str) -> Vec<String>| {
        let Ok(entries) = std::fs::read_dir(cache.join(set)) else {
            eprintln!("not using {set}: not fetched (scripts/testdata.py fetch --group fuzz)");
            return;
        };
        let mut files: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
        files.sort();
        for file in files {
            if file.file_name() == Some(".complete".as_ref()) {
                continue;
            }
            let mut bytes = std::fs::read(&file).expect("corpus file");
            bytes.truncate(4096);
            requests.extend(make(&hex(&bytes)));
        }
    };
    read("zstd-fuzz-fse-read-ncount", &|src| {
        vec![format!("ncount 255 {src}"), format!("ncount 35 {src}")]
    });
    read("zstd-fuzz-huf-decompress", &|src| {
        vec![
            format!("readstats {src}"),
            format!("hufx1 {src}"),
            format!("hufx2 {src}"),
        ]
    });
    requests
}

/// FNV-1a, to record long answers by their hash.
fn fnv64(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// What the replay file keeps of an answer: all of it, or the hash of a long one.
fn recorded_form(answer: &str) -> String {
    if answer.len() <= 160 {
        answer.to_string()
    } else {
        format!("fnv64:{:016x}", fnv64(answer))
    }
}

#[test]
fn port_matches_libzstd() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng::new(0x5EED_0001);
    let mut requests = requests(&mut oracle, &mut rng, 2000);
    requests.extend(corpus_requests());
    let mut problems = Vec::new();
    for request in &requests {
        let want = oracle.ask(request);
        let got = answer(request);
        if got != want && problems.len() < 20 {
            problems.push(format!(
                "{request:.300}\n  libzstd: {want:.300}\n  port:    {got:.300}"
            ));
        }
    }
    eprintln!("compared {} requests with libzstd", requests.len());
    assert!(
        problems.is_empty(),
        "{} requests checked, differences:\n{}",
        requests.len(),
        problems.join("\n")
    );
}

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/common.txt");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(recorded_form(&answer(request)), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked > 1000, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/common.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng::new(0x5EED_0002);
    let mut text = String::from(
        "# Answers from libzstd 1.5.7 (tools/zstd-oracle), replayed by crates/zstd/src/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack-zstd record_oracle_answers -- --ignored\n",
    );
    for request in requests(&mut oracle, &mut rng, 300) {
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{}", recorded_form(&reply));
    }
    std::fs::create_dir_all(recorded_path().parent().expect("folder")).expect("folder");
    std::fs::write(recorded_path(), text).expect("written");
}

#[test]
fn xxh64_streaming_matches_one_call() {
    use crate::common::xxhash::Xxh64State;
    let mut rng = Rng::new(0x5EED_0003);
    for _ in 0..500 {
        let len = rng.range(0, 700) as usize;
        let data = rng.bytes(len);
        let seed = rng.next();
        let mut state = Xxh64State::new(seed);
        let mut at = 0;
        while at < len {
            let step = (rng.range(0, 70) as usize).min(len - at);
            state.update(&data[at..at + step]);
            at += step;
        }
        assert_eq!(state.digest(), xxh64(&data, seed), "{len} bytes");
    }
}

#[test]
fn xxh64_matches_published_values() {
    assert_eq!(xxh64(b"", 0), 0xef46_db37_51d8_e999);
    assert_eq!(xxh64(b"abc", 0), 0x44bc_2cf5_ad77_0999);
}
