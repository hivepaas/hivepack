//! Comparison with zlib 1.3.2 through `tools/zlib-oracle`, for what flate2
//! cannot reach: `Flush::Block` and `Flush::Trees`, `data_type`,
//! `inflateMark`, `inflatePrime`, `inflateSync`, `inflateValidate`, the
//! gzip header, and streams from every compression strategy and memory
//! level.
//!
//! The oracle is a small C program built with zlib's sources by
//! `scripts/testdata.py`. It answers requests such as `inflate 15 - -
//! i4/3/0,i100/100/5 789c...` by calling zlib, one line per request.
//! [`answer`] answers the same requests with the port, in the same format,
//! so the two can be compared as text.
//!
//! - With the oracle built, generated requests are compared with zlib
//!   directly. The streams come from zlib's own compressor, through the
//!   oracle's `deflate` request, then some are damaged.
//! - Everywhere, including where the oracle cannot be built (Windows, and
//!   the emulated i686 and s390x jobs), `testdata/oracle/inflate.txt`
//!   replays answers zlib gave earlier. `cargo test -p hivepack-deflate
//!   --test oracle record_oracle_answers -- --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use hivepack_deflate::{ErrorCode, Flush, GzHeader, InBuffer, Inflate, OutBuffer, Result, Status};

fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/inflate.txt")
}

/// The oracle program, running.
struct Oracle {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Oracle {
    /// The oracle built by `scripts/testdata.py`, or `None` with a note when
    /// it has not been built. CI lists the `generated` group in
    /// `HIVEPACK_TESTDATA_REQUIRED` where it builds the oracle, and then a
    /// missing oracle fails the test.
    fn spawn() -> Option<Oracle> {
        let cache = std::env::var_os("HIVEPACK_TESTDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| repository().join("target/testdata"));
        let folder = cache.join("zlib-oracle");
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

    fn ask(&mut self, request: &str) -> String {
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

fn fnv64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// An answer as the recorded file keeps it: as it is when short, else its
/// FNV-1a hash.
fn recorded_form(answer: &str) -> String {
    if answer.len() <= 160 {
        answer.to_string()
    } else {
        format!("fnv64:{:016x}", fnv64(answer.as_bytes()))
    }
}

/// zlib's return code for a result.
fn code(ret: Result<Status>) -> i32 {
    match ret {
        Ok(Status::Ok) => 0,
        Ok(Status::StreamEnd) => 1,
        Ok(Status::NeedDict) => 2,
        Err(e) => e.code().number(),
    }
}

fn unit_code(ret: Result<()>) -> i32 {
    code(ret.map(|()| Status::Ok))
}

fn flush(number: u32) -> Flush {
    match number {
        0 => Flush::NoFlush,
        1 => Flush::PartialFlush,
        2 => Flush::SyncFlush,
        3 => Flush::FullFlush,
        4 => Flush::Finish,
        5 => Flush::Block,
        _ => Flush::Trees,
    }
}

/// The port's answer to an `inflate` request, in the oracle's format.
fn answer(request: &str) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    let ["inflate", window_bits, head, dict, steps, data] = words[..] else {
        panic!("not an inflate request: {request:.100}");
    };
    let mut strm = match Inflate::new(window_bits.parse().unwrap()) {
        Ok(strm) => strm,
        Err(e) => return format!("err {}", e.code().number()),
    };
    let data = unhex(data);
    let dict = unhex(dict);
    let head_ret = (head != "-").then(|| {
        let max: Vec<usize> = head.split('/').map(|n| n.parse().unwrap()).collect();
        unit_code(strm.get_header(GzHeader::new(max[0], max[1], max[2])))
    });
    let space: usize = steps
        .split(',')
        .filter_map(|step| step.strip_prefix('i'))
        .map(|step| step.split('/').nth(1).unwrap().parse::<usize>().unwrap())
        .sum();
    let mut out = vec![0u8; space];
    let (mut consumed, mut written) = (0, 0);
    let mut text = String::from("ok");
    for step in steps.split(',') {
        let (kind, args) = step.split_at(1);
        let args: Vec<i64> = args
            .split('/')
            .filter(|a| !a.is_empty())
            .map(|a| a.parse().unwrap())
            .collect();
        match kind {
            "i" => {
                let avail = (args[0] as usize).min(data.len() - consumed);
                let room = args[1] as usize;
                let mut input = InBuffer {
                    src: &data[..consumed + avail],
                    pos: consumed,
                };
                let mut output = OutBuffer::new(&mut out[written..written + room]);
                let ret = code(strm.inflate(&mut output, &mut input, flush(args[2] as u32)));
                let read = input.pos - consumed;
                let made = output.pos;
                consumed += read;
                written += made;
                let msg = strm
                    .msg()
                    .map_or_else(|| "-".to_string(), |m| hex(m.as_bytes()));
                let _ = write!(
                    text,
                    " {ret}/{read}/{made}/{}/{}/{msg}",
                    strm.data_type(),
                    strm.mark()
                );
            }
            "s" => {
                let avail = (args[0] as usize).min(data.len() - consumed);
                let mut input = InBuffer {
                    src: &data[..consumed + avail],
                    pos: consumed,
                };
                let ret = unit_code(strm.sync(&mut input));
                let read = input.pos - consumed;
                consumed += read;
                let _ = write!(text, " {ret}/{read}");
            }
            "p" => {
                let _ = write!(
                    text,
                    " {}",
                    unit_code(strm.prime(args[0] as i32, args[1] as i32))
                );
            }
            "d" => {
                let _ = write!(text, " {}", unit_code(strm.set_dictionary(&dict)));
            }
            "v" => {
                strm.validate(args[0] != 0);
                text.push_str(" 0");
            }
            _ => panic!("unknown step {step}"),
        }
    }
    let _ = write!(
        text,
        " {}/{}/{} {:016x}",
        strm.total_in(),
        strm.total_out(),
        strm.adler(),
        fnv64(&out[..written])
    );
    if let Some(head_ret) = head_ret {
        let _ = write!(text, " h{head_ret}");
        if head_ret == 0 {
            let head = strm.header().expect("the header asked for");
            let buffer = |b: &Option<Vec<u8>>| b.as_ref().map_or_else(|| "null".into(), |b| hex(b));
            let _ = write!(
                text,
                "/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}",
                head.text,
                head.time,
                head.xflags,
                head.os,
                head.extra_len,
                head.hcrc,
                head.done,
                buffer(&head.extra),
                buffer(&head.name),
                buffer(&head.comment)
            );
        }
    }
    text
}

/// xorshift64*, so that failures can be replayed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn pick<T: Copy>(&mut self, values: &[T]) -> T {
        values[self.below(values.len() as u64) as usize]
    }
}

/// Data to compress: text, random bytes, runs, or repeats from up to
/// `len` back.
fn make_data(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(len);
    match rng.below(4) {
        0 => {
            let words = [
                "deflate", "the", " ", "window", "of", "a", "block", "\n", "zlib", ", ",
            ];
            while data.len() < len {
                data.extend_from_slice(rng.pick(&words).as_bytes());
            }
        }
        1 => data.extend((0..len).map(|_| rng.next() as u8)),
        2 => {
            while data.len() < len {
                let byte = rng.next() as u8;
                data.extend(std::iter::repeat_n(byte, 1 + rng.below(300) as usize));
            }
        }
        _ => {
            while data.len() < len {
                if data.len() > 10 && rng.below(3) != 0 {
                    let back = 1 + rng.below(data.len() as u64) as usize;
                    for _ in 0..3 + rng.below(100) {
                        data.push(data[data.len() - back]);
                    }
                } else {
                    data.extend((0..1 + rng.below(20)).map(|_| rng.next() as u8 & 0x1f));
                }
            }
        }
    }
    data.truncate(len);
    data
}

/// The wrappers, as deflateInit2 and inflateInit2 take them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wrap {
    Raw,
    Zlib,
    Gzip,
}

/// A stream from zlib's compressor, with the parameters it was made with,
/// or `None` if zlib refused them.
fn stream(
    oracle: &mut Oracle,
    rng: &mut Rng,
    wrap: Wrap,
    wbits: i32,
    dict: &[u8],
    data: &[u8],
) -> Option<Vec<u8>> {
    let level = rng.below(11) as i32 - 1;
    let window_bits = match wrap {
        Wrap::Raw => -wbits,
        Wrap::Zlib => wbits,
        Wrap::Gzip => wbits + 16,
    };
    let mem_level = 1 + rng.below(9);
    let strategy = rng.below(5);
    let mut pieces = Vec::new();
    for _ in 0..rng.below(6) {
        // No Z_FINISH before the end.
        let flush = rng.pick(&[0, 1, 2, 3, 5]);
        pieces.push(format!("{}/{flush}", rng.below(data.len() as u64 + 1)));
    }
    let pieces = if pieces.is_empty() {
        "-".to_string()
    } else {
        pieces.join(",")
    };
    let request = format!(
        "deflate {level} {window_bits} {mem_level} {strategy} {} {pieces} {}",
        hex(dict),
        hex(data)
    );
    let reply = oracle.ask(&request);
    reply.strip_prefix("ok ").map(unhex)
}

/// Bytes changed, bits flipped, cut short or lengthened.
fn damage(rng: &mut Rng, stream: &[u8]) -> Vec<u8> {
    let mut damaged = stream.to_vec();
    for _ in 0..1 + rng.below(3) {
        if damaged.is_empty() {
            break;
        }
        let at = rng.below(damaged.len() as u64) as usize;
        match rng.below(4) {
            0 => damaged[at] ^= 1 << rng.below(8),
            1 => damaged[at] = rng.next() as u8,
            2 => damaged.truncate(at),
            _ => damaged.insert(at, rng.next() as u8),
        }
    }
    damaged
}

/// The steps an inflate request takes: mostly inflate() calls of random
/// sizes and flushes, enough to read the whole stream, with a dictionary
/// set at some point when there is one, and now and then inflatePrime,
/// inflateValidate or inflateSync.
fn steps(rng: &mut Rng, len: usize, dict: bool, sync: bool) -> String {
    let mut steps = Vec::new();
    if rng.below(8) == 0 {
        steps.push(format!("v{}", rng.below(2)));
    }
    if rng.below(10) == 0 {
        let bits = rng.below(20) as i64 - 2;
        steps.push(format!("p{bits}/{}", rng.below(1 << 17)));
    }
    let mut given = 0;
    while given < len + 8 && steps.len() < 80 {
        if dict && rng.below(6) == 0 {
            steps.push("d".to_string());
        }
        if sync && rng.below(12) == 0 {
            let input = 1 + rng.below(40);
            given += input as usize;
            steps.push(format!("s{input}"));
        }
        let input = match rng.below(5) {
            0 => 1,
            1 => 1 + rng.below(16),
            2 => 1 + rng.below(400),
            3 => len as u64,
            _ => rng.below(80),
        };
        let output = match rng.below(6) {
            0 => 0,
            1 => 1,
            2 => 1 + rng.below(300),
            3 => 258 + rng.below(2000),
            _ => 1 + rng.below(20_000),
        };
        let flush = match rng.below(12) {
            0 => 4,
            1 => 5,
            2 => 6,
            3 => 2,
            _ => 0,
        };
        given += input as usize;
        steps.push(format!("i{input}/{output}/{flush}"));
    }
    if dict {
        steps.push("d".to_string());
    }
    // Room to write out the rest.
    steps.push("i0/70000/0".to_string());
    steps.push(format!("i{len}/70000/4"));
    steps.join(",")
}

/// Requests: for each of `count` inputs, a stream from zlib, decompressed
/// as it is and damaged, with window sizes that fit and some that do not.
fn requests(oracle: &mut Oracle, rng: &mut Rng, count: usize) -> Vec<String> {
    let mut requests = Vec::new();
    for _ in 0..count {
        let len = match rng.below(6) {
            0 => rng.below(16) as usize,
            1..=3 => rng.below(2000) as usize,
            4 => rng.below(8000) as usize,
            _ => rng.below(60_000) as usize,
        };
        let data = make_data(rng, len);
        let wrap = rng.pick(&[Wrap::Raw, Wrap::Zlib, Wrap::Gzip]);
        let wbits = 8 + rng.below(8) as i32;
        let dict = if wrap != Wrap::Gzip && rng.below(4) == 0 {
            let len = 1 + rng.below(3000) as usize;
            make_data(rng, len)
        } else {
            Vec::new()
        };
        let Some(stream) = stream(oracle, rng, wrap, wbits, &dict, &data) else {
            continue;
        };
        for round in 0..3 {
            let stream = if round == 2 {
                damage(rng, &stream)
            } else {
                stream.clone()
            };
            // The window: the stream's (zlib may have raised 8 to 9), any
            // for zlib (0) or both wrappers (+32), larger, smaller, or out
            // of range.
            let decode_bits = match rng.below(8) {
                0 => wbits - 1 - rng.below(3) as i32,
                1 => 15,
                2 => rng.pick(&[0, 1, 7, 16, 99]),
                _ => wbits.max(9),
            };
            let window_bits = match (wrap, rng.below(5)) {
                (Wrap::Raw, _) => -decode_bits,
                (Wrap::Zlib, 0) => 0,
                (_, 1) => decode_bits + 32,
                (Wrap::Zlib, _) => decode_bits,
                (Wrap::Gzip, _) => decode_bits + 16,
            };
            let window_bits = if decode_bits == 0 && wrap != Wrap::Zlib {
                window_bits.max(9)
            } else {
                window_bits
            };
            // The header is asked for only without inflateSync, which
            // forgets it, as zlib's inflateReset does.
            let sync = rng.below(5) == 0;
            let head = if wrap == Wrap::Gzip && !sync && rng.below(2) == 0 {
                format!("{}/{}/{}", rng.below(40), rng.below(40), rng.below(40))
            } else {
                "-".to_string()
            };
            let has_dict = !dict.is_empty();
            let steps = steps(rng, stream.len(), has_dict, sync);
            let dict = if has_dict {
                hex(&dict)
            } else {
                "-".to_string()
            };
            requests.push(format!(
                "inflate {window_bits} {head} {dict} {steps} {}",
                hex(&stream)
            ));
        }
    }
    // gzip headers with every field, from the oracle's own deflate of the
    // contents, so that the header fields are compared too.
    for _ in 0..count / 10 {
        let len = rng.below(500) as usize;
        let data = make_data(rng, len);
        let Some(raw) = stream(oracle, rng, Wrap::Raw, 15, &[], &data) else {
            continue;
        };
        let mut member = vec![
            0x1f,
            0x8b,
            8,
            rng.below(32) as u8,
            1,
            2,
            3,
            4,
            0,
            rng.below(256) as u8,
        ];
        let flags = member[3];
        if flags & 4 != 0 {
            let extra = data[..data.len().min(30)].to_vec();
            member.extend_from_slice(&(extra.len() as u16).to_le_bytes());
            member.extend_from_slice(&extra);
        }
        if flags & 8 != 0 {
            member.extend_from_slice(b"name.txt\0");
        }
        if flags & 16 != 0 {
            member.extend_from_slice(b"a comment\0");
        }
        if flags & 2 != 0 {
            let crc = hivepack_deflate::crc32(0, &member) as u16;
            member.extend_from_slice(&crc.to_le_bytes());
        }
        member.extend_from_slice(&raw);
        member.extend_from_slice(&hivepack_deflate::crc32(0, &data).to_le_bytes());
        member.extend_from_slice(&(data.len() as u32).to_le_bytes());
        let member = if rng.below(4) == 0 {
            damage(rng, &member)
        } else {
            member
        };
        let head = format!("{}/{}/{}", rng.below(40), rng.below(12), rng.below(12));
        let steps = steps(rng, member.len(), false, false);
        let window_bits = rng.pick(&[31, 47]);
        requests.push(format!(
            "inflate {window_bits} {head} - {steps} {}",
            hex(&member)
        ));
    }
    requests
}

#[test]
fn port_matches_zlib() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x5eed_0001);
    let requests = requests(&mut oracle, &mut rng, 600);
    assert!(requests.len() > 1500, "only {} requests", requests.len());
    for request in &requests {
        let want = oracle.ask(request);
        assert_eq!(answer(request), want, "{request:.300}");
    }
}

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/inflate.txt");
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
#[ignore = "rewrites testdata/oracle/inflate.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng(0x5eed_0002);
    let mut text = String::from(
        "# Answers from zlib 1.3.2 (tools/zlib-oracle), replayed by crates/deflate/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack-deflate --test oracle record_oracle_answers -- --ignored\n",
    );
    for request in requests(&mut oracle, &mut rng, 500) {
        // Keep the file small: the large inputs are for the live comparison.
        if request.len() > 6_000 {
            continue;
        }
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{}", recorded_form(&reply));
    }
    std::fs::create_dir_all(recorded_path().parent().expect("folder")).expect("folder");
    std::fs::write(recorded_path(), text).expect("written");
}

/// A sanity check of the harness on a request whose answer is known.
#[test]
fn answers_a_known_request() {
    // "hello" with a zlib header, in pieces, then the end with Z_FINISH.
    let request = "inflate 15 - - i4/3/0,i100/100/0,i0/10/4 789ccb48cdc9c90700062c0215";
    let answer = answer(request);
    assert!(answer.starts_with("ok 0/4/1/"), "{answer}");
    assert!(answer.contains(" 13/5/103547413 "), "{answer}");
    let _ = ErrorCode::Data;
}
