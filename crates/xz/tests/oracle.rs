//! Comparison with liblzma 5.8.4 through `tools/xz-oracle`, call by call:
//! what each `lzma_code()` returns, reads and writes, the totals and a
//! hash of the output, the memory usage, the limit and the check, with
//! every decoder.
//!
//! The oracle is a small C program built with liblzma's sources by
//! `scripts/testdata.py`. It answers requests such as
//! `decode stream:1000000:0 c10/5/0,q,c=/100/3 fd377a...` by calling
//! liblzma, one line per request. [`answer`] answers the same requests
//! with the port, in the same format, so the two can be compared as text.
//!
//! - With the oracle built, generated requests are compared with liblzma
//!   directly: streams that liblzma's encoders wrote (.xz at every preset
//!   and check, .lzma, raw LZMA1 and LZMA2, and .lz members made from raw
//!   LZMA1), some damaged, cut short, concatenated or followed by more;
//!   and the test files of XZ Utils, `tests/files`, good, bad and
//!   unsupported. Each is decoded in random pieces, with memory limits
//!   that are reached and raised, and with the decoders' flags.
//! - Everywhere, including where the oracle cannot be built (Windows, and
//!   the emulated i686 and s390x jobs), `testdata/oracle/xz.txt` replays
//!   answers liblzma gave earlier. `cargo test -p hivepack-xz --test oracle
//!   record_oracle_answers -- --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::fmt::Write as _;
use std::path::PathBuf;

use hivepack_xz::{
    Action, CONCATENATED, Check, FAIL_FAST, FILTER_LZMA1, FILTER_LZMA1EXT, FILTER_LZMA2, Filter,
    IGNORE_CHECK, InBuffer, LzmaOptions, MatchFinder, Mode, OutBuffer, Result, Status, Stream,
    TELL_ANY_CHECK, TELL_NO_CHECK, TELL_UNSUPPORTED_CHECK,
};
use support::{Oracle, Rng, cache, damage, fnv64, hex, input, recorded_form, repository, unhex};

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/xz.txt")
}

/// liblzma's return code for a result.
fn code(ret: Result<Status>) -> i32 {
    match ret {
        Ok(status) => status.number(),
        Err(e) => e.number(),
    }
}

fn action(number: u32) -> Action {
    match number {
        0 => Action::Run,
        1 => Action::SyncFlush,
        2 => Action::FullFlush,
        3 => Action::Finish,
        _ => Action::FullBarrier,
    }
}

/// A filter from the oracle's text: `<id>:<dict>:<lc>:<lp>:<pb>:<ext_flags>:
/// <ext_size>:<preset>`.
fn parse_filter(text: &str) -> Filter {
    let f: Vec<&str> = text.split(':').collect();
    let n = |i: usize| f[i].parse::<u64>().unwrap();
    let ext_size = n(6);
    let preset = unhex(f[7]);
    Filter {
        id: match n(0) {
            1 => FILTER_LZMA1,
            2 => FILTER_LZMA1EXT,
            _ => FILTER_LZMA2,
        },
        options: Some(LzmaOptions {
            dict_size: n(1) as u32,
            preset_dict: (!preset.is_empty()).then_some(preset),
            lc: n(2) as u32,
            lp: n(3) as u32,
            pb: n(4) as u32,
            ext_flags: n(5) as u32,
            ext_size_low: ext_size as u32,
            ext_size_high: (ext_size >> 32) as u32,
            ..LzmaOptions::default()
        }),
    }
}

/// An encoder's filter from the oracle's text: `<id>:<dict>:<lc>:<lp>:
/// <pb>:<mode>:<nice_len>:<mf>:<depth>:<ext_flags>:<ext_size>:<preset>`,
/// `<id>` 1, 2 or 21 for LZMA1, LZMA1EXT or LZMA2, or the ID itself.
fn parse_efilter(text: &str) -> Filter {
    let f: Vec<&str> = text.split(':').collect();
    let n = |i: usize| f[i].parse::<u64>().unwrap();
    let ext_size = n(10);
    let preset = unhex(f[11]);
    Filter {
        id: match n(0) {
            1 => FILTER_LZMA1,
            2 => FILTER_LZMA1EXT,
            21 => FILTER_LZMA2,
            id => id,
        },
        options: Some(LzmaOptions {
            dict_size: n(1) as u32,
            preset_dict: (!preset.is_empty()).then_some(preset),
            lc: n(2) as u32,
            lp: n(3) as u32,
            pb: n(4) as u32,
            mode: Mode(n(5) as u32),
            nice_len: n(6) as u32,
            mf: MatchFinder(n(7) as u32),
            depth: n(8) as u32,
            ext_flags: n(9) as u32,
            ext_size_low: ext_size as u32,
            ext_size_high: (ext_size >> 32) as u32,
        }),
    }
}

/// The output space all the steps can ask for.
fn output_space(steps: &str) -> usize {
    steps
        .split(',')
        .filter(|s| s.starts_with('c'))
        .map(|s| s.split('/').nth(1).unwrap().parse::<usize>().unwrap())
        .sum()
}

/// The port's answer to a `decode` request, in the oracle's format.
fn answer(request: &str) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    let ["decode" | "code", decoder, steps, data] = words[..] else {
        panic!("not a decode request: {request:.100}");
    };
    let (kind, args) = decoder.split_once(':').unwrap();
    let args_n: Vec<u64> = args.split(':').filter_map(|a| a.parse().ok()).collect();
    let made = match kind {
        "stream" => Stream::stream_decoder(args_n[0], args_n[1] as u32),
        "auto" => Stream::auto_decoder(args_n[0], args_n[1] as u32),
        "lzip" => Stream::lzip_decoder(args_n[0], args_n[1] as u32),
        "alone" => Stream::alone_decoder(args_n[0]),
        "raw" => Stream::raw_decoder(&[parse_filter(args)]),
        "easyenc" => Stream::easy_encoder(args_n[0] as u32, Check(args_n[1] as u32)),
        "streamenc" => {
            let (check, filter) = args.split_once(':').unwrap();
            Stream::stream_encoder(&[parse_efilter(filter)], Check(check.parse().unwrap()))
        }
        "aloneenc" => Stream::alone_encoder(parse_efilter(args).options.as_ref().unwrap()),
        "rawenc" => Stream::raw_encoder(&[parse_efilter(args)]),
        _ => panic!("no such coder: {decoder}"),
    };
    let mut strm = match made {
        Ok(strm) => strm,
        Err(e) => return format!("err {}", e.number()),
    };
    let data = unhex(data);
    let mut out = vec![0u8; output_space(steps)];
    let (mut consumed, mut written, mut end) = (0, 0, 0);
    let mut text = String::from("ok");
    for step in steps.split(',') {
        let (kind, rest) = step.split_at(1);
        match kind {
            "c" => {
                let args: Vec<&str> = rest.split('/').collect();
                if args[0] != "=" {
                    let n: usize = args[0].parse().unwrap();
                    end = consumed + n.min(data.len() - consumed);
                }
                let room: usize = args[1].parse().unwrap();
                let mut input = InBuffer {
                    src: &data[..end],
                    pos: consumed,
                };
                let mut output = OutBuffer::new(&mut out[written..written + room]);
                let ret =
                    code(strm.code(&mut output, &mut input, action(args[2].parse().unwrap())));
                let read = input.pos - consumed;
                let made = output.pos;
                consumed += read;
                written += made;
                let _ = write!(text, " {ret}/{read}/{made}");
            }
            "m" => {
                let ret = match strm.memlimit_set(rest.parse().unwrap()) {
                    Ok(()) => 0,
                    Err(e) => e.number(),
                };
                let _ = write!(text, " m{ret}");
            }
            _ => {
                let _ = write!(
                    text,
                    " q{}/{}/{}",
                    strm.memusage(),
                    strm.memlimit_get(),
                    strm.get_check().0
                );
            }
        }
    }
    let _ = write!(
        text,
        " {}/{} {:016x}",
        strm.total_in(),
        strm.total_out(),
        fnv64(&out[..written])
    );
    text
}

/// liblzma's encoder, through the oracle: `data` as `format` (xz, alone,
/// raw1 or raw2) at `preset`, with `check` for xz.
fn encode(oracle: &mut Oracle, format: &str, preset: u32, check: u32, data: &[u8]) -> Vec<u8> {
    let reply = oracle.ask(&format!("encode {format} {preset} {check} {}", hex(data)));
    let stream = reply
        .strip_prefix("ok ")
        .unwrap_or_else(|| panic!("encode: {reply}"));
    unhex(stream)
}

/// The dictionary size of a preset.
fn preset_dict_size(preset: u32) -> u32 {
    [
        1 << 18,
        1 << 20,
        2 << 20,
        4 << 20,
        4 << 20,
        8 << 20,
        8 << 20,
        16 << 20,
        32 << 20,
        64 << 20,
    ][preset as usize & 15]
}

/// CRC32 as .lz and .xz have it.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// An .lz member of `data`, version 0 or 1, from liblzma's raw LZMA1
/// encoder, whose presets have lzip's lc=3, lp=0 and pb=2 and end with the
/// end of payload marker that lzip needs.
fn lzip_member(oracle: &mut Oracle, rng: &mut Rng, data: &[u8]) -> Vec<u8> {
    let preset = rng.below(7) as u32;
    let lzma = encode(oracle, "raw1", preset, 0, data);
    let version = rng.below(2) as u8;
    let mut member = b"LZIP".to_vec();
    member.push(version);
    member.push(preset_dict_size(preset).trailing_zeros() as u8);
    member.extend_from_slice(&lzma);
    member.extend_from_slice(&crc32(data).to_le_bytes());
    member.extend_from_slice(&(data.len() as u64).to_le_bytes());
    if version == 1 {
        let size = member.len() as u64 + 8;
        member.extend_from_slice(&size.to_le_bytes());
    }
    member
}

/// A single .xz Stream with check ID `id` in place of its own in the
/// Stream Header and Footer, both CRC32s made again. With an ID of the same
/// size, the check can be skipped but not verified: LZMA_UNSUPPORTED_CHECK.
fn with_check_id(stream: &[u8], id: u32) -> Vec<u8> {
    let mut stream = stream.to_vec();
    let footer = stream.len() - 12;
    stream[7] = id as u8;
    let crc = crc32(&stream[6..8]);
    stream[8..12].copy_from_slice(&crc.to_le_bytes());
    stream[footer + 9] = id as u8;
    let crc = crc32(&stream[footer + 4..footer + 10]);
    stream[footer..footer + 4].copy_from_slice(&crc.to_le_bytes());
    stream
}

/// How much input a step offers: a little, some, or all that is left.
fn chunk(rng: &mut Rng, left: usize) -> usize {
    match rng.below(5) {
        0 => rng.below(8) as usize,
        1 | 2 => rng.below(300) as usize,
        3 => rng.below(5000) as usize,
        _ => left,
    }
}

/// How much output space a step gives: none, a little, some, or plenty.
fn room(rng: &mut Rng) -> usize {
    match rng.below(8) {
        0 => 0,
        1..=3 => 1 + rng.below(100) as usize,
        4..=6 => rng.below(5000) as usize,
        _ => 100_000,
    }
}

/// The steps of a request for `len` bytes of input that decode to about
/// `out_len`: pieces with LZMA_RUN, now and then a query, a memory limit
/// raised, an action a decoder does not take, then LZMA_FINISH.
fn steps(rng: &mut Rng, len: usize, out_len: usize) -> String {
    let mut steps = Vec::new();
    let mut offered = 0;
    while offered < len && steps.len() < 120 {
        match rng.below(16) {
            0 => steps.push("q".to_string()),
            1 => steps.push(format!(
                "m{}",
                rng.pick(&[0, 1, 1 << 16, 1 << 20, 1 << 24, u64::MAX])
            )),
            2 => steps.push(format!("c=/{}/{}", room(rng), rng.pick(&[1, 2, 4]))),
            3 => steps.push(format!("c=/{}/0", room(rng))),
            _ => {
                let n = chunk(rng, len - offered);
                offered += n;
                steps.push(format!("c{n}/{}/0", room(rng)));
            }
        }
    }
    steps.push(format!("c{len}/{}/3", room(rng)));
    for _ in 0..rng.below(3) {
        steps.push(format!("c=/{}/3", room(rng)));
    }
    if rng.below(3) == 0 {
        steps.push(format!("m{}", u64::MAX));
    }
    steps.push(format!("c=/{}/3", out_len + 100));
    steps.push("q".to_string());
    steps.join(",")
}

/// A memory limit: none, or one that some streams reach.
fn memlimit(rng: &mut Rng) -> u64 {
    match rng.below(6) {
        0 => rng.pick(&[0, 1, 1 << 15, 1 << 16, 300_000, 1 << 21, 9 << 20]),
        _ => u64::MAX,
    }
}

/// The flags of the .xz and .lz decoders, now and then one they refuse.
fn flags(rng: &mut Rng) -> u32 {
    let mut flags = 0;
    for flag in [
        TELL_NO_CHECK,
        TELL_UNSUPPORTED_CHECK,
        TELL_ANY_CHECK,
        CONCATENATED,
        IGNORE_CHECK,
        FAIL_FAST,
    ] {
        if rng.below(4) == 0 {
            flags |= flag;
        }
    }
    if rng.below(40) == 0 {
        flags |= 0x40;
    }
    flags
}

/// The test files of XZ Utils, `tests/files`, where they are fetched.
fn test_files() -> Vec<(String, Vec<u8>)> {
    let folder = cache().join("xz-5.8.4-source/xz-5.8.4/tests/files");
    let Ok(entries) = std::fs::read_dir(&folder) else {
        return Vec::new();
    };
    let mut files: Vec<(String, Vec<u8>)> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|x| x == "xz" || x == "lzma" || x == "lz")
        })
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read(&p).unwrap(),
            )
        })
        .collect();
    files.sort();
    files
}

/// A length for an input: empty, short, or up to `max`.
fn length(rng: &mut Rng, max: usize) -> usize {
    match rng.below(8) {
        0 => rng.below(3) as usize,
        1..=4 => rng.below(2000) as usize,
        5 | 6 => rng.below(30_000) as usize,
        _ => rng.below(max as u64 + 1) as usize,
    }
}

/// Generated requests: `count` streams of each kind, with inputs up to
/// `max` bytes, and the test files.
fn requests(oracle: &mut Oracle, rng: &mut Rng, count: usize, max: usize) -> Vec<String> {
    let mut requests = Vec::new();

    // By hand: empty input, and decoders refused.
    for decoder in [
        "stream:0:0",
        "auto:0:0",
        "lzip:0:0",
        "alone:0",
        "stream:1:64",
        "auto:1:128",
    ] {
        requests.push(format!("decode {decoder} c0/10/0,c0/10/0,q,c0/10/3 -"));
    }
    for filter in [
        "21:4096:0:0:0:0:0:-",
        "1:4096:5:0:0:0:0:-",
        "1:4096:3:0:5:0:0:-",
        "2:4096:3:0:2:2:5:-",
        "21:0:0:0:0:0:0:-",
    ] {
        requests.push(format!("decode raw:{filter} c0/10/3 -"));
        requests.push(format!("memusage {filter}"));
    }

    for _ in 0..count {
        let len = length(rng, max);
        let data = input(rng, len);
        let preset = rng.below(10) as u32 | if rng.below(6) == 0 { 1 << 31 } else { 0 };
        let check = rng.pick(&[0, 1, 4, 10, 4, 4]);
        let mut stream = encode(oracle, "xz", preset, check, &data);
        let mut out_len = data.len();
        match rng.below(10) {
            0 | 1 => stream = damage(rng, &stream),
            2 => {
                // Concatenated, with Stream Padding of 0, 4 or 8 bytes, or
                // of 3, which is invalid.
                let padding = rng.pick(&[0, 4, 8, 3]);
                stream.resize(stream.len() + padding, 0);
                let more_len = rng.below(3000) as usize;
                let more = input(rng, more_len);
                stream.extend(encode(oracle, "xz", rng.below(4) as u32, check, &more));
                out_len += more.len();
            }
            3 => stream.extend((0..1 + rng.below(20)).map(|_| rng.next() as u8)),
            5 | 6 if check != 0 => {
                let id = check + 1 + rng.below(2) as u32;
                stream = with_check_id(&stream, id);
            }
            4 => {
                let at = rng.below(stream.len() as u64) as usize;
                stream.truncate(at);
            }
            _ => {}
        }
        let decoder = if rng.below(3) == 0 { "auto" } else { "stream" };
        let steps = steps(rng, stream.len(), out_len);
        requests.push(format!(
            "decode {decoder}:{}:{} {steps} {}",
            memlimit(rng),
            flags(rng),
            hex(&stream)
        ));
    }

    for _ in 0..count / 2 {
        let len = length(rng, max);
        let data = input(rng, len);
        let mut stream = encode(oracle, "alone", rng.below(10) as u32, 0, &data);
        if rng.below(3) == 0 {
            // The size in the header, which lzma_alone_encoder leaves
            // unknown: with the end of payload marker after it, which is
            // valid, or too small or too large.
            let size = (data.len() as u64).wrapping_add(rng.pick(&[0, 0, 0, u64::MAX, 1]));
            stream[5..13].copy_from_slice(&size.to_le_bytes());
        }
        if rng.below(4) == 0 {
            stream = damage(rng, &stream);
        }
        let decoder = if rng.below(3) == 0 {
            format!("auto:{}:{}", memlimit(rng), flags(rng))
        } else {
            format!("alone:{}", memlimit(rng))
        };
        let steps = steps(rng, stream.len(), data.len());
        requests.push(format!("decode {decoder} {steps} {}", hex(&stream)));
    }

    for _ in 0..count / 2 {
        let len = length(rng, max.min(60_000));
        let data = input(rng, len);
        let mut stream = lzip_member(oracle, rng, &data);
        let mut out_len = data.len();
        match rng.below(6) {
            0 => stream = damage(rng, &stream),
            1 => {
                let more_len = rng.below(2000) as usize;
                let more = input(rng, more_len);
                stream.extend(lzip_member(oracle, rng, &more));
                out_len += more.len();
            }
            2 => stream.extend_from_slice(b"trailing data"),
            _ => {}
        }
        let decoder = if rng.below(3) == 0 { "auto" } else { "lzip" };
        let steps = steps(rng, stream.len(), out_len);
        requests.push(format!(
            "decode {decoder}:{}:{} {steps} {}",
            memlimit(rng),
            flags(rng),
            hex(&stream)
        ));
    }

    for _ in 0..count / 2 {
        let len = length(rng, max.min(60_000));
        let data = input(rng, len);
        let preset = rng.below(10) as u32;
        let lzma2 = rng.below(2) == 0;
        let mut stream = encode(
            oracle,
            if lzma2 { "raw2" } else { "raw1" },
            preset,
            0,
            &data,
        );
        if rng.below(5) == 0 {
            stream = damage(rng, &stream);
        }
        // The dictionary the decoder is given: the encoder's, a smaller
        // one, or none at all.
        let dict = match rng.below(4) {
            0 => rng.pick(&[0, 4096, 65_536]),
            _ => preset_dict_size(preset),
        };
        // Now and then a preset dictionary, which the stream does not use
        // but a damaged one may reach into, and which spares LZMA2 the
        // dictionary reset of its first chunk.
        let preset = if rng.below(4) == 0 {
            let len = 1 + rng.below(3000) as usize;
            hex(&input(rng, len))
        } else {
            "-".to_string()
        };
        let filter = if lzma2 {
            format!("21:{dict}:0:0:0:0:0:{preset}")
        } else if rng.below(2) == 0 {
            format!("1:{dict}:3:0:2:0:0:{preset}")
        } else {
            // LZMA1EXT: the size known or not, the marker allowed or not.
            let size = rng.pick(&[data.len() as u64, u64::MAX, data.len() as u64 + 1]);
            format!("2:{dict}:3:0:2:{}:{size}:{preset}", rng.below(2))
        };
        let steps = steps(rng, stream.len(), data.len());
        requests.push(format!("decode raw:{filter} {steps} {}", hex(&stream)));
    }

    for (name, data) in test_files() {
        let decoders: Vec<String> = match name.rsplit('.').next() {
            Some("lzma") => vec![
                "alone:1000000000".into(),
                format!("auto:1000000000:{}", flags(rng)),
            ],
            Some("lz") => vec![
                format!("lzip:1000000000:{}", flags(rng)),
                "auto:1000000000:8".into(),
            ],
            _ => vec![
                "stream:1000000000:0".into(),
                format!("stream:1000000000:{}", flags(rng)),
                format!("auto:{}:{}", memlimit(rng), flags(rng) | CONCATENATED),
            ],
        };
        for decoder in decoders {
            let steps = steps(rng, data.len(), 100_000);
            requests.push(format!("decode {decoder} {steps} {}", hex(&data)));
        }
    }
    requests
}

/// The port's answer to any request.
fn port_answer(request: &str) -> String {
    if let Some(filter) = request.strip_prefix("memusage ") {
        return hivepack_xz::raw_decoder_memusage(&[parse_filter(filter)]).to_string();
    }
    if let Some(filter) = request.strip_prefix("encmem ") {
        return hivepack_xz::raw_encoder_memusage(&[parse_efilter(filter)]).to_string();
    }
    if let Some(preset) = request.strip_prefix("easymem ") {
        let preset = preset.parse().unwrap();
        return format!(
            "{} {}",
            hivepack_xz::easy_encoder_memusage(preset),
            hivepack_xz::easy_decoder_memusage(preset)
        );
    }
    if let Some(size) = request.strip_prefix("bound ") {
        return hivepack_xz::stream_buffer_bound(size.parse().unwrap()).to_string();
    }
    let words: Vec<&str> = request.split(' ').collect();
    if let [kind @ ("ebuf" | "sbuf" | "rbuf"), args, data] = words[..] {
        let data = unhex(data);
        let a: Vec<&str> = args.splitn(3, ':').collect();
        let (out_size, result) = match kind {
            "ebuf" => {
                let out_size: usize = a[2].parse().unwrap();
                let mut out = vec![0; out_size];
                let mut pos = 0;
                let r = hivepack_xz::easy_buffer_encode(
                    a[0].parse().unwrap(),
                    Check(a[1].parse().unwrap()),
                    &data,
                    &mut out,
                    &mut pos,
                );
                (out_size, r.map(|()| out[..pos].to_vec()))
            }
            "sbuf" => {
                let out_size: usize = a[1].parse().unwrap();
                let mut out = vec![0; out_size];
                let mut pos = 0;
                let r = hivepack_xz::stream_buffer_encode(
                    &[parse_efilter(a[2])],
                    Check(a[0].parse().unwrap()),
                    &data,
                    &mut out,
                    &mut pos,
                );
                (out_size, r.map(|()| out[..pos].to_vec()))
            }
            _ => {
                let (out_size, filter) = args.split_once(':').unwrap();
                let out_size: usize = out_size.parse().unwrap();
                let mut out = vec![0; out_size];
                let mut pos = 0;
                let r = hivepack_xz::raw_buffer_encode(
                    &[parse_efilter(filter)],
                    &data,
                    &mut out,
                    &mut pos,
                );
                (out_size, r.map(|()| out[..pos].to_vec()))
            }
        };
        let _ = out_size;
        return match result {
            Ok(bytes) => format!("ok {}", hex(&bytes)),
            Err(e) => format!("err {}", e.number()),
        };
    }
    answer(request)
}

#[test]
fn port_matches_liblzma() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x5eed_c201);
    let requests = requests(&mut oracle, &mut rng, 300, 300_000);
    let mut seen = [0usize; 12];
    let mut ends = 0;
    for request in &requests {
        let want = oracle.ask(request);
        assert_eq!(port_answer(request), want, "{request:.300}");
        for ret in returned(&want) {
            seen[ret] += 1;
        }
        ends += usize::from(returned(&want).contains(&1));
    }
    eprintln!(
        "{} requests, {ends} reach LZMA_STREAM_END, return codes seen {seen:?}",
        requests.len()
    );
    // Every return code from LZMA_OK to LZMA_PROG_ERROR came up, but
    // LZMA_MEM_ERROR, for which an allocation must fail.
    for (ret, count) in seen.iter().enumerate().filter(|&(ret, _)| ret != 5) {
        assert!(*count > 0, "no lzma_code() returned {ret}");
    }
    assert!(
        ends > requests.len() / 3,
        "only {ends} of {} streams end",
        requests.len()
    );
}

/// The return codes of the `lzma_code()` and `lzma_memlimit_set()` calls
/// in an answer to `decode`, or of the initialization that failed.
fn returned(answer: &str) -> Vec<usize> {
    if let Some(err) = answer.strip_prefix("err ") {
        return vec![err.parse().unwrap()];
    }
    let Some(steps) = answer.strip_prefix("ok ") else {
        return Vec::new();
    };
    let words: Vec<&str> = steps.split(' ').collect();
    // "ok <hex>" from the single-call encoders: no calls.
    if words.len() < 2 {
        return Vec::new();
    }
    words[..words.len() - 2]
        .iter()
        .filter(|w| !w.starts_with('q'))
        .filter_map(|w| w.trim_start_matches('m').split('/').next()?.parse().ok())
        .collect()
}

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/xz.txt");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(recorded_form(&port_answer(request)), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked > 500, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/xz.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng(0x5eed_c202);
    let mut text = String::from(
        "# Answers from liblzma 5.8.4 (tools/xz-oracle), replayed by crates/xz/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack-xz --test oracle record_oracle_answers -- --ignored\n",
    );
    for request in requests(&mut oracle, &mut rng, 300, 3000) {
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

// The encoders.

fn recorded_encoder_path() -> PathBuf {
    repository().join("testdata/oracle/xz-encode.txt")
}

/// An encoder's filter, as the oracle reads it: the options of a preset,
/// changed now and then, some of them to values the encoders refuse.
fn efilter(rng: &mut Rng, id: u64, max_dict: u32) -> String {
    let preset = rng.below(10) as u32
        | if rng.below(5) == 0 {
            hivepack_xz::PRESET_EXTREME
        } else {
            0
        };
    let mut o = LzmaOptions::preset(preset).unwrap();
    o.dict_size = match rng.below(12) {
        0 => rng.pick(&[0, 4095, (1 << 30) + (1 << 29) + 1]),
        1..=4 => rng.pick(&[4096, 4097, 1 << 16, 100_000, 1 << 18, 1 << 20]),
        _ => o.dict_size.min(max_dict),
    };
    if rng.below(4) == 0 {
        o.lc = rng.below(5) as u32;
        o.lp = rng.below(5) as u32;
        o.pb = rng.below(5) as u32;
    }
    match rng.below(40) {
        0 => o.mode = Mode(rng.pick(&[0, 3])),
        1..=6 => {
            o.mode = if o.mode == Mode::FAST {
                Mode::NORMAL
            } else {
                Mode::FAST
            }
        }
        _ => {}
    }
    match rng.below(40) {
        0 => o.nice_len = rng.pick(&[0, 1, 274]),
        1..=10 => o.nice_len = rng.pick(&[2, 3, 4, 5, 8, 16, 32, 64, 128, 192, 273]),
        _ => {}
    }
    match rng.below(40) {
        0 => o.mf = MatchFinder(rng.pick(&[0, 0x02, 0x05, 0x15])),
        1..=10 => {
            o.mf = rng.pick(&[
                MatchFinder::HC3,
                MatchFinder::HC4,
                MatchFinder::BT2,
                MatchFinder::BT3,
                MatchFinder::BT4,
            ])
        }
        _ => {}
    }
    if rng.below(5) == 0 {
        o.depth = rng.pick(&[0, 1, 2, 4, 16, 64, 512, 10_000]);
    }
    if id == FILTER_LZMA1EXT {
        o.ext_flags = if rng.below(30) == 0 {
            2
        } else {
            rng.below(2) as u32
        };
    }
    let preset_dict = if rng.below(5) == 0 {
        let len = 1 + rng.below(5000) as usize;
        hex(&input(rng, len))
    } else {
        "-".to_string()
    };
    let id = match id {
        FILTER_LZMA1 => 1,
        FILTER_LZMA1EXT => 2,
        FILTER_LZMA2 => 21,
        id => id,
    };
    format!(
        "{id}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{preset_dict}",
        o.dict_size,
        o.lc,
        o.lp,
        o.pb,
        o.mode.0,
        o.nice_len,
        o.mf.0,
        o.depth,
        o.ext_flags,
        rng.next() >> rng.below(64)
    )
}

/// A filter ID for the encoders: LZMA2 mostly, LZMA1 and LZMA1EXT, and now
/// and then one they do not have.
fn encoder_id(rng: &mut Rng) -> u64 {
    match rng.below(40) {
        0 => rng.pick(&[0x7F, 0x4000_0000_0000_0003, 0x21 + 0x100]),
        1..=8 => FILTER_LZMA1,
        9..=14 => FILTER_LZMA1EXT,
        _ => FILTER_LZMA2,
    }
}

/// An integrity check: the three this build has and none, now and then
/// one it has not, or a number out of range.
fn check(rng: &mut Rng) -> u32 {
    match rng.below(30) {
        0 => rng.pick(&[2, 3, 5, 9, 15, 16]),
        _ => rng.pick(&[0, 1, 4, 10]),
    }
}

/// The steps of an encoding of `len` bytes: pieces with LZMA_RUN, flushes
/// with the actions in `flushes` (each given again until it is done), now
/// and then an action the encoder does not take, queries and memory
/// limits, then LZMA_FINISH with room enough for all the output.
fn encoder_steps(rng: &mut Rng, len: usize, flushes: &[u32]) -> String {
    let mut steps = Vec::new();
    let mut offered = 0;
    while offered < len && steps.len() < 100 {
        match rng.below(30) {
            0 | 1 => steps.push("q".to_string()),
            2 => steps.push(format!("m{}", rng.pick(&[0, 1, 1 << 20, u64::MAX]))),
            3 => steps.push(format!("c=/{}/{}", room(rng), rng.pick(&[1, 2, 4]))),
            4..=7 if !flushes.is_empty() => {
                let action = rng.pick(flushes);
                let n = chunk(rng, len - offered);
                offered += n;
                steps.push(format!("c{n}/{}/{action}", room(rng)));
                for _ in 0..1 + rng.below(4) {
                    steps.push(format!("c=/{}/{action}", room(rng)));
                }
            }
            _ => {
                let n = chunk(rng, len - offered);
                offered += n;
                steps.push(format!("c{n}/{}/0", room(rng)));
            }
        }
    }
    steps.push(format!("c{len}/{}/3", room(rng)));
    for _ in 0..rng.below(4) {
        steps.push(format!("c=/{}/3", room(rng)));
    }
    steps.push(format!("c=/{}/3", len + len / 8 + 70_000));
    steps.push("q".to_string());
    steps.join(",")
}

/// Requests for the encoders: `count` encodings with each kind of encoder,
/// with inputs up to `max` bytes, the single-call encoders, and the memory
/// usage of encoders.
fn encoder_requests(rng: &mut Rng, count: usize, max: usize) -> Vec<String> {
    let mut requests = Vec::new();
    let max_dict = if max > 100_000 { 8 << 20 } else { 1 << 20 };

    for _ in 0..count {
        let len = length(rng, max);
        let data = input(rng, len);
        let (coder, flushes): (String, &[u32]) = match rng.below(8) {
            0 | 1 => {
                let preset = match rng.below(30) {
                    0 => rng.pick(&[10, 1 << 20, 15 | hivepack_xz::PRESET_EXTREME]),
                    _ => {
                        rng.below(10) as u32
                            | if rng.below(5) == 0 {
                                hivepack_xz::PRESET_EXTREME
                            } else {
                                0
                            }
                    }
                };
                // At most preset 7, whose 16 MiB dictionary is quick to
                // set up; the others are tested in one call.
                let preset = if max > 100_000 && preset & 15 > 7 {
                    preset - 2
                } else {
                    preset
                };
                (format!("easyenc:{preset}:{}", check(rng)), &[1, 2, 4])
            }
            2..=4 => {
                let id = if rng.below(20) == 0 {
                    encoder_id(rng)
                } else {
                    FILTER_LZMA2
                };
                (
                    format!("streamenc:{}:{}", check(rng), efilter(rng, id, max_dict)),
                    &[1, 2, 4],
                )
            }
            5 => (
                format!("aloneenc:{}", efilter(rng, FILTER_LZMA1, max_dict)),
                &[],
            ),
            _ => {
                let id = encoder_id(rng);
                let flushes: &[u32] = if rng.below(4) == 0 { &[1, 2] } else { &[1] };
                (format!("rawenc:{}", efilter(rng, id, max_dict)), flushes)
            }
        };
        let steps = encoder_steps(rng, len, flushes);
        requests.push(format!("code {coder} {steps} {}", hex(&data)));
    }

    // Inputs bigger than the window of small dictionaries, which slides
    // (move_window), and runs that fill LZMA2 chunks of 2 MiB.
    if max > 100_000 {
        for _ in 0..12 {
            let len = 1_000_000 + rng.below(2_500_000) as usize;
            let data = input(rng, len);
            // Options the encoder takes, so that it gets through.
            let mut filter = efilter(rng, FILTER_LZMA2, 1 << 16);
            while hivepack_xz::raw_encoder_memusage(&[parse_efilter(&filter)]) == u64::MAX {
                filter = efilter(rng, FILTER_LZMA2, 1 << 16);
            }
            if rng.below(2) == 0 {
                // A dictionary of 4 KiB to 64 KiB.
                let rest = filter.split_once(':').unwrap().1.split_once(':').unwrap().1;
                filter = format!("21:{}:{rest}", 4096 << rng.below(5));
            }
            let coder = if rng.below(2) == 0 {
                format!("streamenc:{}:{filter}", check(rng))
            } else {
                format!("rawenc:{filter}")
            };
            let steps = encoder_steps(rng, len, &[1]);
            requests.push(format!("code {coder} {steps} {}", hex(&data)));
        }
    }

    for _ in 0..count / 3 {
        let len = length(rng, max.min(100_000));
        let data = input(rng, len);
        let bound = hivepack_xz::stream_buffer_bound(len);
        let out_size = match rng.below(5) {
            0 => rng.below(80) as usize,
            1 => bound - rng.below(bound as u64 / 2) as usize,
            _ => bound,
        };
        let request = match rng.below(3) {
            0 => format!(
                "ebuf {}:{}:{out_size} {}",
                rng.below(10) as u32
                    | if rng.below(6) == 0 {
                        hivepack_xz::PRESET_EXTREME
                    } else {
                        0
                    },
                check(rng),
                hex(&data)
            ),
            1 => {
                let id = if rng.below(10) == 0 {
                    encoder_id(rng)
                } else {
                    FILTER_LZMA2
                };
                format!(
                    "sbuf {}:{out_size}:{} {}",
                    check(rng),
                    efilter(rng, id, max_dict),
                    hex(&data)
                )
            }
            _ => {
                let id = encoder_id(rng);
                format!(
                    "rbuf {out_size}:{} {}",
                    efilter(rng, id, max_dict),
                    hex(&data)
                )
            }
        };
        requests.push(request);
    }

    for _ in 0..count / 3 {
        let id = encoder_id(rng);
        requests.push(format!("encmem {}", efilter(rng, id, u32::MAX)));
    }
    for preset in (0..12).chain([1 << 20, 31]) {
        requests.push(format!("easymem {preset}"));
        requests.push(format!("easymem {}", preset | hivepack_xz::PRESET_EXTREME));
    }
    for size in [
        0u64,
        1,
        1000,
        1 << 20,
        1 << 40,
        (1 << 63) - 1,
        u64::MAX - 100,
    ] {
        requests.push(format!("bound {size}"));
    }
    requests
}

#[test]
fn port_encoders_match_liblzma() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x5eed_e201);
    let requests = encoder_requests(&mut rng, 300, 300_000);
    let mut seen = [0usize; 12];
    let mut ends = 0;
    let (mut big, mut big_ends) = (0, 0);
    for request in &requests {
        let want = oracle.ask(request);
        assert_eq!(port_answer(request), want, "{request:.300}");
        for ret in returned(&want) {
            seen[ret] += 1;
        }
        ends += usize::from(returned(&want).contains(&1));
        if request.len() > 2_000_000 {
            big += 1;
            let total_in = want
                .split(' ')
                .rev()
                .nth(1)
                .and_then(|t| t.split('/').next());
            big_ends +=
                usize::from(total_in.is_some_and(|n| n.parse::<u64>().unwrap_or(0) > 1_000_000));
        }
    }
    eprintln!(
        "{} requests, {ends} reach LZMA_STREAM_END, return codes seen {seen:?}",
        requests.len()
    );
    assert!(
        big_ends * 3 >= big,
        "only {big_ends} of {big} big inputs are read"
    );
    // The results encoders give, and the errors they give for options,
    // checks, actions, memory limits and output space.
    for ret in [0, 1, 3, 8, 10, 11] {
        assert!(seen[ret] > 0, "no call returned {ret}");
    }
    assert!(ends > 200, "only {ends} encodings end");
}

#[test]
fn port_encoders_match_recorded_answers() {
    let text =
        std::fs::read_to_string(recorded_encoder_path()).expect("testdata/oracle/xz-encode.txt");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(recorded_form(&port_answer(request)), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked > 300, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/xz-encode.txt from the oracle"]
fn record_encoder_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng(0x5eed_e202);
    let mut text = String::from(
        "# Answers from liblzma 5.8.4's encoders (tools/xz-oracle), replayed by crates/xz/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack-xz --test oracle record_encoder_answers -- --ignored\n",
    );
    for request in encoder_requests(&mut rng, 300, 3000) {
        // Keep the file small: the large inputs are for the live comparison.
        if request.len() > 8_000 {
            continue;
        }
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{}", recorded_form(&reply));
    }
    std::fs::write(recorded_encoder_path(), text).expect("written");
}
