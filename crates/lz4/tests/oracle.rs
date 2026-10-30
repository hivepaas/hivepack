//! Comparison with liblz4 1.10.0 through `tools/lz4-oracle`, call by call:
//! for blocks, what each decoding function returns, the error position
//! included, and everything it writes in the output, past what it decoded
//! too; for frames, what each `LZ4F_decompress` and `LZ4F_getFrameInfo`
//! call returns, reads and writes, and a hash of the output; and XXH32.
//!
//! The oracle is a small C program built with liblz4's sources by
//! `scripts/testdata.py`. It answers requests such as
//! `frame - 0 d10/5,d=/100 04224d18...` by calling liblz4, one line per
//! request. [`answer`] answers the same requests with the port, in the same
//! format, so the two can be compared as text.
//!
//! - With the oracle built, generated requests are compared with liblz4
//!   directly: blocks and frames that liblz4 compressed from inputs of many
//!   kinds, decoded whole, partially, with dictionaries and in random
//!   pieces, some damaged, cut short or followed by more; blocks made up
//!   here, valid or not, with every offset (0 included) and length; frames
//!   put together here with every flag, skippable frames and uncompressed
//!   blocks.
//! - Everywhere, including where the oracle cannot be built (Windows, and
//!   the emulated i686 and s390x jobs), `testdata/oracle/lz4.txt` replays
//!   answers liblz4 gave earlier. `cargo test -p hivepack-lz4 --test oracle
//!   record_oracle_answers -- --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::fmt::Write as _;
use std::path::PathBuf;

use hivepack_lz4::block::{self, DecodeError, StreamDecode};
use hivepack_lz4::frame::{
    DecompressOptions, DecompressionContext, FrameInfo, InBuffer, OutBuffer,
};
use hivepack_lz4::{Xxh32, xxh32};
use support::{
    FrameSettings, Oracle, Rng, c_compress_block, c_compress_frame, damage, fnv64, hex, input,
    pattern, recorded_form, repository, unhex,
};

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/lz4.txt")
}

/// What a block function returns, as liblz4's `int`.
fn block_ret(ret: Result<usize, DecodeError>) -> i64 {
    match ret {
        Ok(size) => size as i64,
        Err(e) => e.number(),
    }
}

fn frame_ret(ret: hivepack_lz4::frame::Result<usize>) -> String {
    match ret {
        Ok(hint) => hint.to_string(),
        Err(e) => e.name().to_string(),
    }
}

fn info_text(info: &FrameInfo) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}:{}",
        info.block_size_id as u32,
        info.block_mode as u32,
        u32::from(info.content_checksum),
        info.frame_type as u32,
        info.content_size,
        info.dict_id,
        u32::from(info.block_checksum)
    )
}

/// The output space all the steps can ask for.
fn output_space(steps: &str) -> usize {
    steps
        .split(',')
        .filter(|step| step.starts_with('d'))
        .map(|step| step.split('/').nth(1).unwrap().parse::<usize>().unwrap())
        .sum()
}

/// The port's answer to a request, in the oracle's format.
fn answer(request: &str) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    match words[..] {
        ["block", mode, capacity, target, dict, data] => {
            let capacity: usize = capacity.parse().unwrap();
            let target: usize = target.parse().unwrap();
            let dict = unhex(dict);
            let data = unhex(data);
            let mut buffer = dict.clone();
            buffer.extend_from_slice(&pattern(capacity));
            let prefix = dict.len();
            let ret = match mode {
                "s" => block::decompress_safe(&data, &mut buffer[prefix..]),
                "p" => block::decompress_safe_partial(&data, &mut buffer[prefix..], target),
                "d" => block::decompress_safe_using_dict(&data, &mut buffer[prefix..], &dict),
                "q" => block::decompress_safe_partial_using_dict(
                    &data,
                    &mut buffer[prefix..],
                    target,
                    &dict,
                ),
                "x" => block::decompress_safe_with_prefix(&data, &mut buffer, prefix),
                "y" => {
                    block::decompress_safe_partial_with_prefix(&data, &mut buffer, prefix, target)
                }
                _ => panic!("mode {mode}"),
            };
            format!("{} {:016x}", block_ret(ret), fnv64(&buffer[prefix..]))
        }
        ["stream", dict, capacity, blocks] => {
            let capacity: usize = capacity.parse().unwrap();
            let mut stream = StreamDecode::new();
            stream.set_dict(&unhex(dict));
            let mut text = String::from("ok");
            for data in blocks.split(',') {
                let mut out = vec![0; capacity];
                let ret = stream.decompress_safe_continue(&unhex(data), &mut out);
                let decoded = ret.unwrap_or(0);
                let _ = write!(text, " {}/{:016x}", block_ret(ret), fnv64(&out[..decoded]));
                if ret.is_err() {
                    break;
                }
            }
            text
        }
        ["frame", dict, skip, steps, data] => {
            let data = unhex(data);
            let dict = (dict != "-").then(|| unhex(dict));
            let options = DecompressOptions {
                skip_checksums: skip == "1",
            };
            let mut dctx = DecompressionContext::new();
            let mut out = vec![0u8; output_space(steps)];
            let (mut consumed, mut written) = (0, 0);
            let mut text = String::from("ok");
            for step in steps.split(',') {
                if step == "r" {
                    dctx.reset();
                    text.push_str(" r");
                    continue;
                }
                let (kind, args) = step.split_at(1);
                let mut args = args.split('/');
                let n: usize = args.next().unwrap().parse().unwrap();
                let end = consumed + n.min(data.len() - consumed);
                let mut input = InBuffer::new(&data[consumed..end]);
                let failed;
                if kind == "d" {
                    let room: usize = args.next().unwrap().parse().unwrap();
                    let mut output = OutBuffer::new(&mut out[written..written + room]);
                    let ret = match &dict {
                        Some(dict) => {
                            dctx.decompress_using_dict(&mut output, &mut input, dict, options)
                        }
                        None => dctx.decompress(&mut output, &mut input, options),
                    };
                    failed = ret.is_err();
                    let _ = write!(text, " {}/{}/{}", frame_ret(ret), input.pos, output.pos);
                    written += output.pos;
                } else {
                    let ret = dctx.get_frame_info(&mut input);
                    failed = ret.is_err();
                    let (info, ret) = match ret {
                        Ok((info, hint)) => (info, Ok(hint)),
                        Err(e) => (FrameInfo::default(), Err(e)),
                    };
                    let _ = write!(
                        text,
                        " {}/{}/{}",
                        frame_ret(ret),
                        input.pos,
                        info_text(&info)
                    );
                }
                consumed += input.pos;
                if failed {
                    break;
                }
            }
            let _ = write!(text, " {:016x}", fnv64(&out[..written]));
            text
        }
        ["compress", accel, capacity, blocks] => {
            let accel: i32 = accel.parse().unwrap();
            let capacity: usize = capacity.parse().unwrap();
            let mut state = block::State::new();
            let mut text = String::from("ok");
            for (i, data) in blocks.split(',').enumerate() {
                let data = unhex(data);
                let mut out = pattern(capacity);
                let ret = if i == 0 {
                    state.compress_fast_ext_state(&data, &mut out, accel)
                } else {
                    state.compress_fast_ext_state_fast_reset(&data, &mut out, accel)
                };
                let _ = write!(text, " {ret}/{:016x}", fnv64(&out));
            }
            text
        }
        ["destsize", accel, capacity, data] => {
            let capacity: usize = capacity.parse().unwrap();
            let mut out = pattern(capacity);
            let (ret, src_size) = block::State::new().compress_dest_size_ext_state(
                &unhex(data),
                &mut out,
                accel.parse().unwrap(),
            );
            format!("{ret} {src_size} {:016x}", fnv64(&out))
        }
        ["cstream", dict, how, accel, capacity, blocks] => {
            let dict = unhex(dict);
            let accel: i32 = accel.parse().unwrap();
            let capacity: usize = capacity.parse().unwrap();
            let mut stream = block::Stream::new();
            let mut dict_stream = block::Stream::new();
            match how {
                "l" => {
                    stream.load_dict(&dict);
                }
                "s" => {
                    stream.load_dict_slow(&dict);
                }
                _ => {
                    dict_stream.load_dict_slow(&dict);
                    stream.reset_fast();
                    stream.attach_dictionary(&dict_stream);
                }
            }
            let mut text = String::from("ok");
            for data in blocks.split(',') {
                let mut out = pattern(capacity);
                let ret = stream.compress_fast_continue(&unhex(data), &mut out, accel);
                let _ = write!(text, " {ret}/{:016x}", fnv64(&out));
            }
            text
        }
        ["hc", level, capacity, blocks] => {
            let level: i32 = level.parse().unwrap();
            let capacity: usize = capacity.parse().unwrap();
            let mut state = hivepack_lz4::hc::StateHc::new();
            let mut text = String::from("ok");
            for (i, data) in blocks.split(',').enumerate() {
                let data = unhex(data);
                let mut out = pattern(capacity);
                let ret = if i == 0 {
                    state.compress_hc_ext_state(&data, &mut out, level)
                } else {
                    state.compress_hc_ext_state_fast_reset(&data, &mut out, level)
                };
                let _ = write!(text, " {ret}/{:016x}", fnv64(&out));
            }
            text
        }
        ["hcdest", level, capacity, data] => {
            let capacity: usize = capacity.parse().unwrap();
            let mut out = pattern(capacity);
            let (ret, src_size) = hivepack_lz4::hc::StateHc::new().compress_hc_dest_size(
                &unhex(data),
                &mut out,
                level.parse().unwrap(),
            );
            format!("{ret} {src_size} {:016x}", fnv64(&out))
        }
        ["hcstream", dict, how, level, capacity, blocks] => {
            let dict = unhex(dict);
            let level: i32 = level.parse().unwrap();
            let capacity: usize = capacity.parse().unwrap();
            let mut stream = hivepack_lz4::hc::StreamHc::new();
            let mut dict_stream = hivepack_lz4::hc::StreamHc::new();
            stream.reset(level);
            if how == "a" {
                dict_stream.reset(level);
                dict_stream.load_dict_hc(&dict);
                stream.reset_fast(level);
                stream.attach_hc_dictionary(&dict_stream);
            } else {
                if how == "f" {
                    stream.favor_decompression_speed(true);
                }
                stream.load_dict_hc(&dict);
            }
            let mut text = String::from("ok");
            for data in blocks.split(',') {
                let mut out = pattern(capacity);
                let ret = stream.compress_hc_continue(&unhex(data), &mut out);
                let _ = write!(text, " {ret}/{:016x}", fnv64(&out));
            }
            text
        }
        ["header", data] => match hivepack_lz4::frame::header_size(&unhex(data)) {
            Ok(size) => size.to_string(),
            Err(e) => e.name().to_string(),
        },
        ["xxh32", seed, pieces, data] => {
            let seed: u32 = seed.parse().unwrap();
            let data = unhex(data);
            let mut state = Xxh32::new(seed);
            let mut at = 0;
            if pieces != "-" {
                for piece in pieces.split(',') {
                    let take = piece.parse::<usize>().unwrap().min(data.len() - at);
                    state.update(&data[at..at + take]);
                    at += take;
                }
            }
            state.update(&data[at..]);
            format!("{:08x} {:08x}", xxh32(&data, seed), state.digest())
        }
        _ => panic!("unknown request {request:.100}"),
    }
}

/*-************************************
 *  Frames, put together or taken apart
 **************************************/

/// A frame header, with its checksum: FLG and BD as given, then the content
/// size and dictionary ID when FLG says so.
fn frame_header(flg: u8, bd: u8, content_size: u64, dict_id: u32) -> Vec<u8> {
    let mut header = 0x184D_2204u32.to_le_bytes().to_vec();
    header.push(flg);
    header.push(bd);
    if flg & 0x08 != 0 {
        header.extend_from_slice(&content_size.to_le_bytes());
    }
    if flg & 0x01 != 0 {
        header.extend_from_slice(&dict_id.to_le_bytes());
    }
    header.push((xxh32(&header[4..], 0) >> 8) as u8);
    header
}

/// A frame cut into its header and its blocks (block header, data and
/// checksum), without the end mark and content checksum.
struct FrameParts {
    flg: u8,
    bd: u8,
    blocks: Vec<Vec<u8>>,
}

fn frame_parts(frame: &[u8]) -> FrameParts {
    let flg = frame[4];
    let bd = frame[5];
    let mut at = 7 + if flg & 0x08 != 0 { 8 } else { 0 } + if flg & 0x01 != 0 { 4 } else { 0 };
    let checksum = if flg & 0x10 != 0 { 4 } else { 0 };
    let mut blocks = Vec::new();
    loop {
        let header = u32::from_le_bytes(frame[at..at + 4].try_into().unwrap());
        if header == 0 {
            break;
        }
        let size = (header & 0x7FFF_FFFF) as usize;
        blocks.push(frame[at..at + 4 + size + checksum].to_vec());
        at += 4 + size + checksum;
    }
    FrameParts { flg, bd, blocks }
}

/// A frame of `blocks`, with the flags `flg` and `bd` (the content size
/// and checksum of `content`, when they say so).
fn frame_of(flg: u8, bd: u8, blocks: &[Vec<u8>], content: &[u8], dict_id: u32) -> Vec<u8> {
    let mut frame = frame_header(flg, bd, content.len() as u64, dict_id);
    for block in blocks {
        frame.extend_from_slice(block);
    }
    frame.extend_from_slice(&[0; 4]);
    if flg & 0x04 != 0 {
        frame.extend_from_slice(&xxh32(content, 0).to_le_bytes());
    }
    frame
}

/// A skippable frame of `len` bytes of anything.
fn skippable(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut frame = (0x184D_2A50u32 + rng.below(16) as u32)
        .to_le_bytes()
        .to_vec();
    frame.extend_from_slice(&(len as u32).to_le_bytes());
    frame.extend((0..len).map(|_| rng.next() as u8));
    frame
}

/// Data compressed in linked blocks of 64 KB: the blocks after the first,
/// and the 64 KB before them, their dictionary.
fn linked_blocks(rng: &mut Rng, data: &[u8], level: u32, block_checksum: bool) -> FrameParts {
    let settings = FrameSettings {
        block_size: 4,
        independent: false,
        block_checksum,
        content_checksum: false,
        content_size: false,
        level,
        auto_flush: false,
        favor_dec_speed: false,
    };
    frame_parts(&c_compress_frame(rng, data, settings))
}

/// A block made up here, from sequences of random literal lengths, offsets
/// (0, and past the history, included) and match lengths, valid or not:
/// what liblz4's compressors never write.
fn synthetic_block(rng: &mut Rng, history: usize, out_len: usize) -> Vec<u8> {
    let mut block = Vec::new();
    let mut produced = 0usize;
    let length_bytes = |block: &mut Vec<u8>, mut rest: usize| {
        while rest >= 255 {
            block.push(255);
            rest -= 255;
        }
        block.push(rest as u8);
    };
    let strict = rng.below(3) > 0;
    loop {
        let room = out_len.saturating_sub(produced);
        let last = room < 20 || rng.below(40) == 0;
        let literals = if last {
            if strict {
                room
            } else {
                rng.below(room as u64 + 3) as usize
            }
        } else {
            match rng.below(4) {
                0 => 0,
                1 => rng.below(15) as usize,
                2 => 15 + rng.below(300) as usize,
                _ => rng.below(5) as usize,
            }
        };
        let literals = if strict && !last {
            literals.min(room.saturating_sub(17))
        } else {
            literals
        };
        let match_len = 4 + match rng.below(4) {
            0 => rng.below(15),
            1 => 15 + rng.below(600),
            _ => rng.below(30),
        } as usize;
        let match_len = if strict {
            match_len
                .min(out_len.saturating_sub(produced + literals + 12))
                .max(4)
        } else {
            match_len
        };
        let token_lit = literals.min(15) as u8;
        let token_match = (match_len - 4).min(15) as u8;
        block.push(token_lit << 4 | if last { 0 } else { token_match });
        if literals >= 15 {
            length_bytes(&mut block, literals - 15);
        }
        block.extend((0..literals).map(|_| rng.next() as u8));
        produced += literals;
        if last {
            break;
        }
        let reach = history + produced;
        let offset = match rng.below(12) {
            0 => 0,
            1 => reach + 1 + rng.below(10) as usize,
            2 => 1 + rng.below(16) as usize,
            3 => 65535,
            _ => 1 + rng.below(reach.clamp(1, 65535) as u64) as usize,
        }
        .min(65535);
        block.extend_from_slice(&(offset as u16).to_le_bytes());
        if match_len - 4 >= 15 {
            length_bytes(&mut block, match_len - 4 - 15);
        }
        produced += match_len;
        if produced > out_len + 100 {
            break;
        }
    }
    block
}

/*-************************************
 *  Requests
 **************************************/

/// A length for an input: empty, short, or up to `max`.
fn length(rng: &mut Rng, max: usize) -> usize {
    match rng.below(10) {
        0 => rng.below(20) as usize,
        1..=3 => rng.below(1000) as usize,
        4..=6 => rng.below(20_000) as usize,
        _ => rng.below(max as u64 + 1) as usize,
    }
}

fn level(rng: &mut Rng) -> i32 {
    match rng.below(5) {
        0 => -(1 + rng.below(70) as i32),
        1 => 0,
        2 => 1 + rng.below(2) as i32,
        3 => 3 + rng.below(7) as i32,
        _ => 10 + rng.below(3) as i32,
    }
}

/// Steps for a frame of `len` bytes decoding to about `out_len`: input and
/// output in pieces of random sizes, enough of them to finish, now and then
/// a frame info or a reset.
fn frame_steps(rng: &mut Rng, len: usize, out_len: usize, with_info: bool) -> String {
    let mut steps = Vec::new();
    let style = rng.below(5);
    // Or the same output space for every call: a block flushed from tmpOut
    // over several calls, at and around 64 KB.
    let uniform = (rng.below(4) == 0).then(|| rng.pick(&[1, 1000, 65535, 65536, 65537, 131_072]));
    let (mut given, mut room) = (0usize, 0usize);
    if with_info && rng.below(3) == 0 {
        steps.push(format!("i{}", rng.pick(&[3, 7, 15, 19, 100])));
    }
    while (given < len + 8 || room < out_len + 8) && steps.len() < 400 {
        let input = if given >= len + 8 {
            rng.below(3) as usize
        } else {
            match style {
                0 => len + 10,
                1 => 1 + rng.below(20) as usize,
                2 => 1 + rng.below(70_000) as usize,
                _ => rng.pick(&[0, 1, 4, 7, 19, 100, 4096, 65536, 70_000, len + 10]),
            }
        };
        let output = if let Some(size) = uniform {
            size
        } else if room >= out_len + 8 {
            rng.below(3) as usize
        } else {
            match rng.below(6) {
                0 => 0,
                1 => 1 + rng.below(100) as usize,
                2 => 65536,
                3 => out_len + 10,
                4 => rng
                    .pick(&[4 << 20, 1 << 20, 256 << 10])
                    .min(out_len + 70_000),
                _ => 1 + rng.below(300_000) as usize,
            }
        };
        if with_info && rng.below(30) == 0 {
            steps.push(format!("i{input}"));
        }
        steps.push(format!("d{input}/{output}"));
        given += input;
        room += output;
    }
    steps.push(format!("d{}/{}", len + 10, out_len + 70_000));
    steps.join(",")
}

/// Generated requests: about `count` of each kind, with inputs up to `max`
/// bytes.
fn requests(rng: &mut Rng, count: usize, max: usize) -> Vec<String> {
    let mut requests = Vec::new();

    // A few by hand: empty and one-byte blocks, outputs of 0 bytes.
    for data in [
        "-",
        "00",
        "01",
        "10",
        "1061",
        "f0",
        "0f0100",
        "00ff",
        "40616263640000",
    ] {
        for capacity in [0, 1, 5, 64] {
            requests.push(format!("block s {capacity} 0 - {data}"));
            requests.push(format!("block p {capacity} 3 - {data}"));
        }
    }
    for data in [
        "-",
        "04",
        "04224d",
        "04224d18",
        "04224d1864",
        "502a4d18",
        "5f2a4d18ff",
        "00000000",
    ] {
        requests.push(format!("header {data}"));
        requests.push(format!("frame - 0 d100/100,d100/100 {data}"));
        requests.push(format!("frame - 0 i100,d100/100 {data}"));
    }

    // XXH32, in one call and in pieces.
    for _ in 0..count {
        let len = rng.below(300) as usize;
        let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let any = rng.next() as u32;
        let seed = rng.pick(&[0, 1, 0x9e37_79b1, any]);
        let pieces: Vec<String> = (0..rng.below(6))
            .map(|_| rng.below(40).to_string())
            .collect();
        let pieces = if pieces.is_empty() {
            "-".into()
        } else {
            pieces.join(",")
        };
        requests.push(format!("xxh32 {seed} {pieces} {}", hex(&data)));
    }

    // Blocks liblz4 compressed, decoded whole, partially, damaged.
    for _ in 0..count {
        let len = length(rng, max);
        let data = input(rng, len);
        let block = c_compress_block(&data, level(rng));
        let block = if rng.below(4) == 0 {
            damage(rng, &block)
        } else {
            block
        };
        let capacity = match rng.below(5) {
            0 => len.saturating_sub(rng.below(20) as usize),
            1 => len + rng.below(80) as usize,
            _ => len,
        };
        let target = rng.below(len as u64 + 20) as usize;
        let mode = rng.pick(&["s", "s", "p", "d", "x"]);
        let block = if mode == "p" && rng.below(2) == 0 {
            block[..rng.below(block.len() as u64 + 1) as usize].to_vec()
        } else {
            block
        };
        requests.push(format!(
            "block {mode} {capacity} {target} - {}",
            hex(&block)
        ));
    }

    // Blocks after a dictionary: the second and later blocks of liblz4's
    // linked frames, with the 64 KB before them in front of the output or
    // apart from it, some of it, or none. They are large: only a few are
    // recorded.
    let large = if max >= 65536 { count } else { 2 };
    for _ in 0..large {
        let len = 65536 + length(rng, max);
        let data = input(rng, len);
        let level = rng.pick(&[0, 0, 3, 9, 12]);
        let parts = linked_blocks(rng, &data, level, false);
        if parts.blocks.len() < 2 {
            continue;
        }
        let index = 1 + rng.below(parts.blocks.len() as u64 - 1) as usize;
        let raw = &parts.blocks[index];
        let header = u32::from_le_bytes(raw[..4].try_into().unwrap());
        if header & 0x8000_0000 != 0 {
            // Stored as it is.
            continue;
        }
        let mut block = raw[4..].to_vec();
        let start = index * 65536;
        let block_len = (len - start).min(65536);
        let dict_len = match rng.below(4) {
            0 => rng.below(65537) as usize,
            1 => 65535,
            _ => 65536,
        };
        let dict = &data[start - dict_len..start];
        if rng.below(5) == 0 {
            block = damage(rng, &block);
        }
        let capacity = match rng.below(4) {
            0 => block_len.saturating_sub(rng.below(20) as usize),
            1 => block_len + rng.below(80) as usize,
            _ => block_len,
        };
        let target = rng.below(block_len as u64 + 20) as usize;
        let mode = rng.pick(&["d", "q", "x", "y", "s"]);
        requests.push(format!(
            "block {mode} {capacity} {target} {} {}",
            hex(dict),
            hex(&block)
        ));
    }

    // Blocks made up here: every offset and length, after histories of
    // every size.
    for _ in 0..count {
        let history = if max >= 65536 || rng.below(15) == 0 {
            rng.pick(&[0, 0, 1, 7, 100, 4000, 65535, 65536, 70_000])
        } else {
            rng.pick(&[0, 0, 1, 7, 100, 1000])
        };
        let history = history.min(rng.below(history as u64 + 1) as usize * 2);
        let dict: Vec<u8> = (0..history).map(|_| rng.below(4) as u8).collect();
        let out_len = rng
            .pick(&[1, 13, 30, 64, 100, 200, 1000, 5000, 70_000])
            .min(max.max(1000));
        let block = synthetic_block(rng, history, out_len);
        let capacity = match rng.below(3) {
            0 => out_len,
            1 => out_len + rng.below(100) as usize,
            _ => rng.below(out_len as u64 + 1) as usize,
        };
        let target = rng.below(out_len as u64 + 20) as usize;
        let mode = rng.pick(&["s", "p", "d", "q", "x", "y"]);
        let dict = if mode == "s" || mode == "p" {
            "-".to_string()
        } else {
            hex(&dict)
        };
        requests.push(format!(
            "block {mode} {capacity} {target} {dict} {}",
            hex(&block)
        ));
    }

    // Streams of blocks: the blocks of a linked frame, one after another.
    for _ in 0..count / 4 {
        let len = length(rng, max * 3);
        let data = input(rng, len);
        let level = rng.pick(&[0, 9]);
        let parts = linked_blocks(rng, &data, level, false);
        let blocks: Vec<String> = parts
            .blocks
            .iter()
            .filter(|raw| u32::from_le_bytes(raw[..4].try_into().unwrap()) & 0x8000_0000 == 0)
            .map(|raw| {
                if rng.below(20) == 0 {
                    hex(&damage(rng, &raw[4..]))
                } else {
                    hex(&raw[4..])
                }
            })
            .collect();
        if blocks.is_empty() {
            continue;
        }
        let capacity = rng.pick(&[65536, 65536, 70_000, 1000]);
        if blocks.len() > 1 && rng.below(2) == 0 {
            // The first block's data as the dictionary of the others.
            let dict = &data[65536 - rng.below(65537) as usize..65536];
            requests.push(format!(
                "stream {} {capacity} {}",
                hex(dict),
                blocks[1..].join(",")
            ));
        } else {
            requests.push(format!("stream - {capacity} {}", blocks.join(",")));
        }
    }

    // Streams of blocks made up here, valid or not, with every offset into
    // the blocks before and the dictionary.
    for _ in 0..count / 2 {
        let dict_len = rng
            .pick(&[0, 0, 10, 1000, 65535, 65536])
            .min(if max >= 65536 { 65536 } else { 1000 });
        let dict: Vec<u8> = (0..dict_len).map(|_| rng.below(4) as u8).collect();
        let mut history = dict_len;
        let mut blocks = Vec::new();
        let out_len = rng.pick(&[13, 30, 64, 100, 1000]);
        for _ in 0..1 + rng.below(5) {
            blocks.push(hex(&synthetic_block(rng, history, out_len)));
            history += out_len;
        }
        let capacity = out_len + rng.pick(&[0, 0, 1, 10, 100]);
        requests.push(format!(
            "stream {} {capacity} {}",
            hex(&dict),
            blocks.join(",")
        ));
    }

    // Frames liblz4 compressed with every setting, in pieces, some damaged,
    // cut short, or followed by more.
    for _ in 0..count {
        let len = length(rng, max);
        let data = input(rng, len);
        let settings = FrameSettings::random(rng);
        let mut frame = c_compress_frame(rng, &data, settings);
        match rng.below(8) {
            0 | 1 => frame = damage(rng, &frame),
            2 => {
                let at = rng.below(frame.len() as u64) as usize;
                frame.truncate(at);
            }
            3 => {
                let more = if rng.below(2) == 0 {
                    let settings = FrameSettings::random(rng);
                    c_compress_frame(rng, &data[..data.len() / 2], settings)
                } else {
                    let len = rng.below(100) as usize;
                    skippable(rng, len)
                };
                frame.extend_from_slice(&more);
            }
            _ => {}
        }
        let skip = u32::from(rng.below(6) == 0);
        let steps = frame_steps(rng, frame.len(), len, true);
        requests.push(format!("frame - {skip} {steps} {}", hex(&frame)));
    }

    // Frames put together here: linked blocks with their dictionary, and
    // every header flag and field.
    for _ in 0..large {
        let len = 65536 + length(rng, max);
        let data = input(rng, len);
        let block_checksum = rng.below(2) == 0;
        let level = rng.pick(&[0, 9]);
        let parts = linked_blocks(rng, &data, level, block_checksum);
        let with_dict = rng.below(3) > 0 && parts.blocks.len() > 1;
        let (blocks, content, dict) = if with_dict {
            (&parts.blocks[1..], &data[65536..], &data[..65536])
        } else {
            (&parts.blocks[..], &data[..], &data[..0])
        };
        let mut flg = parts.flg & !0x0D;
        if rng.below(2) == 0 {
            flg |= 0x04; // content checksum
        }
        if rng.below(3) == 0 {
            flg |= 0x08; // content size
        }
        if rng.below(4) == 0 {
            flg |= 0x01; // dictionary ID
        }
        let mut bd = parts.bd;
        match rng.below(20) {
            0 => flg ^= 0x02,                  // reserved
            1 => flg ^= 0x40 << rng.below(2),  // version
            2 => bd = rng.below(4) as u8 * 16, // block size ID
            3 => bd |= 1 << rng.below(4),      // reserved
            4 => bd |= 0x80,                   // reserved
            5 => flg ^= 0x20,                  // independent blocks
            _ => {}
        }
        let mut frame = frame_of(flg, bd, blocks, content, rng.next() as u32);
        if rng.below(8) == 0 {
            frame = damage(rng, &frame);
        }
        if rng.below(6) == 0 {
            // The content size wrong.
            let sized = frame_of(flg | 0x08, bd, blocks, &content[..content.len() - 1], 0);
            frame = sized;
        }
        if rng.below(5) == 0 {
            let len = rng.below(70) as usize;
            let mut framed = skippable(rng, len);
            framed.extend_from_slice(&frame);
            frame = framed;
        }
        let dict = if with_dict || rng.below(4) == 0 {
            let cut = rng.below(4);
            let dict = if cut == 0 {
                &dict[dict.len() - rng.below(dict.len() as u64 + 1) as usize..]
            } else {
                dict
            };
            hex(dict)
        } else {
            "-".to_string()
        };
        let skip = u32::from(rng.below(6) == 0);
        let steps = frame_steps(rng, frame.len(), content.len(), true);
        requests.push(format!("frame {dict} {skip} {steps} {}", hex(&frame)));
    }

    // Frames of uncompressed blocks, stored as they are, with their
    // checksums.
    for _ in 0..count / 2 {
        let len = length(rng, max.min(300_000));
        let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let settings = FrameSettings {
            block_size: rng.pick(&[4, 5]),
            block_checksum: rng.below(2) == 0,
            ..FrameSettings::random(rng)
        };
        let mut frame = c_compress_frame(rng, &data, settings);
        if rng.below(4) == 0 {
            frame = damage(rng, &frame);
        }
        let skip = u32::from(rng.below(4) == 0);
        let steps = frame_steps(rng, frame.len(), len, false);
        requests.push(format!("frame - {skip} {steps} {}", hex(&frame)));
    }

    // Blocks compressed alone, one state for several, into outputs of
    // every size: enough, too small, or just about right.
    let accels = [-3, 0, 1, 1, 1, 2, 9, 70, 65537, 70_000];
    for _ in 0..count {
        let accel = rng.pick(&accels);
        let n = 1 + rng.below(4) as usize;
        let mut lens = Vec::new();
        let blocks: Vec<String> = (0..n)
            .map(|_| {
                let len = match rng.below(6) {
                    0 => rng.below(20) as usize,
                    1 => 65536 + rng.below(30) as usize - 15,
                    _ => length(rng, max),
                };
                lens.push(len);
                hex(&input(rng, len))
            })
            .collect();
        let biggest = lens.iter().copied().max().unwrap_or(0);
        let bound = block::compress_bound(biggest);
        let capacity = match rng.below(4) {
            0 => bound,
            1 => bound - rng.below(bound as u64 / 4 + 1) as usize,
            2 => rng.below(biggest as u64 + 20) as usize,
            _ => biggest / 2,
        };
        requests.push(format!("compress {accel} {capacity} {}", blocks.join(",")));
    }

    // As much as fits.
    for _ in 0..count / 2 {
        let len = length(rng, max);
        let data = input(rng, len);
        let capacity = match rng.below(4) {
            0 => rng.below(20) as usize,
            1 => block::compress_bound(len),
            _ => rng.below(len as u64 + 50) as usize,
        };
        // liblz4 does not clamp the acceleration here: below 1 its search
        // goes backwards (undefined behaviour), so only 1 and up.
        let accel = rng.pick(&[1, 1, 2, 9, 70, 65537, 70_000]);
        requests.push(format!("destsize {accel} {capacity} {}", hex(&data)));
    }

    // Streams of blocks, after a dictionary loaded or attached.
    for _ in 0..count / 2 {
        let dict_len = match rng.below(5) {
            0 => rng.below(10) as usize,
            1 => 70_000.min(max + 1000),
            _ => rng.below(max.min(70_000) as u64) as usize,
        };
        let dict = input(rng, dict_len);
        let how = rng.pick(&["l", "s", "a"]);
        let n = 1 + rng.below(5) as usize;
        let mut lens = Vec::new();
        let blocks: Vec<String> = (0..n)
            .map(|_| {
                let len = match rng.below(5) {
                    0 => rng.below(10) as usize,
                    1 => 4096 + rng.below(4) as usize,
                    _ => rng.below(max.min(70_000) as u64) as usize,
                };
                lens.push(len);
                // Blocks like the dictionary, to find matches in it.
                let mut data = input(rng, len);
                if !dict.is_empty() && rng.below(2) == 0 {
                    for chunk in data.chunks_mut(97) {
                        let at = rng.below(dict.len() as u64) as usize;
                        let take = chunk.len().min(dict.len() - at);
                        chunk[..take].copy_from_slice(&dict[at..at + take]);
                    }
                }
                hex(&data)
            })
            .collect();
        let biggest = lens.iter().copied().max().unwrap_or(0);
        let bound = block::compress_bound(biggest);
        let capacity = if rng.below(4) == 0 {
            biggest / 2 + 1
        } else {
            bound
        };
        let accel = rng.pick(&accels);
        requests.push(format!(
            "cstream {} {how} {accel} {capacity} {}",
            hex(&dict),
            blocks.join(",")
        ));
    }

    // High compression, at every level, alone and in streams.
    let levels = [-1, 0, 1, 2, 2, 3, 4, 6, 9, 9, 10, 11, 12, 13];
    let hc_max = if max >= 65536 { max / 2 } else { max };
    for _ in 0..count / 2 {
        let level = rng.pick(&levels);
        let n = 1 + rng.below(3) as usize;
        let mut lens = Vec::new();
        let blocks: Vec<String> = (0..n)
            .map(|_| {
                let len = length(rng, hc_max);
                lens.push(len);
                hex(&input(rng, len))
            })
            .collect();
        let biggest = lens.iter().copied().max().unwrap_or(0);
        let bound = block::compress_bound(biggest);
        let capacity = match rng.below(4) {
            0 => bound,
            1 => bound - rng.below(bound as u64 / 4 + 1) as usize,
            2 => rng.below(biggest as u64 + 20) as usize,
            _ => biggest / 2,
        };
        requests.push(format!("hc {level} {capacity} {}", blocks.join(",")));
    }
    for _ in 0..count / 3 {
        let len = length(rng, hc_max);
        let data = input(rng, len);
        let capacity = match rng.below(4) {
            0 => rng.below(20) as usize,
            1 => block::compress_bound(len),
            _ => rng.below(len as u64 + 50) as usize,
        };
        let level = rng.pick(&levels);
        requests.push(format!("hcdest {level} {capacity} {}", hex(&data)));
    }
    for _ in 0..count / 3 {
        let dict_len = match rng.below(4) {
            0 => rng.below(10) as usize,
            _ => rng.below(hc_max.min(70_000) as u64) as usize,
        };
        let dict = input(rng, dict_len);
        let how = rng.pick(&["l", "a", "f"]);
        let level = rng.pick(&levels);
        let n = 1 + rng.below(4) as usize;
        let mut lens = Vec::new();
        let blocks: Vec<String> = (0..n)
            .map(|_| {
                let len = match rng.below(4) {
                    0 => rng.below(10) as usize,
                    1 => 4096 + rng.below(4) as usize,
                    _ => rng.below(hc_max.min(70_000) as u64) as usize,
                };
                lens.push(len);
                let mut data = input(rng, len);
                if !dict.is_empty() && rng.below(2) == 0 {
                    for chunk in data.chunks_mut(97) {
                        let at = rng.below(dict.len() as u64) as usize;
                        let take = chunk.len().min(dict.len() - at);
                        chunk[..take].copy_from_slice(&dict[at..at + take]);
                    }
                }
                hex(&data)
            })
            .collect();
        let biggest = lens.iter().copied().max().unwrap_or(0);
        let bound = block::compress_bound(biggest);
        let capacity = if rng.below(4) == 0 {
            biggest / 2 + 1
        } else {
            bound
        };
        requests.push(format!(
            "hcstream {} {how} {level} {capacity} {}",
            hex(&dict),
            blocks.join(",")
        ));
    }

    // Header sizes.
    for _ in 0..count / 2 {
        let frame = match rng.below(3) {
            0 => frame_header(rng.next() as u8, rng.next() as u8, 0, 0),
            1 => skippable(rng, 3),
            _ => (0..8).map(|_| rng.next() as u8).collect(),
        };
        let cut = rng.below(frame.len() as u64 + 1) as usize;
        requests.push(format!("header {}", hex(&frame[..cut])));
    }

    requests
}

#[test]
fn port_matches_liblz4() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x5eed_1204);
    let requests = requests(&mut rng, 150, 200_000);
    let mut checked = 0;
    for request in &requests {
        let want = oracle.ask(request);
        let got = answer(request);
        if got != want
            && let Some(path) = std::env::var_os("LZ4_ORACLE_DUMP")
        {
            // The whole request, to replay by hand.
            let _ = std::fs::write(path, request);
        }
        assert_eq!(got, want, "{request:.400}");
        checked += 1;
    }
    eprintln!("{checked} requests compared with liblz4");
}

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/lz4.txt");
    let mut checked = 0;
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let (request, want) = line.split_once('\t').expect("request and answer");
        assert_eq!(recorded_form(&answer(request)), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked > 500, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/lz4.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng(0x5eed_1205);
    let mut text = String::from(
        "# Answers from liblz4 1.10.0 (tools/lz4-oracle), replayed by crates/lz4/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack-lz4 --test oracle record_oracle_answers -- --ignored\n",
    );
    for request in requests(&mut rng, 90, 3000) {
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{}", recorded_form(&reply));
    }
    std::fs::create_dir_all(recorded_path().parent().expect("folder")).expect("folder");
    std::fs::write(recorded_path(), text).expect("written");
}
