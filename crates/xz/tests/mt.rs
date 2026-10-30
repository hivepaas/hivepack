//! The threaded encoder where liblzma's results depend on its threads, so
//! that the oracle tests cannot compare them: a timeout that makes calls
//! return early, the progress of the threads, many threads, and a stream
//! dropped while its threads work. The output, which does not depend on
//! them, is compared with liblzma's in `oracle.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use hivepack_xz::{Action, Check, InBuffer, MtOptions, OutBuffer, Status, Stream};
use support::{Rng, input};

/// `data` encoded by the threaded encoder with `options`, with LZMA_FINISH
/// and `room` bytes of output space per call: the Stream, and the number
/// of calls that made no progress.
fn encode(options: &MtOptions, data: &[u8], room: usize) -> (Vec<u8>, usize) {
    let mut strm = Stream::stream_encoder_mt(options).unwrap();
    let mut out = Vec::new();
    let mut input = InBuffer::new(data);
    let mut idle = 0;
    loop {
        let written = out.len();
        out.resize(written + room, 0);
        let before = input.pos;
        let mut output = OutBuffer::new(&mut out[written..]);
        let status = strm.code(&mut output, &mut input, Action::Finish).unwrap();
        let made = output.pos;
        out.truncate(written + made);
        idle += usize::from(made == 0 && input.pos == before);
        if status == Status::StreamEnd {
            return (out, idle);
        }
    }
}

/// The data of a .xz Stream.
fn decode(xz: &[u8], len: usize) -> Vec<u8> {
    let mut strm = Stream::stream_decoder(u64::MAX, 0).unwrap();
    let mut out = vec![0; len + 1];
    let mut output = OutBuffer::new(&mut out);
    let status = strm
        .code(&mut output, &mut InBuffer::new(xz), Action::Finish)
        .unwrap();
    assert_eq!(status, Status::StreamEnd);
    let written = output.pos;
    out.truncate(written);
    out
}

fn options(threads: u32, block_size: u64, preset: u32) -> MtOptions {
    MtOptions {
        threads,
        block_size,
        preset,
        check: Check::CRC64,
        ..MtOptions::default()
    }
}

#[test]
fn a_timeout_returns_early_with_the_same_output() {
    // Random bytes, which take long to compress.
    let mut rng = Rng(0x5eed_3701);
    let data: Vec<u8> = (0..3 << 20).map(|_| rng.next() as u8).collect();
    let without = encode(&options(2, 256 << 10, 6), &data, 1 << 20).0;
    let with = MtOptions {
        timeout: 1,
        ..options(2, 256 << 10, 6)
    };
    let (out, idle) = encode(&with, &data, 1 << 20);
    assert_eq!(out, without);
    // Each Block takes much longer than a millisecond at preset 6.
    assert!(idle > 0, "no call timed out");
    assert_eq!(decode(&out, data.len()), data);
}

#[test]
fn the_progress_grows_to_the_totals() {
    let mut rng = Rng(0x5eed_3702);
    let data = input(&mut rng, 2 << 20);
    let mut strm = Stream::stream_encoder_mt(&options(3, 128 << 10, 3)).unwrap();
    let mut out = vec![0; 3 << 20];
    let mut input = InBuffer::new(&data);
    let mut written = 0;
    let mut last = (0, 0);
    loop {
        let end = (written + 4096).min(out.len());
        let mut output = OutBuffer::new(&mut out[written..end]);
        let status = strm.code(&mut output, &mut input, Action::Finish).unwrap();
        written += output.pos;
        // The output may shrink: a Block that does not compress is
        // written again as it is, in less than its compressed size.
        let progress = strm.get_progress();
        assert!(progress.0 >= last.0, "{progress:?} after {last:?}");
        assert!(progress.0 <= data.len() as u64);
        last = progress;
        if status == Status::StreamEnd {
            break;
        }
    }
    assert_eq!(last, (strm.total_in(), strm.total_out()));
    assert_eq!(decode(&out[..written], data.len()), data);
}

#[test]
fn many_threads_and_small_blocks() {
    let mut rng = Rng(0x5eed_3703);
    let data = input(&mut rng, 1 << 20);
    let (out, _) = encode(&options(16, 1000, 1), &data, 1 << 16);
    assert_eq!(decode(&out, data.len()), data);
    // The same Stream as one thread writes.
    assert_eq!(out, encode(&options(1, 1000, 1), &data, 1 << 20).0);
}

#[test]
fn a_stream_dropped_while_its_threads_work() {
    let mut rng = Rng(0x5eed_3704);
    let data: Vec<u8> = (0..4 << 20).map(|_| rng.next() as u8).collect();
    for threads in [1, 4] {
        let mut strm = Stream::stream_encoder_mt(&options(threads, 256 << 10, 6)).unwrap();
        let mut out = vec![0; 1 << 16];
        let mut input = InBuffer::new(&data);
        // Until the output is full or all the input is given.
        strm.code(&mut OutBuffer::new(&mut out), &mut input, Action::Run)
            .unwrap();
        // The workers are encoding: they are told to exit and joined.
        drop(strm);
    }
}

#[test]
fn the_number_of_hardware_threads() {
    assert!(hivepack_xz::cputhreads() > 0);
}
