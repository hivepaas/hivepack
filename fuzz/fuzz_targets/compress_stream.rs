//! Streams the input through the port and libzstd with the same
//! parameters, in the same pieces, with the same directives and the same
//! room for output, all picked by its first 8 bytes, and checks that every
//! call returns the same, moves as far and writes the same, and that the
//! port decodes the frame back. A panic or a difference is a bug.

#![no_main]

use hivepack_zstd::{CCtx, CParameter as P, EndDirective, ParamSwitch, Strategy};
use libfuzzer_sys::fuzz_target;
use zstd::zstd_safe::{self, CParameter as C, zstd_sys::ZSTD_EndDirective};

/// Calls more than this mean no progress.
const MAX_CALLS: usize = 100_000;

/// xorshift64*, seeded by the input.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A piece size: mostly small, sometimes a few blocks.
    fn piece(&mut self) -> usize {
        let bits = self.next();
        let size = match bits % 4 {
            0 => (bits >> 8) % 16,
            1 => (bits >> 8) % 1000,
            2 => (bits >> 8) % 20_000,
            _ => (bits >> 8) % 300_000,
        };
        size as usize
    }
}

fn name(code: usize) -> String {
    zstd_safe::get_error_name(code).to_string()
}

fuzz_target!(|input: &[u8]| {
    if input.len() < 8 {
        return;
    }
    let (head, src) = input.split_at(8);
    let level =
        [-100, -5, -1, 1, 2, 3, 4, 5, 6, 7, 8, 10, 13, 16, 19, 22][usize::from(head[0]) % 16];
    let window_log = 10 + u32::from(head[1] % 12);
    let stable_out = head[2] & 1 != 0;
    let checksum = head[2] & 2 != 0;
    let max_block = [0, 1024, 4096, 65_536][usize::from(head[2] >> 2) % 4];
    let ldm = head[2] & 16 != 0;
    let mut rng = Rng(u64::from(u32::from_le_bytes([head[3], head[4], head[5], head[6]])) | 1);

    let mut parameters = vec![
        (P::CompressionLevel(level), C::CompressionLevel(level)),
        (P::ChecksumFlag(checksum), C::ChecksumFlag(checksum)),
        (
            P::StableOutBuffer(stable_out),
            C::StableOutBuffer(stable_out),
        ),
        (P::MaxBlockSize(max_block), C::MaxBlockSize(max_block)),
    ];
    // Long distance matching needs a window set: it would take 2^27 bytes.
    if head[7] & 1 != 0 || ldm {
        parameters.push((P::WindowLog(window_log), C::WindowLog(window_log)));
    }
    if ldm {
        // Small parameters, so that it finds matches in small inputs; some
        // left to the library.
        parameters.push((
            P::EnableLongDistanceMatching(ParamSwitch::Enable),
            C::EnableLongDistanceMatching(true),
        ));
        let pick = head[2] >> 5;
        if pick & 1 != 0 {
            let value = 4 + (rng.next() % 61) as u32;
            parameters.push((P::LdmMinMatch(value), C::LdmMinMatch(value)));
        }
        if pick & 2 != 0 {
            let value = (rng.next() % 5) as u32;
            parameters.push((P::LdmHashRateLog(value), C::LdmHashRateLog(value)));
        }
        if pick & 4 != 0 {
            let value = 6 + (rng.next() % 15) as u32;
            parameters.push((P::LdmHashLog(value), C::LdmHashLog(value)));
            let value = 1 + (rng.next() % 8) as u32;
            parameters.push((P::LdmBucketSizeLog(value), C::LdmBucketSizeLog(value)));
        }
    }
    {
        use zstd_safe::Strategy as S;
        let strategies = [
            (Strategy::Fast, S::ZSTD_fast),
            (Strategy::Dfast, S::ZSTD_dfast),
            (Strategy::Greedy, S::ZSTD_greedy),
            (Strategy::Lazy, S::ZSTD_lazy),
            (Strategy::Lazy2, S::ZSTD_lazy2),
            (Strategy::Btlazy2, S::ZSTD_btlazy2),
            (Strategy::Btopt, S::ZSTD_btopt),
            (Strategy::Btultra, S::ZSTD_btultra),
            (Strategy::Btultra2, S::ZSTD_btultra2),
        ];
        let pick = usize::from(head[7] >> 1 & 7) + 8 * usize::from(head[2] >> 7);
        if let Some(&(p, c)) = strategies.get(pick) {
            parameters.push((P::Strategy(Some(p)), C::Strategy(c)));
        }
    }
    if rng.next() % 4 == 0 {
        // The optimal parser's 3-byte hash table.
        parameters.push((P::MinMatch(3), C::MinMatch(3)));
    }
    let switches = [
        (ParamSwitch::Auto, zstd_safe::ParamSwitch::Auto),
        (ParamSwitch::Enable, zstd_safe::ParamSwitch::Enable),
        (ParamSwitch::Disable, zstd_safe::ParamSwitch::Disable),
    ];
    let (p_row, c_row) = switches[usize::from(head[7] >> 4) % 3];
    parameters.push((P::UseRowMatchFinder(p_row), C::UseRowMatchFinder(c_row)));
    // The block splitter after the sequences.
    let (p_split, c_split) = switches[usize::from(head[2] >> 4) % 3];
    parameters.push((
        P::SplitAfterSequences(p_split),
        C::UseBlockSplitter(c_split),
    ));

    let mut c = zstd_safe::CCtx::create();
    let mut p = CCtx::new();
    for (pp, cp) in parameters {
        let want = c.set_parameter(cp).map(|_| ()).map_err(name);
        let got = p
            .set_parameter(pp)
            .map_err(|error| error.code().message().to_string());
        assert!(
            want == got,
            "setting {pp:?}: libzstd {want:?}, port {got:?}"
        );
    }

    // With a stable output buffer, one buffer whose room stays the same.
    let room = hivepack_zstd::compress_bound(src.len()).unwrap_or(0) + 64;
    let (mut c_stable, mut p_stable) = if stable_out {
        (vec![0u8; room], vec![0u8; room])
    } else {
        (Vec::new(), Vec::new())
    };
    let mut stable_pos = 0;
    let mut frame = Vec::new();
    let mut taken = 0;
    for call in 0..MAX_CALLS {
        let in_end = (taken + rng.piece()).min(src.len());
        let directive = if in_end == src.len() && rng.next() % 4 != 0 {
            EndDirective::End
        } else if rng.next() % 8 == 0 {
            EndDirective::Flush
        } else {
            EndDirective::Continue
        };
        let c_directive = match directive {
            EndDirective::Continue => ZSTD_EndDirective::ZSTD_e_continue,
            EndDirective::Flush => ZSTD_EndDirective::ZSTD_e_flush,
            EndDirective::End => ZSTD_EndDirective::ZSTD_e_end,
        };
        let (mut c_fresh, mut p_fresh, out_pos) = if stable_out {
            (Vec::new(), Vec::new(), stable_pos)
        } else {
            let size = rng.piece();
            (vec![0u8; size], vec![0u8; size], 0)
        };
        let (c_dst, p_dst) = if stable_out {
            (&mut c_stable[..], &mut p_stable[..])
        } else {
            (&mut c_fresh[..], &mut p_fresh[..])
        };
        let piece = &src[taken..in_end];

        let (want, ci, co) = {
            let mut output = zstd_safe::OutBuffer::around_pos(&mut *c_dst, out_pos);
            let mut input = zstd_safe::InBuffer::around(piece);
            let result = c.compress_stream2(&mut output, &mut input, c_directive);
            (result.map_err(name), input.pos(), output.pos())
        };
        let (got, pi, po) = {
            let mut output = hivepack_zstd::OutBuffer {
                dst: &mut *p_dst,
                pos: out_pos,
            };
            let mut input = hivepack_zstd::InBuffer::new(piece);
            let result = p.compress_stream2(&mut output, &mut input, directive);
            (result, input.pos, output.pos)
        };
        let got = got.map_err(|error| error.code().message().to_string());
        assert!(
            (&want, ci, co) == (&got, pi, po),
            "call {call} ({directive:?}): libzstd {want:?} read {ci} wrote to {co}, \
             port {got:?} read {pi} wrote to {po}"
        );
        assert!(
            c_dst[out_pos..co] == p_dst[out_pos..po],
            "call {call}: the output differs"
        );
        frame.extend_from_slice(&c_dst[out_pos..co]);
        if stable_out {
            stable_pos = co;
        }
        taken += ci;
        match want {
            Err(_) => return,
            Ok(0) if directive == EndDirective::End => {
                let mut back = vec![0u8; src.len()];
                let size = hivepack_zstd::decompress(&mut back, &frame).expect("the frame decodes");
                assert!(back[..size] == *src, "does not decode back");
                return;
            }
            Ok(_) => {}
        }
    }
    panic!("no end after {MAX_CALLS} calls");
});
