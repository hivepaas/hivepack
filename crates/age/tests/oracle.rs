//! Comparison with age v1.3.2 itself, through `tools/age-oracle`: files that
//! age encrypts, to X25519 keys or a passphrase, armored or not, with
//! payloads around the 64 KiB chunks, then damaged in many ways, are
//! decrypted by both with right and wrong keys and passphrases. The
//! outcome, and the length and SHA-256 of all the plaintext given out,
//! must be the same.
//!
//! The oracle decrypts as `age --decrypt` does (`decrypt` in
//! `cmd/age/age.go`), and tells the outcome apart as age's
//! `testkit_test.go` does; the port answers with [`decrypt_file`].
//!
//! - With the oracle built, generated files are compared with age
//!   directly.
//! - Everywhere, including where it is not built (Windows, and the emulated
//!   i686 and s390x jobs), `testdata/oracle/age.txt` replays answers age
//!   gave earlier for small files. `cargo test -p hivepack-age --test oracle
//!   record_oracle_answers -- --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::fmt::Write as _;
use std::io::Read;
use std::path::PathBuf;

use hivepack_age::{Error, Identity, ScryptIdentity, X25519Identity, decrypt_file};
use hivepack_crypto::Sha256;
use support::{Oracle, Rng, hex, repository, unhex};

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/age.txt")
}

fn outcome(error: &Error) -> &'static str {
    match error {
        Error::Header(_) => "header",
        Error::NoMatch(_) => "no-match",
        Error::HeaderMac => "hmac",
        Error::Armor(_) => "armor",
        Error::Payload(_) => "payload",
        Error::Io(_) => "io",
    }
}

fn answer_with(what: &str, out: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(out);
    format!("{what} {} {}", out.len(), hex(&h.out()))
}

/// The port's answer to a `decrypt` request, as the oracle words it.
fn answer(request: &str, rng: &mut Rng) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    let ["decrypt", spec, file] = words[..] else {
        panic!("unknown request {request:.100}");
    };
    let mut identities: Vec<Box<dyn Identity>> = Vec::new();
    for s in spec.split(',') {
        if let Some(p) = s.strip_prefix("p:") {
            let (pass, log_n) = p.split_once(':').unwrap();
            let mut i = ScryptIdentity::new(&unhex(pass)).unwrap();
            i.set_max_work_factor(log_n.parse().unwrap());
            identities.push(Box::new(i));
        } else {
            identities.push(Box::new(X25519Identity::parse(s).unwrap()));
        }
    }
    let identities: Vec<&dyn Identity> = identities.iter().map(|i| i.as_ref()).collect();
    let file = unhex(file);
    let mut r = match decrypt_file(&file[..], &identities) {
        Ok(r) => r,
        Err(e) => return answer_with(outcome(&e), &[]),
    };
    // Read in pieces of random sizes, some of them empty.
    let mut out = Vec::new();
    loop {
        let mut buf = vec![0; rng.below(100_000) as usize];
        match r.read(&mut buf) {
            Ok(0) if !buf.is_empty() => return answer_with("success", &out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => return answer_with(outcome(&Error::from(e)), &out),
        }
    }
}

/// 1 to 20 random bytes.
fn short(rng: &mut Rng) -> Vec<u8> {
    let len = 1 + rng.below(20) as usize;
    bytes(rng, len)
}

/// Bytes: random, or all zeros.
fn bytes(rng: &mut Rng, len: usize) -> Vec<u8> {
    if rng.below(4) == 0 {
        vec![0; len]
    } else {
        (0..len).map(|_| rng.next() as u8).collect()
    }
}

/// A plaintext length: around the 64 KiB chunks, or anything up to `max`.
fn length(rng: &mut Rng, max: usize) -> usize {
    const CHUNK: usize = 64 * 1024;
    let len = match rng.below(3) {
        0 => {
            let base = CHUNK * rng.below(3) as usize;
            let near = rng.pick(&[0, 1, 2, 15, 16, 17]);
            if rng.below(2) == 0 {
                base.saturating_sub(near)
            } else {
                base + near
            }
        }
        1 => rng.below(300) as usize,
        _ => rng.below(max as u64 + 1) as usize,
    };
    len.min(max)
}

/// Where the header ends, after its closing line.
fn header_end(file: &[u8]) -> usize {
    file.windows(4)
        .position(|w| w == b"\n---")
        .and_then(|at| {
            file[at + 1..]
                .iter()
                .position(|&c| c == b'\n')
                .map(|n| at + 2 + n)
        })
        .unwrap_or(file.len())
}

/// `file`, damaged one way or another, or as it is; `other` is another
/// file to the same recipients.
fn damage(rng: &mut Rng, mut file: Vec<u8>, other: &[u8], armored: bool) -> Vec<u8> {
    if file.is_empty() {
        return file;
    }
    let header = header_end(&file);
    let at = |rng: &mut Rng, len: usize| rng.below(len as u64 + 1) as usize;
    match rng.below(16) {
        0..=3 => {}
        4 => {
            let i = at(rng, file.len() - 1);
            file[i] ^= 1 << rng.below(8);
        }
        5 => {
            let i = at(rng, header.min(file.len()) - 1);
            file[i] ^= 1 << rng.below(8);
        }
        6 => {
            let len = at(rng, file.len());
            file.truncate(len);
        }
        7 => {
            // Cut at a chunk boundary, or near one.
            let chunk = header + 16 + (64 * 1024 + 16) * rng.below(3) as usize;
            let len = (chunk + rng.pick(&[0, 1, 16, 17])).min(file.len());
            file.truncate(len.saturating_sub(rng.below(2) as usize));
        }
        8 => {
            let extra = if armored && rng.below(2) == 0 {
                rng.pick(&[&b" "[..], b"\n", b"\r\n", b"\t\n \n", b"x"])
                    .to_vec()
            } else {
                short(rng)
            };
            file.extend_from_slice(&extra);
        }
        9 => {
            let i = at(rng, file.len() - 1);
            file.remove(i);
        }
        10 => {
            let i = at(rng, file.len());
            file.insert(i, rng.pick(&[b'\n', b' ', b'\r', b'A', b'=', 0]));
        }
        11 => {
            // CRLF line ends in the header, or in all of an armored file.
            let end = if armored { file.len() } else { header };
            let mut out = Vec::new();
            for (i, &c) in file.iter().enumerate() {
                if c == b'\n' && i < end && rng.below(2) == 0 {
                    out.push(b'\r');
                }
                out.push(c);
            }
            file = out;
        }
        12 => {
            // A letter's case changed in the header.
            let i = at(rng, header.min(file.len()) - 1);
            if file[i].is_ascii_alphabetic() {
                file[i] ^= 0x20;
            }
        }
        13 => {
            // A line of the header said twice, or left out.
            let lines: Vec<&[u8]> = file[..header].split_inclusive(|&c| c == b'\n').collect();
            let i = at(rng, lines.len() - 1);
            let mut out: Vec<u8> = Vec::new();
            for (j, line) in lines.iter().enumerate() {
                if j != i || rng.below(2) == 0 {
                    out.extend_from_slice(line);
                }
                if j == i {
                    out.extend_from_slice(line);
                }
            }
            out.extend_from_slice(&file[header..]);
            file = out;
        }
        14 => {
            // This file's header with the other's payload, or the reverse.
            let other_header = header_end(other);
            file = if rng.below(2) == 0 {
                [&file[..header], &other[other_header..]].concat()
            } else {
                [&other[..other_header], &file[header..]].concat()
            };
        }
        _ => {
            // White space before an armored file, or a mangled intro.
            let prefix: &[u8] = rng.pick(&[&b"\n\n  "[..], b"\r\n", b"\xff\xfe", b"garbage\n"]);
            file = [prefix, &file[..]].concat();
        }
    }
    file
}

/// The keys files are encrypted to: CCTV's usual identity, and three that
/// `age-keygen` made. The first is the one the `age` fuzz target tries, so
/// that the files recorded here make a corpus that gets past the header.
const KEYS: [&str; 4] = [
    "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0",
    "AGE-SECRET-KEY-1W0YVT58DJ29ACF8AJECG9HK66C9Y5UWVWJDJNFYRF9VX8LA8E3ZQPQR8XW",
    "AGE-SECRET-KEY-1LP5327FL4GTJFS9AMV3RL6R8C6VDK8ELLN0FVSNMY7ECDHY9YEMQCEYHJ2",
    "AGE-SECRET-KEY-1K9MV3MGWR4DR6ZDMHWWT9YU2H4C6T0MVVYN8VVX09FQ72PNJYWRQCQ369K",
];

/// A passphrase: the fuzz target's (and CCTV's) half of the time, random
/// bytes otherwise.
fn passphrase(rng: &mut Rng) -> Vec<u8> {
    if rng.below(2) == 0 {
        b"password".to_vec()
    } else {
        short(rng)
    }
}

/// (identity, recipient) for each of [`KEYS`].
fn keys() -> Vec<(String, String)> {
    KEYS.iter()
        .map(|k| (k.to_string(), X25519Identity::parse(k).unwrap().recipient()))
        .collect()
}

/// `count` decrypt requests for files the oracle encrypts, with
/// plaintexts up to `max` bytes.
fn requests(oracle: &mut Oracle, rng: &mut Rng, count: usize, max: usize) -> Vec<String> {
    let keys = keys();
    let mut requests = Vec::new();
    for _ in 0..count {
        let armored = rng.below(3) == 0;
        let with_passphrase = rng.below(3) == 0;
        let (recipients, identities) = if with_passphrase {
            let pass = passphrase(rng);
            let log_n = 1 + rng.below(4);
            let recipients = format!("p:{}:{log_n}", hex(&pass));
            // The right passphrase or not; the work factor allowed or not.
            let try_pass = if rng.below(4) == 0 {
                passphrase(rng)
            } else {
                pass
            };
            let max_log_n = if rng.below(6) == 0 {
                log_n - 1
            } else {
                log_n + rng.below(3)
            }
            .max(1);
            let mut identities = vec![format!("p:{}:{max_log_n}", hex(&try_pass))];
            if rng.below(3) == 0 {
                identities.push(keys[rng.below(4) as usize].0.clone());
            }
            (recipients, identities)
        } else {
            let mut to: Vec<usize> = (0..4).filter(|_| rng.below(2) == 0).collect();
            if to.is_empty() {
                to.push(rng.below(4) as usize);
            }
            let recipients: Vec<&str> = to.iter().map(|&i| keys[i].1.as_str()).collect();
            let mut with: Vec<usize> = (0..4).filter(|_| rng.below(3) == 0).collect();
            if with.is_empty() || rng.below(2) == 0 {
                with.push(to[rng.below(to.len() as u64) as usize]);
            }
            let mut identities: Vec<String> = with.iter().map(|&i| keys[i].0.clone()).collect();
            if rng.below(5) == 0 {
                identities.push(format!("p:{}:4", hex(b"not this")));
            }
            (recipients.join(","), identities)
        };
        let len = length(rng, max);
        let plaintext = hex(&bytes(rng, len));
        let reply = oracle.ask(&format!(
            "encrypt {recipients} {} {plaintext}",
            u8::from(armored)
        ));
        let file = unhex(reply.strip_prefix("ok ").unwrap());
        let reply = oracle.ask(&format!("encrypt {recipients} {} -", u8::from(armored)));
        let other = unhex(reply.strip_prefix("ok ").unwrap());
        let file = damage(rng, file, &other, armored);
        requests.push(format!("decrypt {} {}", identities.join(","), hex(&file)));
    }
    requests
}

#[test]
fn port_matches_age() {
    let Some(mut oracle) = Oracle::spawn("age-oracle") else {
        return;
    };
    let mut rng = Rng(0xa9e_c001);
    let requests = requests(&mut oracle, &mut rng, 600, 200_000);
    let mut outcomes = std::collections::BTreeMap::new();
    for request in &requests {
        let want = oracle.ask(request);
        assert_eq!(answer(request, &mut rng), want, "{request:.300}");
        *outcomes
            .entry(want.split(' ').next().unwrap().to_string())
            .or_insert(0) += 1;
    }
    eprintln!("{outcomes:?}");
    // Every outcome comes up.
    for what in ["success", "header", "no-match", "hmac", "armor", "payload"] {
        assert!(outcomes.contains_key(what), "no {what} in {outcomes:?}");
    }
}

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/age.txt");
    let mut rng = Rng(0xa9e_c003);
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(answer(request, &mut rng), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked >= 300, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/age.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn("age-oracle").expect("the oracle is built");
    let mut rng = Rng(0xa9e_c002);
    let mut text = String::from(
        "# Answers from age v1.3.2 (tools/age-oracle), replayed by crates/age/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack-age --test oracle record_oracle_answers -- --ignored\n",
    );
    // Small files keep it small: the large are for the live comparison.
    for request in requests(&mut oracle, &mut rng, 300, 200) {
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{reply}");
    }
    std::fs::create_dir_all(recorded_path().parent().expect("folder")).expect("folder");
    std::fs::write(recorded_path(), text).expect("written");
}
