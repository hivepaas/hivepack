//! The test data described by `testdata/manifest.json`, for the tests in this
//! folder.

// Test helpers: a broken data set should stop the test with its name.
#![allow(dead_code, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub about: String,
    pub upstream: Upstream,
    pub sets: Vec<Set>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub version: String,
    pub commit: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Set {
    pub name: String,
    /// Where a committed set is, under `testdata/`.
    pub path: Option<String>,
    /// How `scripts/testdata.py` downloads the set.
    pub fetch: Option<serde_json::Value>,
    /// How `scripts/testdata.py` generates the set.
    pub generate: Option<serde_json::Value>,
    pub source: String,
    pub license: String,
    pub kind: Kind,
    /// Only these files, relative to the set's folder, when given.
    #[serde(default)]
    pub files: Vec<String>,
    /// `beside`: the original of `x.zst` is `x`, when that file exists.
    pub originals: Option<String>,
    /// Frames that decode to this many zero bytes.
    #[serde(default)]
    pub zeros: BTreeMap<String, usize>,
    /// The dictionary every frame needs, relative to the set's folder.
    pub dictionary: Option<String>,
    /// For a dictionaries set: the inputs, relative to `testdata/`, to
    /// compress with each dictionary.
    #[serde(default)]
    pub inputs: BTreeMap<String, Vec<String>>,
    /// Frames whose content is a dataset of zstd's `tests/regression`.
    #[serde(default)]
    pub regression: BTreeMap<String, String>,
    /// Files whose outcome differs from what the set's kind says.
    #[serde(default)]
    pub expect: BTreeMap<String, Expect>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// Every `.zst` file decodes.
    Frames,
    /// Every `.zst` file fails to decode.
    BadFrames,
    /// Every file is data to compress.
    Inputs,
    /// Every file is a dictionary.
    Dictionaries,
    /// `.dict` files are dictionaries; each `.zst` file decodes with the
    /// one its header names.
    DictFrames,
    /// Arbitrary bytes found by fuzzers; nothing is expected of them.
    Fuzz,
    /// Source code that the script builds tools from.
    Source,
    /// Benchmark inputs, too big for the tests.
    Bench,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    pub result: Outcome,
    pub why: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Decodes,
    Fails,
}

pub fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Where `scripts/testdata.py` puts the sets it fetches and generates.
pub fn cache() -> PathBuf {
    std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository().join("target/testdata"))
}

pub fn manifest() -> Manifest {
    let path = repository().join("testdata/manifest.json");
    let text = std::fs::read_to_string(&path).expect("manifest readable");
    serde_json::from_str(&text).expect("manifest parses")
}

impl Set {
    pub fn committed(&self) -> bool {
        self.path.is_some()
    }

    pub fn folder(&self) -> PathBuf {
        match &self.path {
            Some(path) => repository().join("testdata").join(path),
            None => cache().join(&self.name),
        }
    }

    /// The group `scripts/testdata.py` fetches or generates the set in.
    pub fn group(&self) -> Option<&str> {
        self.fetch
            .as_ref()
            .or(self.generate.as_ref())?
            .get("group")?
            .as_str()
    }

    /// Whether the set is on disk. A missing set fails the test when its
    /// group is listed in `HIVEPACK_TESTDATA_REQUIRED` (for example
    /// `core,generated` in CI, or `all`), and is skipped with a note otherwise.
    pub fn present(&self) -> bool {
        if self.committed() || self.folder().join(".complete").exists() {
            return true;
        }
        let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
        let group = self.group().unwrap_or_default();
        assert!(
            !required.split(',').any(|g| g == "all" || g == group),
            "{} is missing: run `python3 scripts/testdata.py fetch --group {group}`",
            self.name
        );
        eprintln!(
            "skipping {}: not fetched (scripts/testdata.py fetch --group {group})",
            self.name
        );
        false
    }

    /// The set's files, relative to its folder, sorted.
    pub fn list(&self) -> Vec<PathBuf> {
        if !self.files.is_empty() {
            return self.files.iter().map(PathBuf::from).collect();
        }
        let root = self.folder();
        let mut found = Vec::new();
        let mut pending = vec![root.clone()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("set folder readable") {
                let path = entry.expect("folder entry").path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.file_name() != Some(".complete".as_ref()) {
                    found.push(
                        path.strip_prefix(&root)
                            .expect("inside the set")
                            .to_path_buf(),
                    );
                }
            }
        }
        found.sort();
        found
    }

    pub fn frames(&self) -> Vec<PathBuf> {
        self.list()
            .into_iter()
            .filter(|p| p.extension() == Some("zst".as_ref()))
            .collect()
    }

    pub fn read(&self, file: &Path) -> Vec<u8> {
        let path = self.folder().join(file);
        std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    /// What `file` should decode to, when the set says.
    pub fn original(&self, frame: &Path) -> Option<Vec<u8>> {
        let key = frame.to_string_lossy();
        if let Some(&zeros) = self.zeros.get(key.as_ref()) {
            return Some(vec![0; zeros]);
        }
        if self.originals.as_deref() == Some("beside") {
            let original = self.folder().join(frame.with_extension(""));
            if original.exists() {
                return Some(std::fs::read(original).expect("original readable"));
            }
        }
        None
    }

    pub fn expected(&self, file: &Path) -> Option<Outcome> {
        self.expect
            .get(file.to_string_lossy().as_ref())
            .map(|e| e.result)
    }
}

/// Collects every mismatch so a run reports all of them, not just the first.
#[derive(Default)]
pub struct Problems(Vec<String>);

impl Problems {
    pub fn add(&mut self, problem: String) {
        self.0.push(problem);
    }

    pub fn check(self) {
        assert!(
            self.0.is_empty(),
            "{} problems:\n{}",
            self.0.len(),
            self.0.join("\n")
        );
    }
}
