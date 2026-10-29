//! Extracts the input as a ZIP archive with hivepack-extract, its first
//! byte choosing the options, into a scratch folder beside a file that
//! must stay as it was. A panic is a bug, and so is a file written outside
//! the destination, a link that leads outside it, or a count of files the
//! summary does not give. `crates/extract/tests/extract.rs` has the cases
//! made by hand.

#![no_main]

use std::path::{Path, PathBuf};

use hivepack_extract::{Links, Names, OnRefused, Options, extract_zip};
use hivepack_zip::{Archive, OpenFlags};
use libfuzzer_sys::fuzz_target;

/// The paths under `dir`: the files, and the links with their targets.
fn walk(dir: &Path, files: &mut Vec<PathBuf>, links: &mut Vec<(PathBuf, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_symlink() {
            if let Ok(target) = std::fs::read_link(&path) {
                links.push((path, target));
            }
        } else if metadata.is_dir() {
            walk(&path, files, links);
        } else {
            files.push(path);
        }
    }
}

/// Whether `target`, read from the directory of `link`, stays under
/// `root`, by its text.
fn inside(root: &Path, link: &Path, target: &Path) -> bool {
    let Ok(start) = link.parent().unwrap_or(root).strip_prefix(root) else {
        return false;
    };
    let mut depth = start.components().count();
    for component in target.components() {
        match component {
            std::path::Component::ParentDir => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            std::path::Component::Normal(_) => depth += 1,
            std::path::Component::CurDir => {}
            _ => return false,
        }
    }
    true
}

fuzz_target!(|data: &[u8]| {
    let Some((&choice, zip)) = data.split_first() else {
        return;
    };
    let flags = if choice & 1 != 0 { OpenFlags::CHECKCONS } else { OpenFlags(0) };
    let Ok(archive) = Archive::open(zip, flags) else {
        return;
    };
    let mut options = Options::default();
    options.links = [Links::Refuse, Links::AsFile, Links::Inside, Links::Inside][usize::from(choice >> 1 & 3)];
    options.names = if choice & 8 != 0 { Names::Sanitize } else { Names::Strict };
    options.backslash_separator = choice & 16 != 0;
    options.on_refused = if choice & 32 != 0 { OnRefused::Skip } else { OnRefused::Stop };
    options.password = (choice & 64 != 0).then(|| b"foo".to_vec());
    // Small limits keep each run short.
    options.limits.max_entry_size = 256 << 10;
    options.limits.max_total_size = 1 << 20;
    options.limits.max_entries = 200;

    let scratch = std::env::temp_dir().join(format!("hivepack-fuzz-extract-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    if std::fs::create_dir_all(&scratch).is_err() {
        return;
    }
    let sentinel = scratch.join("sentinel");
    if std::fs::write(&sentinel, b"untouched").is_err() {
        return;
    }
    let out = scratch.join("out");
    let result = extract_zip(&archive, &out, &options);

    let mut around: Vec<_> = std::fs::read_dir(&scratch)
        .map(|entries| entries.flatten().map(|e| e.file_name()).collect())
        .unwrap_or_default();
    around.sort();
    let expected: &[&str] = if out.exists() { &["out", "sentinel"] } else { &["sentinel"] };
    assert_eq!(around, expected, "written beside the destination");
    assert_eq!(std::fs::read(&sentinel).ok().as_deref(), Some(&b"untouched"[..]));

    let (mut files, mut links) = (Vec::new(), Vec::new());
    walk(&out, &mut files, &mut links);
    for (link, target) in &links {
        assert_eq!(options.links, Links::Inside, "a link created: {link:?}");
        assert!(inside(&out, link, target), "{link:?} leads outside: {target:?}");
    }
    if let Ok(summary) = result {
        assert_eq!(files.len() as u64, summary.files);
        assert_eq!(links.len() as u64, summary.links);
    }
});
