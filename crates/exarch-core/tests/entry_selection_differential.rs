//! Differential check of `--strip-components` against `bsdtar` on a crafted
//! TAR corpus (spec 022 SC-001). Skipped where `bsdtar` is not installed.
//!
//! Deliberate differences, recorded here so they are not silently chosen:
//!
//! - `bsdtar` (and GNU `tar`) count the leading `./` of a name as a component,
//!   so `./top/x` with `--strip-components 1` gives `top/x`; exarch does not
//!   count it (spec 022 Q5, FR-013) and gives `x`. The offset test pins this.
//! - `bsdtar` overwrites a file that two names map to; exarch keeps the first
//!   under its default `ExistingFiles::Skip` (Q10), so the comparison runs
//!   under `ExistingFiles::Overwrite`.
//! - `bsdtar` extracts a member whose name holds `..` after stripping when the
//!   remaining name is safe; exarch refuses any archive whose original name
//!   holds `..` (path traversal is checked before stripping), so the corpus
//!   keeps such names out.
//! - exarch refuses a symlink whose target escapes the destination at its
//!   stripped landing; `bsdtar` creates it. The corpus keeps links inside.

#![cfg(unix)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

mod sink_support;

use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::PathRewrite;
use exarch_core::SecurityConfig;
use exarch_core::StripComponents;
use sink_support::tar_archive;
use sink_support::tar_entry_mode;
use sink_support::tar_file;
use sink_support::tar_hardlink;
use sink_support::tar_symlink;
use tempfile::TempDir;

fn bsdtar_available() -> bool {
    Command::new("bsdtar")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn tar_dir(name: &str) -> Vec<u8> {
    tar_entry_mode(name, tar::EntryType::Directory, b"", None, 0o755)
}

fn corpus() -> Vec<Vec<u8>> {
    vec![
        tar_dir("top/"),
        tar_file("top/README", b"readme"),
        tar_dir("top/src/"),
        tar_file("top/src/main.rs", b"main"),
        tar_file("top/src/lib/mod.rs", b"mod"),
        tar_file("loose.txt", b"loose"),
        tar_file("a/x", b"first"),
        tar_file("b/x", b"second"),
        tar_dir("top/bin/"),
        tar_file("top/bin/sibling", b"sibling"),
        tar_symlink("top/bin/tool", "sibling"),
        tar_hardlink("top/src/copy.rs", "top/src/main.rs"),
    ]
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, String> {
    let mut found = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            let rel = path.strip_prefix(root).unwrap().to_path_buf();
            let file_type = std::fs::symlink_metadata(&path).unwrap().file_type();
            if file_type.is_symlink() {
                let target = std::fs::read_link(&path).unwrap();
                found.insert(rel, format!("-> {}", target.display()));
            } else if file_type.is_dir() {
                stack.push(path);
            } else {
                found.insert(
                    rel,
                    String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned(),
                );
            }
        }
    }
    found
}

#[test]
fn strip_components_extracts_what_bsdtar_extracts() {
    if !bsdtar_available() {
        eprintln!("bsdtar not found; skipping");
        return;
    }
    let work = TempDir::new().unwrap();
    let archive = work.path().join("corpus.tar");
    std::fs::write(&archive, tar_archive(&corpus())).unwrap();
    let config = SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true);

    for count in 0..=3_u64 {
        let reference = work.path().join(format!("bsdtar-{count}"));
        std::fs::create_dir(&reference).unwrap();
        let status = Command::new("bsdtar")
            .arg("-xf")
            .arg(&archive)
            .arg("--strip-components")
            .arg(count.to_string())
            .arg("-C")
            .arg(&reference)
            .status()
            .unwrap();
        assert!(status.success(), "bsdtar failed at strip {count}");

        let ours = work.path().join(format!("exarch-{count}"));
        let config = match count {
            0 => config.clone(),
            n => config.clone().with_path_rewrite(PathRewrite::Strip(
                StripComponents::new(n.try_into().unwrap(), config.max_path_depth).unwrap(),
            )),
        };
        ExtractRequest::new(&config)
            .with_options(
                ExtractionOptions::default().with_existing_files(ExistingFiles::Overwrite),
            )
            .extract(&archive, &ours)
            .unwrap();

        assert_eq!(
            snapshot(&ours),
            snapshot(&reference),
            "strip {count}: exarch differs from bsdtar"
        );
    }
}

#[test]
fn a_leading_dot_slash_is_not_counted_unlike_bsdtar() {
    if !bsdtar_available() {
        eprintln!("bsdtar not found; skipping");
        return;
    }
    let work = TempDir::new().unwrap();
    let archive = work.path().join("dot.tar");
    std::fs::write(
        &archive,
        tar_archive(&[tar_file("./top/x", b"1"), tar_file("./top/sub/y", b"2")]),
    )
    .unwrap();

    for count in 0..=2_u64 {
        let reference = work.path().join(format!("bsdtar-{}", count + 1));
        std::fs::create_dir(&reference).unwrap();
        let status = Command::new("bsdtar")
            .arg("-xf")
            .arg(&archive)
            .arg("--strip-components")
            .arg((count + 1).to_string())
            .arg("-C")
            .arg(&reference)
            .status()
            .unwrap();
        assert!(status.success());

        let config = match count {
            0 => SecurityConfig::default(),
            n => SecurityConfig::default().with_path_rewrite(PathRewrite::Strip(
                StripComponents::new(
                    n.try_into().unwrap(),
                    SecurityConfig::default().max_path_depth,
                )
                .unwrap(),
            )),
        };
        let ours = work.path().join(format!("exarch-{count}"));
        ExtractRequest::new(&config)
            .with_options(ExtractionOptions::default())
            .extract(&archive, &ours)
            .unwrap();

        assert_eq!(
            snapshot(&ours),
            snapshot(&reference),
            "exarch at {count} equals bsdtar at {}",
            count + 1
        );
    }
}
