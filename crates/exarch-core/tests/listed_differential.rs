//! `ListRequest::for_extraction(..).extract(..)` equals `extract_archive` under
//! the same config.
//!
//! The list pass runs under the extraction config with symlinks, hardlinks,
//! world-writable files and preserved permissions turned off, and extraction
//! then reuses what the list pass kept (the ZIP census output, the TAR spool).
//! This proves that nothing kept depends on those four flags: for each format,
//! each `DecodeReuse` mode and each flag turned on, the extracted tree, the
//! modes, the link targets and the report match a plain extraction.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

mod common;
mod sink_support;

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use common::RawEntry as SevenZEntry;
use common::solid_copy_7z;
use exarch_core::DecodeReuse;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ListRequest;
use exarch_core::ListedExtractOptions;
use exarch_core::NoopProgress;
use exarch_core::ReuseLimit;
use exarch_core::SecurityConfig;
use exarch_testkit::raw_zip::RawEntry as ZipEntry;
use sink_support::tar_archive;
use sink_support::tar_entry_mode;
use sink_support::tar_file;
use sink_support::tar_hardlink;
use sink_support::tar_symlink;
use sink_support::zip_archive;
use sink_support::zip_file;
use sink_support::zip_symlink;
use tempfile::TempDir;

#[derive(Debug, PartialEq, Eq)]
enum Node {
    Dir(u32),
    File(Vec<u8>, u32),
    Link(PathBuf),
}

#[derive(Debug, PartialEq, Eq)]
struct Counts {
    files: usize,
    dirs: usize,
    symlinks: usize,
    bytes: u64,
    skipped: usize,
    warnings: Vec<String>,
}

type Outcome = Result<(BTreeMap<PathBuf, Node>, Counts), String>;

#[cfg(unix)]
fn mode_of(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn mode_of(_: &std::fs::Metadata) -> u32 {
    0
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Node> {
    fn visit(root: &Path, dir: &Path, nodes: &mut BTreeMap<PathBuf, Node>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path.strip_prefix(root).unwrap().to_path_buf();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            if metadata.is_symlink() {
                nodes.insert(rel, Node::Link(std::fs::read_link(&path).unwrap()));
            } else if metadata.is_dir() {
                nodes.insert(rel, Node::Dir(mode_of(&metadata)));
                visit(root, &path, nodes);
            } else {
                nodes.insert(
                    rel,
                    Node::File(std::fs::read(&path).unwrap(), mode_of(&metadata)),
                );
            }
        }
    }
    let mut nodes = BTreeMap::new();
    if root.exists() {
        visit(root, root, &mut nodes);
    }
    nodes
}

fn outcome(result: exarch_core::Result<exarch_core::ExtractionReport>, dest: &Path) -> Outcome {
    match result {
        Ok(report) => Ok((
            snapshot(dest),
            Counts {
                files: report.files_extracted,
                dirs: report.directories_created,
                symlinks: report.symlinks_created,
                bytes: report.bytes_written,
                skipped: report.files_skipped(),
                warnings: report.warnings.iter().map(ToString::to_string).collect(),
            },
        )),
        Err(err) => Err(err.to_string()),
    }
}

fn plain(archive: &Path, config: &SecurityConfig, reuse: DecodeReuse) -> Outcome {
    let out = TempDir::new().unwrap();
    let dest = out.path().join("out");
    let options = ExtractionOptions::default().with_decode_reuse(reuse);
    outcome(
        ExtractRequest::new(config)
            .with_options(options)
            .extract(archive, &dest),
        &dest,
    )
}

fn listed(archive: &Path, config: &SecurityConfig, reuse: DecodeReuse) -> Outcome {
    let out = TempDir::new().unwrap();
    let dest = out.path().join("out");
    let result = ListRequest::new(config)
        .for_extraction(archive, reuse)
        .and_then(|listed| {
            listed.extract(&dest, &ListedExtractOptions::default(), &mut NoopProgress)
        });
    outcome(result, &dest)
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn bzip2(data: &[u8]) -> Vec<u8> {
    let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn xz(data: &[u8]) -> Vec<u8> {
    let mut enc = liblzma::write::XzEncoder::new(Vec::new(), 1);
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn zstd(data: &[u8]) -> Vec<u8> {
    zstd::encode_all(data, 1).unwrap()
}

type Encode = fn(&[u8]) -> Vec<u8>;

fn tar_formats(tar: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let encoders: [(&str, Encode); 4] = [
        ("a.tar.gz", gzip),
        ("a.tar.bz2", bzip2),
        ("a.tar.xz", xz),
        ("a.tar.zst", zstd),
    ];
    let mut formats = vec![("a.tar", tar.to_vec())];
    formats.extend(encoders.map(|(name, encode)| (name, encode(tar))));
    formats
}

fn zip_mode(name: &str, data: &[u8], mode: u32) -> ZipEntry {
    ZipEntry {
        external_attributes: (0o100_000 | mode) << 16,
        ..ZipEntry::stored(name, data)
    }
}

/// What each flag changes, as one archive per format family.
struct Fixture {
    name: &'static str,
    tar: Vec<u8>,
    zip: Vec<u8>,
    sevenz: Vec<u8>,
}

fn fixtures() -> Vec<Fixture> {
    let file = |name| tar_file(name, b"payload");
    vec![
        Fixture {
            name: "plain file",
            tar: tar_archive(&[file("a.txt")]),
            zip: zip_archive(vec![zip_file("a.txt", b"payload")]),
            sevenz: solid_copy_7z(&[SevenZEntry::File("a.txt", b"payload")]),
        },
        Fixture {
            name: "symlink",
            tar: tar_archive(&[file("a.txt"), tar_symlink("link", "a.txt")]),
            zip: zip_archive(vec![
                zip_file("a.txt", b"payload"),
                zip_symlink("link", "a.txt"),
            ]),
            sevenz: solid_copy_7z(&[
                SevenZEntry::File("a.txt", b"payload"),
                SevenZEntry::Link("link", b"a.txt"),
            ]),
        },
        Fixture {
            name: "hardlink",
            tar: tar_archive(&[file("a.txt"), tar_hardlink("hard", "a.txt")]),
            zip: zip_archive(vec![zip_file("a.txt", b"payload")]),
            sevenz: solid_copy_7z(&[SevenZEntry::File("a.txt", b"payload")]),
        },
        Fixture {
            name: "world-writable and special modes",
            tar: tar_archive(&[
                tar_entry_mode("ww.txt", tar::EntryType::Regular, b"w", None, 0o666),
                tar_entry_mode("exec.sh", tar::EntryType::Regular, b"x", None, 0o755),
                tar_entry_mode("suid", tar::EntryType::Regular, b"s", None, 0o4755),
                tar_entry_mode("private", tar::EntryType::Regular, b"p", None, 0o600),
            ]),
            zip: zip_archive(vec![
                zip_mode("ww.txt", b"w", 0o666),
                zip_mode("exec.sh", b"x", 0o755),
                zip_mode("suid", b"s", 0o4755),
                zip_mode("private", b"p", 0o600),
            ]),
            sevenz: solid_copy_7z(&[SevenZEntry::File("ww.txt", b"w")]),
        },
    ]
}

fn configs() -> Vec<(&'static str, SecurityConfig)> {
    let base = SecurityConfig::default;
    vec![
        ("default", base()),
        ("symlinks", base().with_allow_symlinks(true)),
        ("hardlinks", base().with_allow_hardlinks(true)),
        ("world_writable", base().with_allow_world_writable(true)),
        (
            "preserve_permissions",
            base().with_preserve_permissions(true),
        ),
        (
            "all four",
            base()
                .with_allow_symlinks(true)
                .with_allow_hardlinks(true)
                .with_allow_world_writable(true)
                .with_preserve_permissions(true),
        ),
    ]
}

fn reuse_modes() -> [DecodeReuse; 3] {
    [
        DecodeReuse::Off,
        DecodeReuse::Memory(ReuseLimit::DEFAULT),
        DecodeReuse::TempFile(ReuseLimit::DEFAULT),
    ]
}

#[test]
fn listed_extraction_equals_plain_extraction_for_every_format_reuse_mode_and_flag() {
    let mut compared = 0usize;
    let mut extracted = 0usize;
    for fixture in fixtures() {
        let mut archives = tar_formats(&fixture.tar);
        archives.push(("a.zip", fixture.zip.clone()));
        archives.push(("a.7z", fixture.sevenz.clone()));

        for (name, bytes) in archives {
            let dir = TempDir::new().unwrap();
            let archive = dir.path().join(name);
            std::fs::write(&archive, bytes).unwrap();

            for (config_name, config) in configs() {
                for reuse in reuse_modes() {
                    let expected = plain(&archive, &config, reuse);
                    let actual = listed(&archive, &config, reuse);
                    assert_eq!(
                        actual, expected,
                        "{} / {name} / {config_name} / {reuse:?}",
                        fixture.name
                    );
                    compared += 1;
                    extracted += usize::from(expected.is_ok());
                }
            }
        }
    }
    assert!(compared > 400, "{compared}");
    assert!(
        extracted > compared / 3,
        "the comparison must mostly cover successful extractions: {extracted}/{compared}"
    );
}
