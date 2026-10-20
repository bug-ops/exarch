//! Legitimate ZIP archives must pass the default `Enforce` policy untouched.
//!
//! The in-process corpus covers the layouts common producers write: stored and
//! deflated entries, data descriptors, ZIP64 local headers, aligned entries,
//! comments, prepended stubs and empty archives. Archives from other tools
//! (Info-ZIP, `ditto`, 7-Zip, `bsdtar`, Go, ...) are checked by the ignored
//! test below when
//! `EXARCH_ZIP_CORPUS_DIR` points at a directory of them; generate one with
//! `scripts/zip-corpus.sh`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;
use std::io::Write;
use std::path::Path;

use exarch_core::ArchiveError;
use exarch_core::IssueCategory;
use exarch_core::SecurityConfig;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use tempfile::TempDir;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;
use zip::write::ZipWriter;

const STRUCTURAL: [IssueCategory; 4] = [
    IssueCategory::HeaderMismatch,
    IssueCategory::DuplicateEntry,
    IssueCategory::OverlappingEntries,
    IssueCategory::HiddenEntry,
];

fn options(method: CompressionMethod) -> SimpleFileOptions {
    SimpleFileOptions::default().compression_method(method)
}

fn seekable(method: CompressionMethod, large: bool) -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options = options(method).large_file(large);
    // The `zip` writer gives ZIP64 directories local sizes that its own
    // header check rejects, so they stay out of the ZIP64 case.
    if !large {
        zip.add_directory("dir/", options).unwrap();
    }
    zip.start_file("dir/a.txt", options).unwrap();
    zip.write_all(&b"hello world ".repeat(500)).unwrap();
    zip.start_file("empty", options).unwrap();
    zip.start_file("caf\u{e9}.txt", options).unwrap();
    zip.write_all(b"unicode").unwrap();
    zip.finish().unwrap().into_inner()
}

fn streamed(method: CompressionMethod, large: bool) -> Vec<u8> {
    let mut zip = ZipWriter::new_stream(Vec::new());
    let options = options(method).large_file(large);
    zip.start_file("a.txt", options).unwrap();
    zip.write_all(&b"streamed ".repeat(2000)).unwrap();
    zip.start_file("b.txt", options).unwrap();
    zip.write_all(b"second").unwrap();
    zip.finish().unwrap().into_inner()
}

fn aligned() -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options = options(CompressionMethod::Stored).with_alignment(4096);
    for name in ["lib/a.so", "lib/b.so"] {
        zip.start_file(name, options).unwrap();
        zip.write_all(&[7u8; 3000]).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn commented() -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    zip.set_comment("PK\u{3}\u{4} archive comment").unwrap();
    zip.start_file("a.txt", options(CompressionMethod::Deflated))
        .unwrap();
    zip.write_all(b"data").unwrap();
    zip.finish().unwrap().into_inner()
}

fn many_entries() -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options = options(CompressionMethod::Deflated);
    for i in 0..300 {
        zip.start_file(format!("dir{}/file{i}.txt", i % 7), options)
            .unwrap();
        zip.write_all(format!("entry {i}").as_bytes()).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn with_stub(archive: &[u8]) -> Vec<u8> {
    let mut bytes = b"#!/bin/sh\nexit 0\n".repeat(20);
    bytes.extend_from_slice(archive);
    bytes
}

fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let empty = ZipWriter::new(Cursor::new(Vec::new()))
        .finish()
        .unwrap()
        .into_inner();
    vec![
        ("empty", empty),
        ("stored", seekable(CompressionMethod::Stored, false)),
        ("deflated", seekable(CompressionMethod::Deflated, false)),
        ("zip64", seekable(CompressionMethod::Deflated, true)),
        ("streamed", streamed(CompressionMethod::Deflated, false)),
        (
            "streamed_stored",
            streamed(CompressionMethod::Stored, false),
        ),
        (
            "streamed_zip64",
            streamed(CompressionMethod::Deflated, true),
        ),
        ("aligned", aligned()),
        ("commented", commented()),
        ("many", many_entries()),
        (
            "stub",
            with_stub(&seekable(CompressionMethod::Deflated, false)),
        ),
    ]
}

/// Fails if the archive is rejected or reported for its structure. Other
/// rejections (for example Deflate64, which exarch does not admit) are not
/// structural and are accepted here.
fn assert_no_structural_finding(path: &Path, label: &str) {
    let config = SecurityConfig::default();
    match list_archive(path, &config) {
        Ok(_) => {}
        // Not admitted for a reason other than structure: Deflate64 and the like.
        Err(ArchiveError::SecurityViolation { reason }) if reason.starts_with("unsupported") => {
            return;
        }
        Err(e) => panic!("{label}: list rejected: {e}"),
    }
    let report = verify_archive(path, &config).unwrap();
    let findings: Vec<_> = report
        .issues()
        .iter()
        .filter(|i| STRUCTURAL.contains(&i.category))
        .collect();
    assert!(findings.is_empty(), "{label}: {findings:?}");
}

#[test]
fn generated_corpus_has_no_structural_findings() {
    let dir = TempDir::new().unwrap();
    for (label, bytes) in corpus() {
        let path = dir.path().join(format!("{label}.zip"));
        std::fs::write(&path, bytes).unwrap();
        assert_no_structural_finding(&path, label);
    }
}

#[test]
#[ignore = "needs EXARCH_ZIP_CORPUS_DIR"]
fn external_corpus_has_no_structural_findings() {
    let dir = std::env::var_os("EXARCH_ZIP_CORPUS_DIR").expect("EXARCH_ZIP_CORPUS_DIR is not set");
    let mut checked = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "zip" || e == "jar") {
            assert_no_structural_finding(&path, &path.display().to_string());
            checked += 1;
        }
    }
    assert!(checked > 0, "EXARCH_ZIP_CORPUS_DIR holds no archives");
}
