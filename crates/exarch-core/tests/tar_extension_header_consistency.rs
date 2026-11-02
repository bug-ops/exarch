//! TAR header and PAX/GNU extension parsing agrees with the reference readers
//! (`bsdtar`, the Python `tarfile` module) or the archive is refused.
//!
//! Every construct below is read differently by those tools: a payload on a
//! zero-size entry type, duplicate PAX records, GNU sparse names, PAX records
//! stacked with GNU long records, and global PAX headers. `list`, `verify` and
//! `extract` must all refuse them with a typed `InvalidArchive`.

#![allow(clippy::unwrap_used)]

use std::path::Path;

use exarch_core::ArchiveError;
use exarch_core::ErrorCode;
use exarch_core::ManifestEntryKind;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use tempfile::TempDir;

const REGULAR: u8 = b'0';
const HARDLINK: u8 = b'1';
const SYMLINK: u8 = b'2';
const DIRECTORY: u8 = b'5';
const PAX_LOCAL: u8 = b'x';
const PAX_GLOBAL: u8 = b'g';
const GNU_LONG_NAME: u8 = b'L';
const GNU_LONG_LINK: u8 = b'K';

fn header(name: &str, typeflag: u8, size: usize, linkname: &str) -> Vec<u8> {
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    header.set_size(size as u64);
    header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
    header.as_old_mut().linkname[..linkname.len()].copy_from_slice(linkname.as_bytes());
    header.set_entry_type(tar::EntryType::new(typeflag));
    header.set_cksum();
    header.as_bytes().to_vec()
}

fn pad(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.resize(bytes.len().next_multiple_of(512), 0);
    bytes
}

fn entry(name: &str, typeflag: u8, data: &[u8]) -> Vec<u8> {
    pad([header(name, typeflag, data.len(), ""), data.to_vec()].concat())
}

fn link(name: &str, typeflag: u8, linkname: &str) -> Vec<u8> {
    pad(header(name, typeflag, 0, linkname))
}

fn pax_record(key: &str, value: &str) -> String {
    let base = key.len() + value.len() + 3;
    let mut len = base + 1;
    while len.to_string().len() + base != len {
        len = len.to_string().len() + base;
    }
    format!("{len} {key}={value}\n")
}

fn extension(typeflag: u8, records: &[(&str, &str)]) -> Vec<u8> {
    let body: String = records.iter().map(|(k, v)| pax_record(k, v)).collect();
    pad([header("pax", typeflag, body.len(), ""), body.into_bytes()].concat())
}

fn gnu_long(typeflag: u8, value: &str) -> Vec<u8> {
    let mut body = value.as_bytes().to_vec();
    body.push(0);
    pad([header("././@LongLink", typeflag, body.len(), ""), body].concat())
}

fn tar_of(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = entries.concat();
    bytes.resize(bytes.len() + 1024, 0);
    bytes
}

fn config() -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true)
}

fn write_archive(dir: &TempDir, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join("a.tar");
    std::fs::write(&path, bytes).unwrap();
    path
}

fn assert_ambiguous(error: &ArchiveError, expected: &str) {
    let source = match error {
        ArchiveError::PartialExtraction { source, .. } => source,
        other => other,
    };
    assert_eq!(source.error_code(), ErrorCode::InvalidArchive, "{source}");
    assert!(source.to_string().contains(expected), "{source}");
}

fn assert_refused_everywhere(bytes: &[u8], expected: &str) {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, bytes);
    let config = config();

    assert_ambiguous(&list_archive(&archive, &config).unwrap_err(), expected);
    assert_ambiguous(&verify_archive(&archive, &config).unwrap_err(), expected);

    let root = TempDir::new().unwrap();
    let out = root.path().join("out");
    assert_ambiguous(
        &extract_archive(&archive, &out, &config).unwrap_err(),
        expected,
    );
    let leftovers = list_tree(root.path());
    assert!(
        leftovers.iter().all(|p| p.starts_with(&out)),
        "extraction wrote outside the destination: {leftovers:?}"
    );
    assert!(
        !leftovers.iter().any(|p| p.ends_with("lnk")),
        "the ambiguous entry was extracted: {leftovers:?}"
    );
}

fn list_tree(root: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for item in std::fs::read_dir(&dir).unwrap() {
            let path = item.unwrap().path();
            if path.is_dir() {
                pending.push(path.clone());
            }
            found.push(path);
        }
    }
    found
}

fn hidden_member_payload() -> Vec<u8> {
    let mut payload = entry("evil.txt", REGULAR, b"#!/bin/sh\n");
    payload.resize(1024, 0);
    payload
}

#[test]
fn directory_with_payload_is_refused() {
    let bytes = tar_of(&[
        pad([header("x/", DIRECTORY, 1024, ""), hidden_member_payload()].concat()),
        entry("y.txt", REGULAR, b"y\n"),
    ]);
    assert_refused_everywhere(&bytes, "payload");
}

#[test]
fn symlink_and_hardlink_with_payload_are_refused() {
    for typeflag in [SYMLINK, HARDLINK] {
        let bytes = tar_of(&[
            entry("target.txt", REGULAR, b"t"),
            pad([
                header("lnk", typeflag, 1024, "target.txt"),
                hidden_member_payload(),
            ]
            .concat()),
            entry("y.txt", REGULAR, b"y\n"),
        ]);
        assert_refused_everywhere(&bytes, "payload");
    }
}

#[test]
fn directory_with_pax_size_payload_is_refused() {
    let bytes = tar_of(&[
        extension(PAX_LOCAL, &[("size", "512")]),
        pad([header("x/", DIRECTORY, 0, ""), hidden_member_payload()].concat()),
        entry("y.txt", REGULAR, b"y\n"),
    ]);
    assert_refused_everywhere(&bytes, "payload");
}

#[test]
fn directory_without_payload_is_still_listed() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(
        &dir,
        &tar_of(&[
            pad(header("x/", DIRECTORY, 0, "")),
            entry("x/y.txt", REGULAR, b"y"),
        ]),
    );
    let manifest = list_archive(&archive, &config()).unwrap();
    assert!(
        manifest
            .entries()
            .iter()
            .any(|e| e.kind == ManifestEntryKind::Directory)
    );
}

#[test]
fn duplicate_size_records_are_refused() {
    let bytes = tar_of(&[
        extension(PAX_LOCAL, &[("size", "1024"), ("size", "0")]),
        entry("benign.txt", REGULAR, b""),
        hidden_member_payload(),
    ]);
    assert_refused_everywhere(&bytes, "duplicate PAX record \"size\"");
}

#[test]
fn duplicate_path_records_are_refused() {
    let bytes = tar_of(&[
        extension(
            PAX_LOCAL,
            &[("path", "safe.txt"), ("path", "../escaped.txt")],
        ),
        entry("placeholder.txt", REGULAR, b"data\n"),
    ]);
    assert_refused_everywhere(&bytes, "duplicate PAX record \"path\"");
}

#[test]
fn duplicate_linkpath_records_are_refused() {
    let bytes = tar_of(&[
        entry("inside.txt", REGULAR, b"i\n"),
        extension(
            PAX_LOCAL,
            &[("linkpath", "inside.txt"), ("linkpath", "/etc")],
        ),
        link("lnk", SYMLINK, "inside.txt"),
    ]);
    assert_refused_everywhere(&bytes, "duplicate PAX record \"linkpath\"");
}

#[test]
fn non_numeric_pax_size_is_refused() {
    let bytes = tar_of(&[
        extension(PAX_LOCAL, &[("size", "12x")]),
        entry("a.txt", REGULAR, b"a"),
    ]);
    assert_refused_everywhere(&bytes, "`size`");
}

#[test]
fn gnu_sparse_records_are_refused() {
    for key in ["GNU.sparse.name", "GNU.sparse.major", "GNU.sparse.map"] {
        let bytes = tar_of(&[
            extension(PAX_LOCAL, &[(key, "../escaped.txt")]),
            entry("safe.txt", REGULAR, b"data\n"),
        ]);
        assert_refused_everywhere(&bytes, key);
    }
}

#[test]
fn pax_path_with_gnu_long_name_is_refused_in_either_order() {
    let pax = extension(PAX_LOCAL, &[("path", "../escaped.txt")]);
    let long = gnu_long(GNU_LONG_NAME, "safe.txt");
    let file = entry("placeholder.txt", REGULAR, b"data\n");
    for headers in [[pax.clone(), long.clone()], [long, pax]] {
        let bytes = tar_of(&[headers.concat(), file.clone()]);
        assert_refused_everywhere(&bytes, "GNU long name");
    }
}

#[test]
fn pax_linkpath_with_gnu_long_link_is_refused() {
    let bytes = tar_of(&[
        entry("inside.txt", REGULAR, b"i\n"),
        extension(PAX_LOCAL, &[("linkpath", "/etc")]),
        gnu_long(GNU_LONG_LINK, "inside.txt"),
        link("lnk", SYMLINK, "inside.txt"),
    ]);
    assert_refused_everywhere(&bytes, "GNU long link");
}

#[test]
fn global_header_overriding_entry_fields_is_refused() {
    for (key, value) in [("path", "../g.txt"), ("linkpath", "/etc"), ("size", "0")] {
        let bytes = tar_of(&[
            extension(PAX_GLOBAL, &[(key, value)]),
            entry("benign.txt", REGULAR, b"b\n"),
        ]);
        assert_refused_everywhere(&bytes, &format!("global PAX record \"{key}\""));
    }
}

#[test]
fn global_header_after_local_header_is_refused() {
    let bytes = tar_of(&[
        extension(PAX_LOCAL, &[("path", "../escaped.txt")]),
        extension(PAX_GLOBAL, &[("comment", "c")]),
        entry("benign.txt", REGULAR, b"b\n"),
    ]);
    assert_refused_everywhere(&bytes, "follows a local PAX header");
}

#[test]
fn extension_header_without_magic_is_refused() {
    let mut unmarked = tar::Header::new_old();
    unmarked.set_size(0);
    unmarked.set_entry_type(tar::EntryType::new(PAX_LOCAL));
    unmarked.as_old_mut().name[..3].copy_from_slice(b"pax");
    unmarked.set_cksum();
    let bytes = tar_of(&[
        pad(unmarked.as_bytes().to_vec()),
        entry("benign.txt", REGULAR, b"b\n"),
    ]);
    assert_refused_everywhere(&bytes, "lacks a ustar or GNU magic");
}

#[test]
fn legitimate_extension_headers_are_accepted() {
    let long_name = format!("{}/file.txt", "d".repeat(150));
    let archives = [
        tar_of(&[
            extension(PAX_GLOBAL, &[("comment", "0123456789abcdef")]),
            entry("a.txt", REGULAR, b"a"),
        ]),
        tar_of(&[
            extension(
                PAX_LOCAL,
                &[("path", &long_name), ("mtime", "1700000000.5")],
            ),
            entry("placeholder.txt", REGULAR, b"a"),
        ]),
        tar_of(&[
            gnu_long(GNU_LONG_NAME, &long_name),
            entry("placeholder.txt", REGULAR, b"a"),
        ]),
        tar_of(&[
            entry("t.txt", REGULAR, b"t"),
            gnu_long(GNU_LONG_LINK, &long_name),
            link("lnk", SYMLINK, "t.txt"),
        ]),
    ];
    for bytes in archives {
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, &bytes);
        verify_archive(&archive, &config()).unwrap();
        let out = TempDir::new().unwrap();
        extract_archive(&archive, out.path(), &config()).unwrap();
    }
}
