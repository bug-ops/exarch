//! TAR header and PAX/GNU extension parsing agrees with the reference readers
//! (`bsdtar`, the Python `tarfile` module) or the archive is refused.
//!
//! Every construct below is read differently by those tools: a payload on a
//! zero-size entry type, duplicate PAX records, GNU sparse names, PAX records
//! stacked with GNU long records, and global PAX headers. `list`, `verify` and
//! `extract` must all refuse them with a typed `InvalidArchive`.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

use std::assert_matches;
use std::path::Path;

use exarch_core::ArchiveError;
use exarch_core::ErrorCode;
use exarch_core::ManifestEntryKind;
use exarch_core::SecurityConfig;
use exarch_core::TarAmbiguity;
use exarch_core::TarExtensionKind;
use exarch_core::TarHeaderField;
use exarch_core::TarPathKey;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use proptest::prelude::*;
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
    let record = exarch_testkit::pax::record(key.as_bytes(), value.as_bytes());
    String::from_utf8_lossy(&record).into_owned()
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

enum Expected {
    Ambiguity(TarAmbiguity),
    Payload,
}

impl From<TarAmbiguity> for Expected {
    fn from(ambiguity: TarAmbiguity) -> Self {
        Self::Ambiguity(ambiguity)
    }
}

fn key_error(make: fn(String) -> TarAmbiguity, key: &str) -> Expected {
    make(key.to_owned()).into()
}

fn number_error(field: TarHeaderField) -> Expected {
    TarAmbiguity::NonCanonicalNumber { field }.into()
}

fn assert_ambiguous(error: &ArchiveError, expected: &Expected) {
    let source = match error {
        ArchiveError::PartialExtraction { source, .. } => source,
        other => other,
    };
    assert_eq!(source.error_code(), ErrorCode::InvalidArchive, "{source}");
    match expected {
        Expected::Ambiguity(want) => {
            assert_matches!(source, ArchiveError::TarAmbiguity(found) if found == want, "{source}");
        }
        Expected::Payload => {
            assert_matches!(
                source,
                ArchiveError::TarAmbiguity(TarAmbiguity::NonRegularPayload { size: 1.., .. }),
                "{source}"
            );
        }
    }
}

fn assert_refused_everywhere(bytes: &[u8], expected: impl Into<Expected>) {
    let expected = expected.into();
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, bytes);
    let config = config();

    assert_ambiguous(&list_archive(&archive, &config).unwrap_err(), &expected);
    assert_ambiguous(&verify_archive(&archive, &config).unwrap_err(), &expected);

    let root = TempDir::new().unwrap();
    let out = root.path().join("out");
    assert_ambiguous(
        &extract_archive(&archive, &out, &config).unwrap_err(),
        &expected,
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
    assert_refused_everywhere(&bytes, Expected::Payload);
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
        assert_refused_everywhere(&bytes, Expected::Payload);
    }
}

#[test]
fn directory_with_pax_size_payload_is_refused() {
    let bytes = tar_of(&[
        extension(PAX_LOCAL, &[("size", "512")]),
        pad([header("x/", DIRECTORY, 0, ""), hidden_member_payload()].concat()),
        entry("y.txt", REGULAR, b"y\n"),
    ]);
    assert_refused_everywhere(&bytes, Expected::Payload);
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
    assert_refused_everywhere(&bytes, TarAmbiguity::DuplicateRecord { key: "size".into() });
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
    assert_refused_everywhere(&bytes, TarAmbiguity::DuplicateRecord { key: "path".into() });
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
    assert_refused_everywhere(
        &bytes,
        TarAmbiguity::DuplicateRecord {
            key: "linkpath".into(),
        },
    );
}

#[test]
fn non_numeric_pax_size_is_refused() {
    let bytes = tar_of(&[
        extension(PAX_LOCAL, &[("size", "12x")]),
        entry("a.txt", REGULAR, b"a"),
    ]);
    assert_refused_everywhere(&bytes, TarAmbiguity::InvalidSize);
}

#[test]
fn gnu_sparse_records_are_refused() {
    for key in ["GNU.sparse.name", "GNU.sparse.major", "GNU.sparse.map"] {
        let bytes = tar_of(&[
            extension(PAX_LOCAL, &[(key, "../escaped.txt")]),
            entry("safe.txt", REGULAR, b"data\n"),
        ]);
        assert_refused_everywhere(
            &bytes,
            key_error(|key| TarAmbiguity::UnsupportedRecord { key }, key),
        );
    }
}

#[test]
fn pax_path_with_gnu_long_name_is_refused_in_either_order() {
    let pax = extension(PAX_LOCAL, &[("path", "../escaped.txt")]);
    let long = gnu_long(GNU_LONG_NAME, "safe.txt");
    let file = entry("placeholder.txt", REGULAR, b"data\n");
    for headers in [[pax.clone(), long.clone()], [long, pax]] {
        let bytes = tar_of(&[headers.concat(), file.clone()]);
        assert_refused_everywhere(
            &bytes,
            TarAmbiguity::StackedLongRecord {
                key: TarPathKey::Path,
            },
        );
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
    assert_refused_everywhere(
        &bytes,
        TarAmbiguity::StackedLongRecord {
            key: TarPathKey::LinkPath,
        },
    );
}

#[test]
fn global_header_overriding_entry_fields_is_refused() {
    for (key, value) in [("path", "../g.txt"), ("linkpath", "/etc"), ("size", "0")] {
        let bytes = tar_of(&[
            extension(PAX_GLOBAL, &[(key, value)]),
            entry("benign.txt", REGULAR, b"b\n"),
        ]);
        assert_refused_everywhere(
            &bytes,
            key_error(|key| TarAmbiguity::GlobalOverride { key }, key),
        );
    }
}

#[test]
fn global_header_after_local_header_is_refused() {
    let bytes = tar_of(&[
        extension(PAX_LOCAL, &[("path", "../escaped.txt")]),
        extension(PAX_GLOBAL, &[("comment", "c")]),
        entry("benign.txt", REGULAR, b"b\n"),
    ]);
    assert_refused_everywhere(&bytes, TarAmbiguity::LocalBeforeGlobal);
}

#[test]
fn global_header_over_the_metadata_limit_is_refused() {
    const LIMIT: u64 = 1024;
    let comment = "c".repeat(2048);
    let body_len = pax_record("comment", &comment).len() as u64;
    let bytes = tar_of(&[
        extension(PAX_GLOBAL, &[("comment", &comment)]),
        entry("benign.txt", REGULAR, b"b\n"),
    ]);
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &bytes);
    let config = config().with_max_tar_metadata_bytes(exarch_core::non_zero!(LIMIT));
    let expected = Expected::from(TarAmbiguity::GlobalTooLarge {
        size: body_len,
        limit: LIMIT,
    });

    assert_ambiguous(&list_archive(&archive, &config).unwrap_err(), &expected);
    assert_ambiguous(&verify_archive(&archive, &config).unwrap_err(), &expected);
    let out = dir.path().join("out");
    assert_ambiguous(
        &extract_archive(&archive, &out, &config).unwrap_err(),
        &expected,
    );
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
    assert_refused_everywhere(
        &bytes,
        TarAmbiguity::UnrecognizedHeader {
            kind: TarExtensionKind::Pax,
        },
    );
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
    ];
    for bytes in archives {
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, &bytes);
        verify_archive(&archive, &config()).unwrap();
        let out = TempDir::new().unwrap();
        extract_archive(&archive, out.path(), &config()).unwrap();
    }
}

#[test]
fn legitimate_gnu_long_link_is_accepted() {
    let long_name = format!("{}/file.txt", "d".repeat(150));
    let bytes = tar_of(&[
        entry("t.txt", REGULAR, b"t"),
        gnu_long(GNU_LONG_LINK, &long_name),
        link("lnk", SYMLINK, "t.txt"),
    ]);
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &bytes);
    verify_archive(&archive, &config()).unwrap();
    #[cfg(unix)]
    {
        let out = TempDir::new().unwrap();
        extract_archive(&archive, out.path(), &config()).unwrap();
    }
}

const SIZE_FIELD: std::ops::Range<usize> = 124..136;
const CHECKSUM_FIELD: std::ops::Range<usize> = 148..156;

fn refresh_checksum(block: &mut [u8]) {
    block[CHECKSUM_FIELD].fill(b' ');
    let sum: u32 = block.iter().map(|&b| u32::from(b)).sum();
    block[CHECKSUM_FIELD].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

fn patched(mut block: Vec<u8>, edits: &[(usize, &[u8])]) -> Vec<u8> {
    for (offset, bytes) in edits {
        block[*offset..*offset + bytes.len()].copy_from_slice(bytes);
    }
    refresh_checksum(&mut block);
    block
}

fn hidden_payload() -> Vec<u8> {
    let mut payload = entry("hidden.txt", REGULAR, b"hidden\n");
    payload.resize(1024, 0);
    payload
}

fn with_size_field(field: &[u8; 12]) -> Vec<u8> {
    let header = patched(
        header("a.txt", REGULAR, 1024, ""),
        &[(SIZE_FIELD.start, field)],
    );
    tar_of(&[
        entry("pre.txt", REGULAR, b"x"),
        pad([header, hidden_payload()].concat()),
    ])
}

fn with_checksum_field(field: [u8; 8]) -> Vec<u8> {
    let mut block = header("a.txt", REGULAR, 1024, "");
    block[CHECKSUM_FIELD].copy_from_slice(&field);
    tar_of(&[
        entry("pre.txt", REGULAR, b"x"),
        pad([block, hidden_payload()].concat()),
    ])
}

fn checksum_of(block: &[u8]) -> u32 {
    block
        .iter()
        .enumerate()
        .map(|(i, &b)| u32::from(if CHECKSUM_FIELD.contains(&i) { b' ' } else { b }))
        .sum()
}

#[test]
fn non_canonical_size_fields_are_refused() {
    for field in [
        b"+0000002000\0",
        b"\x0b0000002000\0",
        b"\n0000002000\0",
        b"\x0c0000002000\0",
    ] {
        assert_refused_everywhere(&with_size_field(field), number_error(TarHeaderField::Size));
    }
}

#[test]
fn base256_size_with_a_sign_or_high_bytes_is_refused() {
    let mut signed = [0u8; 12];
    signed[0] = 0xC0;
    signed[11] = 0x80;
    let mut wide = [0u8; 12];
    wide[0] = 0x80;
    wide[3] = 1;
    wide[11] = 0x80;
    for field in [signed, wide] {
        assert_refused_everywhere(&with_size_field(&field), number_error(TarHeaderField::Size));
    }
}

#[test]
fn non_canonical_checksum_fields_are_refused() {
    let sum = checksum_of(&header("a.txt", REGULAR, 1024, ""));
    for lead in [b'+', 0x0b, b'\n'] {
        let mut field = [0u8; 8];
        field[0] = lead;
        field[1..7].copy_from_slice(format!("{sum:06o}").as_bytes());
        assert_refused_everywhere(
            &with_checksum_field(field),
            number_error(TarHeaderField::Checksum),
        );
    }
}

#[test]
fn canonical_numeric_fields_are_accepted() {
    let mut base256 = [0u8; 12];
    base256[0] = 0x80;
    base256[10] = 0x04;
    for field in [*b"      2000 \0", base256] {
        let header = patched(
            header("a.txt", REGULAR, 1024, ""),
            &[(SIZE_FIELD.start, &field)],
        );
        let bytes = tar_of(&[pad([header, hidden_payload()].concat())]);
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, &bytes);
        list_archive(&archive, &config()).unwrap();
    }
}

#[test]
fn gnu_sparse_entries_are_refused() {
    let plain = tar_of(&[
        entry("pre.txt", REGULAR, b"x"),
        pad(patched(
            header("sparse.bin", b'S', 0, ""),
            &[(483, b"00000000000\0")],
        )),
    ]);
    assert_refused_everywhere(&plain, TarAmbiguity::SparseEntry);

    let mut sparse = patched(
        header("sparse.bin", b'S', 512, ""),
        &[
            (386, b"00000000000\0"),
            (398, b"00000001000\0"),
            (482, &[2]),
            (483, b"00000001000\0"),
        ],
    );
    sparse.extend(vec![0u8; 512]);
    let desync = tar_of(&[sparse, pad(header("benign.txt", REGULAR, 512, ""))]);
    assert_refused_everywhere(&desync, TarAmbiguity::SparseEntry);
}

#[test]
fn global_header_after_gnu_long_record_is_refused() {
    let global = extension(PAX_GLOBAL, &[("comment", "hi")]);
    let empty_global = extension(PAX_GLOBAL, &[]);
    let cases = [
        tar_of(&[
            gnu_long(GNU_LONG_NAME, "renamed.txt"),
            global.clone(),
            entry("plain.txt", REGULAR, b"d"),
        ]),
        tar_of(&[
            gnu_long(GNU_LONG_LINK, "/etc/passwd"),
            global,
            link("lnk", SYMLINK, "benign"),
        ]),
        tar_of(&[
            gnu_long(GNU_LONG_NAME, "renamed.txt"),
            empty_global,
            entry("plain.txt", REGULAR, b"d"),
        ]),
    ];
    for bytes in cases {
        assert_refused_everywhere(&bytes, TarAmbiguity::LongRecordBeforeGlobal);
    }
}

fn raw_extension(typeflag: u8, body: &[u8]) -> Vec<u8> {
    pad([header("pax", typeflag, body.len(), ""), body.to_vec()].concat())
}

#[test]
fn pax_records_with_an_empty_key_are_refused() {
    let body = [
        pax_record("", "v").into_bytes(),
        pax_record("path", "after.txt").into_bytes(),
    ]
    .concat();
    for typeflag in [PAX_LOCAL, PAX_GLOBAL] {
        let bytes = tar_of(&[
            entry("pre.txt", REGULAR, b"x"),
            raw_extension(typeflag, &body),
            entry("u.txt", REGULAR, b"d"),
        ]);
        assert_refused_everywhere(&bytes, TarAmbiguity::EmptyKey);
    }
}

#[test]
fn pax_records_longer_than_the_reference_limit_are_refused() {
    let big = "A".repeat(1_000_000);
    for typeflag in [PAX_LOCAL, PAX_GLOBAL] {
        let bytes = tar_of(&[
            entry("pre.txt", REGULAR, b"x"),
            extension(typeflag, &[("comment", &big), ("mtime", "0")]),
            entry("u.txt", REGULAR, b"d"),
        ]);
        assert_refused_everywhere(
            &bytes,
            TarAmbiguity::OversizedRecord {
                key: "comment".into(),
            },
        );
    }
}

#[test]
fn global_pax_header_framing_must_be_canonical() {
    let good = pax_record("comment", "hi");
    let bodies = [
        format!("+{good}").into_bytes(),
        format!("0{good}").into_bytes(),
        format!("{good}\n{}", pax_record("comment2", "x")).into_bytes(),
        format!("{good}trailing").into_bytes(),
    ];
    for body in bodies {
        let bytes = tar_of(&[
            raw_extension(PAX_GLOBAL, &body),
            entry("u.txt", REGULAR, b"d"),
        ]);
        assert_refused_everywhere(&bytes, TarAmbiguity::MalformedRecord);
    }
}

#[test]
fn prefix_field_without_a_ustar_magic_is_refused() {
    let with_prefix = |magic: &[u8; 8]| {
        tar_of(&[pad(patched(
            header("a.txt", REGULAR, 0, ""),
            &[(257, magic), (345, b"pfx")],
        ))])
    };
    for magic in [b"ustar  \0", b"\0\0\0\0\0\0\0\0", b"ustar\0  "] {
        assert_refused_everywhere(&with_prefix(magic), TarAmbiguity::PrefixWithoutUstar);
    }
}

#[test]
fn ustar_prefix_field_is_accepted() {
    let bytes = tar_of(&[pad(patched(
        header("a.txt", REGULAR, 0, ""),
        &[(257, b"ustar\0"), (263, b"00"), (345, b"pfx")],
    ))]);
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &bytes);
    let manifest = list_archive(&archive, &config()).unwrap();
    assert_eq!(manifest.entries()[0].path, Path::new("pfx/a.txt"));
}

#[test]
fn long_keys_are_truncated_in_error_messages() {
    let key = "k".repeat(1000);
    let bytes = tar_of(&[
        extension(PAX_LOCAL, &[(&key, "1"), (&key, "2")]),
        entry("a.txt", REGULAR, b"a"),
    ]);
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &bytes);
    let message = list_archive(&archive, &config()).unwrap_err().to_string();
    assert!(message.contains("..."), "{message}");
    assert!(message.len() < 400, "{} bytes: {message}", message.len());
}

#[test]
fn gnu_long_name_traversal_alone_is_still_a_path_traversal() {
    let bytes = tar_of(&[
        gnu_long(GNU_LONG_NAME, "../../escape.txt"),
        entry("u.txt", REGULAR, b"d"),
    ]);
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &bytes);
    assert_eq!(
        list_archive(&archive, &config()).unwrap_err().error_code(),
        ErrorCode::PathTraversal
    );
    let root = TempDir::new().unwrap();
    let out = root.path().join("out");
    assert_eq!(
        extract_archive(&archive, &out, &config())
            .unwrap_err()
            .error_code(),
        ErrorCode::PathTraversal
    );
}

fn with_checksum(mut block: Vec<u8>, lead: u8) -> Vec<u8> {
    let sum = checksum_of(&block);
    block[CHECKSUM_FIELD].copy_from_slice(format!("{}{sum:06o}\0", char::from(lead)).as_bytes());
    block
}

fn with_size(block: Vec<u8>, lead: u8, size: usize) -> Vec<u8> {
    let field = format!("{}{size:010o}\0", char::from(lead));
    patched(block, &[(SIZE_FIELD.start, field.as_bytes())])
}

fn extension_header(
    typeflag: u8,
    body: &[u8],
    corrupt: impl FnOnce(Vec<u8>) -> Vec<u8>,
) -> Vec<u8> {
    pad([
        corrupt(header("hdr", typeflag, body.len(), "")),
        body.to_vec(),
    ]
    .concat())
}

fn pax_body(records: &[(&str, &str)]) -> Vec<u8> {
    records
        .iter()
        .map(|(k, v)| pax_record(k, v))
        .collect::<String>()
        .into_bytes()
}

fn local_pax_with_plus_length(key: &str, value: &str) -> Vec<u8> {
    let payload = format!(" {key}={value}\n");
    let mut total = payload.len() + 2;
    while format!("+{total}").len() + payload.len() != total {
        total = format!("+{total}").len() + payload.len();
    }
    raw_extension(PAX_LOCAL, format!("+{total}{payload}").as_bytes())
}

fn hidden_pair() -> Vec<u8> {
    pad([
        link("hlink", SYMLINK, "/etc/passwd"),
        entry("hidden.txt", REGULAR, b"SMUGGLED\n"),
    ]
    .concat())
}

fn pre() -> Vec<u8> {
    entry("pre.txt", REGULAR, b"x")
}

fn swallowing_member(name: &str, declared: usize) -> Vec<u8> {
    pad([header(name, REGULAR, declared, ""), hidden_pair()].concat())
}

fn plus_size_extension(typeflag: u8, body: &[u8]) -> Vec<u8> {
    extension_header(typeflag, body, |h| with_size(h, b'+', body.len()))
}

fn plus_checksum_extension(typeflag: u8, body: &[u8]) -> Vec<u8> {
    extension_header(typeflag, body, |h| with_checksum(h, b'+'))
}

struct Refusal {
    name: &'static str,
    bytes: Vec<u8>,
    expected: Expected,
}

fn refusal(name: &'static str, entries: &[Vec<u8>], expected: impl Into<Expected>) -> Refusal {
    Refusal {
        name,
        bytes: tar_of(entries),
        expected: expected.into(),
    }
}

fn non_canonical_extension_archives() -> Vec<Refusal> {
    let mut cases = non_canonical_extension_number_archives();
    cases.extend(non_canonical_pax_framing_archives());
    cases
}

fn non_canonical_extension_number_archives() -> Vec<Refusal> {
    let hidden_len = hidden_pair().len();
    let size_body = pax_body(&[("size", &hidden_len.to_string())]);
    vec![
        refusal(
            "x1",
            &[
                pre(),
                plus_size_extension(PAX_LOCAL, &pax_body(&[("path", "from_pax.txt")])),
                entry("ustar.txt", REGULAR, b"d"),
            ],
            number_error(TarHeaderField::Size),
        ),
        refusal(
            "x2",
            &[
                pre(),
                plus_size_extension(GNU_LONG_NAME, b"from_L.txt\0"),
                entry("ustar.txt", REGULAR, b"d"),
            ],
            number_error(TarHeaderField::Size),
        ),
        refusal(
            "x3",
            &[
                pre(),
                plus_checksum_extension(PAX_LOCAL, &size_body),
                swallowing_member("a.txt", 0),
            ],
            number_error(TarHeaderField::Checksum),
        ),
        refusal(
            "p1",
            &[
                pre(),
                plus_checksum_extension(GNU_LONG_NAME, b"long_name.txt\0"),
                swallowing_member("a.txt", hidden_len),
            ],
            number_error(TarHeaderField::Checksum),
        ),
        refusal(
            "p2",
            &[
                pre(),
                plus_checksum_extension(GNU_LONG_LINK, b"benign_target\0"),
                link("lnk", SYMLINK, "/etc/passwd"),
            ],
            number_error(TarHeaderField::Checksum),
        ),
        refusal(
            "p3",
            &[
                pre(),
                plus_checksum_extension(PAX_LOCAL, &pax_body(&[("linkpath", "benign_target")])),
                link("lnk", SYMLINK, "/etc/passwd"),
            ],
            number_error(TarHeaderField::Checksum),
        ),
        refusal(
            "p10",
            &[
                pre(),
                plus_checksum_extension(PAX_LOCAL, &pax_body(&[("path", "from_pax.txt")])),
                entry("ustar.txt", REGULAR, b"d"),
            ],
            number_error(TarHeaderField::Checksum),
        ),
    ]
}

fn non_canonical_pax_framing_archives() -> Vec<Refusal> {
    let hidden_len = hidden_pair().len();
    let blank_line = format!(
        "{}\n{}",
        pax_record("path", "p.txt"),
        pax_record("size", "0")
    );
    vec![
        refusal(
            "e",
            &[
                pre(),
                local_pax_with_plus_length("size", &hidden_len.to_string()),
                swallowing_member("a.txt", 0),
            ],
            TarAmbiguity::MalformedRecord,
        ),
        refusal(
            "e2",
            &[
                pre(),
                local_pax_with_plus_length("path", "pax_name.txt"),
                entry("ustar_name.txt", REGULAR, b"d"),
            ],
            TarAmbiguity::MalformedRecord,
        ),
        refusal(
            "l",
            &[
                raw_extension(PAX_LOCAL, blank_line.as_bytes()),
                swallowing_member("a.txt", hidden_len),
            ],
            TarAmbiguity::MalformedRecord,
        ),
        refusal(
            "p4",
            &[
                pre(),
                local_pax_with_plus_length("linkpath", "benign_target"),
                link("lnk", SYMLINK, "/etc/passwd"),
            ],
            TarAmbiguity::MalformedRecord,
        ),
    ]
}

#[test]
fn non_canonical_extension_header_numbers_and_pax_framing_are_refused() {
    for case in non_canonical_extension_archives() {
        eprintln!("case {}", case.name);
        assert_refused_everywhere(&case.bytes, case.expected);
    }
}

#[test]
fn non_canonical_extension_header_is_refused_through_gzip() {
    use std::io::Write;

    let case = non_canonical_extension_archives()
        .into_iter()
        .find(|case| case.name == "x3")
        .unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&case.bytes).unwrap();

    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.tar.gz");
    std::fs::write(&archive, encoder.finish().unwrap()).unwrap();
    let config = config();
    assert_ambiguous(
        &list_archive(&archive, &config).unwrap_err(),
        &case.expected,
    );
    assert_ambiguous(
        &verify_archive(&archive, &config).unwrap_err(),
        &case.expected,
    );
    let out = TempDir::new().unwrap();
    assert_ambiguous(
        &extract_archive(&archive, out.path().join("out"), &config).unwrap_err(),
        &case.expected,
    );
}

#[test]
fn schily_realsize_record_is_refused() {
    let bytes = tar_of(&[
        extension(PAX_LOCAL, &[("SCHILY.realsize", "1073741824")]),
        entry("big.txt", REGULAR, b"x"),
    ]);
    assert_refused_everywhere(
        &bytes,
        TarAmbiguity::UnsupportedRecord {
            key: "SCHILY.realsize".into(),
        },
    );
}

fn builder_archive(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    build(&mut builder);
    builder.into_inner().unwrap()
}

fn append_sized(builder: &mut tar::Builder<Vec<u8>>, name: &str, declared: u64, data: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(declared);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append_data(&mut header, name, data).unwrap();
}

#[test]
fn archives_from_the_tar_builder_are_accepted() {
    let long_name = format!("{}/{}/file.txt", "d".repeat(120), "e".repeat(120));
    let archives = [
        builder_archive(|b| {
            append_sized(b, &long_name, 4, b"long");
            append_sized(b, "short.txt", 5, b"short");
        }),
        builder_archive(|b| {
            b.append_pax_extensions([("path", long_name.as_bytes()), ("mtime", b"1700000000.5")])
                .unwrap();
            append_sized(b, "placeholder.txt", 3, b"pax");
        }),
        builder_archive(|b| {
            b.append_pax_extensions([("size", &b"5"[..])]).unwrap();
            append_sized(b, "sized.txt", 0, b"hello");
        }),
    ];
    for bytes in archives {
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, &bytes);
        list_archive(&archive, &config()).unwrap();
        verify_archive(&archive, &config()).unwrap();
        let out = TempDir::new().unwrap();
        extract_archive(&archive, out.path(), &config()).unwrap();
    }
}

#[test]
fn git_archive_global_header_with_a_comment_is_accepted() {
    let comment = "0123456789abcdef0123456789abcdef01234567";
    let bytes = tar_of(&[
        extension(PAX_GLOBAL, &[("comment", comment)]),
        pad(header("dir/", DIRECTORY, 0, "")),
        entry("dir/a.txt", REGULAR, b"a"),
    ]);
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &bytes);
    assert_eq!(
        list_archive(&archive, &config()).unwrap().entries().len(),
        2
    );
    verify_archive(&archive, &config()).unwrap();
}

#[test]
fn pax_long_name_and_long_link_headers_may_share_a_window() {
    let long_name = format!("{}/file.txt", "d".repeat(150));
    let bytes = tar_of(&[
        entry("t.txt", REGULAR, b"t"),
        extension(PAX_LOCAL, &[("mtime", "1700000000")]),
        gnu_long(GNU_LONG_NAME, &long_name),
        gnu_long(GNU_LONG_LINK, "t.txt"),
        link("placeholder", SYMLINK, "t.txt"),
    ]);
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &bytes);
    let manifest = list_archive(&archive, &config()).unwrap();
    assert_eq!(manifest.entries()[1].path, Path::new(&long_name));
}

#[test]
fn extension_header_with_a_base256_size_is_accepted() {
    let body = pax_body(&[("path", "long.txt")]);
    let mut field = [0u8; 12];
    field[0] = 0x80;
    field[11] = u8::try_from(body.len()).unwrap();
    let header = patched(
        header("hdr", PAX_LOCAL, body.len(), ""),
        &[(SIZE_FIELD.start, &field)],
    );
    let bytes = tar_of(&[
        pad([header, body].concat()),
        entry("placeholder.txt", REGULAR, b"d"),
    ]);
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &bytes);
    let manifest = list_archive(&archive, &config()).unwrap();
    assert_eq!(manifest.entries()[0].path, Path::new("long.txt"));
}

#[derive(Clone, Copy, Debug)]
enum Naming {
    Plain,
    GnuLong,
    PaxPath,
}

#[derive(Clone, Copy, Debug)]
enum Corruption {
    PlusSize,
    VerticalTabSize,
    PlusChecksum,
    VerticalTabChecksum,
}

fn corrupt(block: Vec<u8>, size: usize, corruption: Option<Corruption>) -> Vec<u8> {
    match corruption {
        None => block,
        Some(Corruption::PlusSize) => with_size(block, b'+', size),
        Some(Corruption::VerticalTabSize) => with_size(block, 0x0b, size),
        Some(Corruption::PlusChecksum) => with_checksum(block, b'+'),
        Some(Corruption::VerticalTabChecksum) => with_checksum(block, 0x0b),
    }
}

fn named_entry(naming: Naming, name: &str, data: &[u8], corruption: Option<Corruption>) -> Vec<u8> {
    let (typeflag, body) = match naming {
        Naming::Plain => return entry(&name[..name.len().min(100)], REGULAR, data),
        Naming::GnuLong => {
            let mut body = name.as_bytes().to_vec();
            body.push(0);
            (GNU_LONG_NAME, body)
        }
        Naming::PaxPath => (PAX_LOCAL, pax_body(&[("path", name)])),
    };
    let block = corrupt(
        header("hdr", typeflag, body.len(), ""),
        body.len(),
        corruption,
    );
    [
        pad([block, body].concat()),
        entry("placeholder", REGULAR, data),
    ]
    .concat()
}

type Leading = Vec<(Naming, String, Vec<u8>)>;

fn archive_with(leading: &Leading, target: (Naming, &str, &[u8], Option<Corruption>)) -> Vec<u8> {
    let mut entries: Vec<Vec<u8>> = leading
        .iter()
        .map(|(naming, name, data)| named_entry(*naming, name, data, None))
        .collect();
    entries.push(named_entry(target.0, target.1, target.2, target.3));
    tar_of(&entries)
}

fn naming_strategy() -> impl Strategy<Value = Naming> {
    prop_oneof![
        Just(Naming::Plain),
        Just(Naming::GnuLong),
        Just(Naming::PaxPath)
    ]
}

fn extension_naming_strategy() -> impl Strategy<Value = Naming> {
    prop_oneof![Just(Naming::GnuLong), Just(Naming::PaxPath)]
}

fn corruption_strategy() -> impl Strategy<Value = Corruption> {
    prop_oneof![
        Just(Corruption::PlusSize),
        Just(Corruption::VerticalTabSize),
        Just(Corruption::PlusChecksum),
        Just(Corruption::VerticalTabChecksum),
    ]
}

fn name_strategy() -> impl Strategy<Value = String> {
    prop_oneof!["[a-z]{1,40}", "[a-z]{101,200}"]
}

fn data_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..1200)
}

fn leading_strategy() -> impl Strategy<Value = Leading> {
    prop::collection::vec((naming_strategy(), name_strategy(), data_strategy()), 0..4)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn canonical_archives_are_never_refused(
        leading in leading_strategy(),
        naming in naming_strategy(),
        name in name_strategy(),
        data in data_strategy(),
    ) {
        let bytes = archive_with(&leading, (naming, &name, &data, None));
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, &bytes);
        let manifest = list_archive(&archive, &config()).unwrap();
        prop_assert_eq!(manifest.entries().len(), leading.len() + 1);
        prop_assert!(verify_archive(&archive, &config()).is_ok());
    }

    #[test]
    fn non_canonical_extension_header_numbers_are_never_accepted(
        leading in leading_strategy(),
        naming in extension_naming_strategy(),
        corruption in corruption_strategy(),
        name in name_strategy(),
        data in data_strategy(),
    ) {
        let bytes = archive_with(&leading, (naming, &name, &data, Some(corruption)));
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, &bytes);
        prop_assert!(list_archive(&archive, &config()).is_err());
        prop_assert!(verify_archive(&archive, &config()).is_err());
    }
}

fn with_padding_bytes(typeflag: u8, body: &[u8], padding: &[u8]) -> Vec<u8> {
    let mut bytes = raw_extension(typeflag, body);
    let at = 512 + body.len();
    assert!(at + padding.len() <= bytes.len(), "padding does not fit");
    bytes[at..at + padding.len()].copy_from_slice(padding);
    bytes
}

fn long_path(len: usize) -> String {
    let mut path: String = "dddddddd/".repeat(len / 9 + 1);
    path.truncate(len - 1);
    path.push('f');
    path
}

#[test]
fn local_pax_header_with_records_in_the_padding_is_refused() {
    let body = pax_body(&[("mtime", "1700000000")]);
    let size_record = pax_record("size", "1024");
    let bytes = tar_of(&[
        with_padding_bytes(PAX_LOCAL, &body, size_record.as_bytes()),
        entry("a.txt", REGULAR, b"a"),
    ]);
    assert_refused_everywhere(&bytes, TarAmbiguity::NonZeroPadding);
}

#[test]
fn local_pax_header_with_a_path_record_in_the_padding_is_refused() {
    let body = pax_body(&[("mtime", "1700000000")]);
    let path_record = pax_record("path", "other.txt");
    let bytes = tar_of(&[
        with_padding_bytes(PAX_LOCAL, &body, path_record.as_bytes()),
        entry("a.txt", REGULAR, b"a"),
    ]);
    assert_refused_everywhere(&bytes, TarAmbiguity::NonZeroPadding);
}

#[test]
fn local_pax_header_with_a_linkpath_record_in_the_padding_is_refused() {
    let body = pax_body(&[("mtime", "1700000000")]);
    let record = pax_record("linkpath", "other.txt");
    let bytes = tar_of(&[
        entry("t.txt", REGULAR, b"t"),
        with_padding_bytes(PAX_LOCAL, &body, record.as_bytes()),
        link("lnk", SYMLINK, "t.txt"),
    ]);
    assert_refused_everywhere(&bytes, TarAmbiguity::NonZeroPadding);
}

#[test]
fn global_pax_header_with_a_path_record_in_the_padding_is_refused() {
    let body = pax_body(&[("comment", "0123456789")]);
    let record = pax_record("path", "other.txt");
    let bytes = tar_of(&[
        with_padding_bytes(PAX_GLOBAL, &body, record.as_bytes()),
        entry("a.txt", REGULAR, b"a"),
    ]);
    assert_refused_everywhere(&bytes, TarAmbiguity::NonZeroPadding);
}

#[test]
fn global_pax_header_with_a_last_padding_byte_set_is_refused() {
    let body = pax_body(&[("comment", "0123456789")]);
    let mut padding = vec![0u8; 512 - body.len()];
    *padding.last_mut().unwrap() = 1;
    let bytes = tar_of(&[
        with_padding_bytes(PAX_GLOBAL, &body, &padding),
        entry("a.txt", REGULAR, b"a"),
        entry("b.txt", REGULAR, b"b"),
    ]);
    assert_refused_everywhere(&bytes, TarAmbiguity::NonZeroPadding);
}

#[test]
fn gnu_long_records_with_non_zero_padding_are_refused() {
    for typeflag in [GNU_LONG_NAME, GNU_LONG_LINK] {
        let body = b"long/name.txt\0";
        let target = if typeflag == GNU_LONG_NAME {
            entry("placeholder.txt", REGULAR, b"a")
        } else {
            link("lnk", SYMLINK, "t.txt")
        };
        let bytes = tar_of(&[
            entry("t.txt", REGULAR, b"t"),
            with_padding_bytes(typeflag, body, b"other.txt\0"),
            target,
        ]);
        assert_refused_everywhere(&bytes, TarAmbiguity::NonZeroPadding);
    }
}

#[test]
fn gnu_long_records_without_a_terminating_nul_are_refused() {
    for typeflag in [GNU_LONG_NAME, GNU_LONG_LINK] {
        let target = if typeflag == GNU_LONG_NAME {
            entry("placeholder.txt", REGULAR, b"a")
        } else {
            link("lnk", SYMLINK, "t.txt")
        };
        let bytes = tar_of(&[
            entry("t.txt", REGULAR, b"t"),
            raw_extension(typeflag, b"long/name.txt"),
            target,
        ]);
        let kind = if typeflag == GNU_LONG_NAME {
            TarExtensionKind::LongName
        } else {
            TarExtensionKind::LongLink
        };
        assert_refused_everywhere(&bytes, TarAmbiguity::MalformedLongRecord { kind });
    }
}

#[test]
fn gnu_long_records_with_a_doubled_nul_are_refused() {
    let bytes = tar_of(&[
        raw_extension(GNU_LONG_NAME, b"long/name.txt\0\0"),
        entry("placeholder.txt", REGULAR, b"a"),
    ]);
    assert_refused_everywhere(
        &bytes,
        TarAmbiguity::MalformedLongRecord {
            kind: TarExtensionKind::LongName,
        },
    );
}

#[test]
fn gnu_long_records_with_an_inner_nul_are_refused() {
    let bytes = tar_of(&[
        raw_extension(GNU_LONG_NAME, b"long\0name.txt\0"),
        entry("placeholder.txt", REGULAR, b"a"),
    ]);
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &bytes);
    assert!(list_archive(&archive, &config()).is_err());
    let report = verify_archive(&archive, &config()).unwrap();
    assert_eq!(report.status(), exarch_core::VerificationStatus::Fail);
    let out = TempDir::new().unwrap();
    assert!(extract_archive(&archive, out.path(), &config()).is_err());
}

#[test]
fn extension_bodies_that_fill_whole_blocks_are_accepted() {
    let value = "a".repeat(499);
    let record = pax_record("comment", &value);
    assert_eq!(record.len(), 512);
    let path = long_path(511);
    let bytes = tar_of(&[
        raw_extension(PAX_GLOBAL, record.as_bytes()),
        raw_extension(PAX_LOCAL, record.as_bytes()),
        gnu_long(GNU_LONG_NAME, &path),
        entry("placeholder.txt", REGULAR, b"a"),
        entry("b.txt", REGULAR, b"b"),
    ]);
    assert_eq!(gnu_long(GNU_LONG_NAME, &path).len(), 1024);
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &bytes);
    let manifest = list_archive(&archive, &config()).unwrap();
    assert_eq!(manifest.entries().len(), 2);
    assert_eq!(manifest.entries()[0].path, Path::new(&path));
    verify_archive(&archive, &config()).unwrap();
}

#[test]
fn non_zero_regular_entry_padding_is_not_an_extension_header_concern() {
    let mut regular = entry("a.txt", REGULAR, b"a");
    regular[512 + 1] = 7;
    let bytes = tar_of(&[regular, entry("b.txt", REGULAR, b"b")]);
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &bytes);
    assert_eq!(
        list_archive(&archive, &config()).unwrap().entries().len(),
        2
    );
}

#[test]
fn trailing_global_pax_header_with_records_in_the_padding_is_refused() {
    let body = pax_body(&[("comment", "0123456789")]);
    let record = pax_record("path", "other.txt");
    let bytes = tar_of(&[
        entry("a.txt", REGULAR, b"a"),
        with_padding_bytes(PAX_GLOBAL, &body, record.as_bytes()),
    ]);
    assert_refused_everywhere(&bytes, TarAmbiguity::NonZeroPadding);
}

#[test]
fn trailing_global_pax_header_with_zero_padding_is_accepted() {
    let bytes = tar_of(&[
        entry("a.txt", REGULAR, b"a"),
        extension(PAX_GLOBAL, &[("comment", "0123456789")]),
    ]);
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &bytes);
    verify_archive(&archive, &config()).unwrap();
    let out = TempDir::new().unwrap();
    extract_archive(&archive, out.path(), &config()).unwrap();
}
