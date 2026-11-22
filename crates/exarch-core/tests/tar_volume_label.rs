//! A GNU volume label (typeflag `V`) is a metadata record that `bsdtar` and
//! the Python `tarfile` module skip. exarch skips it only when no reader can
//! disagree about the member that follows: no local `x`, `L` or `K` header
//! before it and no payload. `list`, `verify` and `extract` must agree.

#![expect(clippy::disallowed_methods, reason = "test fixture setup")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

use std::assert_matches;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ErrorCode;
use exarch_core::SecurityConfig;
use exarch_core::TarAmbiguity;
use exarch_core::TarExtensionKind;
use exarch_core::TarNonRegularKind;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use tempfile::TempDir;

fn header(name: &[u8], typeflag: u8, size: usize) -> Vec<u8> {
    let mut block = [0u8; 512];
    block[..name.len()].copy_from_slice(name);
    block[100..108].copy_from_slice(b"0000644\0");
    block[108..116].copy_from_slice(b"0000000\0");
    block[116..124].copy_from_slice(b"0000000\0");
    block[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    block[136..148].copy_from_slice(b"00000000000\0");
    block[156] = typeflag;
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    block[148..156].copy_from_slice(b"        ");
    let sum: u32 = block.iter().map(|&b| u32::from(b)).sum();
    block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    block.to_vec()
}

fn pad(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.resize(bytes.len().next_multiple_of(512), 0);
    bytes
}

fn pax_record(key: &str, value: &str) -> String {
    let rest = format!(" {key}={value}\n");
    let mut total = rest.len() + 1;
    loop {
        let next = rest.len() + total.to_string().len();
        if next == total {
            return format!("{total}{rest}");
        }
        total = next;
    }
}

fn pax_extension(records: &[(&str, &str)]) -> Vec<u8> {
    let body: String = records.iter().map(|(k, v)| pax_record(k, v)).collect();
    pad([header(b"PaxHeader/x", b'x', body.len()), body.into_bytes()].concat())
}

fn gnu_long(typeflag: u8, value: &str) -> Vec<u8> {
    let mut body = value.as_bytes().to_vec();
    body.push(0);
    pad([header(b"././@LongLink", typeflag, body.len()), body].concat())
}

fn file() -> Vec<u8> {
    pad([header(b"f.txt", b'0', 3), b"abc".to_vec()].concat())
}

fn hidden_member() -> Vec<u8> {
    pad([header(b"hidden.txt", b'0', 3), b"xyz".to_vec()].concat())
}

fn label(size: usize) -> Vec<u8> {
    header(b"label", b'V', size)
}

fn tar_of(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = parts.concat();
    bytes.resize(bytes.len() + 1024, 0);
    bytes
}

fn write_archive(dir: &TempDir, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join("a.tar");
    std::fs::write(&path, bytes).unwrap();
    path
}

fn listed_names(archive: &Path) -> Vec<String> {
    list_archive(archive, &SecurityConfig::default())
        .unwrap()
        .entries()
        .iter()
        .map(|entry| entry.path.to_string_lossy().into_owned())
        .collect()
}

fn assert_skipped_everywhere(bytes: &[u8]) {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, bytes);
    let config = SecurityConfig::default();

    let names = listed_names(&archive);
    assert_eq!(names, ["f.txt"]);
    assert!(verify_archive(&archive, &config).unwrap().is_safe());

    let out = TempDir::new().unwrap();
    extract_archive(&archive, out.path(), &config).unwrap();
    let extracted: Vec<_> = std::fs::read_dir(out.path())
        .unwrap()
        .map(|item| item.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(extracted.len(), names.len(), "{extracted:?} vs {names:?}");
    for name in &extracted {
        assert_eq!(std::fs::read(out.path().join(name)).unwrap(), b"abc");
    }
}

fn assert_ambiguous(error: &ArchiveError, expected: &TarAmbiguity) {
    let source = match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    };
    assert_eq!(source.error_code(), ErrorCode::InvalidArchive, "{source}");
    assert_matches!(source, ArchiveError::TarAmbiguity(found) if found == expected, "{source}");
}

fn assert_refused_everywhere(bytes: &[u8], expected: &TarAmbiguity) {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, bytes);
    let config = SecurityConfig::default();

    assert_ambiguous(&list_archive(&archive, &config).unwrap_err(), expected);
    assert_ambiguous(&verify_archive(&archive, &config).unwrap_err(), expected);
    let out = TempDir::new().unwrap();
    assert_ambiguous(
        &extract_archive(&archive, out.path(), &config).unwrap_err(),
        expected,
    );
    assert!(
        !out.path().join("evil.txt").exists() && !out.path().join("evil2.txt").exists(),
        "a renamed member was extracted"
    );
}

fn before_label(kind: TarExtensionKind) -> TarAmbiguity {
    TarAmbiguity::ExtensionBeforeLabel { kind }
}

#[test]
fn a_label_with_no_data_is_skipped_before_a_file() {
    assert_skipped_everywhere(&tar_of(&[label(0), file()]));
}

#[test]
fn several_labels_are_skipped() {
    let second = header(b"l2", b'V', 0);
    assert_skipped_everywhere(&tar_of(&[header(b"l1", b'V', 0), second, file()]));
}

#[test]
fn a_label_after_the_last_file_is_skipped() {
    assert_skipped_everywhere(&tar_of(&[file(), label(0)]));
}

#[test]
fn a_global_header_before_a_label_is_fine() {
    let global = pad([
        header(b"pax_global_header", b'g', pax_record("comment", "x").len()),
        pax_record("comment", "x").into_bytes(),
    ]
    .concat());
    assert_skipped_everywhere(&tar_of(&[global, label(0), file()]));
}

#[test]
fn a_pax_path_before_a_label_is_refused() {
    let bytes = tar_of(&[pax_extension(&[("path", "evil.txt")]), label(0), file()]);
    assert_refused_everywhere(&bytes, &before_label(TarExtensionKind::Pax));
}

#[test]
fn a_gnu_long_name_before_a_label_is_refused() {
    let bytes = tar_of(&[gnu_long(b'L', "evil2.txt"), label(0), file()]);
    assert_refused_everywhere(&bytes, &before_label(TarExtensionKind::LongName));
}

#[test]
fn a_gnu_long_link_before_a_label_is_refused() {
    let bytes = tar_of(&[gnu_long(b'K', "target"), label(0), file()]);
    assert_refused_everywhere(&bytes, &before_label(TarExtensionKind::LongLink));
}

#[test]
fn a_pax_size_that_hides_a_member_behind_a_zero_size_label_is_refused() {
    let hidden = hidden_member();
    let bytes = tar_of(&[
        pax_extension(&[("size", &hidden.len().to_string())]),
        label(0),
        hidden,
        file(),
    ]);
    assert_refused_everywhere(&bytes, &before_label(TarExtensionKind::Pax));
}

#[test]
fn a_pax_size_zero_before_a_label_with_a_header_size_is_refused_as_an_extension() {
    let hidden = hidden_member();
    let bytes = tar_of(&[
        pax_extension(&[("size", "0")]),
        label(hidden.len()),
        hidden,
        file(),
    ]);
    assert_refused_everywhere(&bytes, &before_label(TarExtensionKind::Pax));
}

#[test]
fn a_label_with_a_header_size_is_refused_as_a_payload() {
    let hidden = hidden_member();
    let bytes = tar_of(&[label(hidden.len()), hidden, file()]);
    assert_refused_everywhere(
        &bytes,
        &TarAmbiguity::NonRegularPayload {
            kind: TarNonRegularKind::VolumeLabel,
            size: 512 + 512,
            path: "label".into(),
        },
    );
}
