//! A ZIP that mixes plain and AES-encrypted entries needs a password only when
//! the run extracts an encrypted entry (#1261, spec 024 FR-015): an encrypted
//! entry (file, directory or symlink) the selection skips is never decrypted,
//! still fails path validation, and counts like the same entry unencrypted.

#![cfg(feature = "encryption")]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

mod sink_support;

use std::io::Cursor;
use std::io::Write as _;
use std::sync::Arc;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::EncryptionRefusal;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionReport;
use exarch_core::MemoryLimit;
use exarch_core::MemorySink;
use exarch_core::Password;
use exarch_core::SecurityConfig;
use exarch_core::SeekableFormat;
use exarch_core::SinkExtractRequest;
use exarch_core::SinkOptions;
use exarch_core::SkipKind;
use exarch_core::Violation;
use sink_support::Tree;
use sink_support::signature;
use sink_support::walk;
use tempfile::TempDir;
use zip::AesMode;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

const RIGHT: &[u8] = b"correct-horse";
const WRONG: &[u8] = b"wrong-horse";

#[derive(Clone, Copy)]
enum Item<'a> {
    File(&'a str, &'a [u8]),
    Dir(&'a str),
    Symlink(&'a str, &'a str),
}

fn password(bytes: &[u8]) -> Arc<Password> {
    Arc::new(Password::new(bytes.to_vec()).unwrap())
}

fn options(encrypted: bool) -> SimpleFileOptions {
    let options = SimpleFileOptions::default();
    if encrypted {
        options.with_aes_encryption(AesMode::Aes256, "correct-horse")
    } else {
        options
    }
}

/// Builds a ZIP; `sealed` decides which entries are AES-256 encrypted.
fn zip(items: &[Item<'_>], sealed: impl Fn(&str) -> bool) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for item in items {
        match *item {
            Item::File(name, data) => {
                writer.start_file(name, options(sealed(name))).unwrap();
                writer.write_all(data).unwrap();
            }
            Item::Dir(name) => {
                writer.add_directory(name, options(false)).unwrap();
            }
            Item::Symlink(name, target) => {
                writer
                    .add_symlink(name, target, options(sealed(name)))
                    .unwrap();
            }
        }
    }
    writer.finish().unwrap().into_inner()
}

/// Directory entries stay plain: an AES directory would carry a payload, which
/// the structure check refuses on its own.
fn is_sealed(name: &str) -> bool {
    !name.ends_with('/')
        && (name.starts_with("sub")
            || name.starts_with("lnk")
            || name.contains("sealed")
            || name == ".")
}

fn mixed() -> Vec<Item<'static>> {
    vec![
        Item::File("p.txt", b"plain\n"),
        Item::Dir("q/"),
        Item::File("q/r.txt", b"plain too\n"),
        Item::Dir("sub/"),
        Item::File("sub/e.txt", b"secret\n"),
        Item::Symlink("lnk", "p.txt"),
    ]
}

fn mixed_zip() -> Vec<u8> {
    zip(&mixed(), is_sealed)
}

fn config() -> SecurityConfig {
    SecurityConfig::default().with_allow_symlinks(true)
}

type Outcome = (TempDir, Result<ExtractionReport, ArchiveError>);

fn extract(bytes: &[u8], config: &SecurityConfig, secret: Option<&[u8]>) -> Outcome {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.zip");
    std::fs::write(&archive, bytes).unwrap();
    let dest = TempDir::new().unwrap();
    let request = ExtractRequest::new(config).with_password(secret.map(password));
    let result = request.extract(&archive, dest.path());
    (dest, result)
}

fn tree(outcome: &Outcome) -> Tree {
    walk(outcome.0.path())
}

fn cause(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    }
}

fn refusal(error: &ArchiveError) -> EncryptionRefusal {
    match cause(error) {
        ArchiveError::SecurityViolation {
            kind: Violation::Encrypted { reason, .. },
            ..
        } => *reason,
        other => panic!("expected an encryption refusal, got {other}"),
    }
}

fn selecting(includes: &[&str], excludes: &[&str]) -> SecurityConfig {
    let mut config = config();
    for pattern in includes {
        config = config.try_add_include(pattern).unwrap();
    }
    for pattern in excludes {
        config = config.try_add_exclude(pattern).unwrap();
    }
    config
}

/// The run over the sealed archive equals the run over its unencrypted twin
/// without a password: outcome, written tree and selection counts.
fn assert_matches_plain_twin(
    items: &[Item<'_>],
    config: &SecurityConfig,
    secret: Option<&[u8]>,
    context: &str,
) {
    let sealed = extract(&zip(items, is_sealed), config, secret);
    let plain = extract(&zip(items, |_| false), config, None);

    assert_eq!(tree(&sealed), tree(&plain), "{context}: tree");
    match (&sealed.1, &plain.1) {
        (Ok(sealed), Ok(plain)) => {
            assert_eq!(
                sealed.skipped.count(SkipKind::NotSelected),
                plain.skipped.count(SkipKind::NotSelected),
                "{context}: not-selected count"
            );
            assert_eq!(sealed.files_extracted, plain.files_extracted, "{context}");
        }
        (Err(sealed), Err(plain)) => {
            assert_eq!(signature(sealed), signature(plain), "{context}");
        }
        (sealed, plain) => panic!("{context}: sealed {sealed:?} vs plain {plain:?}"),
    }
}

#[test]
fn extract_of_the_mixed_zip_selecting_everything_without_a_password_is_password_required() {
    let outcome = extract(&mixed_zip(), &config(), None);

    let error = outcome.1.as_ref().unwrap_err();

    assert_eq!(refusal(error), EncryptionRefusal::PasswordRequired);
    assert_eq!(tree(&outcome), Tree::default());
}

#[test]
fn extract_with_an_include_of_plain_entries_needs_no_password() {
    let outcome = extract(&mixed_zip(), &selecting(&["p.txt", "q"], &[]), None);

    outcome.1.as_ref().unwrap();
    assert_eq!(
        std::fs::read(outcome.0.path().join("p.txt")).unwrap(),
        b"plain\n"
    );
    assert_eq!(
        std::fs::read(outcome.0.path().join("q/r.txt")).unwrap(),
        b"plain too\n"
    );
    assert!(!outcome.0.path().join("sub").exists());
    assert!(!outcome.0.path().join("lnk").exists());
}

#[test]
fn extract_with_excludes_of_every_encrypted_entry_needs_no_password() {
    let outcome = extract(&mixed_zip(), &selecting(&[], &["sub", "lnk"]), None);

    let report = outcome.1.as_ref().unwrap();

    assert_eq!(
        std::fs::read(outcome.0.path().join("p.txt")).unwrap(),
        b"plain\n"
    );
    assert_eq!(report.skipped.count(SkipKind::NotSelected), 3);
}

#[test]
fn extract_with_a_wrong_password_ignores_it_when_no_encrypted_entry_is_selected() {
    let outcome = extract(&mixed_zip(), &selecting(&["p.txt"], &[]), Some(WRONG));

    outcome.1.as_ref().unwrap();
    assert!(outcome.0.path().join("p.txt").exists());
}

#[test]
fn extract_with_the_right_password_leaves_unselected_encrypted_entries_unwritten() {
    let outcome = extract(&mixed_zip(), &selecting(&["p.txt"], &[]), Some(RIGHT));

    outcome.1.as_ref().unwrap();
    assert!(outcome.0.path().join("p.txt").exists());
    assert!(!outcome.0.path().join("sub").exists());
}

#[test]
fn extract_selecting_an_encrypted_file_without_a_password_is_password_required_and_writes_nothing()
{
    let outcome = extract(&mixed_zip(), &selecting(&["sub/e.txt"], &[]), None);

    let error = outcome.1.as_ref().unwrap_err();

    assert_eq!(refusal(error), EncryptionRefusal::PasswordRequired);
    assert_eq!(tree(&outcome), Tree::default());
}

#[test]
fn extract_selecting_an_encrypted_file_with_a_wrong_password_is_wrong_password() {
    let outcome = extract(
        &mixed_zip(),
        &selecting(&["p.txt", "sub/e.txt"], &[]),
        Some(WRONG),
    );

    let error = outcome.1.as_ref().unwrap_err();

    assert_eq!(refusal(error), EncryptionRefusal::WrongPassword);
}

#[test]
fn extract_selecting_an_encrypted_file_with_the_right_password_extracts_it() {
    let outcome = extract(
        &mixed_zip(),
        &selecting(&["p.txt", "sub/e.txt"], &[]),
        Some(RIGHT),
    );

    outcome.1.as_ref().unwrap();
    assert_eq!(
        std::fs::read(outcome.0.path().join("sub/e.txt")).unwrap(),
        b"secret\n"
    );
}

#[test]
fn extract_selecting_an_encrypted_symlink_without_a_password_is_password_required() {
    let outcome = extract(&mixed_zip(), &selecting(&["lnk"], &[]), None);

    let error = outcome.1.as_ref().unwrap_err();

    assert_eq!(refusal(error), EncryptionRefusal::PasswordRequired);
}

#[test]
fn extract_of_an_unselected_encrypted_directory_and_symlink_matches_the_plain_twin() {
    for secret in [None, Some(WRONG), Some(RIGHT)] {
        assert_matches_plain_twin(
            &mixed(),
            &selecting(&["p.txt", "q"], &[]),
            secret,
            &format!("include, password {:?}", secret.is_some()),
        );
        assert_matches_plain_twin(
            &mixed(),
            &selecting(&[], &["sub", "lnk"]),
            secret,
            &format!("exclude, password {:?}", secret.is_some()),
        );
    }
}

#[test]
fn extract_with_an_include_matched_only_by_an_excluded_encrypted_entry_matches_the_plain_twin() {
    assert_matches_plain_twin(
        &mixed(),
        &selecting(&["sub/e.txt"], &["sub"]),
        None,
        "include matched only by an excluded entry",
    );
    assert_matches_plain_twin(
        &mixed(),
        &selecting(&["p.txt", "sub/e.txt"], &["sub"]),
        None,
        "include matched by an excluded entry next to a plain match",
    );
}

#[test]
fn extract_with_an_unselected_encrypted_traversal_name_is_refused_like_a_plain_one() {
    let items = [
        Item::File("p.txt", b"plain\n"),
        Item::File("sealed/../../x", b"secret\n"),
    ];
    let config = selecting(&["p.txt"], &[]);

    let sealed = extract(&zip(&items, is_sealed), &config, None);
    let plain = extract(&zip(&items, |_| false), &config, None);

    let sealed_error = sealed.1.as_ref().unwrap_err();
    assert_eq!(
        signature(sealed_error),
        signature(plain.1.as_ref().unwrap_err())
    );
    assert!(
        !matches!(
            cause(sealed_error),
            ArchiveError::SecurityViolation {
                kind: Violation::Encrypted { .. },
                ..
            }
        ),
        "{sealed_error:?}"
    );
}

#[test]
fn extract_of_unselected_encrypted_names_in_every_spelling_matches_the_plain_twin() {
    for name in [
        "sealed/./x.txt",
        "sealed//x.txt",
        "sealed\\x.txt",
        "./sealed.txt",
        "sealed/sub/../x.txt",
    ] {
        let items = [
            Item::File("p.txt", b"plain\n"),
            Item::File(name, b"secret\n"),
        ];

        assert_matches_plain_twin(&items, &selecting(&["p.txt"], &[]), None, name);
    }
}

#[test]
fn extract_of_an_unselected_absolute_encrypted_name_matches_the_plain_twin() {
    let items = [
        Item::File("p.txt", b"plain\n"),
        Item::File("/sealed.txt", b"secret\n"),
    ];

    for absolute in [false, true] {
        let config = selecting(&["p.txt"], &[]).with_allow_absolute_paths(absolute);

        assert_matches_plain_twin(&items, &config, None, &format!("absolute {absolute}"));
    }
}

#[test]
fn extract_of_an_encrypted_entry_resolving_to_the_root_matches_the_plain_twin_without_a_password() {
    let items = [Item::File("p.txt", b"plain\n"), Item::File(".", b"")];

    assert_matches_plain_twin(&items, &config(), None, "root entry, everything selected");
    assert_matches_plain_twin(
        &items,
        &selecting(&["p.txt"], &[]),
        None,
        "root entry, plain selected",
    );
}

#[test]
fn memory_extract_with_an_include_of_plain_entries_needs_no_password() {
    let mut sink = MemorySink::new(MemoryLimit::DEFAULT);

    SinkExtractRequest::new(&selecting(&["p.txt", "q"], &[]))
        .with_options(SinkOptions::default())
        .extract(
            ArchiveReader::seekable(Cursor::new(mixed_zip()), SeekableFormat::Zip),
            &mut sink,
        )
        .unwrap();

    let stored: Vec<_> = sink
        .iter()
        .map(|(path, _)| path.to_string_lossy().into_owned())
        .collect();
    assert!(stored.contains(&"p.txt".to_owned()), "{stored:?}");
    assert!(
        stored.iter().all(|path| !path.starts_with("sub")),
        "{stored:?}"
    );
}

#[test]
fn memory_extract_selecting_an_encrypted_file_without_a_password_is_password_required() {
    let mut sink = MemorySink::new(MemoryLimit::DEFAULT);

    let error = SinkExtractRequest::new(&selecting(&["sub/e.txt"], &[]))
        .with_options(SinkOptions::default())
        .extract(
            ArchiveReader::seekable(Cursor::new(mixed_zip()), SeekableFormat::Zip),
            &mut sink,
        )
        .unwrap_err();

    assert_eq!(refusal(&error), EncryptionRefusal::PasswordRequired);
}
