//! Encrypted archives beyond the protected acceptance tests of
//! `encryption_password.rs`: non-solid 7z fixtures (`tests/data/encryption`),
//! tampered and mixed ZIP entries, and the secrecy of the password.

#![cfg(feature = "encryption")]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

mod sink_support;

use std::assert_matches;
use std::io::Write as _;
use std::num::NonZeroU64;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use exarch_core::ArchiveError;
use exarch_core::DecompressionBudget;
use exarch_core::EncryptionRefusal;
use exarch_core::ExtractRequest;
use exarch_core::IntegrityCheck;
use exarch_core::IntegrityStatus;
use exarch_core::ListRequest;
use exarch_core::Password;
use exarch_core::SecurityConfig;
use exarch_core::UnverifiedReason;
use exarch_core::VerificationOptions;
use exarch_core::VerifyRequest;
use exarch_core::Violation;
use sink_support::Tree;
use sink_support::walk;
use tempfile::TempDir;

const RIGHT: &[u8] = b"correct-horse";
const WRONG: &[u8] = b"wrong-horse";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/encryption")
        .join(name)
}

fn password(bytes: &[u8]) -> Arc<Password> {
    Arc::new(Password::new(bytes.to_vec()).unwrap())
}

fn refusal(error: &ArchiveError) -> EncryptionRefusal {
    let cause = match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    };
    match cause {
        ArchiveError::SecurityViolation {
            kind: Violation::Encrypted { reason, .. },
            ..
        } => *reason,
        other => panic!("expected an encryption refusal, got {other}"),
    }
}

fn extract_path(
    archive: &Path,
    password: Option<Arc<Password>>,
    config: &SecurityConfig,
) -> (TempDir, Result<(), ArchiveError>) {
    let dest = TempDir::new().unwrap();
    let request = ExtractRequest::new(config);
    let request = match password {
        Some(password) => request.with_password(password),
        None => request,
    };
    let result = request.extract(archive, dest.path()).map(drop);
    (dest, result)
}

fn tree(dest: &TempDir) -> Tree {
    walk(dest.path())
}

fn entries(dest: &TempDir) -> usize {
    std::fs::read_dir(dest.path()).unwrap().count()
}

fn files(dest: &TempDir) -> usize {
    tree(dest).files.len()
}

#[test]
fn nonsolid_sevenz_equals_its_plaintext_twin() {
    let config = SecurityConfig::default();
    let (plain, result) = extract_path(&fixture("plain.7z"), None, &config);
    result.unwrap();
    for archive in ["content.7z", "header.7z"] {
        let (decrypted, result) = extract_path(&fixture(archive), Some(password(RIGHT)), &config);
        result.unwrap();
        assert_eq!(tree(&decrypted), tree(&plain), "{archive}");
    }
}

#[test]
fn nonsolid_sevenz_without_a_password_is_password_required() {
    for archive in ["content.7z", "header.7z"] {
        let (dest, result) = extract_path(&fixture(archive), None, &SecurityConfig::default());

        assert_eq!(
            refusal(&result.unwrap_err()),
            EncryptionRefusal::PasswordRequired,
            "{archive}"
        );
        assert_eq!(entries(&dest), 0, "{archive}");
    }
}

#[test]
fn nonsolid_sevenz_with_a_wrong_password_is_wrong_password_or_corrupt() {
    for archive in ["content.7z", "header.7z"] {
        let (dest, result) = extract_path(
            &fixture(archive),
            Some(password(WRONG)),
            &SecurityConfig::default(),
        );

        assert_eq!(
            refusal(&result.unwrap_err()),
            EncryptionRefusal::WrongPasswordOrCorrupt,
            "{archive}"
        );
        assert_eq!(files(&dest), 0, "{archive}");
    }
}

#[test]
fn nonsolid_sevenz_over_the_kdf_budget_is_refused_before_any_write() {
    let config = SecurityConfig::default().with_max_kdf_work(NonZeroU64::new(1).unwrap());
    for archive in ["content.7z", "header.7z"] {
        let (dest, result) = extract_path(&fixture(archive), Some(password(RIGHT)), &config);

        assert_eq!(
            refusal(&result.unwrap_err()),
            EncryptionRefusal::KdfCostExceeded,
            "{archive}"
        );
        assert_eq!(entries(&dest), 0, "{archive}");
    }
}

#[test]
fn a_kdf_budget_of_one_derivation_admits_every_block_of_the_archive() {
    // Both content blocks use power 19 and the same (empty) salt, so the
    // archive costs one derivation however many files it holds.
    let config = SecurityConfig::default().with_max_kdf_work(NonZeroU64::new(1 << 19).unwrap());
    let (_dest, result) = extract_path(&fixture("content.7z"), Some(password(RIGHT)), &config);

    result.unwrap();
}

#[test]
fn nonsolid_sevenz_list_and_verify_follow_the_password() {
    let config = SecurityConfig::default();
    for archive in ["content.7z", "header.7z"] {
        let listed = ListRequest::new(&config)
            .with_password(password(RIGHT))
            .list(fixture(archive))
            .unwrap();
        let report = VerifyRequest::new(&config)
            .with_password(password(RIGHT))
            .verify(fixture(archive))
            .unwrap();

        assert!(
            listed
                .entries()
                .iter()
                .any(|e| e.path.ends_with("inner.txt")),
            "{archive}"
        );
        assert!(report.issues().is_empty(), "{archive}: {report:?}");

        let without = ListRequest::new(&config).list(fixture(archive));
        if archive == "header.7z" {
            assert_eq!(
                refusal(&without.unwrap_err()),
                EncryptionRefusal::PasswordRequired
            );
        } else {
            assert_eq!(without.unwrap().entries().len(), listed.entries().len());
        }
    }
}

#[test]
fn a_non_utf8_password_cannot_open_a_7z() {
    let bytes = Arc::new(Password::new(vec![0xFF, 0xFE, b'x']).unwrap());
    for archive in ["content.7z", "header.7z"] {
        let (_dest, result) = extract_path(
            &fixture(archive),
            Some(bytes.clone()),
            &SecurityConfig::default(),
        );

        assert_eq!(
            refusal(&result.unwrap_err()),
            EncryptionRefusal::UnusablePassword,
            "{archive}"
        );
    }
}

#[test]
fn a_non_utf8_password_is_ignored_for_an_unencrypted_7z() {
    let bytes = Arc::new(Password::new(vec![0xFF, 0xFE, b'x']).unwrap());

    let (_dest, result) = extract_path(
        &fixture("plain.7z"),
        Some(bytes),
        &SecurityConfig::default(),
    );

    result.unwrap();
}

fn aes_zip() -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/encryption/aes256.zip"))
        .unwrap()
}

fn extract_bytes(
    bytes: &[u8],
    password: Option<Arc<Password>>,
) -> (TempDir, Result<(), ArchiveError>) {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.zip");
    std::fs::File::create(&archive)
        .unwrap()
        .write_all(bytes)
        .unwrap();
    extract_path(&archive, password, &SecurityConfig::default())
}

/// Offset of the first ciphertext byte of the first entry that has data: its
/// local header, then the AES salt (16 bytes for AES-256) and the 2-byte
/// password verifier.
fn first_ciphertext_offset(bytes: &[u8]) -> usize {
    let mut at = 0;
    loop {
        assert_eq!(&bytes[at..at + 4], b"PK\x03\x04");
        let compressed = u32::from_le_bytes(bytes[at + 18..at + 22].try_into().unwrap());
        let name = usize::from(u16::from_le_bytes([bytes[at + 26], bytes[at + 27]]));
        let extra = usize::from(u16::from_le_bytes([bytes[at + 28], bytes[at + 29]]));
        let data = at + 30 + name + extra;
        if compressed > 0 {
            return data + 16 + 2;
        }
        at = data;
    }
}

#[test]
fn a_flipped_ciphertext_byte_is_authentication_failed_and_publishes_no_file() {
    let mut bytes = aes_zip();
    let at = first_ciphertext_offset(&bytes);
    bytes[at] ^= 0x01;

    let (dest, result) = extract_bytes(&bytes, Some(password(RIGHT)));

    assert_eq!(
        refusal(&result.unwrap_err()),
        EncryptionRefusal::AuthenticationFailed
    );
    assert_eq!(files(&dest), 0);
}

#[test]
fn a_flipped_verifier_byte_is_wrong_password() {
    let mut bytes = aes_zip();
    let at = first_ciphertext_offset(&bytes) - 1;
    bytes[at] ^= 0x01;

    let (_dest, result) = extract_bytes(&bytes, Some(password(RIGHT)));

    assert_eq!(
        refusal(&result.unwrap_err()),
        EncryptionRefusal::WrongPassword
    );
}

#[test]
fn the_password_never_appears_in_errors_or_debug_output() {
    let secret = "s3cr3t-horse-value";
    let supplied = Arc::new(Password::new(secret.as_bytes().to_vec()).unwrap());
    for archive in [
        fixture("content.7z"),
        fixture("header.7z"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/encryption/aes256.zip"),
    ] {
        let (_dest, result) =
            extract_path(&archive, Some(supplied.clone()), &SecurityConfig::default());

        let error = result.unwrap_err();

        let text = format!("{error} {error:?} {supplied:?}");
        assert!(!text.contains(secret), "{archive:?}: {text}");
    }
}

fn integrity_options() -> VerificationOptions {
    VerificationOptions::default()
        .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT))
}

#[test]
fn verify_of_an_encrypted_zip_without_a_password_counts_its_entries_unverified() {
    let archive = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/encryption/aes256.zip");

    let report = VerifyRequest::new(&SecurityConfig::default())
        .with_options(integrity_options())
        .verify(archive)
        .unwrap();

    assert_eq!(report.integrity_status(), IntegrityStatus::Incomplete);
    let gaps = report.integrity_gaps().unwrap();
    assert_eq!(gaps.count(UnverifiedReason::Encrypted), 2);
    assert!(
        gaps.entries()
            .iter()
            .any(|entry| entry.path().ends_with("inner.txt"))
    );
}

#[test]
fn verify_of_an_encrypted_zip_with_the_password_decodes_every_entry() {
    let archive = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/encryption/aes256.zip");

    let report = VerifyRequest::new(&SecurityConfig::default())
        .with_options(integrity_options())
        .with_password(password(RIGHT))
        .verify(archive)
        .unwrap();

    assert_eq!(report.integrity_status(), IntegrityStatus::Pass);
}

#[test]
fn verify_of_a_tampered_encrypted_zip_reports_corrupt_data() {
    let mut bytes = aes_zip();
    let at = first_ciphertext_offset(&bytes);
    bytes[at] ^= 0x01;
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("tampered.zip");
    std::fs::write(&archive, &bytes).unwrap();

    let report = VerifyRequest::new(&SecurityConfig::default())
        .with_options(integrity_options())
        .with_password(password(RIGHT))
        .verify(&archive)
        .unwrap();

    assert_eq!(report.integrity_status(), IntegrityStatus::Fail);
}

/// A ZIP with one plain and two AES entries (AES-128 and AES-256), each
/// encrypted under `correct-horse`.
fn mixed_zip() -> Vec<u8> {
    use zip::AesMode;
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let plain = SimpleFileOptions::default();
    writer.start_file("plain.txt", plain).unwrap();
    writer.write_all(b"plain\n").unwrap();
    for (name, mode) in [
        ("aes128.txt", AesMode::Aes128),
        ("aes256.txt", AesMode::Aes256),
    ] {
        let options = SimpleFileOptions::default().with_aes_encryption(mode, "correct-horse");
        writer.start_file(name, options).unwrap();
        writer.write_all(b"secret\n").unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[test]
fn a_zip_mixing_plain_and_encrypted_entries_extracts_each_by_its_own_state() {
    let (dest, result) = extract_bytes(&mixed_zip(), Some(password(RIGHT)));

    result.unwrap();
    let tree = tree(&dest);
    assert_eq!(tree.files.len(), 3);
    assert_eq!(
        std::fs::read(dest.path().join("plain.txt")).unwrap(),
        b"plain\n"
    );
    assert_eq!(
        std::fs::read(dest.path().join("aes128.txt")).unwrap(),
        b"secret\n"
    );
    assert_eq!(
        std::fs::read(dest.path().join("aes256.txt")).unwrap(),
        b"secret\n"
    );
}

#[test]
fn a_mixed_zip_without_a_password_is_refused_before_any_write() {
    let (dest, result) = extract_bytes(&mixed_zip(), None);

    assert_eq!(
        refusal(&result.unwrap_err()),
        EncryptionRefusal::PasswordRequired
    );
    assert_eq!(entries(&dest), 0);
}

fn many() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/enc-many.7z")
}

fn expected_many() -> Tree {
    let mut expected = Tree::default();
    for i in 0..300 {
        expected.files.insert(
            PathBuf::from(format!("f{i:03}")),
            (i % 100).to_string().into_bytes(),
        );
    }
    expected
}

#[test]
fn a_many_file_nonsolid_7z_extracts_to_its_plaintext_twin() {
    let (dest, result) = extract_path(&many(), Some(password(RIGHT)), &SecurityConfig::default());

    result.unwrap();
    assert_eq!(tree(&dest), expected_many());
}

#[test]
fn a_many_file_7z_costs_one_derivation_not_one_per_block() {
    // 300 blocks of power 19 would cost 300 * 2^19 > the default 2^27 if every
    // block were charged; the single (power, salt) run costs 2^19.
    let config = SecurityConfig::default().with_max_kdf_work(NonZeroU64::new(1 << 19).unwrap());

    let (dest, result) = extract_path(&many(), Some(password(RIGHT)), &config);

    result.unwrap();
    assert_eq!(tree(&dest), expected_many());
}

/// One AES-256 entry written by a streaming writer, so it uses a data
/// descriptor and its local header carries no sizes.
fn streamed_aes_zip() -> Vec<u8> {
    use zip::AesMode;
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    let mut writer = ZipWriter::new_stream(Vec::new());
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .with_aes_encryption(AesMode::Aes256, "correct-horse");
    writer.start_file("s.txt", options).unwrap();
    writer.write_all(&[b'a'; 300]).unwrap();
    writer.finish().unwrap().into_inner()
}

#[test]
fn an_aes_entry_with_a_data_descriptor_extracts_when_untouched() {
    let (dest, result) = extract_bytes(&streamed_aes_zip(), Some(password(RIGHT)));

    result.unwrap();
    assert_eq!(
        std::fs::read(dest.path().join("s.txt")).unwrap(),
        vec![b'a'; 300]
    );
}

#[test]
fn a_descriptor_and_header_planted_in_aes_ciphertext_are_refused() {
    let mut bytes = streamed_aes_zip();
    let name = usize::from(u16::from_le_bytes([bytes[26], bytes[27]]));
    let extra = usize::from(u16::from_le_bytes([bytes[28], bytes[29]]));
    let data = 30 + name + extra;
    let mut planted = b"PK\x07\x08".to_vec();
    planted.extend_from_slice(&[0; 12]);
    planted.extend_from_slice(b"PK\x03\x04\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0z");
    let at = data + 60;
    bytes[at..at + planted.len()].copy_from_slice(&planted);

    let (dest, result) = extract_bytes(&bytes, Some(password(RIGHT)));

    assert_matches!(result, Err(ArchiveError::ZipInconsistency(_)), "{result:?}");
    assert_eq!(entries(&dest), 0);
}
