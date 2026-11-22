//! The listing that precedes an extraction (`ListRequest::for_extraction`)
//! leaves the payload of an encrypted ZIP entry the selection skips unread, so
//! a wrong password is not reported for it, while a selected encrypted entry
//! still checks the password and the plain `list` path checks every encrypted
//! entry (#1261).

#![cfg(feature = "encryption")]
#![expect(clippy::disallowed_methods, reason = "test fixture setup")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

use std::io::Cursor;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use exarch_core::ArchiveError;
use exarch_core::DecodeReuse;
use exarch_core::EncryptionRefusal;
use exarch_core::ListRequest;
use exarch_core::Password;
use exarch_core::SecurityConfig;
use exarch_core::Violation;
use tempfile::TempDir;
use zip::AesMode;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

const RIGHT: &[u8] = b"correct-horse";
const WRONG: &[u8] = b"wrong-horse";

fn password(bytes: &[u8]) -> Arc<Password> {
    Arc::new(Password::new(bytes.to_vec()).unwrap())
}

fn mixed_zip(dir: &TempDir) -> PathBuf {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file("p.txt", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"plain\n").unwrap();
    writer
        .start_file(
            "sub/e.txt",
            SimpleFileOptions::default().with_aes_encryption(AesMode::Aes256, "correct-horse"),
        )
        .unwrap();
    writer.write_all(b"secret\n").unwrap();
    let path = dir.path().join("mix.zip");
    std::fs::write(&path, writer.finish().unwrap().into_inner()).unwrap();
    path
}

fn selecting(include: &str) -> SecurityConfig {
    SecurityConfig::default().try_add_include(include).unwrap()
}

fn for_extraction(
    archive: &std::path::Path,
    config: &SecurityConfig,
    secret: Option<&[u8]>,
) -> Result<(), ArchiveError> {
    ListRequest::new(config)
        .with_password(secret.map(password))
        .for_extraction(archive, DecodeReuse::default())
        .map(drop)
}

fn refusal(error: &ArchiveError) -> EncryptionRefusal {
    match error {
        ArchiveError::SecurityViolation {
            kind: Violation::Encrypted { reason, .. },
            ..
        } => *reason,
        other => panic!("expected an encryption refusal, got {other}"),
    }
}

#[test]
fn unselected_encrypted_entries_stay_unread_with_a_wrong_password() {
    let dir = TempDir::new().unwrap();

    for secret in [None, Some(WRONG), Some(RIGHT)] {
        for_extraction(&mixed_zip(&dir), &selecting("p.txt"), secret).unwrap();
    }
}

#[test]
fn selected_encrypted_entries_still_check_the_password() {
    let dir = TempDir::new().unwrap();
    let archive = mixed_zip(&dir);
    let config = selecting("sub/e.txt");

    let wrong = for_extraction(&archive, &config, Some(WRONG)).unwrap_err();
    for_extraction(&archive, &config, Some(RIGHT)).unwrap();

    assert_eq!(refusal(&wrong), EncryptionRefusal::WrongPassword);
}

#[test]
fn the_default_list_path_checks_every_encrypted_entry() {
    let dir = TempDir::new().unwrap();
    let archive = mixed_zip(&dir);
    let config = selecting("p.txt");

    let wrong = ListRequest::new(&config)
        .with_password(Some(password(WRONG)))
        .list(&archive)
        .unwrap_err();
    ListRequest::new(&config)
        .with_password(Some(password(RIGHT)))
        .list(&archive)
        .unwrap();

    assert_eq!(refusal(&wrong), EncryptionRefusal::WrongPassword);
}
