//! Regression tests for vulnerability classes found in reference libraries:
//! libarchive #3858, sevenz-rust2 #161 and an AES-CTR tamper of a `--force`
//! target.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

use std::assert_matches;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::SecurityConfig;
use tempfile::TempDir;

fn overwrite() -> ExtractionOptions {
    ExtractionOptions::default().with_existing_files(ExistingFiles::Overwrite)
}

fn tar_with(entries: &[(&str, &[u8])], links: &[(&str, &str)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, data) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_size(data.len() as u64);
        builder.append_data(&mut header, name, *data).unwrap();
    }
    for (name, target) in links {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        header.set_mode(0o644);
        builder.append_link(&mut header, name, target).unwrap();
    }
    builder.into_inner().unwrap()
}

fn archive_in(dir: &Path, bytes: &[u8]) -> PathBuf {
    let path = dir.join("self.tar");
    std::fs::write(&path, bytes).unwrap();
    path
}

/// libarchive #3858: an entry naming the archive being read must not truncate
/// it.
#[cfg(unix)]
#[test]
fn libarchive_3858_entry_naming_the_archive_does_not_truncate_it_during_the_read() {
    use std::io::Read as _;

    let dir = TempDir::new().unwrap();
    let bytes = tar_with(
        &[
            ("self.tar", b"replacement"),
            ("after", b"read after the self entry"),
        ],
        &[],
    );
    let archive = archive_in(dir.path(), &bytes);
    let mut original = std::fs::File::open(&archive).unwrap();

    let result = ExtractRequest::new(&SecurityConfig::default())
        .with_options(overwrite())
        .extract(&archive, dir.path());

    result.unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("after")).unwrap(),
        b"read after the self entry"
    );
    let mut kept = Vec::new();
    original.read_to_end(&mut kept).unwrap();
    assert_eq!(kept, bytes);
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
}

/// libarchive #3858, hardlink variant: refused as an occupied destination even
/// under `Overwrite`, so it does not exercise self-truncation.
#[test]
fn libarchive_3858_hardlink_named_like_the_archive_is_refused_and_leaves_it_intact() {
    let dir = TempDir::new().unwrap();
    let bytes = tar_with(&[("x", b"payload")], &[("self.tar", "x")]);
    let archive = archive_in(dir.path(), &bytes);

    let result = ExtractRequest::new(&SecurityConfig::default().with_allow_hardlinks(true))
        .with_options(overwrite())
        .extract(&archive, dir.path());

    let error = result.unwrap_err();
    let exarch_core::ArchiveError::PartialExtraction(partial) = &error else {
        panic!("expected a partial extraction, got {error:?}");
    };
    assert_matches!(
        partial.cause(),
        exarch_core::ArchiveError::DestinationOccupied { .. }
    );
    assert_eq!(std::fs::read(&archive).unwrap(), bytes);
}

/// sevenz-rust2 #161: a stored setuid mode is never applied, with or without
/// `preserve_permissions`.
#[cfg(unix)]
#[test]
fn sevenz_rust2_161_stored_setuid_mode_is_not_applied() {
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt as _;

    const UNIX_EXTENSION: u32 = 0x8000;
    const S_IFREG: u32 = 0o10_0000;

    let mut entry = sevenz_rust2::ArchiveEntry::new_file("suid");
    entry.has_stream = true;
    entry.size = 4;
    entry.has_windows_attributes = true;
    entry.windows_attributes = UNIX_EXTENSION | ((S_IFREG | 0o4755) << 16);
    let mut writer = sevenz_rust2::ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    writer
        .push_archive_entry(entry, Some(Cursor::new(b"body".to_vec())))
        .unwrap();
    let bytes = writer.finish().unwrap().into_inner();
    let work = TempDir::new().unwrap();
    let archive = work.path().join("suid.7z");
    std::fs::write(&archive, bytes).unwrap();

    for preserve in [false, true] {
        let out = TempDir::new().unwrap();
        let config = SecurityConfig::default().with_preserve_permissions(preserve);

        ExtractRequest::new(&config)
            .extract(&archive, out.path())
            .unwrap();

        let mode = std::fs::metadata(out.path().join("suid"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7000, 0, "preserve={preserve}: {mode:o}");
    }
}

/// AES-CTR tamper: a modified encrypted entry is refused and the existing
/// `--force` target survives.
#[cfg(feature = "encryption")]
#[test]
fn aes_ctr_tamper_of_an_existing_force_target_is_refused_and_keeps_the_target() {
    use std::sync::Arc;

    use exarch_core::ArchiveError;
    use exarch_core::EncryptionRefusal;
    use exarch_core::Password;
    use exarch_core::Violation;

    const SENTINEL: &[u8] = b"existing target";

    let mut bytes = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/encryption/aes256.zip"),
    )
    .unwrap();
    // The first entry with data: local header, then name, extra, salt (16) and
    // verifier (2).
    let mut at = 0;
    let (name, ciphertext) = loop {
        assert_eq!(&bytes[at..at + 4], b"PK\x03\x04");
        let compressed = u32::from_le_bytes(bytes[at + 18..at + 22].try_into().unwrap());
        let name_len = usize::from(u16::from_le_bytes([bytes[at + 26], bytes[at + 27]]));
        let extra = usize::from(u16::from_le_bytes([bytes[at + 28], bytes[at + 29]]));
        let data = at + 30 + name_len + extra;
        if compressed > 0 {
            let name = String::from_utf8(bytes[at + 30..at + 30 + name_len].to_vec()).unwrap();
            break (name, data + 16 + 2);
        }
        at = data;
    };
    bytes[ciphertext] ^= 0x01;
    let work = TempDir::new().unwrap();
    let archive = work.path().join("tampered.zip");
    std::fs::write(&archive, bytes).unwrap();
    let out = TempDir::new().unwrap();
    let target = out.path().join(&name);
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    std::fs::write(&target, SENTINEL).unwrap();

    let result = ExtractRequest::new(&SecurityConfig::default())
        .with_options(overwrite())
        .with_password(Some(Arc::new(
            Password::new(b"correct-horse".to_vec()).unwrap(),
        )))
        .extract(&archive, out.path());

    let error = result.unwrap_err();
    let cause = match &error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    };
    assert_matches!(
        cause,
        ArchiveError::SecurityViolation {
            kind: Violation::Encrypted {
                reason: EncryptionRefusal::AuthenticationFailed,
                ..
            },
            ..
        }
    );
    assert_eq!(std::fs::read(&target).unwrap(), SENTINEL);
    let leftovers: Vec<_> = std::fs::read_dir(target.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(leftovers.len(), 1, "{leftovers:?}");
}
