//! 7z extraction restores the Unix permission bits an entry stores through the
//! TAR/ZIP sanitizer (#1296), and an AES block whose `PPMd` decoder cannot
//! start under a wrong password is the password refusal in `extract` as in
//! `verify` (#1289).

#![expect(clippy::disallowed_methods, reason = "test fixture setup")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

use std::io::Cursor;
use std::path::Path;

use exarch_core::ExtractRequest;
use exarch_core::MemoryEntry;
use exarch_core::MemoryExtractRequest;
use exarch_core::NoopProgress;
use exarch_core::SecurityConfig;
use exarch_core::extract_reader_to_memory;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sevenz_rust2::SourceReader;
use tempfile::TempDir;

const S_IFREG: u32 = 0o100_000;
#[cfg(unix)]
const S_IFDIR: u32 = 0o040_000;

/// An entry carrying `word` as its whole attribute word.
fn with_attributes(mut entry: ArchiveEntry, word: u32) -> ArchiveEntry {
    entry.has_windows_attributes = true;
    entry.windows_attributes = word;
    entry
}

/// An entry whose attributes carry `mode` as a Unix mode with the extension
/// flag.
fn with_unix_mode(entry: ArchiveEntry, mode: u32) -> ArchiveEntry {
    with_attributes(entry, 0x8000 | (mode << 16))
}

fn file_entry(name: &str, size: usize) -> ArchiveEntry {
    let mut entry = ArchiveEntry::new_file(name);
    entry.has_stream = true;
    entry.size = size as u64;
    entry
}

fn sevenz(entries: Vec<ArchiveEntry>) -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    for entry in entries {
        if entry.has_stream {
            let body = vec![b'x'; usize::try_from(entry.size).unwrap()];
            writer
                .push_archive_entry(entry, Some(SourceReader::from(Cursor::new(body))))
                .unwrap();
        } else {
            writer.push_archive_entry::<&[u8]>(entry, None).unwrap();
        }
    }
    writer.finish().unwrap().into_inner()
}

fn unix_files(names_modes: &[(&str, u32)]) -> Vec<u8> {
    sevenz(
        names_modes
            .iter()
            .map(|&(name, mode)| with_unix_mode(file_entry(name, 4), S_IFREG | mode))
            .collect(),
    )
}

#[cfg(unix)]
fn extract_to_host(bytes: &[u8], config: &SecurityConfig) -> TempDir {
    let dest = TempDir::new().unwrap();
    let scratch = TempDir::new().unwrap();
    let path = scratch.path().join("a.7z");
    std::fs::write(&path, bytes).unwrap();
    ExtractRequest::new(config)
        .extract(&path, dest.path())
        .unwrap();
    dest
}

fn memory_modes(bytes: &[u8], config: &SecurityConfig) -> Vec<(String, Option<u32>)> {
    let reader = exarch_core::ArchiveReader::from_bytes(bytes.to_vec(), None).unwrap();
    let request = MemoryExtractRequest::default().with_config(config.clone());
    let (_report, sink) = extract_reader_to_memory(reader, &request, &mut NoopProgress).unwrap();
    sink.into_entries()
        .into_iter()
        .filter_map(|(path, entry)| match entry {
            MemoryEntry::File { mode, .. } => Some((
                path.to_string_lossy().into_owned(),
                mode.map(exarch_core::SanitizedMode::as_u32),
            )),
            _ => None,
        })
        .collect()
}

#[cfg(unix)]
fn host_mode(dest: &TempDir, name: &str) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(dest.path().join(name))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777
}

#[cfg(unix)]
#[test]
fn stored_modes_are_restored_and_executables_keep_the_execute_bit() {
    let bytes = unix_files(&[("run.sh", 0o755), ("ro.txt", 0o444), ("plain.txt", 0o640)]);

    let dest = extract_to_host(&bytes, &SecurityConfig::default());

    assert_eq!(host_mode(&dest, "run.sh"), 0o755);
    assert_eq!(host_mode(&dest, "ro.txt"), 0o444);
    assert_eq!(host_mode(&dest, "plain.txt"), 0o640);
}

#[test]
fn memory_extraction_reports_the_same_sanitized_modes() {
    let bytes = unix_files(&[("run.sh", 0o755), ("ro.txt", 0o444), ("plain.txt", 0o640)]);

    let mut modes = memory_modes(&bytes, &SecurityConfig::default());
    modes.sort();

    assert_eq!(
        modes,
        [
            ("plain.txt".to_owned(), Some(0o640)),
            ("ro.txt".to_owned(), Some(0o444)),
            ("run.sh".to_owned(), Some(0o755)),
        ]
    );
}

#[cfg(unix)]
#[test]
fn setuid_setgid_and_sticky_are_stripped_and_world_write_follows_policy() {
    let bytes = unix_files(&[
        ("suid", 0o4755),
        ("sgid", 0o2755),
        ("both", 0o6755),
        ("sticky", 0o1777),
        ("world", 0o777),
    ]);

    let default = extract_to_host(&bytes, &SecurityConfig::default());
    assert_eq!(host_mode(&default, "suid"), 0o755);
    assert_eq!(host_mode(&default, "sgid"), 0o755);
    assert_eq!(host_mode(&default, "both"), 0o755);
    assert_eq!(host_mode(&default, "sticky"), 0o775);
    assert_eq!(host_mode(&default, "world"), 0o775);

    let permissive = extract_to_host(
        &bytes,
        &SecurityConfig::default().with_allow_world_writable(true),
    );
    assert_eq!(host_mode(&permissive, "suid"), 0o755);
    assert_eq!(host_mode(&permissive, "both"), 0o755);
    assert_eq!(host_mode(&permissive, "sticky"), 0o777);
    assert_eq!(host_mode(&permissive, "world"), 0o777);
}

#[cfg(unix)]
#[test]
fn the_bits_match_tar_for_the_same_stored_mode() {
    let modes = [0o4755_u32, 0o2755, 0o6755, 0o777, 0o640];
    let mut builder = tar::Builder::new(Vec::new());
    for (index, mode) in modes.iter().enumerate() {
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(*mode);
        header.set_cksum();
        builder
            .append_data(&mut header, format!("f{index}"), &b"xxxx"[..])
            .unwrap();
    }
    let tar_bytes = builder.into_inner().unwrap();
    let scratch = TempDir::new().unwrap();
    let tar_path = scratch.path().join("a.tar");
    std::fs::write(&tar_path, tar_bytes).unwrap();
    let tar_dest = TempDir::new().unwrap();
    ExtractRequest::new(&SecurityConfig::default())
        .extract(&tar_path, tar_dest.path())
        .unwrap();

    let names: Vec<(String, u32)> = modes
        .iter()
        .enumerate()
        .map(|(index, mode)| (format!("f{index}"), *mode))
        .collect();
    let pairs: Vec<(&str, u32)> = names.iter().map(|(n, m)| (n.as_str(), *m)).collect();
    let sevenz_dest = extract_to_host(&unix_files(&pairs), &SecurityConfig::default());

    for (name, _) in &names {
        assert_eq!(
            host_mode(&sevenz_dest, name),
            host_mode(&tar_dest, name),
            "{name}"
        );
    }
}

#[cfg(unix)]
#[test]
fn mode_zero_is_applied_as_is() {
    let dest = extract_to_host(&unix_files(&[("locked", 0)]), &SecurityConfig::default());

    assert_eq!(host_mode(&dest, "locked"), 0);
    std::fs::set_permissions(
        dest.path().join("locked"),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
}

#[cfg(unix)]
#[test]
fn entries_without_a_stored_mode_keep_the_default() {
    let bytes = sevenz(vec![
        file_entry("flagless", 4),
        with_attributes(file_entry("windows-only", 4), 0x1),
        with_attributes(file_entry("high-bits-no-flag", 4), 0o755 << 16),
        with_unix_mode(ArchiveEntry::new_directory("dir"), S_IFDIR | 0o555),
    ]);

    let dest = extract_to_host(&bytes, &SecurityConfig::default());

    let default = host_mode(&dest, "flagless");
    assert_eq!(host_mode(&dest, "windows-only"), default);
    assert_eq!(host_mode(&dest, "high-bits-no-flag"), default);
    assert_ne!(host_mode(&dest, "dir") & 0o200, 0, "directory stays usable");
    assert_eq!(
        memory_modes(&bytes, &SecurityConfig::default())
            .into_iter()
            .filter(|(_, mode)| mode.is_some())
            .count(),
        0
    );
}

#[cfg(unix)]
#[test]
fn the_flag_without_type_bits_is_a_regular_file_with_its_mode() {
    let bytes = sevenz(vec![with_attributes(
        file_entry("typeless", 4),
        0x8000 | (0o750 << 16),
    )]);

    let dest = extract_to_host(&bytes, &SecurityConfig::default());

    assert_eq!(host_mode(&dest, "typeless"), 0o750);
}

#[test]
fn every_permission_and_special_bit_is_masked_to_the_sanitized_range() {
    let bytes = sevenz(vec![with_unix_mode(
        file_entry("ones", 4),
        S_IFREG | 0o7777,
    )]);

    let modes = memory_modes(&bytes, &SecurityConfig::default());

    assert_eq!(modes, [("ones".to_owned(), Some(0o775))]);
}

#[test]
fn an_all_ones_attribute_word_is_refused_for_its_undefined_type() {
    let bytes = sevenz(vec![with_attributes(file_entry("ones", 4), 0xFFFF_8000)]);
    let reader = exarch_core::ArchiveReader::from_bytes(bytes, None).unwrap();

    let error =
        extract_reader_to_memory(reader, &MemoryExtractRequest::default(), &mut NoopProgress)
            .unwrap_err();

    assert!(matches!(
        error,
        exarch_core::ArchiveError::SecurityViolation {
            kind: exarch_core::Violation::UndefinedUnixType { .. },
            ..
        }
    ));
}

#[cfg(unix)]
#[test]
fn force_over_an_existing_file_applies_the_archive_mode() {
    use exarch_core::ExistingFiles;
    use exarch_core::ExtractionOptions;
    use std::os::unix::fs::PermissionsExt;

    let dest = TempDir::new().unwrap();
    let existing = dest.path().join("run.sh");
    std::fs::write(&existing, b"old").unwrap();
    std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o600)).unwrap();
    let scratch = TempDir::new().unwrap();
    let path = scratch.path().join("a.7z");
    std::fs::write(&path, unix_files(&[("run.sh", 0o755)])).unwrap();

    ExtractRequest::new(&SecurityConfig::default())
        .with_options(ExtractionOptions::default().with_existing_files(ExistingFiles::Overwrite))
        .extract(&path, dest.path())
        .unwrap();

    assert_eq!(std::fs::read(&existing).unwrap(), b"xxxx");
    assert_eq!(host_mode(&dest, "run.sh"), 0o755);
}

#[cfg(unix)]
#[test]
fn a_skipped_duplicate_keeps_the_first_files_mode() {
    let bytes = unix_files(&[("dup", 0o640), ("dup", 0o755)]);

    let dest = extract_to_host(&bytes, &SecurityConfig::default());

    assert_eq!(host_mode(&dest, "dup"), 0o640);
}

#[cfg(feature = "encryption")]
mod ppmd_key {
    use std::sync::Arc;

    use super::Path;
    use super::TempDir;
    use exarch_core::ArchiveError;
    use exarch_core::DecompressionBudget;
    use exarch_core::EncryptionRefusal;
    use exarch_core::IntegrityCheck;
    use exarch_core::Password;
    use exarch_core::VerificationOptions;
    use exarch_core::VerifyRequest;
    use exarch_core::Violation;
    use sevenz_rust2::EncoderConfiguration;
    use sevenz_rust2::encoder_options::AesEncoderOptions;
    use sevenz_rust2::encoder_options::PpmdOptions;

    use super::*;

    fn archive(content: EncoderConfiguration, plaintext: &[u8]) -> Vec<u8> {
        let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
        writer.set_encrypt_header(false);
        writer.set_content_methods(vec![
            AesEncoderOptions::new(sevenz_rust2::Password::new("correct")).into(),
            content,
        ]);
        let mut entry = ArchiveEntry::new_file("text.txt");
        entry.has_stream = true;
        entry.size = plaintext.len() as u64;
        writer
            .push_archive_entry(
                entry,
                Some(SourceReader::from(Cursor::new(plaintext.to_vec()))),
            )
            .unwrap();
        writer.finish().unwrap().into_inner()
    }

    fn text() -> Vec<u8> {
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        (0..12_000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                    [usize::from(state.to_le_bytes()[0] % 64)]
            })
            .collect()
    }

    fn password(bytes: &[u8]) -> Arc<Password> {
        Arc::new(Password::new(bytes.to_vec()).unwrap())
    }

    fn is_key_refusal(error: &ArchiveError) -> bool {
        let cause = match error {
            ArchiveError::PartialExtraction(partial) => partial.cause(),
            other => other,
        };
        matches!(
            cause,
            ArchiveError::SecurityViolation {
                kind: Violation::Encrypted {
                    reason: EncryptionRefusal::WrongPasswordOrCorrupt,
                    ..
                },
                ..
            }
        )
    }

    fn extract(path: &Path, secret: &[u8]) -> exarch_core::Result<()> {
        let dest = TempDir::new().unwrap();
        ExtractRequest::new(&SecurityConfig::default())
            .with_password(Some(password(secret)))
            .extract(path, dest.path())
            .map(drop)
    }

    fn verified_issues(path: &Path, secret: &[u8]) -> Vec<(String, String)> {
        let report = VerifyRequest::new(&SecurityConfig::default())
            .with_options(
                VerificationOptions::default()
                    .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT)),
            )
            .with_password(Some(password(secret)))
            .verify(path)
            .unwrap();
        report
            .issues()
            .iter()
            .map(|issue| (issue.category().to_string(), issue.message()))
            .collect()
    }

    #[test]
    fn a_wrong_password_on_a_ppmd_aes_block_is_the_password_refusal_in_extract_and_verify() {
        let scratch = TempDir::new().unwrap();
        let path = scratch.path().join("ppmd.7z");
        std::fs::write(
            &path,
            archive(
                PpmdOptions::from_order_memory_size(6, 1 << 18).into(),
                &text(),
            ),
        )
        .unwrap();
        extract(&path, b"correct").unwrap();
        assert!(verified_issues(&path, b"correct").is_empty());
        let refusal_issues = verified_issues(&path, b"wrong-0");
        assert!(
            refusal_issues
                .iter()
                .any(|(_, message)| message.contains("password")),
            "{refusal_issues:?}"
        );

        for attempt in 0..40 {
            let wrong = format!("wrong-{attempt}");
            let extracted = extract(&path, wrong.as_bytes()).unwrap_err();
            assert!(is_key_refusal(&extracted), "{wrong}: {extracted}");
            let issues = verified_issues(&path, wrong.as_bytes());
            assert_eq!(issues, refusal_issues, "{wrong}");
        }
    }

    #[test]
    fn a_corrupt_plain_ppmd_block_keeps_the_invalid_archive_error() {
        let scratch = TempDir::new().unwrap();
        let path = scratch.path().join("plain.7z");
        let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
        writer.set_content_methods(vec![PpmdOptions::from_order_memory_size(6, 1 << 18).into()]);
        let plaintext = text();
        let mut entry = ArchiveEntry::new_file("text.txt");
        entry.has_stream = true;
        entry.size = plaintext.len() as u64;
        writer
            .push_archive_entry(entry, Some(SourceReader::from(Cursor::new(plaintext))))
            .unwrap();
        let mut bytes = writer.finish().unwrap().into_inner();
        for byte in &mut bytes[32..48] {
            *byte ^= 0xFF;
        }
        std::fs::write(&path, bytes).unwrap();

        let error = extract(&path, b"unused").unwrap_err();

        assert!(!is_key_refusal(&error), "{error}");
    }
}
