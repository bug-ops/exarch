//! Extraction honors `SecurityConfig::permissions` for every format (#1308):
//! `Normalize` gives a regular file the sanitized archive mode minus the
//! process umask (as `tar` does without `-p`, execute bits kept), while
//! `Preserve` gives exactly the sanitized archive mode.

#![cfg(unix)]
#![expect(clippy::disallowed_methods, reason = "test fixture setup")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::MemoryEntry;
use exarch_core::MemoryExtractRequest;
use exarch_core::NoopProgress;
use exarch_core::PermissionPolicy;
use exarch_core::SanitizedMode;
use exarch_core::SecurityConfig;
use exarch_core::Staging;
use exarch_core::extract_reader_to_memory;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sevenz_rust2::SourceReader;
use std::io::Cursor;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use tempfile::TempDir;

/// The last three have no owner read or write bit to hand the kernel at
/// create, so Normalize must take them back through the descriptor.
const STORED: [(&str, u32); 6] = [
    ("plain", 0o640),
    ("run.sh", 0o755),
    ("owner", 0o700),
    ("locked", 0o000),
    ("readonly", 0o444),
    ("group-only", 0o070),
];

fn tar_archive(dir: &TempDir) -> PathBuf {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, mode) in STORED {
        let mut header = tar::Header::new_gnu();
        header.set_size(2);
        header.set_mode(mode);
        builder.append_data(&mut header, name, &b"hi"[..]).unwrap();
    }
    let path = dir.path().join("a.tar");
    std::fs::write(&path, builder.into_inner().unwrap()).unwrap();
    path
}

fn zip_archive(dir: &TempDir) -> PathBuf {
    let mut writer = zip::write::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, mode) in STORED {
        let options = zip::write::SimpleFileOptions::default().unix_permissions(mode);
        writer.start_file(name, options).unwrap();
        writer.write_all(b"hi").unwrap();
    }
    let path = dir.path().join("a.zip");
    std::fs::write(&path, writer.finish().unwrap().into_inner()).unwrap();
    path
}

fn sevenz_bytes() -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    for (name, mode) in STORED {
        let mut entry = ArchiveEntry::new_file(name);
        entry.has_stream = true;
        entry.size = 2;
        entry.has_windows_attributes = true;
        entry.windows_attributes = 0x8000 | ((0o100_000 | mode) << 16);
        writer
            .push_archive_entry(entry, Some(SourceReader::from(Cursor::new(b"hi".to_vec()))))
            .unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn sevenz_archive(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("a.7z");
    std::fs::write(&path, sevenz_bytes()).unwrap();
    path
}

fn config(policy: PermissionPolicy) -> SecurityConfig {
    SecurityConfig::default().with_preserve_permissions(policy.preserves())
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

/// The mode the kernel gives a file created with `mode` under the current
/// umask, so the expectation never reads the umask itself.
fn created_with(mode: u32) -> u32 {
    let probe = TempDir::new().unwrap();
    let file = probe.path().join("probe");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&file)
        .unwrap();
    mode_of(&file)
}

fn default_file_mode() -> u32 {
    created_with(0o666)
}

fn extract_into(make: fn(&TempDir) -> PathBuf, policy: PermissionPolicy) -> TempDir {
    let work = TempDir::new().unwrap();
    let archive = make(&work);
    let out = TempDir::new().unwrap();
    ExtractRequest::new(&config(policy))
        .extract(&archive, out.path())
        .unwrap();
    out
}

fn extracted_modes(make: fn(&TempDir) -> PathBuf, policy: PermissionPolicy) -> Vec<u32> {
    let out = extract_into(make, policy);
    STORED
        .iter()
        .map(|(name, _)| mode_of(&out.path().join(name)))
        .collect()
}

fn assert_policy_applies(make: fn(&TempDir) -> PathBuf) {
    assert_eq!(
        extracted_modes(make, PermissionPolicy::Normalize),
        STORED.map(|(_, mode)| created_with(mode)),
        "Normalize keeps the archive mode minus the umask, execute bit included"
    );
    assert_eq!(
        extracted_modes(make, PermissionPolicy::Preserve),
        STORED.map(|(_, mode)| mode),
        "Preserve applies the archive mode exactly"
    );
}

#[test]
fn tar_honors_the_permission_policy() {
    assert_policy_applies(tar_archive);
}

#[test]
fn zip_honors_the_permission_policy() {
    assert_policy_applies(zip_archive);
}

#[test]
fn sevenz_honors_the_permission_policy() {
    assert_policy_applies(sevenz_archive);
}

#[test]
fn the_default_configuration_normalizes() {
    let work = TempDir::new().unwrap();
    let archive = tar_archive(&work);
    let out = TempDir::new().unwrap();
    ExtractRequest::new(&SecurityConfig::default())
        .extract(&archive, out.path())
        .unwrap();
    assert_eq!(mode_of(&out.path().join("run.sh")), created_with(0o755));
}

const CHILD_ENV: &str = "EXARCH_PERMISSION_POLICY_UMASK_CHILD";

#[test]
fn the_umask_cuts_normalized_modes_but_not_preserved_ones() {
    if std::env::var_os(CHILD_ENV).is_some() {
        for make in [tar_archive, zip_archive, sevenz_archive] {
            assert_eq!(
                extracted_modes(make, PermissionPolicy::Normalize),
                [0o600, 0o700, 0o700, 0o000, 0o400, 0o000]
            );
            assert_eq!(
                extracted_modes(make, PermissionPolicy::Preserve),
                [0o640, 0o755, 0o700, 0o000, 0o444, 0o070]
            );
        }
        return;
    }
    let status = std::process::Command::new("sh")
        .args(["-c", "umask 077; exec \"$0\" --exact \"$1\" --nocapture"])
        .arg(std::env::current_exe().unwrap())
        .arg("the_umask_cuts_normalized_modes_but_not_preserved_ones")
        .env(CHILD_ENV, "1")
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn directories_get_the_default_mode_under_both_policies() {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mode(0o700);
    builder.append_data(&mut header, "d/", &b""[..]).unwrap();
    let work = TempDir::new().unwrap();
    let archive = work.path().join("d.tar");
    std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();

    let probe = TempDir::new().unwrap();
    std::fs::create_dir(probe.path().join("p")).unwrap();
    let default_dir = mode_of(&probe.path().join("p"));
    for policy in [PermissionPolicy::Normalize, PermissionPolicy::Preserve] {
        let out = TempDir::new().unwrap();
        ExtractRequest::new(&config(policy))
            .extract(&archive, out.path())
            .unwrap();
        assert_eq!(mode_of(&out.path().join("d")), default_dir, "{policy:?}");
    }
}

#[test]
fn force_replacement_follows_the_policy() {
    for policy in [PermissionPolicy::Normalize, PermissionPolicy::Preserve] {
        let work = TempDir::new().unwrap();
        let archive = tar_archive(&work);
        let out = TempDir::new().unwrap();
        let target = out.path().join("plain");
        std::fs::write(&target, b"old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let options = ExtractionOptions::default().with_existing_files(ExistingFiles::Overwrite);

        ExtractRequest::new(&config(policy))
            .with_options(options)
            .extract(&archive, out.path())
            .unwrap();

        let expected = if policy.preserves() {
            0o640
        } else {
            created_with(0o640)
        };
        assert_eq!(mode_of(&target), expected, "{policy:?}");
    }
}

#[test]
fn a_sevenz_entry_without_a_unix_mode_gets_the_default_mode() {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    let mut entry = ArchiveEntry::new_file("bare");
    entry.has_stream = true;
    entry.size = 2;
    writer
        .push_archive_entry(entry, Some(SourceReader::from(Cursor::new(b"hi".to_vec()))))
        .unwrap();
    let work = TempDir::new().unwrap();
    let archive = work.path().join("b.7z");
    std::fs::write(&archive, writer.finish().unwrap().into_inner()).unwrap();

    for policy in [PermissionPolicy::Normalize, PermissionPolicy::Preserve] {
        let out = TempDir::new().unwrap();
        ExtractRequest::new(&config(policy))
            .extract(&archive, out.path())
            .unwrap();
        assert_eq!(
            mode_of(&out.path().join("bare")),
            default_file_mode(),
            "{policy:?}"
        );
    }
}

#[test]
fn the_memory_sink_reports_the_sanitized_mode_under_both_policies() {
    let bytes = sevenz_bytes();
    for policy in [PermissionPolicy::Normalize, PermissionPolicy::Preserve] {
        let reader = exarch_core::ArchiveReader::from_bytes(bytes.clone(), None).unwrap();
        let request = MemoryExtractRequest::default().with_config(config(policy));
        let (_report, sink) =
            extract_reader_to_memory(reader, &request, &mut NoopProgress).unwrap();
        let modes: Vec<_> = sink
            .into_entries()
            .into_iter()
            .filter_map(|(path, entry)| match entry {
                MemoryEntry::File { mode, .. } if path == Path::new("plain") => {
                    Some(mode.map(SanitizedMode::as_u32))
                }
                _ => None,
            })
            .collect();
        assert_eq!(modes, [Some(0o640)], "{policy:?}");
    }
}

#[test]
fn atomic_staging_follows_the_policy() {
    for policy in [PermissionPolicy::Normalize, PermissionPolicy::Preserve] {
        let work = TempDir::new().unwrap();
        let archive = tar_archive(&work);
        let dest = work.path().join("dest");
        let options = ExtractionOptions::default().with_staging(Staging::Atomic);

        ExtractRequest::new(&config(policy))
            .with_options(options)
            .extract(&archive, &dest)
            .unwrap();

        let expected = STORED.map(|(_, mode)| {
            if policy.preserves() {
                mode
            } else {
                created_with(mode)
            }
        });
        let actual = STORED.map(|(name, _)| mode_of(&dest.join(name)));
        assert_eq!(actual, expected, "{policy:?}");
    }
}
