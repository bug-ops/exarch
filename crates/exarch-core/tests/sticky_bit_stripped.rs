//! A regular file never gets the sticky bit on extraction, whatever the format
//! stored: TAR and ZIP end with the same mode as 7z for the same stored bits
//! (#1305). The ZIP case is a parity check: ZIP already dropped the bit.

#![cfg(unix)]
#![expect(clippy::disallowed_methods, reason = "test fixture setup")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

mod sink_support;

use exarch_core::ExtractRequest;
use exarch_core::SecurityConfig;
use sink_support::testkit::raw_zip::RawEntry;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tempfile::TempDir;

const STORED: [u32; 3] = [0o7777, 0o1755, 0o1644];
const EXPECTED: [u32; 3] = [0o775, 0o755, 0o644];

fn tar_archive(dir: &TempDir) -> PathBuf {
    let mut builder = tar::Builder::new(Vec::new());
    for (index, mode) in STORED.iter().enumerate() {
        let mut header = tar::Header::new_gnu();
        header.set_size(2);
        header.set_mode(*mode);
        builder
            .append_data(&mut header, format!("f{index}"), &b"hi"[..])
            .unwrap();
    }
    let path = dir.path().join("a.tar");
    std::fs::write(&path, builder.into_inner().unwrap()).unwrap();
    path
}

fn zip_archive(dir: &TempDir) -> PathBuf {
    // The zip writer masks modes to 0o777, so the raw builder stores the full
    // mode. The zip reader clears special bits itself, so this case guards the
    // end result, not `sanitize_permissions`.
    let entries = STORED
        .iter()
        .enumerate()
        .map(|(index, mode)| RawEntry {
            external_attributes: (0o100_000 | mode) << 16,
            ..RawEntry::stored(&format!("f{index}"), b"hi")
        })
        .collect();
    let path = dir.path().join("a.zip");
    std::fs::write(&path, sink_support::zip_archive(entries)).unwrap();
    path
}

fn assert_sticky_stripped(make: fn(&TempDir) -> PathBuf) {
    let work = TempDir::new().unwrap();
    let archive = make(&work);
    let out = TempDir::new().unwrap();

    ExtractRequest::new(&SecurityConfig::default().with_preserve_permissions(true))
        .extract(&archive, out.path())
        .unwrap();

    for (index, expected) in EXPECTED.iter().enumerate() {
        let mode = std::fs::metadata(out.path().join(format!("f{index}")))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, *expected, "f{index}");
    }
}

#[test]
fn tar_regular_file_loses_the_sticky_bit() {
    assert_sticky_stripped(tar_archive);
}

#[test]
fn zip_regular_file_loses_the_sticky_bit() {
    assert_sticky_stripped(zip_archive);
}

#[test]
fn directory_modes_are_not_restored_so_sticky_never_appears() {
    let work = TempDir::new().unwrap();
    let mut builder = tar::Builder::new(Vec::new());
    for (name, mode) in [("sticky/", 0o1755), ("plain/", 0o700)] {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(mode);
        builder.append_data(&mut header, name, &b""[..]).unwrap();
    }
    let archive = work.path().join("d.tar");
    std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
    let out = TempDir::new().unwrap();

    ExtractRequest::new(&SecurityConfig::default().with_preserve_permissions(true))
        .extract(&archive, out.path())
        .unwrap();

    let mode_of = |name: &str| {
        std::fs::metadata(out.path().join(name))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    };
    assert_eq!(mode_of("sticky"), mode_of("plain"));
    assert_eq!(mode_of("sticky") & 0o1000, 0);
}
