//! A TAR entry that is not a file, directory or link (device node, FIFO, or an
//! unknown typeflag such as GNU `M`) is refused as a security violation by
//! `extract`, `list` and `verify` alike, and the refusal names the typeflag.

#![expect(clippy::disallowed_methods, reason = "test fixture setup")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

use exarch_core::ErrorCode;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use tempfile::TempDir;

fn tar_with_special_entry(kind: tar::EntryType) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let mut file = tar::Header::new_gnu();
    file.set_entry_type(tar::EntryType::Regular);
    file.set_size(2);
    file.set_mode(0o644);
    file.set_cksum();
    builder
        .append_data(&mut file, "ok.txt", &b"hi"[..])
        .unwrap();

    let mut special = tar::Header::new_gnu();
    special.set_entry_type(kind);
    special.set_size(0);
    special.set_mode(0o644);
    special.set_cksum();
    builder
        .append_data(&mut special, "special", &[][..])
        .unwrap();

    builder.into_inner().unwrap()
}

#[test]
fn special_entries_are_security_violations_everywhere() {
    let kinds = [
        ("char", tar::EntryType::Char),
        ("block", tar::EntryType::Block),
        ("fifo", tar::EntryType::Fifo),
        ("gnu-multivolume", tar::EntryType::new(b'M')),
        ("gnu-dumpdir", tar::EntryType::new(b'D')),
    ];
    let config = SecurityConfig::default();

    for (name, kind) in kinds {
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("special.tar");
        std::fs::write(&archive, tar_with_special_entry(kind)).unwrap();
        let out = TempDir::new().unwrap();

        let extract = extract_archive(&archive, out.path(), &config).unwrap_err();
        assert_eq!(
            extract.error_code(),
            ErrorCode::SecurityViolation,
            "{name}: {extract}"
        );
        let list = list_archive(&archive, &config).unwrap_err();
        assert_eq!(
            list.error_code(),
            ErrorCode::SecurityViolation,
            "{name}: {list}"
        );
        let verify = verify_archive(&archive, &config).unwrap_err();
        assert_eq!(
            verify.error_code(),
            ErrorCode::SecurityViolation,
            "{name}: {verify}"
        );
    }
}

#[test]
fn an_unsupported_typeflag_is_named_by_its_character_and_byte() {
    let config = SecurityConfig::default();

    for (kind, shown) in [
        (b'M', "'M' (0x4D)"),
        (b'D', "'D' (0x44)"),
        (b'Z', "'Z' (0x5A)"),
        (0x01, "0x01"),
    ] {
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("special.tar");
        std::fs::write(&archive, tar_with_special_entry(tar::EntryType::new(kind))).unwrap();

        let expected = format!("unsupported entry type: {shown}");
        let list = list_archive(&archive, &config).unwrap_err().to_string();
        assert!(list.contains(&expected), "{list}");
        let verify = verify_archive(&archive, &config).unwrap_err().to_string();
        assert!(verify.contains(&expected), "{verify}");
        let out = TempDir::new().unwrap();
        let extract = extract_archive(&archive, out.path(), &config)
            .unwrap_err()
            .to_string();
        assert!(extract.contains(&expected), "{extract}");
    }
}
