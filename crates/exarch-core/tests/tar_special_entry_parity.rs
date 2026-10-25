//! A TAR entry that is not a file, directory or link (device node, FIFO, or an
//! unknown typeflag such as GNU `V`) is refused as a security violation by
//! `extract`, `list` and `verify` alike.

#![allow(clippy::unwrap_used)]

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
        ("gnu-volume-header", tar::EntryType::new(b'V')),
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
            "SECURITY_VIOLATION",
            "{name}: {extract}"
        );
        let list = list_archive(&archive, &config).unwrap_err();
        assert_eq!(list.error_code(), "SECURITY_VIOLATION", "{name}: {list}");
        let verify = verify_archive(&archive, &config).unwrap_err();
        assert_eq!(
            verify.error_code(),
            "SECURITY_VIOLATION",
            "{name}: {verify}"
        );
    }
}
