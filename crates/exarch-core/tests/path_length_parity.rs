//! `list`, `verify` and `extract` give one verdict on an entry path that is
//! longer than the host path limit, whatever its component count.

#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::path::PathBuf;

use exarch_core::SecurityConfig;
use exarch_core::VerificationStatus;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use tempfile::TempDir;

const COMPONENT: usize = 200;

fn entry_name(components: usize) -> String {
    vec!["n".repeat(COMPONENT); components].join("/")
}

fn write_archive(dir: &TempDir, name: &str) -> PathBuf {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(1);
    header.set_mode(0o644);
    header.set_entry_type(tar::EntryType::Regular);
    builder.append_data(&mut header, name, &b"x"[..]).unwrap();
    let path = dir.path().join("long.tar");
    std::fs::write(&path, builder.into_inner().unwrap()).unwrap();
    path
}

struct Verdicts {
    list: bool,
    verify: bool,
    extract: bool,
}

fn verdicts(archive: &Path, config: &SecurityConfig) -> Verdicts {
    let out = TempDir::new().unwrap();
    Verdicts {
        list: list_archive(archive, config).is_ok(),
        verify: verify_archive(archive, config)
            .is_ok_and(|report| report.status() == VerificationStatus::Pass),
        extract: extract_archive(archive, out.path(), config).is_ok(),
    }
}

#[test]
fn verdicts_agree_for_every_component_count() {
    let config = SecurityConfig::default();
    for components in [4, 5, 6, 10, 20, 21, 25] {
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, &entry_name(components));
        let v = verdicts(&archive, &config);
        assert!(
            v.list == v.verify && v.list == v.extract,
            "{components} components: list={} verify={} extract={}",
            v.list,
            v.verify,
            v.extract
        );
    }
}

#[test]
fn an_overlong_name_of_a_skipped_extension_is_not_refused_by_extract() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &format!("{}.bin", entry_name(25)));
    let config = SecurityConfig::default().with_allowed_extensions(vec!["txt".to_string()]);
    let out = TempDir::new().unwrap();

    let report = extract_archive(&archive, out.path(), &config).unwrap();
    assert_eq!(report.files_skipped, 1);
}

#[cfg(not(windows))]
#[test]
fn a_path_above_every_unix_limit_is_refused_everywhere() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &entry_name(25));
    let config = SecurityConfig::default();
    let out = TempDir::new().unwrap();

    let err = extract_archive(&archive, out.path(), &config).unwrap_err();
    assert!(matches!(err, exarch_core::ArchiveError::Io(_)), "{err}");
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    assert!(list_archive(&archive, &config).is_err());
    assert!(verify_archive(&archive, &config).is_ok_and(|r| r.status() != VerificationStatus::Pass));
}

#[cfg(unix)]
mod landing {
    use super::*;

    #[cfg(target_os = "macos")]
    const CHAIN: (usize, usize) = (3, 255);
    #[cfg(not(target_os = "macos"))]
    const CHAIN: (usize, usize) = (14, 255);

    #[cfg(target_os = "macos")]
    const REST: (usize, usize) = (3, 100);
    #[cfg(not(target_os = "macos"))]
    const REST: (usize, usize) = (3, 200);

    fn join(components: (usize, usize)) -> String {
        vec!["c".repeat(components.1); components.0].join("/")
    }

    fn header(kind: tar::EntryType, size: u64) -> tar::Header {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o755);
        header.set_entry_type(kind);
        header.set_size(size);
        header
    }

    #[test]
    fn a_short_entry_landing_above_the_limit_through_a_symlink_is_refused() {
        let chain = join(CHAIN);
        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_data(&mut header(tar::EntryType::Directory, 0), &chain, &b""[..])
            .unwrap();
        builder
            .append_link(&mut header(tar::EntryType::Symlink, 0), "d", &chain)
            .unwrap();
        builder
            .append_data(
                &mut header(tar::EntryType::Regular, 1),
                format!("d/{}", join(REST)),
                &b"x"[..],
            )
            .unwrap();
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("landing.tar");
        std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();

        let config = SecurityConfig::default().with_allow_symlinks(true);
        let out = TempDir::new().unwrap();
        assert!(extract_archive(&archive, out.path(), &config).is_err());
        assert!(!out.path().join("d").join(join(REST)).exists());
    }
}
