//! A directory entry over an archive symlink to a file is `ReplacesSymlink`
//! (`EXISTING_SYMLINK`) even when the host path of the landing is past
//! `PATH_MAX`, as for the short path (#1215).

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

use exarch_core::ArchiveError;
use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::SecurityConfig;
use exarch_core::Violation;
use tempfile::TempDir;

const MAX_ENTRY: usize = if cfg!(target_os = "macos") {
    1022
} else {
    4094
};

fn long_prefix(len: usize) -> String {
    let mut name = String::new();
    while name.len() < len {
        if !name.is_empty() {
            name.push('/');
        }
        let room = len - name.len();
        name.push_str(&"n".repeat(room.min(200)));
    }
    name
}

fn archive(prefix: &str) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut file = tar::Header::new_gnu();
    file.set_size(2);
    file.set_mode(0o644);
    file.set_cksum();
    builder
        .append_data(&mut file, format!("{prefix}/t"), &b"ok"[..])
        .unwrap();
    let mut link = tar::Header::new_gnu();
    link.set_entry_type(tar::EntryType::Symlink);
    link.set_size(0);
    link.set_mode(0o777);
    link.set_cksum();
    builder
        .append_link(&mut link, format!("{prefix}/l"), "t")
        .unwrap();
    let mut dir = tar::Header::new_gnu();
    dir.set_entry_type(tar::EntryType::Directory);
    dir.set_size(0);
    dir.set_mode(0o755);
    dir.set_cksum();
    builder
        .append_data(&mut dir, format!("{prefix}/l/"), std::io::empty())
        .unwrap();
    builder.into_inner().unwrap()
}

#[test]
fn directory_over_an_archive_symlink_past_path_max_is_replaces_symlink() {
    let work = TempDir::new().unwrap();
    let archive_path = work.path().join("a.tar");
    std::fs::write(&archive_path, archive(&long_prefix(MAX_ENTRY - 4))).unwrap();

    for policy in [
        ExistingFiles::Skip,
        ExistingFiles::Refuse,
        ExistingFiles::Overwrite,
    ] {
        let out = TempDir::new().unwrap();

        let error = ExtractRequest::new(&SecurityConfig::default().with_allow_symlinks(true))
            .with_options(ExtractionOptions::default().with_existing_files(policy))
            .extract(&archive_path, out.path())
            .unwrap_err();

        let cause = match &error {
            ArchiveError::PartialExtraction(partial) => partial.cause(),
            other => other,
        };
        assert!(
            matches!(
                cause,
                ArchiveError::SecurityViolation {
                    kind: Violation::ReplacesSymlink { .. },
                    ..
                }
            ),
            "{policy:?}: {error}"
        );
    }
}
