//! A hidden directory below a source directory is left out whole unless hidden
//! entries are included, so secrets under `.ssh`, `.aws` or `.gnupg` cannot
//! reach an archive under a visible file name.
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

use std::path::Path;
use std::path::PathBuf;

use exarch_core::CreateRequest;
use exarch_core::CreationReport;
use exarch_core::OutputFile;
use exarch_core::SecurityConfig;
use exarch_core::SkipKind;
use exarch_core::creation::CreationConfig;
use exarch_core::list_archive;
use tempfile::TempDir;

fn write(root: &Path, relative: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, b"secret").unwrap();
}

fn tree() -> TempDir {
    let src = TempDir::new().unwrap();
    for relative in [
        "visible.txt",
        "src/main.rs",
        "src/.ssh/id_rsa",
        "src/.config/app/secret",
        "src/.config/visible_inside/note.txt",
        "deep/er/.gnupg/private-keys-v1.d/key",
        ".aws/credentials",
    ] {
        write(src.path(), relative);
    }
    src
}

fn create(source: &Path, name: &str, config: &CreationConfig) -> (Vec<PathBuf>, CreationReport) {
    let out = TempDir::new().unwrap();
    let archive = out.path().join(name);
    let report = CreateRequest::new(config)
        .create(&OutputFile::replace(&archive), &[source])
        .unwrap();
    let mut names: Vec<PathBuf> = list_archive(&archive, &SecurityConfig::default())
        .unwrap()
        .entries()
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    names.sort();
    (names, report)
}

#[test]
fn hidden_directories_are_never_entered() {
    for name in ["out.tar.gz", "out.zip"] {
        let src = tree();
        let (names, report) = create(src.path(), name, &CreationConfig::default());

        for leaked in [
            ".ssh",
            ".config",
            ".gnupg",
            ".aws",
            "id_rsa",
            "secret",
            "credentials",
        ] {
            assert!(
                !names.iter().any(|n| n
                    .components()
                    .any(|c| c.as_os_str().to_string_lossy().contains(leaked))),
                "{name}: {leaked} leaked into {names:?}"
            );
        }
        assert!(names.contains(&PathBuf::from("visible.txt")), "{name}");
        assert!(names.contains(&PathBuf::from("src/main.rs")), "{name}");
        assert!(
            !names
                .iter()
                .any(|n| n.ends_with("note.txt") || n.ends_with("key")),
            "{name}: a visible name inside a hidden directory must not be archived: {names:?}"
        );

        assert_eq!(
            report.skipped.count(SkipKind::Hidden),
            3 + 1,
            "{name}: each hidden directory is counted once, not once per descendant"
        );
        let skipped: Vec<_> = report
            .skipped
            .sample()
            .iter()
            .map(|s| s.path.clone())
            .collect();
        for expected in [".aws", "src/.ssh", "src/.config", "deep/er/.gnupg"] {
            assert!(
                skipped.contains(&PathBuf::from(expected)),
                "{name}: {skipped:?}"
            );
        }
    }
}

#[test]
fn including_hidden_entries_archives_them() {
    for name in ["out.tar.gz", "out.zip"] {
        let src = tree();
        let config = CreationConfig::default().with_include_hidden(true);
        let (names, report) = create(src.path(), name, &config);

        for expected in [
            ".aws/credentials",
            "src/.ssh/id_rsa",
            "src/.config/app/secret",
            "src/.config/visible_inside/note.txt",
            "deep/er/.gnupg/private-keys-v1.d/key",
        ] {
            assert!(
                names.contains(&PathBuf::from(expected)),
                "{name}: {expected}"
            );
        }
        assert_eq!(report.skipped.count(SkipKind::Hidden), 0, "{name}");
    }
}

#[test]
fn a_hidden_source_directory_named_by_the_caller_is_archived() {
    for name in ["out.tar.gz", "out.zip"] {
        let src = TempDir::new().unwrap();
        let hidden_root = src.path().join(".project");
        write(&hidden_root, "a.txt");
        write(&hidden_root, ".inner/b.txt");

        let (names, report) = create(&hidden_root, name, &CreationConfig::default());

        assert!(names.contains(&PathBuf::from("a.txt")), "{name}: {names:?}");
        assert!(
            !names.iter().any(|n| n.ends_with("b.txt")),
            "{name}: {names:?}"
        );
        assert_eq!(report.skipped.count(SkipKind::Hidden), 1, "{name}");
    }
}

#[test]
fn a_file_source_named_directly_is_archived_even_when_hidden() {
    for name in ["out.tar.gz", "out.zip"] {
        let src = TempDir::new().unwrap();
        write(src.path(), ".env");

        let (names, _) = create(&src.path().join(".env"), name, &CreationConfig::default());

        assert_eq!(names, [PathBuf::from(".env")], "{name}");
    }
}
