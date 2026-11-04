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
    std::fs::write(path, b"payload").unwrap();
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

        let skipped_parts = [
            ".ssh",
            ".config",
            ".gnupg",
            ".aws",
            "id_rsa",
            "secret",
            "credentials",
        ];
        let archived = skipped_parts.iter().position(|part| {
            names.iter().any(|n| {
                n.components()
                    .any(|c| c.as_os_str().to_string_lossy().contains(part))
            })
        });
        assert!(
            archived.is_none(),
            "{name}: an entry below a skipped hidden directory was archived (part {archived:?}): {names:?}"
        );
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

fn create_many(sources: &[&Path], config: &CreationConfig) -> (Vec<PathBuf>, CreationReport) {
    let out = TempDir::new().unwrap();
    let archive = out.path().join("out.tar.gz");
    let report = CreateRequest::new(config)
        .create(&OutputFile::replace(&archive), sources)
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

#[cfg(unix)]
#[test]
fn a_hidden_symlink_to_a_directory_is_skipped_with_and_without_following() {
    for follow in [false, true] {
        let src = TempDir::new().unwrap();
        write(src.path(), "real/data.txt");
        std::os::unix::fs::symlink(src.path().join("real"), src.path().join(".link")).unwrap();

        let config = CreationConfig::default().with_follow_symlinks(follow);
        let (names, report) = create_many(&[src.path()], &config);

        assert!(
            !names.iter().any(|n| n.starts_with(".link")),
            "follow={follow}: {names:?}"
        );
        assert!(
            names.contains(&PathBuf::from("real/data.txt")),
            "follow={follow}"
        );
        assert_eq!(report.skipped.count(SkipKind::Hidden), 1, "follow={follow}");
    }
}

/// The visible name of a link decides: with `follow_symlinks` the contents of
/// `keys -> .ssh` are archived under `keys/`, while `.ssh` itself is skipped.
/// Without following, only the link is stored.
#[cfg(unix)]
#[test]
fn a_visibly_named_link_to_a_hidden_directory_follows_the_visible_name() {
    let src = TempDir::new().unwrap();
    write(src.path(), ".ssh/id_rsa");
    std::os::unix::fs::symlink(src.path().join(".ssh"), src.path().join("keys")).unwrap();

    let followed = CreationConfig::default().with_follow_symlinks(true);
    let (names, _) = create_many(&[src.path()], &followed);
    assert!(names.contains(&PathBuf::from("keys/id_rsa")), "{names:?}");
    assert!(!names.iter().any(|n| n.starts_with(".ssh")), "{names:?}");

    let (names, _) = create_many(&[src.path()], &CreationConfig::default());
    assert!(names.contains(&PathBuf::from("keys")), "{names:?}");
    assert!(!names.iter().any(|n| n.ends_with("id_rsa")), "{names:?}");
}

#[test]
fn every_source_root_is_walked_even_when_one_is_hidden() {
    let src = TempDir::new().unwrap();
    write(src.path(), "plain/a.txt");
    write(src.path(), ".named/b.txt");
    write(src.path(), ".named/.inner/c.txt");
    let plain = src.path().join("plain");
    let dot_root = src.path().join(".named");

    let (names, report) = create_many(
        &[plain.as_path(), dot_root.as_path()],
        &CreationConfig::default(),
    );

    assert!(names.contains(&PathBuf::from("a.txt")), "{names:?}");
    assert!(names.contains(&PathBuf::from("b.txt")), "{names:?}");
    assert!(!names.iter().any(|n| n.ends_with("c.txt")), "{names:?}");
    assert_eq!(report.skipped.count(SkipKind::Hidden), 1);
}

#[test]
fn a_dotted_source_path_and_a_hidden_subdirectory_source() {
    let src = TempDir::new().unwrap();
    write(src.path(), "a.txt");
    write(src.path(), ".cache/x.txt");

    let dotted = src.path().join(".");
    let (names, report) = create_many(&[dotted.as_path()], &CreationConfig::default());
    assert!(names.contains(&PathBuf::from("a.txt")), "{names:?}");
    assert!(!names.iter().any(|n| n.ends_with("x.txt")), "{names:?}");
    assert_eq!(report.skipped.count(SkipKind::Hidden), 1);

    let hidden = src.path().join(".").join(".cache");
    let (names, _) = create_many(&[hidden.as_path()], &CreationConfig::default());
    assert!(names.contains(&PathBuf::from("x.txt")), "{names:?}");
}

/// Hidden directories are judged by their name on disk, before `strip_prefix`
/// is applied, so stripping a hidden directory's name does not reveal it.
#[test]
fn strip_prefix_naming_a_hidden_directory_does_not_reveal_it() {
    let src = TempDir::new().unwrap();
    write(src.path(), "visible.txt");
    write(src.path(), ".cfg/secret.txt");

    let config = CreationConfig::default().with_strip_prefix(Some(PathBuf::from(".cfg")));
    let (names, report) = create_many(&[src.path()], &config);

    assert!(names.contains(&PathBuf::from("visible.txt")), "{names:?}");
    assert!(
        !names.iter().any(|n| n.ends_with("secret.txt")),
        "{names:?}"
    );
    assert_eq!(report.skipped.count(SkipKind::Hidden), 1);
}

#[cfg(unix)]
#[test]
fn a_non_utf8_hidden_directory_name_is_skipped() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let src = TempDir::new().unwrap();
    write(src.path(), "visible.txt");
    let hidden = src.path().join(OsStr::from_bytes(b".caf\xe9"));
    if std::fs::create_dir(&hidden).is_err() {
        return;
    }
    std::fs::write(hidden.join("secret.txt"), b"payload").unwrap();

    let (names, report) = create_many(&[src.path()], &CreationConfig::default());

    assert!(names.contains(&PathBuf::from("visible.txt")), "{names:?}");
    assert!(
        !names.iter().any(|n| n.ends_with("secret.txt")),
        "{names:?}"
    );
    assert_eq!(report.skipped.count(SkipKind::Hidden), 1);
}
