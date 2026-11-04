//! `list`, `verify` and `extract` give one verdict on an entry path that is
//! longer than the host path limit, whatever its component count.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

#[cfg(unix)]
use std::num::NonZeroUsize;
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

fn write_archive_of(dir: &TempDir, entries: &[(&str, &[u8])]) -> PathBuf {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, data) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        builder.append_data(&mut header, name, *data).unwrap();
    }
    let path = dir.path().join("mixed.tar");
    std::fs::write(&path, builder.into_inner().unwrap()).unwrap();
    path
}

#[test]
fn an_overlong_name_of_a_skipped_extension_is_not_refused_in_any_destination_state() {
    let long = format!("{}.bin", entry_name(25));
    let dir = TempDir::new().unwrap();
    let archive = write_archive_of(&dir, &[("ok.txt", b"hi"), (&long, b"x")]);
    let config = SecurityConfig::default()
        .try_add_allowed_extension("txt")
        .unwrap();

    assert!(list_archive(&archive, &config).is_ok());
    assert!(
        verify_archive(&archive, &config).is_ok_and(|r| r.status() == VerificationStatus::Pass)
    );

    let fresh = TempDir::new().unwrap();
    let report = extract_archive(&archive, fresh.path().join("new"), &config).unwrap();
    assert_eq!(report.files_skipped, 1);

    let existing = TempDir::new().unwrap();
    let report = extract_archive(&archive, existing.path(), &config).unwrap();
    assert_eq!(report.files_skipped, 1);
    assert!(existing.path().join("ok.txt").is_file());
}

#[cfg(target_os = "macos")]
const HOST_PATH_LIMIT: usize = 1023;
#[cfg(all(unix, not(target_os = "macos")))]
const HOST_PATH_LIMIT: usize = 4095;
#[cfg(windows)]
const HOST_PATH_LIMIT: usize = 32767;

/// A name of exactly `len` bytes made of components of at most `component_max`.
fn name_of_len_in(len: usize, component_max: usize) -> String {
    let mut name = String::new();
    while name.len() < len {
        if !name.is_empty() {
            name.push('/');
        }
        let room = len - name.len();
        name.push_str(&"n".repeat(room.min(component_max)));
    }
    assert_eq!(name.len(), len);
    name
}

fn name_of_len(len: usize) -> String {
    name_of_len_in(len, COMPONENT)
}

#[cfg(unix)]
#[test]
fn the_host_path_limit_is_the_exact_boundary_in_every_command() {
    let config = SecurityConfig::default();
    for (len, accepted) in [
        (HOST_PATH_LIMIT - 1, true),
        (HOST_PATH_LIMIT, true),
        (HOST_PATH_LIMIT + 1, false),
    ] {
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, &name_of_len(len));
        let v = verdicts(&archive, &config);
        assert_eq!(
            (v.list, v.verify, v.extract),
            (accepted, accepted, accepted),
            "{len} bytes"
        );
    }
}

#[cfg(not(windows))]
#[test]
fn a_path_above_every_unix_limit_is_refused_everywhere() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &entry_name(25));
    let config = SecurityConfig::default();
    let out = TempDir::new().unwrap();

    let err = extract_archive(&archive, out.path(), &config).unwrap_err();
    std::assert_matches!(err, exarch_core::ArchiveError::Io(_), "{err}");
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    assert!(list_archive(&archive, &config).is_err());
    assert!(
        verify_archive(&archive, &config).is_ok_and(|r| r.status() != VerificationStatus::Pass)
    );
}

// A short entry that lands above the host path limit through a symlink is
// refused on every platform (see #885).
mod landing {
    use super::*;

    const REST_BYTES: usize = 302;

    fn rest() -> String {
        vec!["r".repeat(100); 3].join("/")
    }

    fn archive_with_chain(chain_len: usize) -> (TempDir, PathBuf) {
        let chain = name_of_len(chain_len);
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
                format!("d/{}/f", rest()),
                &b"x"[..],
            )
            .unwrap();
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("landing.tar");
        std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
        (dir, archive)
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
        // Windows refuses the symlink itself, so a short chain suffices there.
        let chain_len = if cfg!(windows) {
            20
        } else {
            HOST_PATH_LIMIT - REST_BYTES + 1
        };
        let (_dir, archive) = archive_with_chain(chain_len);

        let config = SecurityConfig::default().with_allow_symlinks(true);
        let out = TempDir::new().unwrap();
        let err = extract_archive(&archive, out.path(), &config).unwrap_err();

        #[cfg(unix)]
        assert_eq!(
            err.ffi_kind(),
            exarch_core::FfiKind::Io(std::io::ErrorKind::InvalidFilename),
            "{err}"
        );
        #[cfg(windows)]
        let _ = err;
        assert!(!out.path().join("d").join(rest()).join("f").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_landing_inside_the_limit_through_a_symlink_is_extracted() {
        let out = TempDir::new().unwrap();
        let dest_len = out.path().canonicalize().unwrap().as_os_str().len();
        let reserved = 64 + dest_len + 1 + REST_BYTES + 1;
        assert!(
            HOST_PATH_LIMIT > reserved,
            "destination of {dest_len} bytes leaves no room under the host path limit"
        );
        let chain_len = HOST_PATH_LIMIT - reserved;
        let (_dir, archive) = archive_with_chain(chain_len);

        let config = SecurityConfig::default().with_allow_symlinks(true);
        extract_archive(&archive, out.path(), &config).unwrap();

        assert!(out.path().join("d").join(rest()).join("f").is_file());
    }

    /// Linux-sized entries need ~34 components, above the default depth cap.
    #[cfg(unix)]
    fn deep_config() -> SecurityConfig {
        SecurityConfig::default()
            .with_allow_symlinks(true)
            .with_max_path_depth(NonZeroUsize::new(64).unwrap())
    }

    #[cfg(unix)]
    const TOO_LONG: &str = "file name too long";

    #[cfg(unix)]
    #[derive(Clone, Copy, Debug)]
    enum Shape {
        FileUnderShortDirs,
        FileWithMaxLeaf,
        DirectoryEntry,
    }

    #[cfg(unix)]
    impl Shape {
        const ALL: [Self; 3] = [
            Self::FileUnderShortDirs,
            Self::FileWithMaxLeaf,
            Self::DirectoryEntry,
        ];

        fn kind(self) -> tar::EntryType {
            match self {
                Self::DirectoryEntry => tar::EntryType::Directory,
                Self::FileUnderShortDirs | Self::FileWithMaxLeaf => tar::EntryType::Regular,
            }
        }

        /// An entry of exactly `len` bytes below the link `d`.
        fn entry(self, len: usize) -> String {
            match self {
                Self::FileUnderShortDirs => format!("d/{}/f", name_of_len_in(len - 4, 127)),
                Self::FileWithMaxLeaf => {
                    format!("d/{}/{}", name_of_len(len - 3 - 255), "l".repeat(255))
                }
                Self::DirectoryEntry => format!("d/{}", name_of_len_in(len - 2, 127)),
            }
        }
    }

    #[cfg(unix)]
    /// `d -> cc` with a short `cc`, so only the tail makes the landing long.
    fn archive_below_short_chain(shape: Shape, entry_len: usize) -> (TempDir, PathBuf) {
        let body: &[u8] = match shape {
            Shape::DirectoryEntry => b"",
            Shape::FileUnderShortDirs | Shape::FileWithMaxLeaf => b"x",
        };
        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_data(&mut header(tar::EntryType::Directory, 0), "cc", &b""[..])
            .unwrap();
        builder
            .append_link(&mut header(tar::EntryType::Symlink, 0), "d", "cc")
            .unwrap();
        builder
            .append_data(
                &mut header(shape.kind(), body.len() as u64),
                shape.entry(entry_len),
                body,
            )
            .unwrap();
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("short-chain.tar");
        std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
        (dir, archive)
    }

    #[cfg(unix)]
    #[test]
    fn the_landing_limit_is_exact_and_independent_of_the_destination_length() {
        let config = deep_config();
        for shape in Shape::ALL {
            // `cc` is one byte longer than `d`, so the landing is one byte
            // longer than the entry.
            for (entry_len, accepted) in [(HOST_PATH_LIMIT - 1, true), (HOST_PATH_LIMIT, false)] {
                let (_dir, archive) = archive_below_short_chain(shape, entry_len);
                let out = TempDir::new().unwrap();
                let result = extract_archive(&archive, out.path(), &config);
                let case = format!("{shape:?} entry of {entry_len} bytes");
                if accepted {
                    let report = result.unwrap_or_else(|e| panic!("{case}: {e:?}"));
                    let (files, dirs) = match shape {
                        Shape::DirectoryEntry => (0, 2),
                        Shape::FileUnderShortDirs | Shape::FileWithMaxLeaf => (1, 1),
                    };
                    assert_eq!(
                        (report.files_extracted, report.directories_created),
                        (files, dirs),
                        "{case}"
                    );
                } else {
                    let err = result
                        .err()
                        .unwrap_or_else(|| panic!("{case} was accepted"));
                    assert!(err.to_string().contains(TOO_LONG), "{case}: {err}");
                }
            }
        }
    }

    // #945: verify must judge the projected landing like extract does.
    #[cfg(unix)]
    #[test]
    fn verify_and_extract_agree_on_the_projected_landing_limit() {
        let config = deep_config();
        for shape in Shape::ALL {
            for (entry_len, accepted) in [(HOST_PATH_LIMIT - 1, true), (HOST_PATH_LIMIT, false)] {
                let (_dir, archive) = archive_below_short_chain(shape, entry_len);
                let out = TempDir::new().unwrap();
                let extracted = extract_archive(&archive, out.path(), &config).is_ok();
                let verified = verify_archive(&archive, &config)
                    .is_ok_and(|report| report.status() == VerificationStatus::Pass);
                let reader = exarch_core::ArchiveReader::tar(
                    std::io::Cursor::new(std::fs::read(&archive).unwrap()),
                    None,
                );
                let sunk = exarch_core::extract_to_sink(
                    reader,
                    &mut exarch_core::MemorySink::default(),
                    &config,
                    &exarch_core::SinkOptions::default(),
                )
                .is_ok();
                assert_eq!(
                    (extracted, verified, sunk),
                    (accepted, accepted, accepted),
                    "{shape:?} entry of {entry_len} bytes"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_preexisting_symlink_out_of_the_root_still_refuses_a_long_tail() {
        let base = TempDir::new().unwrap();
        let dest = base.path().join("dest");
        let outside = base.path().join("outside");
        std::fs::create_dir(&dest).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, dest.join("d")).unwrap();

        let entry = Shape::FileUnderShortDirs.entry(HOST_PATH_LIMIT - 1);
        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_data(&mut header(tar::EntryType::Regular, 1), &entry, &b"x"[..])
            .unwrap();
        let archive = base.path().join("escape.tar");
        std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();

        let config = deep_config();
        let err = extract_archive(&archive, &dest, &config).unwrap_err();

        assert!(!err.to_string().contains(TOO_LONG), "{err}");
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    }

    // Pins the refusal of #895: the link `d -> chain` resolves by absolute
    // path, so a chain within the relative limit but past the absolute one
    // is refused as a symlink parent. Flip this when #895 lands.
    #[cfg(unix)]
    #[test]
    fn a_link_to_a_chain_past_the_absolute_limit_is_refused_as_a_symlink_parent() {
        let chain = name_of_len(HOST_PATH_LIMIT - 8);
        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_data(
                &mut header(tar::EntryType::Regular, 1),
                format!("{chain}/x"),
                &b"x"[..],
            )
            .unwrap();
        builder
            .append_link(&mut header(tar::EntryType::Symlink, 0), "d", &chain)
            .unwrap();
        builder
            .append_data(&mut header(tar::EntryType::Regular, 1), "d/f", &b"x"[..])
            .unwrap();
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("chain.tar");
        std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();

        let config = SecurityConfig::default().with_allow_symlinks(true);
        let out = TempDir::new().unwrap();
        let err = extract_archive(&archive, out.path(), &config).unwrap_err();

        std::assert_matches!(
            err.ffi_kind(),
            exarch_core::FfiKind::SecurityViolation {
                sub_code: exarch_core::SecurityViolationSubCode::ExistingSymlink,
                ..
            },
            "{err}"
        );
    }
}
