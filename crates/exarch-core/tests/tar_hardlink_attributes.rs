//! A hardlink member's own attributes never reach a symlink target.
//!
//! Regression guard for the class fixed in `python/cpython` gh-160297: a hard
//! link member whose target is a symlink member was extracted as a copy of that
//! symlink, and the hard link's owner, mode and mtime were then applied through
//! the symlink to its target, possibly a file outside the destination. exarch
//! copies the resolved target's bytes into an independent file and sets no
//! attribute on the link path afterwards; these tests pin that.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

mod sink_support;

use std::io::Cursor;
use std::path::Path;

use exarch_core::ArchiveReader;
use exarch_core::SecurityConfig;
use exarch_core::SinkOptions;
use exarch_core::extract_to_sink;
use sink_support::RecordingSink;

const TARGET_MODE: u32 = 0o644;
const LINK_MODE: u32 = 0o600;
const TARGET_MTIME: u64 = 1_700_000_000;
const LINK_MTIME: u64 = 1;

fn links_config() -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true)
}

fn append(
    builder: &mut tar::Builder<Vec<u8>>,
    name: &str,
    kind: tar::EntryType,
    data: &[u8],
    link: Option<&str>,
    (mode, mtime): (u32, u64),
) {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_mode(mode);
    header.set_mtime(mtime);
    header.set_size(data.len() as u64);
    match link {
        Some(link) => builder.append_link(&mut header, name, link).unwrap(),
        None => builder.append_data(&mut header, name, data).unwrap(),
    }
}

/// `real.txt`, the symlink `s -> real.txt` and the hardlink `h -> s`, whose
/// own mode and mtime differ from the target's.
fn hardlink_through_symlink_tar() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let target = (TARGET_MODE, TARGET_MTIME);
    let link = (LINK_MODE, LINK_MTIME);
    append(
        &mut builder,
        "real.txt",
        tar::EntryType::Regular,
        b"data",
        None,
        target,
    );
    append(
        &mut builder,
        "s",
        tar::EntryType::Symlink,
        b"",
        Some("real.txt"),
        link,
    );
    append(
        &mut builder,
        "h",
        tar::EntryType::Link,
        b"",
        Some("s"),
        link,
    );
    builder.into_inner().unwrap()
}

#[cfg(unix)]
#[test]
fn host_hardlink_attributes_do_not_reach_the_symlink_target() {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::TempDir::new().unwrap();
    let archive = temp.path().join("links.tar");
    std::fs::write(&archive, hardlink_through_symlink_tar()).unwrap();
    let dest = temp.path().join("dest");

    exarch_core::extract_archive(&archive, &dest, &links_config()).unwrap();

    let real = std::fs::symlink_metadata(dest.join("real.txt")).unwrap();
    assert_eq!(real.permissions().mode() & 0o7777, TARGET_MODE);
    assert_ne!(
        u64::try_from(real.mtime()).unwrap(),
        LINK_MTIME,
        "the hardlink member's mtime must not be applied to the symlink target"
    );

    let link = std::fs::symlink_metadata(dest.join("h")).unwrap();
    assert!(link.file_type().is_file(), "the hardlink is a regular file");
    assert_eq!(
        link.nlink(),
        1,
        "the hardlink member is an independent copy"
    );
    assert_eq!(std::fs::read(dest.join("h")).unwrap(), b"data");
    assert_eq!(
        std::fs::read_link(dest.join("s")).unwrap(),
        Path::new("real.txt")
    );
    assert_eq!(
        std::fs::read_dir(temp.path()).unwrap().count(),
        2,
        "nothing but the archive and the destination exists"
    );
}

#[test]
fn sink_hardlink_attributes_do_not_reach_the_symlink_target() {
    let reader = ArchiveReader::tar(Cursor::new(hardlink_through_symlink_tar()), None);
    let mut sink = RecordingSink::default();

    extract_to_sink(reader, &mut sink, &links_config(), &SinkOptions::default()).unwrap();

    assert_eq!(sink.tree.files[Path::new("h")], b"data");
    assert_eq!(
        sink.modes[Path::new("real.txt")],
        Some(TARGET_MODE),
        "the target keeps its own mode"
    );
    assert!(
        !sink.modes.contains_key(Path::new("h")),
        "a hardlink is delivered as a link, not as a file with its own attributes"
    );
    assert_eq!(
        sink.finished
            .iter()
            .filter(|path| path.as_path() == Path::new("real.txt"))
            .count(),
        1,
        "the target is written once"
    );
}
