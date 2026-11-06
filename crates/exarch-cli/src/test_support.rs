//! Builders for the report values the formatter tests feed in.
//!
//! The core reports are `#[non_exhaustive]`, so a test cannot write a struct
//! literal; these keep the call sites short.

#![allow(clippy::expect_used)]

use exarch_core::ArchiveEntry;
use exarch_core::ArchiveManifest;
use exarch_core::ArchiveType;
use exarch_core::CreationWarning;
use exarch_core::ExtractionWarning;
use exarch_core::ManifestEntryKind;
use exarch_core::SecurityConfig;
use exarch_core::Skip;
use exarch_core::SkipKind;
use exarch_core::Skips;
use std::io;
use std::io::Write;
use std::path::PathBuf;

/// `count` skipped duplicates.
pub fn skips(count: usize) -> Skips {
    let mut skips = Skips::default();
    for i in 0..count {
        let skip = Skip::new(SkipKind::Duplicate, format!("f{i}"));
        assert!(skips.record(skip).is_ok());
    }
    skips
}

/// An extraction warning whose text contains `text`.
pub fn extraction_warning(text: &str) -> ExtractionWarning {
    ExtractionWarning::BackupCleanupFailed {
        path: PathBuf::from("backup"),
        identity: exarch_core::BackupIdentity::Verified,
        io_kind: exarch_core::IoKind::Other,
        message: text.into(),
    }
}

/// A creation warning whose text contains `text`.
pub fn creation_warning(text: &str) -> CreationWarning {
    CreationWarning::ZipRatioCheckFailed {
        reason: text.to_string(),
    }
}

/// A writer whose every write and flush fails with `kind`.
pub struct FailingWriter(pub io::ErrorKind);

impl Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(self.0.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(self.0.into())
    }
}

/// A manifest of `keep.txt` and `drop.txt` listed under a selection that
/// excludes `drop.txt`, with the config that judges it: one entry of each
/// core disposition.
pub fn selected_manifest() -> (ArchiveManifest, SecurityConfig) {
    let config = SecurityConfig::default()
        .try_add_exclude("drop.txt")
        .expect("literal pattern is valid");
    let mut manifest = ArchiveManifest::with_selection(ArchiveType::Tar, config.selection.clone());
    for name in ["keep.txt", "drop.txt"] {
        let entry = ArchiveEntry::new(
            PathBuf::from(name),
            ManifestEntryKind::File {
                size: exarch_core::Uncompressed(1),
            },
        );
        manifest.add_entry(entry).expect("entry fits the manifest");
    }
    (manifest, config)
}
