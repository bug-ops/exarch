//! Builders for the report values the formatter tests feed in.
//!
//! The core reports are `#[non_exhaustive]`, so a test cannot write a struct
//! literal; these keep the call sites short.

use exarch_core::CreationWarning;
use exarch_core::ExtractionWarning;
use exarch_core::Skip;
use exarch_core::SkipKind;
use exarch_core::Skips;
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
