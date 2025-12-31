//! Archive inspection without extraction.
//!
//! This module provides functions to inspect archive contents and verify
//! their security without writing files to disk.
//!
//! # Examples
//!
//! ```no_run
//! use exarch_core::SecurityConfig;
//! use exarch_core::list_archive;
//! use exarch_core::verify_archive;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = SecurityConfig::default();
//!
//! // List archive contents
//! let manifest = list_archive("archive.tar.gz", &config)?;
//! println!("Archive contains {} files", manifest.total_entries);
//!
//! // Verify archive security
//! let report = verify_archive("archive.tar.gz", &config)?;
//! if report.is_safe() {
//!     println!("Archive is safe to extract");
//! }
//! # Ok(())
//! # }
//! ```

pub mod list;
pub mod manifest;
pub mod report;
pub mod verify;

pub use list::list_archive;
pub use manifest::ArchiveEntry;
pub use manifest::ArchiveManifest;
pub use manifest::ManifestEntryType;
pub use report::CheckStatus;
pub use report::IssueCategory;
pub use report::IssueSeverity;
pub use report::VerificationIssue;
pub use report::VerificationReport;
pub use report::VerificationStatus;
pub use verify::verify_archive;
