//! Memory-safe archive extraction library with security validation.
//!
//! `exarch-core` provides a safe API for extracting archive files (tar, zip)
//! with built-in protection against common security vulnerabilities like
//! path traversal, zip bombs, symlink attacks, and hardlink attacks.
//!
//! # Examples
//!
//! ```no_run
//! use exarch_core::SecurityConfig;
//! use exarch_core::extract_archive;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = SecurityConfig::default();
//! let report = extract_archive("archive.tar.gz", "/output/dir", &config)?;
//! println!("Extracted {} files", report.files_extracted);
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod api;
pub mod archive;
pub mod config;
pub mod copy;
pub mod creation;
pub mod error;
pub mod extraction;
pub mod formats;
pub mod inspection;
pub mod io;
pub mod report;
pub mod security;
pub mod types;

// Re-export main API types
pub use api::create_archive;
pub use api::create_archive_with_progress;
pub use api::extract_archive;
pub use api::extract_archive_with_progress;
pub use api::list_archive;
pub use api::verify_archive;
pub use archive::Archive;
pub use archive::ArchiveBuilder;
pub use config::SecurityConfig;
pub use error::ExtractionError;
pub use error::FfiErrorMessage;
pub use error::QuotaResource;
pub use error::Result;
pub use report::ExtractionReport;
pub use report::NoopProgress;
pub use report::ProgressCallback;

// Re-export creation types
pub use creation::ArchiveCreator;
pub use creation::CreationConfig;
pub use creation::CreationReport;

// Re-export inspection types
pub use inspection::ArchiveEntry;
pub use inspection::ArchiveManifest;
pub use inspection::CheckStatus;
pub use inspection::IssueCategory;
pub use inspection::IssueSeverity;
pub use inspection::ManifestEntryType;
pub use inspection::VerificationIssue;
pub use inspection::VerificationReport;
pub use inspection::VerificationStatus;

// Re-export types module for easier access
pub use types::DestDir;
pub use types::EntryType;
pub use types::SafePath;
pub use types::SafeSymlink;
