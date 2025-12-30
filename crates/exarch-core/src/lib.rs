//! Memory-safe archive extraction library with security validation.
//!
//! `exarch-core` provides a safe API for extracting archive files (tar, zip)
//! with built-in protection against common security vulnerabilities like
//! path traversal, zip bombs, symlink attacks, and hardlink attacks.
//!
//! # Examples
//!
//! ```no_run
//! use exarch_core::{extract_archive, SecurityConfig};
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
pub mod error;
pub mod extraction;
pub mod formats;
pub mod report;
pub mod security;

// Re-export main API types
pub use api::extract_archive;
pub use archive::{Archive, ArchiveBuilder};
pub use config::SecurityConfig;
pub use error::{ExtractionError, Result};
pub use report::ExtractionReport;
