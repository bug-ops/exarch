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
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod api;
pub(crate) mod closed_enum;
pub mod config;
pub(crate) mod copy;
pub mod creation;
pub mod error;
pub mod formats;
pub mod inspection;
mod limit;
mod listed;
mod path_text;
#[cfg(test)]
use exarch_testkit::raw_zip;
pub mod reader;
pub mod report;
mod request;
pub mod security;
pub mod sink;
#[cfg(test)]
pub(crate) mod test_utils;
pub mod types;
pub mod writer;

// Re-export main API types
pub use api::create_archive;
pub use api::extract_archive;
pub use api::list_archive;
pub use api::verify_archive;
pub use config::Admit;
pub use config::DecodeReuse;
pub use config::DecompressionBudget;
pub use config::ExtractionOptions;
pub use config::IntegrityCheck;
pub use config::ListOptions;
pub use config::ParallelDecode;
pub use config::ReuseLimit;
pub use config::SecurityConfig;
pub use config::SolidArchives;
pub use config::SolidLimits;
pub use config::StoredTargets;
pub use config::VerificationOptions;
pub use config::ZipConsistencyPolicy;
pub use error::ArchiveError;
pub use error::CentralRecordOrdinal;
pub use error::CompressionRatio;
pub use error::ConfigProblem;
pub use error::ConfigSetting;
pub use error::EndRecordKind;
pub use error::ErrorCode;
pub use error::ExcludeRefusal;
pub use error::FfiErrorMessage;
pub use error::FfiKind;
pub use error::HiddenRegion;
pub use error::InvalidArchiveSubCode;
pub use error::IoContext;
pub use error::KindSource;
pub use error::Malformation;
pub use error::NativeKind;
pub use error::Partial;
pub use error::PartialOutcome;
pub use error::PartialWrites;
pub use error::PolicySetting;
pub use error::PortableHazard;
pub use error::QuotaKind;
pub use error::QuotaResource;
pub use error::ReaderFormatError;
pub use error::Result;
pub use error::SecurityViolationSubCode;
pub use error::SolidMemoryScope;
pub use error::SpecialFile;
pub use error::SubCode;
pub use error::TarAmbiguity;
pub use error::TarExtensionKind;
pub use error::TarHeaderField;
pub use error::TarNonRegularKind;
pub use error::TarPathKey;
pub use error::TarTrailerRefusal;
pub use error::TrailerCorruption;
pub use error::Unclassified;
pub use error::Violation;
pub use error::ZipBombDetails;
pub use error::ZipBombScope;
pub use error::ZipEntryIndex;
pub use error::ZipHeaderField;
pub use error::ZipInconsistency;
pub use error::ZipNonRegularKind;
pub use error::ZipStreamUndecided;
pub use error::ZipUncomparable;
/// Formats an archive-relative, attacker-authored path for an FFI error
/// message without redaction. Shared by `exarch-python` and `exarch-node`.
pub use error::redaction::format_entry_path_for_error;
/// Sanitizes a `std::io::Error` message for an FFI error message. Shared by
/// `exarch-python` and `exarch-node`.
pub use error::redaction::sanitize_io_error_for_error;
/// Redacts a host-derived filesystem path for an FFI error message in
/// release builds. Shared by `exarch-python` and `exarch-node`.
pub use error::redaction::sanitize_path_for_error;
pub use limit::Limit;
pub use limit::RatioLimit;
pub use limit::non_zero_u64;
pub use limit::non_zero_usize;
pub use limit::positive_from_f64;
pub use limit::positive_from_i128;
pub use reader::ArchiveReader;
pub use reader::SeekableFormat;
pub use report::EntryPosition;
pub use report::EntryTotal;
pub use report::ExtractionReport;
pub use report::ExtractionWarning;
pub use report::NoopProgress;
pub use report::ProgressCallback;
pub use report::Skip;
pub use report::SkipKind;
pub use report::Skips;
pub use request::CreateRequest;
pub use request::ExtractRequest;
pub use request::ListRequest;
pub use request::OutputFile;
pub use request::OutputFormat;
pub use request::OutputPolicy;
pub use request::SinkExtractRequest;
pub use request::VerifyRequest;

// Re-export creation types
pub use creation::CreationConfig;
pub use creation::CreationReport;
pub use creation::CreationWarning;
pub use creation::ExcludePattern;
pub use writer::ArchiveWriter;

// Re-export inspection types
pub use inspection::ArchiveEntry;
pub use inspection::ArchiveManifest;
pub use inspection::CheckStatus;
pub use inspection::EntryCompression;
pub use inspection::Finding;
pub use inspection::Heuristic;
pub use inspection::IntegrityGaps;
pub use inspection::IntegrityStatus;
pub use inspection::IssueCategory;
pub use inspection::IssueSeverity;
pub use inspection::Landing;
pub use inspection::LandingKind;
pub use inspection::LandingPath;
pub use inspection::LinkTarget;
pub use inspection::ManifestEntryKind;
pub use inspection::ManifestEntryType;
pub use inspection::NameCollisionKind;
pub use inspection::OversizedEntry;
pub use inspection::PathOccupant;
pub use inspection::SolidBlock;
pub use inspection::UnverifiedEntry;
pub use inspection::UnverifiedReason;
pub use inspection::VerificationIssue;
pub use inspection::VerificationReport;
pub use inspection::VerificationStatus;
pub use path_text::bytes_text;
pub use path_text::path_text;
pub use security::fs_view::LinkKind;

// Re-export security types
pub use listed::ListedArchive;
pub use listed::ListedExtractOptions;
pub use security::AdmittedSize;
pub use security::Compressed;
pub use security::EntrySize;
pub use security::HardlinkTarget;
pub use security::RawMode;
pub use security::SanitizedMode;
pub use security::Uncompressed;
/// Validates a raw, caller-supplied path string before it enters the
/// archive pipeline. Shared by `exarch-python` and `exarch-node`.
pub use security::boundary::BoundaryPath;
/// Maximum length, in bytes, of a single `SecurityConfig` entry — an
/// allowed extension or a banned path component. Shared by `exarch-python`
/// and `exarch-node`.
pub use security::boundary::MAX_CONFIG_ENTRY_LENGTH;
/// Maximum length, in bytes, of a raw path string accepted at the FFI
/// boundary. Shared by `exarch-python` and `exarch-node`.
pub use security::boundary::MAX_PATH_LENGTH;
pub use security::fs_view::PathModel;
pub use sink::CallbackEntry;
pub use sink::CallbackError;
pub use sink::CallbackSink;
pub use sink::EntrySink;
pub use sink::MemoryEntry;
pub use sink::MemoryEntryKind;
pub use sink::MemoryExtractRequest;
pub use sink::MemoryFile;
pub use sink::MemoryLimit;
pub use sink::MemorySink;
pub use sink::SinkFull;
pub use sink::SinkOptions;
pub use sink::extract_reader_to_callback;
pub use sink::extract_reader_to_memory;
pub use types::Extension;
pub use types::PathComponentName;

// Re-export types module for easier access
pub use types::CheckedLinkTarget;
pub use types::DestDir;
pub use types::SafePath;
pub use types::SafeSymlink;
