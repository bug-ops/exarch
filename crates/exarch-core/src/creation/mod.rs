//! Archive creation module.
//!
//! This module provides functionality for creating archives from filesystem
//! sources with security and configuration options.

pub(crate) mod filters;
pub(crate) mod walker;

pub(crate) mod compression;
pub(crate) mod config;
pub(crate) mod progress;
pub(crate) mod report;
pub(crate) mod source;
pub(crate) mod staged;
pub(crate) mod tar;
pub(crate) mod zip;

// Re-exports for public API
pub use config::CompressionLevel;
pub use config::CreationConfig;
pub use filters::ExcludePattern;
pub use report::CreationReport;
pub use report::CreationWarning;
pub use report::CreationWarningKind;
