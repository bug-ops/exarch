//! Archive creation module.
//!
//! This module provides functionality for creating archives from filesystem
//! sources with security and configuration options.

pub mod filters;
pub(crate) mod walker;

pub(crate) mod compression;
pub mod config;
pub mod creator;
pub(crate) mod progress;
pub mod report;
pub(crate) mod staged;
pub mod tar;
pub mod zip;

// Re-exports for public API
pub use config::CompressionLevel;
pub use config::CreationConfig;
pub use creator::ArchiveCreator;
pub use filters::ExcludePattern;
pub use report::CreationReport;
pub use report::CreationWarning;
