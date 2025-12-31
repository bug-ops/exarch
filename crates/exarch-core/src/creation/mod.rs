//! Archive creation module.
//!
//! This module provides functionality for creating archives from filesystem
//! sources with security and configuration options.

pub mod filters;
pub mod walker;

pub mod config;
pub mod creator;
pub mod report;
pub mod tar;
pub mod zip;

// Re-exports for public API
pub use config::CreationConfig;
pub use creator::ArchiveCreator;
pub use report::CreationReport;
pub use walker::EntryType;
pub use walker::FilteredEntry;
pub use walker::FilteredWalker;
