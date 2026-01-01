//! Archive creation module.
//!
//! This module provides functionality for creating archives from filesystem
//! sources with security and configuration options.

pub mod filters;
pub mod walker;

pub mod compression;
pub mod config;
pub mod creator;
pub mod progress;
pub mod report;
pub mod tar;
pub mod zip;

// Re-exports for public API
pub use compression::CompressionLevel;
pub use compression::compression_level_to_bzip2;
pub use compression::compression_level_to_flate2;
pub use compression::compression_level_to_xz;
pub use compression::compression_level_to_zstd;
pub use compression::convert_compression_level;
pub use config::CreationConfig;
pub use creator::ArchiveCreator;
pub use progress::ProgressReader;
pub use progress::ProgressTracker;
pub use report::CreationReport;
pub use walker::EntryType;
pub use walker::FilteredEntry;
pub use walker::FilteredWalker;
