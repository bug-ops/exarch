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
pub mod tar;
pub mod zip;

// Re-exports for public API
pub use compression::CompressionLevel;
pub use config::CreationConfig;
pub use creator::ArchiveCreator;
pub use report::CreationReport;
pub(crate) use tar::TarBz2Creator;
pub(crate) use tar::TarCreator;
pub(crate) use tar::TarGzCreator;
pub(crate) use tar::TarXzCreator;
pub(crate) use tar::TarZstCreator;
pub(crate) use zip::ZipCreator;
