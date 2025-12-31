//! Archive format implementations.

pub mod detect;
pub mod tar;
pub mod traits;
pub mod zip;

// Re-export main types for convenience
pub use tar::TarArchive;
pub use traits::ArchiveFormat;
