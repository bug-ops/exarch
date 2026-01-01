//! Archive format implementations.

mod common;
pub mod compression;
pub mod detect;
pub mod tar;
pub mod traits;
pub mod zip;

// Re-export main types for convenience
pub use compression::CompressionCodec;
pub use tar::TarArchive;
pub use tar::open_tar_bz2;
pub use tar::open_tar_gz;
pub use tar::open_tar_xz;
pub use tar::open_tar_zst;
pub use traits::ArchiveFormat;
pub use zip::ZipArchive;
