//! Archive format implementations.

pub(crate) mod chunk_search;
pub(crate) mod common;
pub mod compression;
pub mod detect;
pub(crate) mod dir_walker;
#[cfg(any(unix, target_os = "wasi"))]
pub(crate) mod handle_resolution;
pub(crate) mod pinned_dir;
pub(crate) mod run_record;
pub mod sevenz;
pub(crate) mod source_fault;
pub mod tar;
pub(crate) mod tar_extension_headers;
pub(crate) mod tar_metadata_limit;
pub(crate) mod target;
pub mod traits;
pub mod zip;
pub(crate) mod zip_reuse;
pub(crate) mod zip_structure;
pub(crate) mod zip_tail;
pub(crate) mod zstd_window;

// Re-export main types for convenience
pub use compression::CompressionCodec;
pub use sevenz::SevenZArchive;
pub use tar::TarArchive;
pub use zip::ZipArchive;
