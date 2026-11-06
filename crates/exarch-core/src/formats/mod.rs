//! Archive format implementations.

pub(crate) mod chunk_search;
pub(crate) mod common;
pub(crate) mod compression;
pub(crate) mod detect;
pub(crate) mod dir_walker;
pub(crate) mod file_identity;
#[cfg(any(unix, target_os = "wasi"))]
pub(crate) mod handle_resolution;
pub(crate) mod occupant;
pub(crate) mod pinned_dir;
pub(crate) mod run_record;
pub(crate) mod sevenz;
pub(crate) mod source_fault;
pub(crate) mod tar;
pub(crate) mod tar_extension_headers;
pub(crate) mod tar_metadata_limit;
pub(crate) mod target;
pub(crate) mod traits;
pub(crate) mod zip;
pub(crate) mod zip_reuse;
pub(crate) mod zip_structure;
pub(crate) mod zip_tail;
pub(crate) mod zstd_window;

// Re-export main types for convenience
pub use compression::CompressionCodec;
pub(crate) use sevenz::SevenZArchive;
pub(crate) use tar::TarArchive;
pub(crate) use zip::ZipArchive;
