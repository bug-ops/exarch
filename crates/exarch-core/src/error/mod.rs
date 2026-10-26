//! Error types for archive operations.

pub mod io_context;
pub mod messages;
pub mod redaction;
pub mod types;
pub mod zip_inconsistency;

pub use io_context::IoContext;
pub use messages::FfiErrorMessage;
pub use types::ArchiveError;
pub use types::CompressionRatio;
pub use types::QuotaResource;
pub use types::Result;
pub use types::ZipBombDetails;
pub use types::ZipBombScope;
pub use zip_inconsistency::CentralRecordOrdinal;
pub use zip_inconsistency::EndRecordKind;
pub use zip_inconsistency::HiddenRegion;
pub use zip_inconsistency::ZipEntryIndex;
pub use zip_inconsistency::ZipHeaderField;
pub use zip_inconsistency::ZipInconsistency;
pub use zip_inconsistency::ZipUncomparable;
