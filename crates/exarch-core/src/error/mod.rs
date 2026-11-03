//! Error types for archive operations.

pub mod io_context;
pub mod messages;
pub mod redaction;
pub mod tar_ambiguity;
pub mod tar_trailer;
pub mod types;
pub mod zip_inconsistency;

pub use io_context::IoContext;
pub use messages::ErrorCode;
pub use messages::FfiErrorMessage;
pub use messages::FfiKind;
pub use messages::InvalidArchiveSubCode;
pub use messages::PartialOutcome;
pub use messages::SecurityViolationSubCode;
pub use tar_ambiguity::TarAmbiguity;
pub use tar_ambiguity::TarExtensionKind;
pub use tar_ambiguity::TarHeaderField;
pub use tar_ambiguity::TarNonRegularKind;
pub use tar_ambiguity::TarPathKey;
pub use tar_trailer::TarTrailerRefusal;
pub use tar_trailer::TrailerCorruption;
pub use types::ArchiveError;
pub use types::CompressionRatio;
pub use types::PartialWrites;
pub use types::PolicySetting;
pub use types::QuotaResource;
pub use types::ReaderFormatError;
pub use types::Result;
pub use types::ZipBombDetails;
pub use types::ZipBombScope;
pub use zip_inconsistency::CentralRecordOrdinal;
pub use zip_inconsistency::EndRecordKind;
pub use zip_inconsistency::HiddenRegion;
pub use zip_inconsistency::ZipEntryIndex;
pub use zip_inconsistency::ZipHeaderField;
pub use zip_inconsistency::ZipInconsistency;
pub use zip_inconsistency::ZipNonRegularKind;
pub use zip_inconsistency::ZipStreamUndecided;
pub use zip_inconsistency::ZipUncomparable;

#[cfg(test)]
mod policy_setting_tests;
