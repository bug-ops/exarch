//! Error types for archive operations.

pub mod messages;
pub mod types;

pub use messages::FfiErrorMessage;
pub use types::ArchiveError;
pub use types::QuotaResource;
pub use types::Result;
