//! Security validation modules.

pub mod hardlink;
pub mod path;
pub mod permissions;
pub mod quota;
pub mod symlink;
pub mod validator;
pub mod zipbomb;

// Re-export public types and functions
pub use hardlink::HardlinkTracker;
pub use path::validate_path;
pub use permissions::sanitize_permissions;
pub use quota::QuotaTracker;
pub use symlink::validate_symlink;
pub use validator::EntryValidator;
pub use validator::ValidatedEntry;
pub use validator::ValidatedEntryType;
pub use validator::ValidationReport;
pub use zipbomb::validate_compression_ratio;
