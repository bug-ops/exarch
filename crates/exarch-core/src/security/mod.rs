//! Security validation modules.

pub(crate) mod context;
pub(crate) mod hardlink;
pub(crate) mod path;
pub(crate) mod permissions;
pub(crate) mod quota;
pub(crate) mod symlink;
pub mod validator;
pub(crate) mod zipbomb;

// Re-export public API types
pub use validator::EntryValidator;
pub use validator::ValidatedEntry;
pub use validator::ValidatedEntryType;
pub use validator::ValidationReport;

// Security primitives exposed under the `testing` feature for external
// benchmarks and integration tests that cannot access pub(crate) items.
#[cfg(feature = "testing")]
pub use hardlink::HardlinkTracker;
#[cfg(feature = "testing")]
pub use path::validate_path;
#[cfg(feature = "testing")]
pub use permissions::sanitize_permissions;
#[cfg(feature = "testing")]
pub use quota::QuotaTracker;
#[cfg(feature = "testing")]
pub use symlink::validate_symlink;
#[cfg(feature = "testing")]
pub use zipbomb::validate_compression_ratio;
