//! Type-safe wrappers for archive extraction operations.
//!
//! This module provides newtypes that enforce security validation at the type
//! level. All types are validated upon construction and cannot be created from
//! raw types without going through validation.
//!
//! # Design Principles
//!
//! - Type-driven security: Invalid states cannot be represented
//! - Zero-cost abstractions: Newtypes compile to underlying types
//! - No `From<RawType>` implementations for security types
//! - All constructors perform validation

pub(crate) mod config_entry;
pub(crate) mod dest_dir;
mod entry_type;
mod parent_check;
pub(crate) mod safe_path;
pub(crate) mod safe_symlink;

pub use config_entry::Extension;
pub use config_entry::ExtensionFilter;
pub use config_entry::Extensions;
pub use config_entry::PathComponentName;
pub use dest_dir::DestDir;
pub(crate) use entry_type::EntryType;
#[cfg(all(feature = "testing", any(unix, target_os = "wasi")))]
pub use parent_check::Walked;
pub use safe_path::SafePath;
pub use safe_symlink::CheckedLinkTarget;
pub use safe_symlink::SafeSymlink;
