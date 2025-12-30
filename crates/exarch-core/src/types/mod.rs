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

pub mod dest_dir;
pub mod entry_type;
pub mod safe_path;
pub mod safe_symlink;

pub use dest_dir::DestDir;
pub use entry_type::EntryType;
pub use safe_path::SafePath;
pub use safe_symlink::SafeSymlink;
