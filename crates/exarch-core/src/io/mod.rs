//! I/O utilities for archive operations.
//!
//! This module provides reusable I/O wrappers and utilities used across
//! different archive formats.

pub mod counting;

// Re-export main types for convenience
pub use counting::CountingWriter;
