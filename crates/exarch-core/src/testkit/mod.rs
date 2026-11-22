//! Fixture builders for tests: hand-built ZIP archives and PAX records.
//!
//! The lib compiles this module for its own tests; integration tests include it
//! with `#[path = "../src/testkit/mod.rs"]`, and the unpublished
//! `exarch-testkit` crate re-exports the same files for the CLI tests.

#![allow(
    dead_code,
    unreachable_pub,
    reason = "files shared with test binaries that use only part of them"
)]

pub mod pax;
pub mod raw_zip;
