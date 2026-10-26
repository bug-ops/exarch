//! Fixtures shared by the `exarch-core` and `exarch-cli` test suites.
//!
//! Not published: it is a dev-dependency of the crates under test and exists so
//! that archives with deliberately inconsistent bytes are written by one
//! builder instead of by hand in every test.

pub mod raw_zip;
