//! Fixtures shared by the `exarch-core` and `exarch-cli` test suites.
//!
//! Not published. The sources live in `exarch-core/src/testkit/` so that the
//! core package ships and tests itself without this crate; this facade
//! re-exports the same files for the CLI tests.

#[path = "../../exarch-core/src/testkit/pax.rs"]
pub mod pax;
#[path = "../../exarch-core/src/testkit/raw_zip.rs"]
pub mod raw_zip;
