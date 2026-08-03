//! A `ValidatedEntry` must not be assemblable from outside the crate via
//! struct-literal syntax. Its fields are private and its only constructor,
//! `ValidatedEntry::new`, is `pub(crate)` — so external code has no path to
//! a `ValidatedEntry` other than observing one already produced by
//! `EntryValidator::validate_entry`.

use exarch_core::security::ValidatedEntry;

#[allow(unreachable_code)]
fn main() {
    let _entry = ValidatedEntry {
        safe_path: todo!(),
        entry_type: todo!(),
        mode: None,
    };
}
