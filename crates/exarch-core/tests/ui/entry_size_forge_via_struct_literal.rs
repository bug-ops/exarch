//! An `EntrySize` must not be assemblable from outside the crate with a struct
//! literal: its fields are private, so the only constructor is
//! `EntrySize::new`.

use exarch_core::EntrySize;

#[allow(unreachable_code)]
fn main() {
    let _size = EntrySize {
        uncompressed: todo!(),
        compressed: todo!(),
    };
}
