#![no_main]

use std::io::Cursor;

use exarch_core::formats::ArchiveFormat as _;
use exarch_core::formats::SevenZArchive;
use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    let config = common::config();

    if let Ok(archive) = SevenZArchive::new(Cursor::new(data), config) {
        let _ = archive.list();
    }
    if let Ok(archive) = SevenZArchive::new(Cursor::new(data), config) {
        let _ = archive.verify(&common::verification_options());
    }
});
