#![no_main]

use std::io::Cursor;

use exarch_core::formats::ArchiveFormat as _;
use exarch_core::formats::ZipArchive;
use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    let config = common::validated();

    if let Ok(mut archive) = ZipArchive::new(Cursor::new(data)) {
        let _ = archive.list(config);
    }
    if let Ok(mut archive) = ZipArchive::new(Cursor::new(data)) {
        let _ = archive.verify(config);
    }
});
