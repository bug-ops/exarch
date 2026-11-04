#![no_main]

use std::io::Cursor;

use exarch_core::formats::ArchiveFormat as _;
use exarch_core::formats::ZipArchive;
use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    for config in [common::config(), common::config_ignoring_zip_structure()] {
        if let Ok(archive) = ZipArchive::new(Cursor::new(data), config) {
            let _ = archive.list();
        }
        if let Ok(archive) = ZipArchive::new(Cursor::new(data), config) {
            let _ = archive.verify(&common::verification_options());
        }
    }
});
