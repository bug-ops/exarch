#![no_main]

use std::io::Cursor;

use exarch_core::formats::ArchiveFormat as _;
use exarch_core::formats::TarArchive;
use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    let config = common::config();

    let archive = TarArchive::new(Cursor::new(data), config);
    let _ = archive.list();

    let archive = TarArchive::new(Cursor::new(data), config);
    let _ = archive.verify(&common::verification_options());
});
