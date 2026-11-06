#![no_main]

use std::io::Cursor;

use exarch_core::ArchiveReader;
use exarch_core::ArchiveType;
use exarch_core::ListRequest;
use exarch_core::VerifyRequest;
use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    let config = common::config();

    let _ = ListRequest::new(config).list_reader(ArchiveReader::of_type(
        Cursor::new(data),
        ArchiveType::SevenZ,
    ));
    let _ = VerifyRequest::new(config)
        .with_options(common::verification_options())
        .verify_reader(ArchiveReader::of_type(
            Cursor::new(data),
            ArchiveType::SevenZ,
        ));
});
