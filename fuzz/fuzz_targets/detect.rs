#![no_main]

//! `ArchiveReader::detect` and `detect_stream` on arbitrary bytes.
//!
//! Detection peeks a header and must leave the input as it found it:
//!
//! - `detect` restores the stream position, on success and on failure, from any
//!   starting offset;
//! - `detect_stream` replays every byte it consumed, so reading through the
//!   detected reader lists the same archive as reading the bytes with the
//!   detected format stated explicitly.

use std::io::Cursor;
use std::io::Seek as _;
use std::io::SeekFrom;

use exarch_core::list_reader;
use exarch_core::ArchiveReader;
use exarch_core::ListOptions;
use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    let Some((&offset, archive)) = data.split_first() else {
        return;
    };
    check_seekable_position(archive, usize::from(offset));
    check_stream_replay(archive);
});

fn check_seekable_position(bytes: &[u8], offset: usize) {
    let start = u64::try_from(offset.min(bytes.len())).unwrap_or(0);
    let mut cursor = Cursor::new(bytes);
    cursor
        .seek(SeekFrom::Start(start))
        .expect("seeking a cursor within its buffer cannot fail");

    let _ = ArchiveReader::detect(&mut cursor);

    assert_eq!(
        cursor.position(),
        start,
        "detect must restore the stream position"
    );
}

fn check_stream_replay(bytes: &[u8]) {
    let Ok(streamed) = ArchiveReader::detect_stream(bytes) else {
        return;
    };
    let format = streamed.format();
    let config = common::config();
    let options = ListOptions::default();

    let via_stream = list_reader(streamed, config, &options);
    let via_format = list_reader(
        ArchiveReader::of_type(Cursor::new(bytes), format),
        config,
        &options,
    );

    assert_eq!(
        format!("{via_stream:?}"),
        format!("{via_format:?}"),
        "detect_stream must replay the bytes it consumed"
    );
}
