//! Platforms without a download-origin mark: nothing is read or written.

use std::fs::File;
use std::io;

/// No value exists, so no mark can be held.
#[derive(Clone, Copy)]
#[allow(
    clippy::empty_enums,
    reason = "uninhabited on purpose, stable has no `!`"
)]
pub(super) enum Mark {}

pub(super) const SUPPORTED: bool = false;

#[expect(
    clippy::unnecessary_wraps,
    reason = "same signature as the macOS and Windows read"
)]
pub(super) fn read(_file: &File) -> io::Result<Option<Mark>> {
    Ok(None)
}

pub(super) fn write_file(mark: Mark, _file: &File) -> io::Result<()> {
    match mark {}
}
