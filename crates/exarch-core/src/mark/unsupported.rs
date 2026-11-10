//! Platforms without a download-origin mark: nothing is read or written.

use std::fs::File;
use std::io;

/// No value exists, so no mark can be held.
#[derive(Clone, Copy)]
pub(super) enum Mark {}

pub(super) const SUPPORTED: bool = false;

pub(super) fn read(_file: &File) -> io::Result<Option<Mark>> {
    Ok(None)
}

pub(super) fn write_file(mark: Mark, _file: &File) -> io::Result<()> {
    match mark {}
}
