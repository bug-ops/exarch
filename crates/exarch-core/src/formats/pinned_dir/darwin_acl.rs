//! The macOS extended security attribute of an open file, read and written
//! through its descriptor.
//!
//! This module holds the only `unsafe` code of the macOS ACL support: two safe
//! wrappers over `fgetattrlist` and `fsetattrlist` for
//! `ATTR_CMN_EXTENDED_SECURITY`. Both take a `&File`, so the attribute is the
//! one of the object the descriptor names and never the one a path resolves to
//! later. They move opaque bytes; checking and interpreting them is the job of
//! `staging::acl`, in safe code.

#![deny(clippy::undocumented_unsafe_blocks)]

use std::fs::File;
use std::io;
use std::mem::size_of;
use std::mem::size_of_val;
use std::os::fd::AsRawFd;

use rustix::io::Errno;

/// `u64` words of the attribute buffers (512 words, 4096 bytes); an ACL of the
/// largest size macOS allows (128 entries) needs about 3.2 KiB.
const BUFFER_WORDS: usize = 512;

const REFERENCE_LEN: usize = size_of::<libc::attrreference_t>();

/// What reading the extended security attribute returned.
#[derive(Debug)]
pub(crate) enum Fetched {
    /// The whole attribute buffer: a native-endian `u32` total length, an
    /// `attrreference_t`, and the data it points at.
    Complete(Box<[u8]>),
    /// The attribute did not fit the buffer.
    Truncated,
}

fn extended_security_list() -> libc::attrlist {
    libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_EXTENDED_SECURITY,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    }
}

/// Reads the extended security attribute of `file`.
///
/// # Errors
///
/// The OS error of `fgetattrlist`, for example `ENOTSUP` on a volume without
/// ACL support.
pub(crate) fn fetch(file: &File) -> io::Result<Fetched> {
    let mut list = extended_security_list();
    let mut buffer = [0_u64; BUFFER_WORDS];
    // SAFETY: `list` is a valid `attrlist` and `buffer` is writable for the
    // `size_of_val(&buffer)` bytes passed, both outliving the call; the
    // descriptor is open because `file` is borrowed for the whole call.
    let result = unsafe {
        libc::fgetattrlist(
            file.as_raw_fd(),
            (&raw mut list).cast(),
            buffer.as_mut_ptr().cast(),
            size_of_val(&buffer),
            libc::FSOPT_REPORT_FULLSIZE,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(code) if code == Errno::RANGE.raw_os_error() => Ok(Fetched::Truncated),
            _ => Err(error),
        };
    }
    let bytes: Vec<u8> = buffer.iter().flat_map(|word| word.to_ne_bytes()).collect();
    let length = bytes
        .first_chunk::<4>()
        .map(|length| u32::from_ne_bytes(*length))
        .and_then(|length| usize::try_from(length).ok());
    let complete = length.and_then(|length| bytes.get(..length)).map(Box::from);
    Ok(complete.map_or(Fetched::Truncated, Fetched::Complete))
}

/// Makes `filesec`, a serialized `kauth_filesec`, the extended security
/// attribute of `file`.
///
/// # Errors
///
/// `InvalidInput` for a value that does not fit the buffer; otherwise the OS
/// error of `fsetattrlist`.
pub(crate) fn store(file: &File, filesec: &[u8]) -> io::Result<()> {
    let too_large = || io::Error::from(io::ErrorKind::InvalidInput);
    let total = REFERENCE_LEN
        .checked_add(filesec.len())
        .filter(|total| *total <= BUFFER_WORDS * size_of::<u64>())
        .ok_or_else(too_large)?;
    let reference = libc::attrreference_t {
        attr_dataoffset: i32::try_from(REFERENCE_LEN).map_err(|_| too_large())?,
        attr_length: u32::try_from(filesec.len()).map_err(|_| too_large())?,
    };
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(&reference.attr_dataoffset.to_ne_bytes());
    bytes.extend_from_slice(&reference.attr_length.to_ne_bytes());
    bytes.extend_from_slice(filesec);
    let mut words: Vec<u64> = bytes
        .chunks(size_of::<u64>())
        .map(|chunk| {
            let mut word = [0_u8; size_of::<u64>()];
            for (target, byte) in word.iter_mut().zip(chunk) {
                *target = *byte;
            }
            u64::from_ne_bytes(word)
        })
        .collect();
    let mut list = extended_security_list();
    // SAFETY: `list` is a valid `attrlist`; `words` holds `total` initialized
    // bytes (rounded up to whole words) laid out as an `attrreference_t`
    // followed by its data, and outlives the call; the descriptor is open
    // because `file` is borrowed for the whole call.
    let result = unsafe {
        libc::fsetattrlist(
            file.as_raw_fd(),
            (&raw mut list).cast(),
            words.as_mut_ptr().cast(),
            total,
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
