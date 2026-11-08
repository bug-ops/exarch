//! Directory-relative file operations through the NT native API.
//!
//! Win32 path APIs resolve every component of a joined path, so a pinned
//! directory that is converted into a mount point (or renamed away and replaced
//! by a junction) redirects `CreateFileW(dir\name)`. `NtCreateFile` with
//! `OBJECT_ATTRIBUTES::RootDirectory` set to the pinned handle opens `name`
//! relative to that handle instead, and `NtSetInformationFile` renames
//! and deletes through handles, so no operation re-resolves the directory's
//! path. This is the scheme the standard library's `remove_dir_all` fix for
//! CVE-2022-21658 uses.
//!
//! This is the only module in the crate that uses `unsafe` on Windows. Every
//! export is a safe function taking a [`Leaf`], so the "one non-empty normal
//! component" invariant is carried by the type: an empty `ObjectName` would
//! reopen the root itself.

#![deny(clippy::undocumented_unsafe_blocks)]

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::mem::offset_of;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsHandle;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::BorrowedHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::os::windows::io::RawHandle;
use std::ptr::null;
use std::ptr::null_mut;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::FILE_CREATE;
use windows_sys::Wdk::Storage::FileSystem::FILE_DIRECTORY_FILE;
use windows_sys::Wdk::Storage::FileSystem::FILE_INFORMATION_CLASS;
use windows_sys::Wdk::Storage::FileSystem::FILE_NON_DIRECTORY_FILE;
use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN_REPARSE_POINT;
use windows_sys::Wdk::Storage::FileSystem::FILE_RENAME_INFORMATION;
use windows_sys::Wdk::Storage::FileSystem::FILE_SYNCHRONOUS_IO_NONALERT;
use windows_sys::Wdk::Storage::FileSystem::FileDispositionInformation;
use windows_sys::Wdk::Storage::FileSystem::FileDispositionInformationEx;
use windows_sys::Wdk::Storage::FileSystem::FileRenameInformation;
use windows_sys::Wdk::Storage::FileSystem::FileRenameInformationEx;
use windows_sys::Wdk::Storage::FileSystem::NtCreateFile;
use windows_sys::Wdk::Storage::FileSystem::NtFsControlFile;
use windows_sys::Wdk::Storage::FileSystem::NtSetInformationFile;
use windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER;
use windows_sys::Win32::Foundation::ERROR_NOT_SUPPORTED;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::OBJ_CASE_INSENSITIVE;
use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
use windows_sys::Win32::Foundation::UNICODE_STRING;
use windows_sys::Win32::Storage::FileSystem::DELETE;
use windows_sys::Win32::Storage::FileSystem::FILE_ACCESS_RIGHTS;
use windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_FLAG_DELETE;
use windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;
use windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_INFO;
use windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_INFO_EX;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::FILE_ID_INFO;
use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
use windows_sys::Win32::Storage::FileSystem::FileIdInfo;
use windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandleEx;
use windows_sys::Win32::Storage::FileSystem::MAXIMUM_REPARSE_DATA_BUFFER_SIZE;
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;
use windows_sys::Win32::System::WindowsProgramming::FILE_RENAME_FLAG_POSIX_SEMANTICS;
use windows_sys::Win32::System::WindowsProgramming::FILE_RENAME_FLAG_REPLACE_IF_EXISTS;

use super::Leaf;

/// What `NtCreateFile` does when the name does and does not exist.
#[derive(Debug, Clone, Copy)]
pub(super) enum Disposition {
    /// Open the existing object; fail if it is absent.
    Open,
    /// Create the object; fail with `AlreadyExists` if the name is taken.
    Create,
}

/// Which kind of object the name must be.
#[derive(Debug, Clone, Copy)]
pub(super) enum Kind {
    /// Either; the caller inspects the returned handle.
    Any,
    /// A directory (`FILE_DIRECTORY_FILE`).
    Directory,
    /// Anything but a directory (`FILE_NON_DIRECTORY_FILE`).
    NonDirectory,
}

/// The access, creation and type requirements of one [`create_at`] call.
#[derive(Debug, Clone, Copy)]
pub(super) struct Request {
    pub(super) access: FILE_ACCESS_RIGHTS,
    pub(super) disposition: Disposition,
    pub(super) kind: Kind,
    pub(super) attributes: FILE_FLAGS_AND_ATTRIBUTES,
}

impl Request {
    /// Opens an existing name of any kind with the given access.
    pub(super) const fn open(access: FILE_ACCESS_RIGHTS) -> Self {
        Self {
            access,
            disposition: Disposition::Open,
            kind: Kind::Any,
            attributes: 0,
        }
    }
}

const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

fn wide(name: &OsStr) -> Vec<u16> {
    name.encode_wide().collect()
}

fn length_u32(len: usize) -> io::Result<u32> {
    u32::try_from(len).map_err(|_| io::Error::from(io::ErrorKind::InvalidFilename))
}

fn nt_error(status: i32) -> io::Error {
    // SAFETY: `RtlNtStatusToDosError` only maps a status code to an error code.
    let code = unsafe { RtlNtStatusToDosError(status) };
    io::Error::from_raw_os_error(code.cast_signed())
}

/// Opens or creates `name` relative to the directory handle `dir`.
///
/// A reparse point at `name` is opened itself, never followed. Every share mode
/// is granted, matching Unix, where a held directory can be renamed and writes
/// follow the descriptor. `SYNCHRONIZE` is always requested so the standard
/// library's synchronous file I/O works on the result.
pub(super) fn create_at(
    dir: BorrowedHandle<'_>,
    name: Leaf<'_>,
    request: Request,
) -> io::Result<OwnedHandle> {
    let mut name_units = wide(name.as_os_str());
    let name_bytes = u16::try_from(name_units.len().saturating_mul(size_of::<u16>()))
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidFilename))?;
    let object_name = UNICODE_STRING {
        Length: name_bytes,
        MaximumLength: name_bytes,
        Buffer: name_units.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: length_u32(size_of::<OBJECT_ATTRIBUTES>())?,
        RootDirectory: dir.as_raw_handle(),
        ObjectName: &raw const object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let disposition = match request.disposition {
        Disposition::Open => FILE_OPEN,
        Disposition::Create => FILE_CREATE,
    };
    let kind = match request.kind {
        Kind::Any => 0,
        Kind::Directory => FILE_DIRECTORY_FILE,
        Kind::NonDirectory => FILE_NON_DIRECTORY_FILE,
    };
    let mut handle: HANDLE = null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();

    // SAFETY: `attributes` points at `object_name`, which points at
    // `name_units`; all three outlive the call. `RootDirectory` is a live
    // handle borrowed from `dir`. `handle` and `status_block` are valid for
    // writes, and the allocation size, security descriptor and EA buffer are
    // null with a zero EA length.
    let status = unsafe {
        NtCreateFile(
            &raw mut handle,
            request.access | SYNCHRONIZE,
            &raw const attributes,
            &raw mut status_block,
            null(),
            request.attributes,
            SHARE_ALL,
            disposition,
            kind | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    };
    if status < 0 {
        return Err(nt_error(status));
    }
    // SAFETY: the call succeeded, so `handle` is a newly opened handle that
    // nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// The raw reparse data of the reparse point `name` inside `dir`, as
/// `FSCTL_GET_REPARSE_POINT` returns it.
///
/// The name is opened as itself, never followed, and the control code runs on
/// that handle, so no path is formed. A name that is not a reparse point is an
/// error (`ERROR_NOT_A_REPARSE_POINT`).
pub(super) fn reparse_data_at(dir: BorrowedHandle<'_>, name: Leaf<'_>) -> io::Result<Vec<u8>> {
    let file = create_at(dir, name, Request::open(FILE_READ_ATTRIBUTES))?;
    let capacity = MAXIMUM_REPARSE_DATA_BUFFER_SIZE;
    let mut buffer = vec![0_u8; capacity as usize];
    let mut status_block = IO_STATUS_BLOCK::default();

    // SAFETY: `file` is a live handle opened with
    // `FILE_SYNCHRONOUS_IO_NONALERT`, so the call completes before returning
    // and keeps no pointer. The event, APC routine, APC context and input
    // buffer are null with a zero input length. `buffer` is valid for writes of
    // `capacity` bytes and `status_block` is valid for writes.
    let status = unsafe {
        NtFsControlFile(
            file.as_raw_handle(),
            null_mut(),
            None,
            null(),
            &raw mut status_block,
            FSCTL_GET_REPARSE_POINT,
            null(),
            0,
            buffer.as_mut_ptr().cast(),
            capacity,
        )
    };
    if status < 0 {
        return Err(nt_error(status));
    }
    buffer.truncate(status_block.Information.min(buffer.len()));
    Ok(buffer)
}

/// An `NtSetInformationFile` payload in 8-aligned storage.
struct InfoBuffer {
    words: Vec<u64>,
    len: u32,
}

impl InfoBuffer {
    /// Copies `bytes` into zeroed storage of at least `min_len` bytes.
    fn new(bytes: &[u8], min_len: usize) -> io::Result<Self> {
        let len = bytes.len().max(min_len);
        let mut words = vec![0_u64; len.div_ceil(size_of::<u64>())];
        for (word, chunk) in words.iter_mut().zip(bytes.chunks(size_of::<u64>())) {
            let mut raw = [0_u8; size_of::<u64>()];
            if let Some(head) = raw.get_mut(..chunk.len()) {
                head.copy_from_slice(chunk);
            }
            *word = u64::from_ne_bytes(raw);
        }
        Ok(Self {
            words,
            len: length_u32(len)?,
        })
    }
}

fn put(bytes: &mut [u8], offset: usize, value: &[u8]) -> io::Result<()> {
    bytes
        .get_mut(offset..offset.saturating_add(value.len()))
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?
        .copy_from_slice(value);
    Ok(())
}

/// Sets file information through `NtSetInformationFile`, whose `RootDirectory`
/// semantics for renames are documented and not DOS-converted on the way in.
fn set_info(
    handle: BorrowedHandle<'_>,
    class: FILE_INFORMATION_CLASS,
    info: &InfoBuffer,
) -> io::Result<()> {
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `info.words` is 8-aligned and holds at least `info.len`
    // initialized bytes, `handle` is a live handle, `status_block` is valid for
    // writes, and the call does not retain either buffer.
    let status = unsafe {
        NtSetInformationFile(
            handle.as_raw_handle(),
            &raw mut status_block,
            info.words.as_ptr().cast(),
            info.len,
            class,
        )
    };
    if status < 0 {
        Err(nt_error(status))
    } else {
        Ok(())
    }
}

/// Builds a `FILE_RENAME_INFORMATION` that moves to the bare name `name`
/// inside `root`. A NUL follows the name, outside `FileNameLength`.
fn rename_info(root: RawHandle, name: &[u16], flags: u32) -> io::Result<InfoBuffer> {
    let name_bytes = name.len().saturating_mul(size_of::<u16>());
    let name_offset = offset_of!(FILE_RENAME_INFORMATION, FileName);
    let mut bytes = vec![
        0_u8;
        name_offset
            .saturating_add(name_bytes)
            .saturating_add(size_of::<u16>())
    ];
    put(
        &mut bytes,
        offset_of!(FILE_RENAME_INFORMATION, Anonymous),
        &flags.to_ne_bytes(),
    )?;
    put(
        &mut bytes,
        offset_of!(FILE_RENAME_INFORMATION, RootDirectory),
        &root.addr().to_ne_bytes(),
    )?;
    put(
        &mut bytes,
        offset_of!(FILE_RENAME_INFORMATION, FileNameLength),
        &length_u32(name_bytes)?.to_ne_bytes(),
    )?;
    for (index, unit) in name.iter().enumerate() {
        let at = name_offset.saturating_add(index.saturating_mul(size_of::<u16>()));
        put(&mut bytes, at, &unit.to_ne_bytes())?;
    }
    InfoBuffer::new(&bytes, size_of::<FILE_RENAME_INFORMATION>())
}

fn has_code(err: &io::Error, code: u32) -> bool {
    err.raw_os_error().map(i32::cast_unsigned) == Some(code)
}

/// Whether the filesystem or OS build lacks the `*Ex` information classes.
fn lacks_ex_classes(err: &io::Error) -> bool {
    has_code(err, ERROR_INVALID_PARAMETER) || has_code(err, ERROR_NOT_SUPPORTED)
}

/// Whether a rename replaces an existing target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Replace {
    /// Replace the target if it exists, even if it is open.
    IfExists,
    /// Fail if the target exists.
    Never,
}

impl Replace {
    const fn flag(self) -> u32 {
        match self {
            Self::IfExists => FILE_RENAME_FLAG_REPLACE_IF_EXISTS,
            Self::Never => 0,
        }
    }
}

/// Renames `from` over `to`, both inside `dir`.
///
/// Uses POSIX semantics, so the target is replaced even if it is open, and
/// falls back to the legacy rename where the filesystem or OS build does not
/// support them.
pub(super) fn rename_within(
    dir: BorrowedHandle<'_>,
    from: Leaf<'_>,
    to: Leaf<'_>,
) -> io::Result<()> {
    rename_with(dir, from, to, Replace::IfExists)
}

/// Renames `from` to `to`, both inside `dir`, replacing `to` only as `replace`
/// says.
pub(super) fn rename_with(
    dir: BorrowedHandle<'_>,
    from: Leaf<'_>,
    to: Leaf<'_>,
    replace: Replace,
) -> io::Result<()> {
    let source = create_at(dir, from, Request::open(DELETE | FILE_READ_ATTRIBUTES))?;
    let target = wide(to.as_os_str());
    let root = dir.as_raw_handle();
    let posix = rename_info(
        root,
        &target,
        replace.flag() | FILE_RENAME_FLAG_POSIX_SEMANTICS,
    )?;
    match set_info(source.as_handle(), FileRenameInformationEx, &posix) {
        Err(err) if lacks_ex_classes(&err) => {
            let legacy = rename_info(root, &target, replace.flag())?;
            set_info(source.as_handle(), FileRenameInformation, &legacy)
        }
        other => other,
    }
}

/// Deletes the non-directory `name` inside `dir`.
///
/// A real directory is refused with `IsADirectory`. A symlink or junction at
/// `name` is removed itself, never its target. A read-only file is not
/// overridden, unlike `std::fs::remove_file`.
pub(super) fn remove_file(dir: BorrowedHandle<'_>, name: Leaf<'_>) -> io::Result<()> {
    let file = File::from(create_at(
        dir,
        name,
        Request::open(DELETE | FILE_READ_ATTRIBUTES),
    )?);
    if file.metadata()?.is_dir() {
        return Err(io::Error::from(io::ErrorKind::IsADirectory));
    }
    let posix = InfoBuffer::new(
        &(FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS).to_ne_bytes(),
        size_of::<FILE_DISPOSITION_INFO_EX>(),
    )?;
    match set_info(file.as_handle(), FileDispositionInformationEx, &posix) {
        Err(err) if lacks_ex_classes(&err) => {
            let legacy = InfoBuffer::new(&[1], size_of::<FILE_DISPOSITION_INFO>())?;
            set_info(file.as_handle(), FileDispositionInformation, &legacy)
        }
        other => other,
    }
}

/// The volume serial number and 128-bit file id of the open `handle`, from
/// `FileIdInfo` only.
///
/// `None` when the volume cannot provide them. There is deliberately no
/// fallback to the 64-bit `GetFileInformationByHandle` index: it is not unique
/// on `ReFS`, and a wrong "same" or "different" is worse than "unknown".
pub(in crate::formats) fn file_id(handle: BorrowedHandle<'_>) -> Option<(u64, u128)> {
    let mut info = FILE_ID_INFO::default();
    // SAFETY: `info` is a valid, writable `FILE_ID_INFO` of exactly the size
    // passed, `handle` is a live handle, and the call retains neither.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle(),
            FileIdInfo,
            (&raw mut info).cast(),
            length_u32(size_of::<FILE_ID_INFO>()).ok()?,
        )
    };
    if ok == 0 {
        return None;
    }
    nonzero_file_id(info.FileId.Identifier).map(|id| (info.VolumeSerialNumber, id))
}

/// The file id, or `None` for the all-zero id some redirectors report for
/// every file: it names nothing, so it must not compare equal to itself.
fn nonzero_file_id(identifier: [u8; 16]) -> Option<u128> {
    Some(u128::from_le_bytes(identifier)).filter(|&id| id != 0)
}

#[cfg(test)]
mod file_id_tests {
    use super::nonzero_file_id;

    #[test]
    fn an_all_zero_file_id_is_unknown() {
        assert_eq!(nonzero_file_id([0; 16]), None);
        let mut id = [0; 16];
        id[0] = 7;
        assert_eq!(nonzero_file_id(id), Some(7));
    }
}
