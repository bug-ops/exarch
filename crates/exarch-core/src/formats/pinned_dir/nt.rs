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
//! This module and its child [`security`] are the non-test `unsafe` surface of
//! the crate on Windows; `dacl_probe` is a test-only third. Every name-taking
//! export here is a safe function taking a [`Leaf`], so the "one non-empty
//! normal component" invariant is carried by the type: an empty `ObjectName`
//! would reopen the root itself, which only [`reopen_dir`] does, on purpose.
//! [`security`] exports tokens and descriptors instead, each owning the memory
//! its Win32 call hands out.

#![deny(clippy::undocumented_unsafe_blocks)]

use std::ffi::OsStr;
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
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
use std::slice;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::FILE_CREATE;
use windows_sys::Wdk::Storage::FileSystem::FILE_DIRECTORY_FILE;
use windows_sys::Wdk::Storage::FileSystem::FILE_FULL_DIR_INFORMATION;
use windows_sys::Wdk::Storage::FileSystem::FILE_INFORMATION_CLASS;
use windows_sys::Wdk::Storage::FileSystem::FILE_NON_DIRECTORY_FILE;
use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN_REPARSE_POINT;
use windows_sys::Wdk::Storage::FileSystem::FILE_RENAME_INFORMATION;
use windows_sys::Wdk::Storage::FileSystem::FILE_SYNCHRONOUS_IO_NONALERT;
use windows_sys::Wdk::Storage::FileSystem::FileDispositionInformation;
use windows_sys::Wdk::Storage::FileSystem::FileDispositionInformationEx;
use windows_sys::Wdk::Storage::FileSystem::FileFullDirectoryInformation;
use windows_sys::Wdk::Storage::FileSystem::FileRenameInformation;
use windows_sys::Wdk::Storage::FileSystem::FileRenameInformationEx;
use windows_sys::Wdk::Storage::FileSystem::NtCreateFile;
use windows_sys::Wdk::Storage::FileSystem::NtFsControlFile;
use windows_sys::Wdk::Storage::FileSystem::NtQueryDirectoryFile;
use windows_sys::Wdk::Storage::FileSystem::NtSetInformationFile;
use windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER;
use windows_sys::Win32::Foundation::ERROR_NOT_SUPPORTED;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::OBJ_CASE_INSENSITIVE;
use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
use windows_sys::Win32::Foundation::STATUS_NO_MORE_FILES;
use windows_sys::Win32::Foundation::UNICODE_STRING;
use windows_sys::Win32::Security::ACCESS_ALLOWED_ACE;
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::ACL_REVISION;
use windows_sys::Win32::Security::AddAccessAllowedAceEx;
use windows_sys::Win32::Security::CONTAINER_INHERIT_ACE;
use windows_sys::Win32::Security::GetLengthSid;
use windows_sys::Win32::Security::InitializeAcl;
use windows_sys::Win32::Security::InitializeSecurityDescriptor;
use windows_sys::Win32::Security::OBJECT_INHERIT_ACE;
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::Security::SE_DACL_PROTECTED;
use windows_sys::Win32::Security::SECURITY_DESCRIPTOR;
use windows_sys::Win32::Security::SetSecurityDescriptorControl;
use windows_sys::Win32::Security::SetSecurityDescriptorDacl;
use windows_sys::Win32::Storage::FileSystem::DELETE;
use windows_sys::Win32::Storage::FileSystem::FILE_ACCESS_RIGHTS;
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_FLAG_DELETE;
use windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;
use windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_INFO;
use windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_INFO_EX;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE;
use windows_sys::Win32::Storage::FileSystem::FILE_ID_INFO;
use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
use windows_sys::Win32::Storage::FileSystem::FileIdInfo;
use windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandleEx;
use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;
use windows_sys::Win32::Storage::FileSystem::MAXIMUM_REPARSE_DATA_BUFFER_SIZE;
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;
use windows_sys::Win32::System::SystemServices::FILE_NAMED_STREAMS;
use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
use windows_sys::Win32::System::WindowsProgramming::FILE_RENAME_FLAG_POSIX_SEMANTICS;
use windows_sys::Win32::System::WindowsProgramming::FILE_RENAME_FLAG_REPLACE_IF_EXISTS;
use windows_sys::core::BOOL;

use super::Leaf;
use super::dir_info;

pub(in crate::formats) mod security;

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
    // SAFETY: a null descriptor is allowed.
    unsafe { create_with(dir, Target::Name(name), request, null()) }
}

/// What a relative open names.
#[derive(Debug, Clone, Copy)]
enum Target<'a> {
    /// A name inside the directory.
    Name(Leaf<'a>),
    /// The directory itself, which a zero-length name reopens.
    Itself,
    /// The [`ZONE_STREAM`] of the file the root handle is open on.
    ZoneStream,
}

/// The alternate data stream that carries Mark-of-the-Web, named relative to
/// the handle of the file it belongs to; never joined to a path string.
const ZONE_STREAM: &str = ":Zone.Identifier";

/// Whether the volume `file` lives on supports named streams; FAT, exFAT and
/// some network shares do not.
fn volume_names_streams(file: &File) -> io::Result<bool> {
    let mut flags = 0_u32;
    // SAFETY: the handle is live for the call and every output pointer is
    // either null (not requested, with a zero size) or valid for writes.
    let queried = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &raw mut flags,
            null_mut(),
            0,
        )
    };
    if queried == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags & FILE_NAMED_STREAMS != 0)
}

/// Reads the `Zone.Identifier` stream of the file `file` is open on, at most
/// `limit` bytes plus one so the caller can tell an oversized stream from one
/// that fits; `None` when the file has no such stream, which includes a
/// volume that supports no streams.
///
/// A volume query that itself fails is not taken for "no streams": the stream
/// read then decides, and its error stays an error.
///
/// # Errors
///
/// The OS error of the open or the read.
pub(crate) fn read_zone_stream(file: &File, limit: usize) -> io::Result<Option<Vec<u8>>> {
    if matches!(volume_names_streams(file), Ok(false)) {
        return Ok(None);
    }
    let request = Request {
        kind: Kind::NonDirectory,
        ..Request::open(FILE_GENERIC_READ)
    };
    // SAFETY: a null descriptor is allowed.
    let opened = unsafe { create_with(file.as_handle(), Target::ZoneStream, request, null()) };
    let handle = match opened {
        Ok(handle) => handle,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let bound = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut content = Vec::new();
    File::from(handle).take(bound).read_to_end(&mut content)?;
    Ok(Some(content))
}

/// Creates the `Zone.Identifier` stream of the file `file` is open on, with
/// `content`; fails if the file already has one.
///
/// # Errors
///
/// The OS error of the create or the write, including a volume without
/// streams.
pub(crate) fn write_zone_stream(file: &File, content: &[u8]) -> io::Result<()> {
    let request = Request {
        access: FILE_GENERIC_WRITE,
        disposition: Disposition::Create,
        kind: Kind::NonDirectory,
        attributes: 0,
    };
    // SAFETY: a null descriptor is allowed.
    let handle = unsafe { create_with(file.as_handle(), Target::ZoneStream, request, null()) }?;
    File::from(handle).write_all(content)
}

/// Opens the directory `dir` again, with `access`, relative to itself.
///
/// This is how a handle opened for security access gets one for listing
/// without naming the directory again, so nothing is resolved by path. A
/// reparse point is opened itself.
pub(super) fn reopen_dir(
    dir: BorrowedHandle<'_>,
    access: FILE_ACCESS_RIGHTS,
) -> io::Result<OwnedHandle> {
    let request = Request {
        kind: Kind::Directory,
        ..Request::open(access)
    };
    // SAFETY: a null descriptor is allowed.
    unsafe { create_with(dir, Target::Itself, request, null()) }
}

/// [`create_at`] with the security descriptor `security` for a created object;
/// null keeps the inherited one.
///
/// # Safety
///
/// `security` must be null or point at a valid security descriptor that
/// outlives the call.
unsafe fn create_with(
    dir: BorrowedHandle<'_>,
    name: Target<'_>,
    request: Request,
    security: *const c_void,
) -> io::Result<OwnedHandle> {
    let mut name_units = match name {
        Target::Name(leaf) => wide(leaf.as_os_str()),
        Target::Itself => Vec::new(),
        Target::ZoneStream => ZONE_STREAM.encode_utf16().collect(),
    };
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
        SecurityDescriptor: security.cast(),
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
    // writes, the security descriptor is null or valid for the call (the
    // caller's contract), and the allocation size and EA buffer are null with
    // a zero EA length.
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

/// The turn of a Win32 `BOOL` into the OS error of the call that returned it.
pub(super) fn win32(ok: BOOL) -> io::Result<()> {
    (ok != 0).ok_or_else(io::Error::last_os_error)
}

/// An absolute security descriptor whose DACL is protected and grants the
/// current user full control, inherited by every child.
///
/// A protected DACL ignores the parent's, so no other principal is named.
struct OwnerOnlyDescriptor {
    descriptor: SECURITY_DESCRIPTOR,
    /// The DACL `descriptor` points at; 4-aligned as an ACL requires.
    _acl: Vec<u32>,
}

impl OwnerOnlyDescriptor {
    /// The ACL header and one allow entry, without the SID that follows it.
    const ACL_WITHOUT_SID: usize =
        size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>();

    /// Builds the descriptor from the SID of the effective token's user.
    ///
    /// # Errors
    ///
    /// The OS error of the failed step; there is no fallback descriptor.
    fn for_current_user() -> io::Result<Self> {
        let user = security::EffectiveToken::open()?.user()?;
        let sid = user.sid();
        // SAFETY: `user` owns a valid SID that outlives the call.
        let sid_length = unsafe { GetLengthSid(sid) } as usize;
        let acl_length = Self::ACL_WITHOUT_SID.saturating_add(sid_length);
        let mut acl = vec![0_u32; acl_length.div_ceil(size_of::<u32>())];
        let capacity = length_u32(acl.len().saturating_mul(size_of::<u32>()))?;
        // SAFETY: `acl` is writable, 4-aligned and `capacity` bytes long.
        win32(unsafe { InitializeAcl(acl.as_mut_ptr().cast(), capacity, ACL_REVISION) })?;
        // SAFETY: `acl` was initialized above with room for one entry holding
        // `sid`, which is valid.
        win32(unsafe {
            AddAccessAllowedAceEx(
                acl.as_mut_ptr().cast(),
                ACL_REVISION,
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                FILE_ALL_ACCESS,
                sid,
            )
        })?;
        let mut descriptor = SECURITY_DESCRIPTOR::default();
        let ptr: PSECURITY_DESCRIPTOR = (&raw mut descriptor).cast();
        // SAFETY: `ptr` points at a writable `SECURITY_DESCRIPTOR`.
        win32(unsafe { InitializeSecurityDescriptor(ptr, SECURITY_DESCRIPTOR_REVISION) })?;
        // SAFETY: `ptr` was initialized above, and `acl` is a valid ACL whose
        // heap buffer stays where it is when the vector moves into `Self`.
        win32(unsafe { SetSecurityDescriptorDacl(ptr, 1, acl.as_ptr().cast(), 0) })?;
        // SAFETY: `ptr` is a valid descriptor.
        win32(unsafe { SetSecurityDescriptorControl(ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED) })?;
        Ok(Self {
            descriptor,
            _acl: acl,
        })
    }

    fn as_ptr(&self) -> *const c_void {
        (&raw const self.descriptor).cast()
    }
}

/// Creates the directory `name` inside `dir` with a protected DACL that grants
/// only the current user, and that every child inherits.
///
/// Fails closed: when the descriptor cannot be built or applied, nothing is
/// created and the error comes back; the parent's ACL is never used instead.
pub(super) fn create_private_dir_at(dir: BorrowedHandle<'_>, name: Leaf<'_>) -> io::Result<()> {
    let descriptor = OwnerOnlyDescriptor::for_current_user()?;
    let request = Request {
        access: SYNCHRONIZE | FILE_READ_ATTRIBUTES,
        disposition: Disposition::Create,
        kind: Kind::Directory,
        attributes: 0,
    };
    // SAFETY: `descriptor` owns a valid descriptor until it drops after the
    // call.
    unsafe { create_with(dir, Target::Name(name), request, descriptor.as_ptr()) }.map(drop)
}

const _: () = {
    assert!(offset_of!(FILE_FULL_DIR_INFORMATION, NextEntryOffset) == dir_info::NEXT_ENTRY_OFFSET);
    assert!(offset_of!(FILE_FULL_DIR_INFORMATION, FileNameLength) == dir_info::FILE_NAME_LENGTH);
    assert!(offset_of!(FILE_FULL_DIR_INFORMATION, FileName) == dir_info::FILE_NAME);
};

/// The names of the entries of the directory `dir`, without `.` and `..`, each
/// as UTF-16 code units. `dir` must be open with `FILE_LIST_DIRECTORY`.
///
/// # Errors
///
/// The OS error, or `InvalidData` when the records the kernel returned do not
/// parse: the caller must treat the directory as unlistable, not as partial.
pub(super) fn list_names(dir: BorrowedHandle<'_>) -> io::Result<Vec<Vec<u16>>> {
    const BUFFER_BYTES: usize = 64 * 1024;
    let mut buffer = vec![0_u64; BUFFER_BYTES.div_ceil(size_of::<u64>())];
    let mut names = Vec::new();
    let mut restart = true;
    loop {
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: `dir` is a live handle opened with
        // `FILE_SYNCHRONOUS_IO_NONALERT`, so the call completes before
        // returning and keeps no pointer. The event, APC routine, APC context
        // and file name filter are null. `buffer` is valid for writes of
        // `BUFFER_BYTES` bytes and `status_block` is valid for writes.
        let status = unsafe {
            NtQueryDirectoryFile(
                dir.as_raw_handle(),
                null_mut(),
                None,
                null(),
                &raw mut status_block,
                buffer.as_mut_ptr().cast(),
                length_u32(BUFFER_BYTES)?,
                FileFullDirectoryInformation,
                false,
                null(),
                restart,
            )
        };
        if status == STATUS_NO_MORE_FILES {
            return Ok(names);
        }
        if status < 0 {
            return Err(nt_error(status));
        }
        restart = false;
        let written = status_block.Information.min(BUFFER_BYTES);
        // SAFETY: `buffer` is `BUFFER_BYTES` initialized bytes (zeroed, then
        // written by the call) and `written` does not exceed that; the borrow
        // ends before the next call writes to the buffer.
        let bytes = unsafe { slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), written) };
        let batch =
            dir_info::names(bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        names.extend(batch);
    }
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
    win32(ok).ok()?;
    nonzero_file_id(info.FileId.Identifier).map(|id| (info.VolumeSerialNumber, id))
}

/// The file id, or `None` for the all-zero id some redirectors report for
/// every file: it names nothing, so it must not compare equal to itself.
fn nonzero_file_id(identifier: [u8; 16]) -> Option<u128> {
    Some(u128::from_le_bytes(identifier)).filter(|&id| id != 0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod stream_volume_tests {
    use super::volume_names_streams;

    #[test]
    fn the_volume_of_a_temp_file_names_streams() {
        let file = tempfile::tempfile().unwrap();
        assert!(volume_names_streams(&file).unwrap());
    }
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod owner_only_tests {
    use super::OwnerOnlyDescriptor;
    use crate::formats::pinned_dir::dacl_probe;

    #[test]
    fn the_owner_only_descriptor_is_a_protected_inheritable_full_control_grant() {
        let descriptor = OwnerOnlyDescriptor::for_current_user().unwrap();

        let expected = dacl_probe::normalized_sddl(&format!(
            "D:P(A;OICI;FA;;;{})",
            dacl_probe::current_user()
        ));
        assert_eq!(dacl_probe::dacl_sddl_of(descriptor.as_ptr()), expected);
    }
}
