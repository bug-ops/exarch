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
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::mem::offset_of;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsHandle;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::BorrowedHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::os::windows::io::RawHandle;
use std::ptr::NonNull;
use std::ptr::null;
use std::ptr::null_mut;
use std::slice;

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
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Foundation::OBJ_CASE_INSENSITIVE;
use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
use windows_sys::Win32::Foundation::UNICODE_STRING;
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::ACL_REVISION;
use windows_sys::Win32::Security::ACL_SIZE_INFORMATION;
use windows_sys::Win32::Security::AclSizeInformation;
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::Authorization::GetSecurityInfo;
use windows_sys::Win32::Security::Authorization::SDDL_REVISION_1;
use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
use windows_sys::Win32::Security::Authorization::SetSecurityInfo;
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::GetAclInformation;
use windows_sys::Win32::Security::GetSecurityDescriptorDacl;
use windows_sys::Win32::Security::GetTokenInformation;
use windows_sys::Win32::Security::InitializeAcl;
use windows_sys::Win32::Security::OBJECT_SECURITY_INFORMATION;
use windows_sys::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::Security::TOKEN_USER;
use windows_sys::Win32::Security::TokenUser;
use windows_sys::Win32::Security::UNPROTECTED_DACL_SECURITY_INFORMATION;
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
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Threading::OpenProcessToken;
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
    // SAFETY: a null descriptor is allowed.
    unsafe { create_with(dir, name, request, null()) }
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
    name: Leaf<'_>,
    request: Request,
    security: *const c_void,
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

/// A self-relative security descriptor whose DACL is protected and grants the
/// current user full control, inherited by every child.
///
/// A protected DACL ignores the parent's, so no other principal is named.
struct OwnerOnlyDescriptor(PSECURITY_DESCRIPTOR);

impl OwnerOnlyDescriptor {
    /// Builds the descriptor from the SID of the process token's user.
    ///
    /// # Errors
    ///
    /// The OS error of the failed step; there is no fallback descriptor.
    fn for_current_user() -> io::Result<Self> {
        let sddl: Vec<u16> = format!("D:P(A;OICI;FA;;;{})", current_user_sid()?)
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `sddl` is a NUL-terminated UTF-16 string that outlives the
        // call, `descriptor` is valid for writes, and the size out-pointer is
        // null, which the API allows.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }
}

impl Drop for OwnerOnlyDescriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated by the conversion call with
        // `LocalAlloc` and is freed exactly once, here.
        unsafe { LocalFree(self.0) };
    }
}

/// The string form of the SID of the user the current process runs as.
pub(super) fn current_user_sid() -> io::Result<String> {
    let mut token: HANDLE = null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo handle that needs no
    // closing, and `token` is valid for writes.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so `token` is a newly opened handle that
    // nothing else owns.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };

    let mut needed = 0_u32;
    // SAFETY: a null buffer of length zero asks only for the required size,
    // which is written to `needed`; `token` is a live handle.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            null_mut(),
            0,
            &raw mut needed,
        );
    }
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0_u64; (needed as usize).div_ceil(size_of::<u64>())];
    // SAFETY: `buffer` is valid for writes of `needed` bytes (it has at least
    // that many), `token` is a live handle and `needed` is valid for writes.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &raw mut needed,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so `buffer` starts with an initialized
    // `TOKEN_USER`, and the 8-aligned storage satisfies its alignment.
    let sid = unsafe { buffer.as_ptr().cast::<TOKEN_USER>().read() }
        .User
        .Sid;
    // SAFETY: `sid` points into `buffer`, which is alive and holds the SID the
    // token call just wrote.
    unsafe { sid_to_string(sid) }
}

/// The string form of `sid`.
///
/// # Safety
///
/// `sid` must point at a valid SID.
pub(super) unsafe fn sid_to_string(sid: *mut c_void) -> io::Result<String> {
    let mut slot = MaybeUninit::<*mut u16>::uninit();
    // SAFETY: the caller guarantees `sid` is a valid SID, and `slot` is valid
    // for writes.
    if unsafe { ConvertSidToStringSidW(sid, slot.as_mut_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so it wrote the string pointer to `slot`.
    let text = NonNull::new(unsafe { slot.assume_init() })
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    // SAFETY: on success `text` points at a NUL-terminated UTF-16 string
    // allocated by the API, so every offset up to the NUL is readable.
    let units = unsafe {
        let mut len = 0;
        while *text.as_ptr().add(len) != 0 {
            len = len.saturating_add(1);
        }
        slice::from_raw_parts(text.as_ptr(), len)
    };
    let parsed = String::from_utf16(units).map_err(|_| io::Error::from(io::ErrorKind::InvalidData));
    // SAFETY: `text` was allocated by `ConvertSidToStringSidW` with
    // `LocalAlloc`, `units` is no longer used, and it is freed once.
    unsafe { LocalFree(text.as_ptr().cast()) };
    parsed
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
    unsafe { create_with(dir, name, request, descriptor.0.cast_const()) }.map(drop)
}

/// Replaces the DACL of the directory `dir` with one that inherits from its
/// parent, and re-derives the inherited entries of everything below it.
///
/// `dir` must be open with `READ_CONTROL` and `WRITE_DAC`. The explicit list
/// passed is empty, not null: a null DACL would grant everyone full access if
/// the system did not merge the parent's entries, while an empty one leaves the
/// directory closed.
///
/// When the parent has no inheritable entries the merge leaves an empty DACL,
/// on the directory and on everything below it. That is detected by reading the
/// DACL back, the owner-only DACL is put back and an error is returned, so a
/// root is never published unreadable.
pub(super) fn inherit_dacl(dir: BorrowedHandle<'_>) -> io::Result<()> {
    const _: () = assert!(size_of::<ACL>() == size_of::<[u32; 2]>());
    let mut empty = [0_u32; 2];
    // SAFETY: `empty` is writable, 4-aligned and exactly `size_of::<ACL>()`
    // bytes, the length passed.
    let ok = unsafe {
        InitializeAcl(
            empty.as_mut_ptr().cast(),
            length_u32(size_of::<ACL>())?,
            ACL_REVISION,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `empty` is an initialized empty ACL that outlives the call.
    unsafe {
        set_dacl(
            dir,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            empty.as_ptr().cast(),
        )
    }?;
    match ace_count(dir) {
        Ok(entries) if entries > 0 => Ok(()),
        Ok(_) => {
            restore_owner_only(dir)?;
            Err(io::Error::other(
                "the parent has no inheritable entries; the directory stays owner-only",
            ))
        }
        Err(err) => {
            restore_owner_only(dir)?;
            Err(err)
        }
    }
}

/// Puts the protected, current-user-only DACL back on `dir`, which must be
/// open with `WRITE_DAC`, and re-derives what its children inherited.
fn restore_owner_only(dir: BorrowedHandle<'_>) -> io::Result<()> {
    let owner_only = OwnerOnlyDescriptor::for_current_user()?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl: *mut ACL = null_mut();
    // SAFETY: the descriptor is valid until `owner_only` drops, and the three
    // out-pointers are valid for writes.
    let ok = unsafe {
        GetSecurityDescriptorDacl(
            owner_only.0,
            &raw mut present,
            &raw mut acl,
            &raw mut defaulted,
        )
    };
    if ok == 0 || present == 0 || acl.is_null() {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    // SAFETY: `acl` points into the descriptor, which outlives the call.
    unsafe {
        set_dacl(
            dir,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            acl,
        )
    }
}

/// `SetSecurityInfo` on the DACL of `dir` with `flags`, which must select the
/// DACL only.
///
/// # Safety
///
/// `acl` must point at a valid ACL that outlives the call.
unsafe fn set_dacl(
    dir: BorrowedHandle<'_>,
    flags: OBJECT_SECURITY_INFORMATION,
    acl: *const ACL,
) -> io::Result<()> {
    // SAFETY: `dir` is a live handle, `acl` is valid by the caller's contract,
    // and the owner, group and SACL are null because `flags` selects only the
    // DACL.
    let code = unsafe {
        SetSecurityInfo(
            dir.as_raw_handle(),
            SE_FILE_OBJECT,
            flags,
            null_mut(),
            null_mut(),
            acl,
            null(),
        )
    };
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code.cast_signed()))
    }
}

/// The number of entries in the DACL of `dir`, which must be open with
/// `READ_CONTROL`. A null DACL counts as none.
fn ace_count(dir: BorrowedHandle<'_>) -> io::Result<u32> {
    let info_len = length_u32(size_of::<ACL_SIZE_INFORMATION>())?;
    let mut acl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `dir` is a live handle, the owner, group and SACL out-pointers
    // are null because only the DACL is requested, and `acl` and `descriptor`
    // are valid for writes.
    let code = unsafe {
        GetSecurityInfo(
            dir.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &raw mut acl,
            null_mut(),
            &raw mut descriptor,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(code.cast_signed()));
    }
    let mut size = ACL_SIZE_INFORMATION::default();
    let counted = if acl.is_null() {
        Ok(0)
    } else {
        // SAFETY: `acl` points into `descriptor`, which is alive, and `size`
        // is writable and of exactly the length passed.
        let ok =
            unsafe { GetAclInformation(acl, (&raw mut size).cast(), info_len, AclSizeInformation) };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(size.AceCount)
        }
    };
    // SAFETY: `descriptor` was allocated by `GetSecurityInfo` with
    // `LocalAlloc`, and `acl` is no longer used.
    unsafe { LocalFree(descriptor) };
    counted
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
