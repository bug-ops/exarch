//! Test-only reader of a directory's DACL, for the Windows tests that check
//! who may reach a staging directory.

#![deny(clippy::undocumented_unsafe_blocks)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs::OpenOptions;
use std::io;
use std::mem::MaybeUninit;
use std::mem::offset_of;
use std::mem::size_of;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr::NonNull;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::ACCESS_ALLOWED_ACE;
use windows_sys::Win32::Security::ACE_HEADER;
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::ACL_REVISION;
use windows_sys::Win32::Security::ACL_SIZE_INFORMATION;
use windows_sys::Win32::Security::AclSizeInformation;
use windows_sys::Win32::Security::AddAccessAllowedAceEx;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::Authorization::GetSecurityInfo;
use windows_sys::Win32::Security::Authorization::SDDL_REVISION_1;
use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::GetAce;
use windows_sys::Win32::Security::GetAclInformation;
use windows_sys::Win32::Security::GetSecurityDescriptorControl;
use windows_sys::Win32::Security::GetSecurityDescriptorDacl;
use windows_sys::Win32::Security::ImpersonateSelf;
use windows_sys::Win32::Security::InitializeAcl;
use windows_sys::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::Security::RevertToSelf;
use windows_sys::Win32::Security::SE_DACL_AUTO_INHERITED;
use windows_sys::Win32::Security::SE_DACL_PROTECTED;
use windows_sys::Win32::Security::SecurityImpersonation;
use windows_sys::Win32::Security::UNPROTECTED_DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

use super::nt::current_user_sid;
use super::nt::sid_to_string;

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const READ_CONTROL: u32 = 0x0002_0000;
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
const OBJECT_INHERIT_ACE: u8 = 0x01;
const CONTAINER_INHERIT_ACE: u8 = 0x02;

/// One entry of a DACL.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Ace {
    /// Whether it is an `ACCESS_ALLOWED_ACE`.
    pub(crate) allows: bool,
    /// The `AceFlags` byte (`INHERITED_ACE` is 0x10).
    pub(crate) flags: u8,
    /// The SID in string form.
    pub(crate) sid: String,
}

impl Ace {
    /// Whether the system marked this entry as inherited from a parent.
    pub(crate) const fn inherited(&self) -> bool {
        self.flags & 0x10 != 0
    }

    /// Whether children of the directory carrying this entry inherit it.
    pub(crate) const fn inheritable(&self) -> bool {
        self.flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) != 0
    }
}

/// A DACL as the tests need it.
#[derive(Debug)]
pub(crate) struct Dacl {
    /// `SE_DACL_PROTECTED`: the parent's entries are ignored.
    pub(crate) protected: bool,
    /// `SE_DACL_AUTO_INHERITED`: the entries marked inherited were derived by
    /// the system.
    pub(crate) auto_inherited: bool,
    /// Whether there is no DACL at all, which grants everyone full access.
    pub(crate) null: bool,
    pub(crate) aces: Vec<Ace>,
}

impl Dacl {
    /// Whether `other` has the same bits and entries, in the same order.
    pub(crate) fn same_as(&self, other: &Self) -> bool {
        self.protected == other.protected
            && self.auto_inherited == other.auto_inherited
            && self.null == other.null
            && self.aces == other.aces
    }
}

/// A thread that impersonates the process user, reverted on drop.
pub(crate) struct Impersonation;

impl Impersonation {
    /// Starts impersonating on the calling thread.
    pub(crate) fn start() -> Self {
        // SAFETY: `ImpersonateSelf` takes only an impersonation level.
        let ok = unsafe { ImpersonateSelf(SecurityImpersonation) };
        assert_ne!(ok, 0, "ImpersonateSelf failed");
        Self
    }
}

impl Drop for Impersonation {
    fn drop(&mut self) {
        // SAFETY: `RevertToSelf` takes no arguments.
        unsafe { RevertToSelf() };
    }
}

/// The string SID of the user running the tests.
pub(crate) fn current_user() -> String {
    current_user_sid().unwrap()
}

/// Reads the DACL of the file or directory at `path`, following a link there.
pub(crate) fn read(path: &Path) -> Dacl {
    read_with(path, FILE_FLAG_BACKUP_SEMANTICS)
}

/// Reads the DACL of the entry at `path` itself, without following a link.
pub(crate) fn read_itself(path: &Path) -> Dacl {
    read_with(
        path,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )
}

fn read_with(path: &Path, flags: u32) -> Dacl {
    let file = OpenOptions::new()
        .access_mode(READ_CONTROL)
        .custom_flags(flags)
        .open(path)
        .unwrap();
    let mut acl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: the handle is live, and the owner, group and SACL out-pointers
    // are null because only the DACL is requested; `acl` and `descriptor` are
    // valid for writes.
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &raw mut acl,
            null_mut(),
            &raw mut descriptor,
        )
    };
    assert_eq!(code, ERROR_SUCCESS, "GetSecurityInfo failed");
    let control = control(descriptor);
    let dacl = Dacl {
        protected: control & SE_DACL_PROTECTED != 0,
        auto_inherited: control & SE_DACL_AUTO_INHERITED != 0,
        null: acl.is_null(),
        aces: entries(acl).unwrap(),
    };
    // SAFETY: `descriptor` was allocated by `GetSecurityInfo` with
    // `LocalAlloc`, and `acl` points into it and is no longer used.
    unsafe { LocalFree(descriptor) };
    dacl
}

/// Replaces the DACL of the directory `path` with a protected one holding a
/// single, non-inheritable entry that grants the current user full access, so
/// that children created below it inherit nothing.
pub(crate) fn restrict_to_current_user_without_inheritance(path: &Path) {
    use std::os::windows::ffi::OsStrExt;

    let mut sid = MaybeUninit::<*mut std::ffi::c_void>::uninit();
    let text: Vec<u16> = current_user()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `text` is NUL-terminated and `sid` is valid for writes.
    let ok = unsafe { ConvertStringSidToSidW(text.as_ptr(), sid.as_mut_ptr()) };
    assert_ne!(ok, 0, "ConvertStringSidToSidW failed");
    // SAFETY: the call succeeded, so it wrote the SID pointer to `sid`.
    let sid = unsafe { sid.assume_init() };

    // Room for the header, one entry and a SID of the maximum length.
    let mut acl = [0_u32; 32];
    // SAFETY: `acl` is writable, 4-aligned and exactly the length passed.
    let ok = unsafe {
        InitializeAcl(
            acl.as_mut_ptr().cast(),
            u32::try_from(size_of_val(&acl)).unwrap(),
            ACL_REVISION,
        )
    };
    assert_ne!(ok, 0, "InitializeAcl failed");
    // SAFETY: `acl` was initialized above with room for the entry, and `sid`
    // is a valid SID.
    let ok = unsafe {
        AddAccessAllowedAceEx(
            acl.as_mut_ptr().cast(),
            ACL_REVISION,
            0,
            FILE_ALL_ACCESS,
            sid,
        )
    };
    assert_ne!(ok, 0, "AddAccessAllowedAceEx failed");

    let name: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `name` is NUL-terminated, the owner, group and SACL are null
    // because only the DACL is selected, and `acl` is a valid ACL that outlives
    // the call.
    let code = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl.as_ptr().cast(),
            std::ptr::null(),
        )
    };
    // SAFETY: `sid` was allocated by `ConvertStringSidToSidW` with `LocalAlloc`
    // and is no longer used.
    unsafe { LocalFree(sid) };
    assert_eq!(code, ERROR_SUCCESS, "SetNamedSecurityInfoW failed");
    let dacl = read(path);
    assert!(
        dacl.aces.iter().all(|ace| !ace.inheritable()),
        "the fixture parent still has inheritable entries: {:?}",
        dacl.aces
    );
}

/// Sets the DACL of the directory `path` from the SDDL string `sddl`, with the
/// protection its `P` flag says; `D:NO_ACCESS_CONTROL` gives a null DACL.
pub(crate) fn set_dacl_from_sddl(path: &Path, sddl: &str) {
    use std::os::windows::ffi::OsStrExt;

    let text: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `text` is NUL-terminated, `descriptor` is valid for writes and
    // the size out-pointer is null, which the API allows.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            null_mut(),
        )
    };
    assert_ne!(ok, 0, "the SDDL string {sddl} does not parse");
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl: *mut ACL = null_mut();
    // SAFETY: `descriptor` is valid, and the three out-pointers are valid for
    // writes.
    let ok = unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut acl,
            &raw mut defaulted,
        )
    };
    assert_ne!(ok, 0, "GetSecurityDescriptorDacl failed");
    let protection = if control(descriptor) & SE_DACL_PROTECTED == 0 {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    } else {
        PROTECTED_DACL_SECURITY_INFORMATION
    };
    let name: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `name` is NUL-terminated, the owner, group and SACL are null
    // because only the DACL is selected, and `acl` is null or points into
    // `descriptor`, which outlives the call.
    let code = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | protection,
            null_mut(),
            null_mut(),
            acl,
            std::ptr::null(),
        )
    };
    // SAFETY: `descriptor` was allocated by the conversion with `LocalAlloc`
    // and is no longer used.
    unsafe { LocalFree(descriptor) };
    assert_eq!(code, ERROR_SUCCESS, "SetNamedSecurityInfoW failed");
}

fn control(descriptor: PSECURITY_DESCRIPTOR) -> u16 {
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: `descriptor` is a valid descriptor and both out-pointers are
    // valid for writes.
    let ok =
        unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) };
    assert_ne!(ok, 0, "GetSecurityDescriptorControl failed");
    control
}

fn entries(acl: *const ACL) -> io::Result<Vec<Ace>> {
    if acl.is_null() {
        return Ok(Vec::new());
    }
    let mut size = ACL_SIZE_INFORMATION::default();
    // SAFETY: `acl` is a valid ACL, and `size` is writable and of exactly the
    // length passed.
    let ok = unsafe {
        GetAclInformation(
            acl,
            (&raw mut size).cast(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).unwrap(),
            AclSizeInformation,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    (0..size.AceCount).map(|index| entry(acl, index)).collect()
}

fn entry(acl: *const ACL, index: u32) -> io::Result<Ace> {
    let mut slot = MaybeUninit::uninit();
    // SAFETY: `acl` is a valid ACL, `index` is below its entry count, and
    // `slot` is valid for writes.
    if unsafe { GetAce(acl, index, slot.as_mut_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `GetAce` returned non-zero, so it wrote the entry pointer to
    // `slot`.
    let ace = NonNull::new(unsafe { slot.assume_init() })
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    // SAFETY: `ace` points at a live entry; every entry starts with an
    // `ACE_HEADER`.
    let header = unsafe { ace.as_ptr().cast::<ACE_HEADER>().read_unaligned() };
    let allows = header.AceType == ACCESS_ALLOWED_ACE_TYPE;
    Ok(Ace {
        allows,
        flags: header.AceFlags,
        sid: if allows {
            // SAFETY: the entry is an `ACCESS_ALLOWED_ACE` (checked above), so
            // its SID starts at `SidStart`, inside the entry.
            let sid = unsafe {
                ace.as_ptr()
                    .cast::<u8>()
                    .add(offset_of!(ACCESS_ALLOWED_ACE, SidStart))
            };
            // SAFETY: `sid` points at the entry's SID, and the ACL outlives the
            // call.
            unsafe { sid_to_string(sid.cast())? }
        } else {
            String::new()
        },
    })
}
