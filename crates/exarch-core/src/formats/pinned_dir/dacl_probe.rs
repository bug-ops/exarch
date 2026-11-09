//! Test-only reader of a directory's DACL, for the Windows tests that check
//! who may reach a staging directory.

#![deny(clippy::undocumented_unsafe_blocks)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs::OpenOptions;
use std::io;
use std::mem::offset_of;
use std::mem::size_of;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::ACCESS_ALLOWED_ACE;
use windows_sys::Win32::Security::ACE_HEADER;
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::ACL_SIZE_INFORMATION;
use windows_sys::Win32::Security::AclSizeInformation;
use windows_sys::Win32::Security::Authorization::GetSecurityInfo;
use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::GetAce;
use windows_sys::Win32::Security::GetAclInformation;
use windows_sys::Win32::Security::GetSecurityDescriptorControl;
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::Security::SE_DACL_PROTECTED;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

use super::nt::current_user_sid;
use super::nt::sid_to_string;

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const READ_CONTROL: u32 = 0x0002_0000;

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
}

/// A DACL as the tests need it.
#[derive(Debug)]
pub(crate) struct Dacl {
    /// `SE_DACL_PROTECTED`: the parent's entries are ignored.
    pub(crate) protected: bool,
    pub(crate) aces: Vec<Ace>,
}

/// The string SID of the user running the tests.
pub(crate) fn current_user() -> String {
    current_user_sid().unwrap()
}

/// Reads the DACL of the file or directory at `path`.
pub(crate) fn read(path: &Path) -> Dacl {
    let file = OpenOptions::new()
        .access_mode(READ_CONTROL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
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
    let dacl = Dacl {
        protected: control(descriptor) & SE_DACL_PROTECTED != 0,
        aces: entries(acl).unwrap(),
    };
    // SAFETY: `descriptor` was allocated by `GetSecurityInfo` with
    // `LocalAlloc`, and `acl` points into it and is no longer used.
    unsafe { LocalFree(descriptor) };
    dacl
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
    let mut ace = null_mut();
    // SAFETY: `acl` is a valid ACL, `index` is below its entry count, and `ace`
    // is valid for writes.
    if unsafe { GetAce(acl, index, &raw mut ace) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: every entry starts with an `ACE_HEADER`.
    let header = unsafe { ace.cast::<ACE_HEADER>().read_unaligned() };
    // SAFETY: the SID of an `ACCESS_ALLOWED_ACE` starts at `SidStart`, inside
    // the entry. The test DACLs hold only entries of that layout, and the type
    // is checked below before the string is trusted.
    let sid = unsafe {
        ace.cast::<u8>()
            .add(offset_of!(ACCESS_ALLOWED_ACE, SidStart))
    };
    let allows = header.AceType == ACCESS_ALLOWED_ACE_TYPE;
    Ok(Ace {
        allows,
        flags: header.AceFlags,
        sid: if allows {
            // SAFETY: the entry is an `ACCESS_ALLOWED_ACE` (checked above), so
            // `sid` points at its SID, and the ACL outlives the call.
            unsafe { sid_to_string(sid.cast())? }
        } else {
            String::new()
        },
    })
}
