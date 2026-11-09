//! Tokens and security descriptors for the Windows staging root.
//!
//! Every `unsafe` call here wraps one Win32 security API behind a type that
//! owns the memory the API hands out, so the walk that rewrites a published
//! tree ([`super::super::dacl_walk`]) is safe code.

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::BorrowedHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::ptr::null;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::Foundation::ERROR_NO_TOKEN;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::TRUE;
use windows_sys::Win32::Security::ACE_HEADER;
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::ACL_SIZE_INFORMATION;
use windows_sys::Win32::Security::AclSizeInformation;
use windows_sys::Win32::Security::CONTAINER_INHERIT_ACE;
use windows_sys::Win32::Security::CreatePrivateObjectSecurityEx;
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::DestroyPrivateObjectSecurity;
use windows_sys::Win32::Security::GENERIC_MAPPING;
use windows_sys::Win32::Security::GROUP_SECURITY_INFORMATION;
use windows_sys::Win32::Security::GetAce;
use windows_sys::Win32::Security::GetAclInformation;
use windows_sys::Win32::Security::GetKernelObjectSecurity;
use windows_sys::Win32::Security::GetSecurityDescriptorControl;
use windows_sys::Win32::Security::GetSecurityDescriptorDacl;
use windows_sys::Win32::Security::GetTokenInformation;
use windows_sys::Win32::Security::OBJECT_INHERIT_ACE;
use windows_sys::Win32::Security::OBJECT_SECURITY_INFORMATION;
use windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION;
use windows_sys::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::Security::PSID;
use windows_sys::Win32::Security::SE_DACL_AUTO_INHERIT_REQ;
use windows_sys::Win32::Security::SE_DACL_AUTO_INHERITED;
use windows_sys::Win32::Security::SE_DACL_PROTECTED;
use windows_sys::Win32::Security::SEF_AVOID_OWNER_CHECK;
use windows_sys::Win32::Security::SEF_AVOID_PRIVILEGE_CHECK;
use windows_sys::Win32::Security::SEF_DACL_AUTO_INHERIT;
use windows_sys::Win32::Security::SetKernelObjectSecurity;
use windows_sys::Win32::Security::SetSecurityDescriptorControl;
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::Security::TOKEN_USER;
use windows_sys::Win32::Security::TokenUser as TokenUserClass;
use windows_sys::Win32::Security::UNPROTECTED_DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_EXECUTE;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE;
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Threading::GetCurrentThread;
use windows_sys::Win32::System::Threading::OpenProcessToken;
use windows_sys::Win32::System::Threading::OpenThreadToken;

use super::has_code;
use super::length_u32;
use super::win32;

/// Where an [`EffectiveToken`] came from.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::formats) enum TokenSource {
    /// The impersonation token of the calling thread.
    Thread,
    /// The token of the process, used when the thread does not impersonate.
    Process,
}

/// The token access checks and new objects are made under: the calling
/// thread's impersonation token when it has one, else the process token.
///
/// Using the process token under impersonation would name a user that does not
/// own the objects the thread creates.
#[derive(Debug)]
pub(in crate::formats) struct EffectiveToken {
    handle: OwnedHandle,
    #[cfg(test)]
    source: TokenSource,
}

impl EffectiveToken {
    /// Opens the effective token with `TOKEN_QUERY`.
    ///
    /// The process token is the fallback only when the thread has no token
    /// (`ERROR_NO_TOKEN`); any other failure is returned, never papered over.
    ///
    /// # Errors
    ///
    /// The OS error of the failed open.
    pub(in crate::formats) fn open() -> io::Result<Self> {
        let mut token: HANDLE = null_mut();
        // SAFETY: `GetCurrentThread` returns a pseudo handle that needs no
        // closing, and `token` is valid for writes.
        let thread =
            unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw mut token) };
        if thread != 0 {
            // SAFETY: the call succeeded, so `token` is a newly opened handle
            // that nothing else owns.
            let handle = unsafe { OwnedHandle::from_raw_handle(token) };
            return Ok(Self {
                handle,
                #[cfg(test)]
                source: TokenSource::Thread,
            });
        }
        let err = io::Error::last_os_error();
        if !has_code(&err, ERROR_NO_TOKEN) {
            return Err(err);
        }
        // SAFETY: `GetCurrentProcess` returns a pseudo handle that needs no
        // closing, and `token` is valid for writes.
        win32(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) })?;
        // SAFETY: the call succeeded, so `token` is a newly opened handle that
        // nothing else owns.
        let handle = unsafe { OwnedHandle::from_raw_handle(token) };
        Ok(Self {
            handle,
            #[cfg(test)]
            source: TokenSource::Process,
        })
    }

    /// Which token this is.
    #[cfg(test)]
    pub(in crate::formats) const fn source(&self) -> TokenSource {
        self.source
    }

    /// The user of the token, with the memory its SID lives in.
    ///
    /// # Errors
    ///
    /// The OS error of the failed query.
    pub(in crate::formats) fn user(&self) -> io::Result<TokenUser> {
        let mut needed = 0_u32;
        // SAFETY: a null buffer of length zero asks only for the required
        // size, which is written to `needed`; the token is a live handle.
        unsafe {
            GetTokenInformation(
                self.handle.as_raw_handle(),
                TokenUserClass,
                null_mut(),
                0,
                &raw mut needed,
            );
        }
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0_u64; (needed as usize).div_ceil(size_of::<u64>())];
        // SAFETY: `buffer` is valid for writes of `needed` bytes (it has at
        // least that many), the token is a live handle and `needed` is valid
        // for writes.
        let ok = unsafe {
            GetTokenInformation(
                self.handle.as_raw_handle(),
                TokenUserClass,
                buffer.as_mut_ptr().cast(),
                needed,
                &raw mut needed,
            )
        };
        win32(ok)?;
        Ok(TokenUser { buffer })
    }

    fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle()
    }
}

/// The user of a token, as the `TOKEN_USER` record the query wrote.
#[derive(Debug)]
pub(in crate::formats) struct TokenUser {
    /// Starts with an initialized `TOKEN_USER` whose SID points into the same
    /// allocation, so the SID lives as long as this value.
    buffer: Vec<u64>,
}

impl TokenUser {
    /// The user's SID, valid while `self` is alive.
    pub(in crate::formats) fn sid(&self) -> PSID {
        // SAFETY: `buffer` starts with the `TOKEN_USER` the query wrote, and
        // its 8-aligned storage satisfies the alignment.
        unsafe { self.buffer.as_ptr().cast::<TOKEN_USER>().read() }
            .User
            .Sid
    }
}

/// Which parts of an object's descriptor [`SecurityDescriptor::read`] fetches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::formats) enum Part {
    /// The owner and the owning group: what a creator descriptor carries, so a
    /// derived DACL resolves `CREATOR OWNER` and `CREATOR GROUP` as the kernel
    /// does at create time.
    OwnerAndGroup,
    /// The owner, the group and the DACL.
    OwnerGroupAndDacl,
}

impl Part {
    const fn information(self) -> OBJECT_SECURITY_INFORMATION {
        match self {
            Self::OwnerAndGroup => OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
            Self::OwnerGroupAndDacl => {
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
            }
        }
    }
}

/// Whether a descriptor has a DACL at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::formats) enum DaclState {
    /// No DACL: the object grants everyone full access.
    Null,
    /// A DACL, possibly empty, with this many entries.
    Present {
        /// The number of entries.
        entries: u32,
    },
}

/// Whether a DACL ignores the entries its parent would give it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaclProtection {
    Protected,
    Inheriting,
}

impl DaclProtection {
    const fn of(control: u16) -> Self {
        if control & SE_DACL_PROTECTED != 0 {
            Self::Protected
        } else {
            Self::Inheriting
        }
    }

    const fn flag(self) -> OBJECT_SECURITY_INFORMATION {
        match self {
            Self::Protected => PROTECTED_DACL_SECURITY_INFORMATION,
            Self::Inheriting => UNPROTECTED_DACL_SECURITY_INFORMATION,
        }
    }
}

/// What kind of object a descriptor is derived for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::formats) enum ObjectKind {
    /// A directory (or a junction or directory symlink): container-only
    /// inheritable entries apply.
    Container,
    /// Anything else.
    Leaf,
}

/// The control word of a valid descriptor.
fn control_of(descriptor: PSECURITY_DESCRIPTOR) -> io::Result<u16> {
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: the callers pass a valid descriptor, and both out-pointers are
    // valid for writes.
    let ok =
        unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) };
    win32(ok)?;
    Ok(control)
}

/// Makes a stored descriptor record that its DACL is auto-inherited when it is.
///
/// `SetKernelObjectSecurity` only stores `SE_DACL_AUTO_INHERITED` on an object
/// when the descriptor also requests it.
fn request_auto_inherited(descriptor: PSECURITY_DESCRIPTOR) -> io::Result<()> {
    if control_of(descriptor)? & SE_DACL_AUTO_INHERITED == 0 {
        return Ok(());
    }
    // SAFETY: the callers pass a valid descriptor they own exclusively.
    let ok = unsafe {
        SetSecurityDescriptorControl(
            descriptor,
            SE_DACL_AUTO_INHERIT_REQ,
            SE_DACL_AUTO_INHERIT_REQ,
        )
    };
    win32(ok)
}

/// A self-relative security descriptor read from an object.
#[derive(Debug)]
pub(in crate::formats) struct SecurityDescriptor(Box<[u64]>);

impl SecurityDescriptor {
    const READ_ATTEMPTS: usize = 4;

    /// Reads `part` of the descriptor of the object `handle` names, which
    /// must be open with `READ_CONTROL`.
    ///
    /// # Errors
    ///
    /// The OS error; `PermissionDenied` when the caller may not read it.
    pub(in crate::formats) fn read(handle: BorrowedHandle<'_>, part: Part) -> io::Result<Self> {
        let mut words = vec![0_u64; 64];
        for _ in 0..Self::READ_ATTEMPTS {
            let capacity = words.len().saturating_mul(size_of::<u64>());
            let mut needed = 0_u32;
            // SAFETY: `words` is valid for writes of `capacity` bytes, the
            // handle is live and `needed` is valid for writes.
            let ok = unsafe {
                GetKernelObjectSecurity(
                    handle.as_raw_handle(),
                    part.information(),
                    words.as_mut_ptr().cast(),
                    length_u32(capacity)?,
                    &raw mut needed,
                )
            };
            if ok != 0 {
                let mut read = Self(words.into_boxed_slice());
                request_auto_inherited(read.as_mut_ptr())?;
                return Ok(read);
            }
            let err = io::Error::last_os_error();
            if !has_code(&err, ERROR_INSUFFICIENT_BUFFER) || needed as usize <= capacity {
                return Err(err);
            }
            words = vec![0_u64; (needed as usize).div_ceil(size_of::<u64>())];
        }
        Err(io::Error::from(io::ErrorKind::InvalidData))
    }

    fn as_mut_ptr(&mut self) -> PSECURITY_DESCRIPTOR {
        self.0.as_mut_ptr().cast()
    }

    fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        // The pointer is only handed to APIs that read through it.
        self.0.as_ptr().cast_mut().cast()
    }
}

/// The DACL of a valid descriptor and its entry count, or `None` when the
/// descriptor has no DACL (or a null one). The pointer points into the
/// descriptor and is valid as long as it is.
fn dacl_of(descriptor: PSECURITY_DESCRIPTOR) -> io::Result<Option<(*mut ACL, u32)>> {
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl: *mut ACL = null_mut();
    // SAFETY: the callers pass a valid descriptor, and the three out-pointers
    // are valid for writes.
    let ok = unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut acl,
            &raw mut defaulted,
        )
    };
    win32(ok)?;
    if present == 0 || acl.is_null() {
        return Ok(None);
    }
    let mut size = ACL_SIZE_INFORMATION::default();
    // SAFETY: `acl` points into the descriptor, which is alive, and `size` is
    // writable and of exactly the length passed.
    let ok = unsafe {
        GetAclInformation(
            acl,
            (&raw mut size).cast(),
            length_u32(size_of::<ACL_SIZE_INFORMATION>())?,
            AclSizeInformation,
        )
    };
    win32(ok)?;
    Ok(Some((acl, size.AceCount)))
}

/// A descriptor made by `CreatePrivateObjectSecurityEx`.
#[derive(Debug)]
pub(in crate::formats) struct Derived(PSECURITY_DESCRIPTOR);

impl Derived {
    /// The descriptor an object of `kind` gets when it is created under
    /// `parent` by the owner and group in `creator`, with `token` as the
    /// creating user.
    ///
    /// `creator` carries the object's real owner and group and no DACL, so no
    /// explicit entry is merged in. The owner and privilege checks are skipped:
    /// this reproduces a creation the kernel already allowed.
    ///
    /// # Errors
    ///
    /// The OS error of the derivation.
    pub(in crate::formats) fn new(
        parent: &Descriptor<'_>,
        creator: &SecurityDescriptor,
        kind: ObjectKind,
        token: &EffectiveToken,
    ) -> io::Result<Self> {
        let mapping = GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ,
            GenericWrite: FILE_GENERIC_WRITE,
            GenericExecute: FILE_GENERIC_EXECUTE,
            GenericAll: FILE_ALL_ACCESS,
        };
        let mut flags = SEF_AVOID_OWNER_CHECK | SEF_AVOID_PRIVILEGE_CHECK;
        if control_of(parent.as_ptr())? & SE_DACL_AUTO_INHERITED != 0 {
            flags |= SEF_DACL_AUTO_INHERIT;
        }
        let mut derived: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: both descriptors are valid for the call, the object type is
        // null, `derived` is valid for writes, the token is a live handle with
        // `TOKEN_QUERY` and the mapping outlives the call.
        let ok = unsafe {
            CreatePrivateObjectSecurityEx(
                parent.as_ptr(),
                creator.as_ptr(),
                &raw mut derived,
                null(),
                i32::from(kind == ObjectKind::Container),
                flags,
                token.raw(),
                &raw const mapping,
            )
        };
        win32(ok)?;
        let derived = Self(derived);
        request_auto_inherited(derived.0)?;
        Ok(derived)
    }

    /// Whether the descriptor has a DACL, and how many entries it holds.
    ///
    /// # Errors
    ///
    /// The OS error of reading the descriptor.
    pub(in crate::formats) fn dacl_state(&self) -> io::Result<DaclState> {
        Ok(match dacl_of(self.0)? {
            None => DaclState::Null,
            Some((_, entries)) => DaclState::Present { entries },
        })
    }
}

impl Drop for Derived {
    fn drop(&mut self) {
        // SAFETY: the descriptor was made by `CreatePrivateObjectSecurityEx`
        // and is destroyed exactly once, here.
        unsafe { DestroyPrivateObjectSecurity(&raw const self.0) };
    }
}

/// A descriptor that is either read from an object or derived for one.
#[derive(Debug)]
pub(in crate::formats) enum Descriptor<'a> {
    /// Read from an object.
    Read(&'a SecurityDescriptor),
    /// Derived from a parent's.
    Derived(Derived),
}

impl Descriptor<'_> {
    /// Whether the DACL has an entry that children inherit.
    ///
    /// A missing or null DACL has none. A parent without one gives a child
    /// the token's default DACL, so the caller must check this before
    /// deriving from it.
    ///
    /// # Errors
    ///
    /// The OS error of reading the descriptor.
    pub(in crate::formats) fn has_inheritable_entries(&self) -> io::Result<bool> {
        let Some((acl, entries)) = dacl_of(self.as_ptr())? else {
            return Ok(false);
        };
        for index in 0..entries {
            let mut ace: *mut c_void = null_mut();
            // SAFETY: `acl` points into the descriptor, which is alive, `index`
            // is below its entry count and `ace` is valid for writes.
            win32(unsafe { GetAce(acl, index, &raw mut ace) })?;
            // SAFETY: on success `ace` points at a live entry in the ACL, and
            // every entry starts with an `ACE_HEADER`.
            let header = unsafe { ace.cast::<ACE_HEADER>().read_unaligned() };
            if u32::from(header.AceFlags) & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) != 0 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        match self {
            Self::Read(read) => read.as_ptr(),
            Self::Derived(derived) => derived.0,
        }
    }
}

/// Replaces the DACL of the object `handle` names with the one in
/// `descriptor`, keeping its protection and auto-inheritance bits.
///
/// A descriptor without a DACL stores a null DACL, as a faithful copy of one
/// must. `handle` must be open with `WRITE_DAC`.
///
/// # Errors
///
/// The OS error of the write.
pub(in crate::formats) fn apply_dacl(
    handle: BorrowedHandle<'_>,
    descriptor: &Descriptor<'_>,
) -> io::Result<()> {
    let ptr = descriptor.as_ptr();
    let protection = DaclProtection::of(control_of(ptr)?);
    // SAFETY: the handle is live, and `ptr` is a valid descriptor that
    // outlives the call and is only read.
    let ok = unsafe {
        SetKernelObjectSecurity(
            handle.as_raw_handle(),
            DACL_SECURITY_INFORMATION | protection.flag(),
            ptr,
        )
    };
    win32(ok)
}

/// The owner, group and DACL of a directory, as read from it.
///
/// Opaque outside `pinned_dir`: it can only be read from a directory and
/// applied to one, never edited, so a copied DACL keeps every bit it had.
#[derive(Debug)]
pub(crate) struct DirSecurity(SecurityDescriptor);

impl DirSecurity {
    /// Wraps a descriptor read with [`Part::OwnerGroupAndDacl`].
    pub(in crate::formats) const fn new(read: SecurityDescriptor) -> Self {
        Self(read)
    }

    pub(in crate::formats) const fn descriptor(&self) -> Descriptor<'_> {
        Descriptor::Read(&self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::formats::pinned_dir::dacl_probe;

    #[test]
    fn the_token_is_the_process_token_without_impersonation() {
        let token = EffectiveToken::open().unwrap();

        assert_eq!(token.source(), TokenSource::Process);
        assert_eq!(
            dacl_probe::sid_string_of(&token.user().unwrap()),
            dacl_probe::current_user()
        );
    }

    #[test]
    fn the_token_is_the_thread_token_under_impersonation() {
        let _impersonation = dacl_probe::Impersonation::start();

        let token = EffectiveToken::open().unwrap();

        assert_eq!(token.source(), TokenSource::Thread);
        assert_eq!(
            dacl_probe::sid_string_of(&token.user().unwrap()),
            dacl_probe::current_user()
        );
    }
}
