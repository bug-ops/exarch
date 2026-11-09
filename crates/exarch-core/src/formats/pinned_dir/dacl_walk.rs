//! Rewrites the DACLs of a published tree through handles.
//!
//! The staging tree is owner-only while it is extracted, and its entries carry
//! the owner-only entry the staging root inherited. Once the root is published
//! each entry must get the DACL it would have had if it had been created in
//! place under the destination. The walk derives that DACL for every entry from
//! its parent's final one, as the kernel does at create time, and applies it
//! through a handle.
//!
//! Every entry is opened relative to its parent's handle with the reparse
//! point opened itself, so a junction planted inside the tree is never
//! followed: it gets its own DACL rewritten and is not descended. Entries are
//! opened for `READ_CONTROL`, `WRITE_DAC` and `FILE_READ_ATTRIBUTES` only, so a
//! file the owner may not read is still reachable. Directories are listed
//! through a second handle reopened on the first.
//!
//! The walk is iterative with an explicit stack: the DACLs are derived top
//! down and applied post-order, so a directory is rewritten only after
//! everything below it, and every directory the walk still has to list is
//! owner-only until then.

use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::AsHandle;
use std::os::windows::io::BorrowedHandle;
use std::os::windows::io::OwnedHandle;

use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
use windows_sys::Win32::Storage::FileSystem::FILE_LIST_DIRECTORY;
use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::FILE_TRAVERSE;
use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
use windows_sys::Win32::Storage::FileSystem::WRITE_DAC;

use super::Leaf;
use super::nt;
use super::nt::Request;
use super::nt::security;
use super::nt::security::Derived;
use super::nt::security::Descriptor;
use super::nt::security::EffectiveToken;
use super::nt::security::ObjectKind;
use super::nt::security::Part;
use super::nt::security::SecurityDescriptor;

const ENTRY_ACCESS: u32 = READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES;
const LISTING_ACCESS: u32 = FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES;

/// What the walk does with an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryClass {
    /// A real directory: rewritten after everything below it.
    Tree,
    /// A junction or symlink to a directory: rewritten itself, never
    /// descended.
    Link,
    /// Anything else.
    Leaf,
}

impl EntryClass {
    const fn of(attributes: u32) -> Self {
        if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            Self::Leaf
        } else if attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
            Self::Tree
        } else {
            Self::Link
        }
    }

    const fn kind(self) -> ObjectKind {
        match self {
            Self::Tree | Self::Link => ObjectKind::Container,
            Self::Leaf => ObjectKind::Leaf,
        }
    }
}

/// An entry opened for its security, with what the walk needs to know of it.
struct Entry {
    handle: OwnedHandle,
    class: EntryClass,
}

/// The DACL a directory ends up with: the root's is the caller's, every other
/// one is derived by the walk.
enum Computed<'a> {
    Root(&'a Descriptor<'a>),
    Derived(Descriptor<'static>),
}

impl<'a> Computed<'a> {
    const fn get(&self) -> &Descriptor<'a> {
        match self {
            Self::Root(root) => root,
            Self::Derived(derived) => derived,
        }
    }
}

/// A directory whose entries are being rewritten.
struct Level<'d> {
    /// Opened for listing, and the parent of its entries' opens.
    listing: OwnedHandle,
    /// Opened for `WRITE_DAC`; `None` for the root, which the caller rewrites
    /// last.
    apply: Option<OwnedHandle>,
    computed: Computed<'d>,
    names: Vec<OsString>,
}

/// One normal path component, or an `InvalidData` error.
fn leaf_of(name: &OsStr) -> io::Result<Leaf<'_>> {
    Leaf::of_name(name).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
}

fn list(listing: BorrowedHandle<'_>) -> io::Result<Vec<OsString>> {
    Ok(nt::list_names(listing)?
        .into_iter()
        .map(|units| OsString::from_wide(&units))
        .collect())
}

fn open_entry(parent: BorrowedHandle<'_>, name: &OsStr) -> io::Result<Entry> {
    let handle = nt::create_at(parent, leaf_of(name)?, Request::open(ENTRY_ACCESS))?;
    let file = File::from(handle);
    let attributes = file.metadata()?.file_attributes();
    Ok(Entry {
        handle: OwnedHandle::from(file),
        class: EntryClass::of(attributes),
    })
}

/// Gives every entry below the directory `root` the DACL it would have had
/// created in place under a directory whose DACL is `computed`.
///
/// `root` must be open with `READ_CONTROL`, `WRITE_DAC` and
/// `FILE_READ_ATTRIBUTES`; it is not rewritten. The first failure stops the
/// walk and leaves the entries not yet reached as they were.
///
/// # Errors
///
/// The OS error of the first open, listing, derivation or write that failed,
/// or `InvalidData` for a listing that does not parse.
pub(super) fn rewrite_children(
    root: BorrowedHandle<'_>,
    computed: &Descriptor<'_>,
    token: &EffectiveToken,
) -> io::Result<()> {
    let listing = nt::reopen_dir(root, LISTING_ACCESS)?;
    let names = list(listing.as_handle())?;
    let mut stack = vec![Level {
        listing,
        apply: None,
        computed: Computed::Root(computed),
        names,
    }];
    while let Some(level) = stack.last_mut() {
        let Some(name) = level.names.pop() else {
            if let Some(done) = stack.pop()
                && let Some(apply) = done.apply
            {
                security::apply_dacl(apply.as_handle(), done.computed.get())?;
            }
            continue;
        };
        let entry = open_entry(level.listing.as_handle(), &name)?;
        let creator = SecurityDescriptor::read(entry.handle.as_handle(), Part::OwnerAndGroup)?;
        let derived = Derived::new(level.computed.get(), &creator, entry.class.kind(), token)?;
        let computed = Computed::Derived(Descriptor::Derived(derived));
        if entry.class == EntryClass::Tree {
            let listing = nt::reopen_dir(entry.handle.as_handle(), LISTING_ACCESS)?;
            let names = list(listing.as_handle())?;
            stack.push(Level {
                listing,
                apply: Some(entry.handle),
                computed,
                names,
            });
        } else {
            security::apply_dacl(entry.handle.as_handle(), computed.get())?;
        }
    }
    Ok(())
}
