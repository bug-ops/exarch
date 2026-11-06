//! Typed security-policy refusals.
//!
//! [`Violation`] is the payload of [`ArchiveError::SecurityViolation`]. Each
//! kind fixes its own message, its [`SecurityViolationSubCode`] and the
//! `SecurityConfig` setting that relaxes it, so none of the three can be
//! supplied next to a kind that contradicts it.
//!
//! [`ArchiveError::SecurityViolation`]: super::ArchiveError::SecurityViolation

use std::fmt;

use super::messages::SecurityViolationSubCode;
use super::types::PolicySetting;
use crate::security::fs_view::LinkKind;
use crate::security::fs_view::PathModel;

/// A Unix file type that exarch never creates.
///
/// # Examples
///
/// ```
/// use exarch_core::SpecialFile;
///
/// assert_eq!(SpecialFile::Fifo.noun(), "FIFO");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpecialFile {
    /// A named pipe.
    Fifo,
    /// A character device node.
    CharDevice,
    /// A block device node.
    BlockDevice,
    /// A Unix domain socket.
    Socket,
}

impl SpecialFile {
    /// The noun used in refusal messages.
    #[must_use]
    pub const fn noun(self) -> &'static str {
        match self {
            Self::Fifo => "FIFO",
            Self::CharDevice => "character device",
            Self::BlockDevice => "block device",
            Self::Socket => "socket",
        }
    }
}

/// Why a path component is hazardous on some supported platform but not
/// necessarily on the host.
///
/// # Examples
///
/// ```
/// use exarch_core::PortableHazard;
///
/// assert_eq!(
///     PortableHazard::Backslash.to_string(),
///     "contains a backslash"
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PortableHazard {
    /// Not valid UTF-8, so UTF-16 and UTF-8 filesystems would read it
    /// differently.
    NotUtf8,
    /// `\` separates components on Windows.
    Backslash,
    /// One of `<>"|?*` or a control character, which Windows refuses.
    ForbiddenCharacter,
}

impl fmt::Display for PortableHazard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotUtf8 => "not valid UTF-8",
            Self::Backslash => "contains a backslash",
            Self::ForbiddenCharacter => "contains a character Windows refuses",
        })
    }
}

/// What a 7z header itself says an entry is: a directory has no stream and is
/// not flagged as an empty file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeKind {
    /// Holds data or is an empty file.
    File,
    /// Has no stream and is not an empty file.
    Directory,
}

impl NativeKind {
    const fn noun(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
        }
    }

    const fn opposite(self) -> &'static str {
        match self {
            Self::File => "directory",
            Self::Directory => "regular file",
        }
    }
}

/// Where a claim about a 7z entry's kind was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KindSource {
    /// The Unix mode in the high 16 bits of the attributes.
    UnixMode,
    /// The Windows `FILE_ATTRIBUTE_DIRECTORY` bit.
    WindowsAttribute,
}

impl KindSource {
    const fn noun(self) -> &'static str {
        match self {
            Self::UnixMode => "Unix mode",
            Self::WindowsAttribute => "Windows attributes",
        }
    }
}

/// Why an operation was denied by security policy.
///
/// Text payloads are already rendered (escaped where an attacker controls
/// them), so a `Violation` never holds a crate-private type.
/// [`Self::relaxable_by`] and [`Self::sub_code`] are derived from the kind.
///
/// # Examples
///
/// ```
/// use exarch_core::ArchiveError;
/// use exarch_core::PolicySetting;
/// use exarch_core::SecurityViolationSubCode;
/// use exarch_core::Violation;
///
/// let kind = Violation::BannedComponent {
///     component: ".git".into(),
/// };
/// assert_eq!(kind.relaxable_by(), Some(PolicySetting::BannedComponents));
/// assert_eq!(kind.sub_code(), SecurityViolationSubCode::PathName);
/// assert_eq!(kind.to_string(), "banned path component: .git");
///
/// let err = ArchiveError::from(kind);
/// assert_eq!(err.relaxable_by(), Some(PolicySetting::BannedComponents));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Violation {
    /// An entry or argument path is empty.
    EmptyPath,
    /// An entry path contains a NUL byte.
    NulInPath {
        /// The path, rendered for display.
        path: Box<str>,
    },
    /// A caller-supplied path argument contains a NUL byte.
    NulInPathArgument,
    /// A caller-supplied path argument exceeds the length limit.
    PathTooLong {
        /// Length of the path in bytes.
        len: usize,
        /// The limit in bytes.
        max: usize,
    },
    /// A path component is on the banned list.
    BannedComponent {
        /// The component.
        component: Box<str>,
    },
    /// A path component holds a character no supported platform accepts.
    UnsafeComponent {
        /// What makes the component hazardous.
        hazard: PortableHazard,
        /// The rule set that found it.
        model: PathModel,
        /// The component, escaped.
        component: Box<str>,
    },
    /// A path component is a Windows reserved device name.
    ReservedDeviceName {
        /// The component, escaped.
        component: Box<str>,
    },
    /// A path component ends with a dot or a space.
    TrailingDotOrSpace {
        /// The component, escaped.
        component: Box<str>,
    },
    /// A path component contains `:`.
    StreamSeparator {
        /// The component, escaped.
        component: Box<str>,
    },
    /// An entry path is deeper than the limit.
    PathDepth {
        /// Depth of the path.
        depth: usize,
        /// The limit.
        max: usize,
    },
    /// A symlink target is deeper than the limit.
    SymlinkTargetDepth {
        /// Depth of the target.
        depth: usize,
        /// The limit.
        max: usize,
    },
    /// A link target is empty.
    LinkTargetEmpty(LinkKind),
    /// A link target contains a NUL byte.
    LinkTargetNul(LinkKind),
    /// A symlink target contains a banned path component.
    LinkTargetBannedComponent {
        /// The component.
        component: Box<str>,
    },
    /// A symlink target stored as entry data is above the host limit.
    LinkTargetTooLarge {
        /// Size of the stored target in bytes.
        size: u64,
        /// The limit in bytes.
        max: u64,
    },
    /// A link entry has no target.
    LinkTargetMissing(LinkKind),
    /// A link target was not read, so it cannot be validated.
    LinkTargetUnread(LinkKind),
    /// A link target could not be read, so it cannot be validated.
    LinkTargetUnreadable(LinkKind),
    /// A Windows reparse point, whose target cannot be read.
    ReparsePointTarget {
        /// The entry name.
        name: Box<str>,
    },
    /// The kind of link is disabled by the configuration.
    LinksNotAllowed(LinkKind),
    /// A path component below the destination is a symlink the policy refuses.
    SymlinkComponent {
        /// The walked path up to and including the symlink.
        walked: Box<str>,
    },
    /// A parent of the entry is a symlink that does not resolve to a
    /// directory.
    SymlinkParent {
        /// The entry that would be created.
        entry: Box<str>,
        /// The blocking parent.
        parent: Box<str>,
    },
    /// The destination changed between the check that vetted it and the
    /// replace that acts on it.
    DestinationChanged,
    /// The entry would replace an existing symlink.
    ReplacesSymlink {
        /// The entry path.
        rel: Box<str>,
    },
    /// A device node, FIFO or socket.
    SpecialEntry {
        /// Which special file.
        kind: SpecialFile,
        /// The entry name, when the format reports it.
        name: Option<Box<str>>,
    },
    /// A TAR typeflag that is not a file, directory or link.
    UnsupportedTarType {
        /// The typeflag, rendered.
        kind: Box<str>,
    },
    /// A 7z Unix mode whose type bits name no defined file type.
    UndefinedUnixType {
        /// The type bits, shifted down.
        bits: u8,
        /// The entry name.
        name: Box<str>,
    },
    /// A 7z entry whose recorded kind contradicts its native kind.
    KindContradiction {
        /// What the 7z header says.
        native: NativeKind,
        /// Where the contradicting claim was recorded.
        claimed_by: KindSource,
        /// The entry name.
        name: Box<str>,
    },
    /// A root entry that is not a directory.
    RootEntryNotDirectory,
    /// A ZIP root entry that is neither a directory nor an empty file.
    RootEntryNotDirectoryOrEmptyFile,
    /// The whole archive is password-protected.
    EncryptedArchive,
    /// One ZIP entry is encrypted.
    EncryptedEntry {
        /// The entry name.
        name: Box<str>,
    },
    /// A ZIP compression method exarch does not read.
    UnsupportedCompressionMethod {
        /// The method, rendered.
        method: Box<str>,
    },
    /// A solid 7z archive while solid archives are disabled.
    SolidArchive,
    /// A stream decompressed past its declared size.
    DeclaredSizeExceeded {
        /// The declared uncompressed size in bytes.
        declared: u64,
    },
    /// A stream ended before its declared size.
    DeclaredSizeMismatch {
        /// The declared uncompressed size in bytes.
        declared: u64,
        /// The bytes actually produced.
        actual: u64,
    },
    /// A hardlink target changed while it was being copied.
    HardlinkTargetChanged,
    /// A TAR read passed the metadata budget.
    TarMetadataBudget {
        /// The budget in bytes.
        limit: u64,
    },
    /// A TAR archive drained more synthesized bytes than the cross-entry cap.
    TarSyntheticBudget {
        /// The cap in bytes.
        limit: u64,
    },
    /// The host cannot create symlinks.
    SymlinksUnsupported,
    /// Extraction can fail at an entry unless duplicates are skipped.
    ConflictUnlessSkipped {
        /// The entry path.
        rel: Box<str>,
        /// The filesystem error, rendered.
        cause: Box<str>,
    },
    /// Extraction fails at an entry.
    ConflictFails {
        /// The entry path.
        rel: Box<str>,
        /// The filesystem error, rendered.
        cause: Box<str>,
    },
    /// A hardlink whose target entry the extraction does not write.
    HardlinkTargetNotExtracted {
        /// The hardlink entry path.
        link: Box<str>,
        /// The target path, as the archive names it.
        target: Box<str>,
    },
    /// A symlink or hardlink entry under a flattening rewrite.
    LinkUnderFlatten {
        /// Which kind of link the entry is.
        kind: LinkKind,
        /// The entry path.
        name: Box<str>,
    },
    /// A source path to archive lies outside the archive root.
    SourceOutsideRoot {
        /// The source path.
        path: Box<str>,
        /// The root directory.
        root: Box<str>,
    },
}

impl Violation {
    /// The `SecurityConfig` setting whose current value refused the entry, or
    /// `None` when no setting relaxes this refusal.
    #[must_use]
    pub const fn relaxable_by(&self) -> Option<PolicySetting> {
        match self {
            Self::BannedComponent { .. } | Self::LinkTargetBannedComponent { .. } => {
                Some(PolicySetting::BannedComponents)
            }
            Self::ReservedDeviceName { .. } => Some(PolicySetting::WindowsReservedNames),
            Self::PathDepth { .. } | Self::SymlinkTargetDepth { .. } => {
                Some(PolicySetting::MaxPathDepth)
            }
            Self::LinksNotAllowed(LinkKind::Symlink) | Self::SymlinkComponent { .. } => {
                Some(PolicySetting::Symlinks)
            }
            Self::LinksNotAllowed(LinkKind::Hardlink) => Some(PolicySetting::Hardlinks),
            Self::SolidArchive => Some(PolicySetting::SolidArchives),
            Self::TarMetadataBudget { .. } => Some(PolicySetting::MaxTarMetadataBytes),
            Self::EmptyPath
            | Self::NulInPath { .. }
            | Self::NulInPathArgument
            | Self::PathTooLong { .. }
            | Self::UnsafeComponent { .. }
            | Self::TrailingDotOrSpace { .. }
            | Self::StreamSeparator { .. }
            | Self::LinkTargetEmpty(_)
            | Self::LinkTargetNul(_)
            | Self::LinkTargetTooLarge { .. }
            | Self::LinkTargetMissing(_)
            | Self::LinkTargetUnread(_)
            | Self::LinkTargetUnreadable(_)
            | Self::ReparsePointTarget { .. }
            | Self::SymlinkParent { .. }
            | Self::ReplacesSymlink { .. }
            | Self::SpecialEntry { .. }
            | Self::UnsupportedTarType { .. }
            | Self::UndefinedUnixType { .. }
            | Self::KindContradiction { .. }
            | Self::RootEntryNotDirectory
            | Self::RootEntryNotDirectoryOrEmptyFile
            | Self::EncryptedArchive
            | Self::EncryptedEntry { .. }
            | Self::UnsupportedCompressionMethod { .. }
            | Self::DeclaredSizeExceeded { .. }
            | Self::DeclaredSizeMismatch { .. }
            | Self::HardlinkTargetChanged
            | Self::DestinationChanged
            | Self::TarSyntheticBudget { .. }
            | Self::SymlinksUnsupported
            | Self::ConflictUnlessSkipped { .. }
            | Self::ConflictFails { .. }
            | Self::HardlinkTargetNotExtracted { .. }
            | Self::LinkUnderFlatten { .. }
            | Self::SourceOutsideRoot { .. } => None,
        }
    }

    /// The family this kind belongs to.
    #[must_use]
    pub const fn sub_code(&self) -> SecurityViolationSubCode {
        use SecurityViolationSubCode as C;
        match self {
            Self::EmptyPath
            | Self::NulInPath { .. }
            | Self::NulInPathArgument
            | Self::PathTooLong { .. }
            | Self::BannedComponent { .. }
            | Self::UnsafeComponent { .. }
            | Self::ReservedDeviceName { .. }
            | Self::TrailingDotOrSpace { .. }
            | Self::StreamSeparator { .. } => C::PathName,
            Self::PathDepth { .. } | Self::SymlinkTargetDepth { .. } => C::PathDepth,
            Self::LinkTargetEmpty(_)
            | Self::LinkTargetNul(_)
            | Self::LinkTargetBannedComponent { .. }
            | Self::LinkTargetTooLarge { .. }
            | Self::LinkTargetMissing(_)
            | Self::LinkTargetUnread(_)
            | Self::LinkTargetUnreadable(_)
            | Self::HardlinkTargetNotExtracted { .. }
            | Self::ReparsePointTarget { .. } => C::LinkTarget,
            Self::LinksNotAllowed(_) | Self::LinkUnderFlatten { .. } => C::LinkPolicy,
            Self::SymlinkComponent { .. }
            | Self::SymlinkParent { .. }
            | Self::ReplacesSymlink { .. } => C::ExistingSymlink,
            Self::SpecialEntry { .. }
            | Self::UnsupportedTarType { .. }
            | Self::UndefinedUnixType { .. }
            | Self::KindContradiction { .. } => C::EntryType,
            Self::RootEntryNotDirectory | Self::RootEntryNotDirectoryOrEmptyFile => C::RootEntry,
            Self::EncryptedArchive | Self::EncryptedEntry { .. } => C::Encrypted,
            Self::UnsupportedCompressionMethod { .. } => C::CompressionMethod,
            Self::SolidArchive => C::SolidArchive,
            Self::DeclaredSizeExceeded { .. } | Self::DeclaredSizeMismatch { .. } => {
                C::DeclaredSize
            }
            Self::HardlinkTargetChanged | Self::DestinationChanged => C::ConcurrentChange,
            Self::TarMetadataBudget { .. } | Self::TarSyntheticBudget { .. } => C::TarMetadata,
            Self::SymlinksUnsupported => C::Platform,
            Self::ConflictUnlessSkipped { .. } | Self::ConflictFails { .. } => C::OutputConflict,
            Self::SourceOutsideRoot { .. } => C::SourcePath,
        }
    }
}

pub(crate) fn fmt_tar_read_budget(f: &mut fmt::Formatter<'_>, limit: u64) -> fmt::Result {
    write!(
        f,
        "TAR metadata read budget exceeded: more than {limit} bytes read while searching for \
         the next archive entry (long-name/long-link/PAX headers, or a run of GNU sparse \
         extension blocks)"
    )
}

pub(crate) fn fmt_tar_synthetic_budget(f: &mut fmt::Formatter<'_>, limit: u64) -> fmt::Result {
    write!(
        f,
        "TAR cumulative synthetic-byte drain budget exceeded: more than {limit} bytes of \
         synthesized (unbacked) padding drained from unread entries across this archive"
    )
}

impl fmt::Display for Violation {
    #[expect(
        clippy::too_many_lines,
        reason = "one flat match over every kind keeps each message next to its kind"
    )]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath => f.write_str(crate::types::safe_path::EMPTY_PATH_REASON),
            Self::NulInPath { path } => write!(f, "path contains null bytes: {path}"),
            Self::NulInPathArgument => {
                f.write_str("path contains null bytes - potential security issue")
            }
            Self::PathTooLong { len, max } => write!(
                f,
                "path exceeds maximum length of {max} bytes (got {len} bytes)"
            ),
            Self::BannedComponent { component } => {
                write!(f, "banned path component: {component}")
            }
            Self::UnsafeComponent {
                hazard,
                model: PathModel::Portable,
                component,
            } => write!(f, "path component is not portable ({hazard}): {component}"),
            Self::UnsafeComponent {
                hazard, component, ..
            } => write!(f, "path component {hazard}: {component}"),
            Self::KindContradiction {
                native,
                claimed_by,
                name,
            } => write!(
                f,
                "7z entry is a {} but its {} says {}: {name}",
                native.noun(),
                claimed_by.noun(),
                native.opposite()
            ),
            Self::ReservedDeviceName { component } => {
                write!(f, "Windows reserved device name: {component}")
            }
            Self::TrailingDotOrSpace { component } => {
                write!(f, "path component ends with '.' or ' ': {component}")
            }
            Self::StreamSeparator { component } => {
                write!(f, "path component contains ':': {component}")
            }
            Self::PathDepth { depth, max } => {
                write!(f, "path depth {depth} exceeds maximum {max}")
            }
            Self::SymlinkTargetDepth { depth, max } => {
                write!(f, "symlink target depth {depth} exceeds maximum {max}")
            }
            Self::LinkTargetEmpty(kind) => write!(f, "{kind} target is empty"),
            Self::LinkTargetNul(kind) => write!(f, "{kind} target contains null bytes"),
            Self::LinkTargetBannedComponent { component } => {
                write!(f, "symlink target contains banned component: {component}")
            }
            Self::LinkTargetTooLarge { size, max } => {
                write!(f, "symlink target too large: {size} bytes (max {max})")
            }
            Self::LinkTargetMissing(kind) => write!(f, "{kind} target is missing"),
            Self::LinkTargetUnread(kind) => {
                write!(f, "{kind} target was not read, so it cannot be validated")
            }
            Self::LinkTargetUnreadable(kind) => write!(
                f,
                "{kind} target could not be read, so it cannot be validated"
            ),
            Self::ReparsePointTarget { name } => write!(
                f,
                "symlink detected in 7z archive: {name} (Windows reparse point attribute set). \
                 Its target cannot be read due to sevenz-rust2 API limitations."
            ),
            Self::LinksNotAllowed(kind) => write!(f, "{kind}s not allowed"),
            Self::SymlinkComponent { walked } => {
                write!(f, "path component is a symlink: {walked}")
            }
            Self::SymlinkParent { entry, parent } => write!(
                f,
                "refusing to create {entry} under the existing symlink at {parent}"
            ),
            Self::ReplacesSymlink { rel } => {
                write!(f, "refusing to replace the existing symlink at {rel}")
            }
            Self::SpecialEntry { kind, name: None } => {
                write!(f, "{} entries not supported", kind.noun())
            }
            Self::SpecialEntry {
                kind,
                name: Some(name),
            } => write!(f, "{} entries not supported: {name}", kind.noun()),
            Self::UnsupportedTarType { kind } => write!(f, "unsupported entry type: {kind}"),
            Self::UndefinedUnixType { bits, name } => write!(
                f,
                "7z entry has an undefined Unix file type ({bits:#x}): {name}"
            ),
            Self::RootEntryNotDirectory => {
                f.write_str("archive root entry '.' must be a directory")
            }
            Self::RootEntryNotDirectoryOrEmptyFile => {
                f.write_str("archive root entry '.' must be a directory or an empty regular file")
            }
            Self::EncryptedArchive => f.write_str(
                "archive is encrypted (password-protected). Encrypted archives are not \
                 supported; decrypt the archive externally and try again.",
            ),
            Self::EncryptedEntry { name } => write!(f, "encrypted entry detected: {name}"),
            Self::UnsupportedCompressionMethod { method } => {
                write!(f, "unsupported compression method: {method}")
            }
            Self::SolidArchive => {
                f.write_str("solid 7z archives are not allowed (enable allow_solid_archives)")
            }
            Self::DeclaredSizeExceeded { declared } => write!(
                f,
                "decompressed size exceeded the declared uncompressed size of {declared} bytes"
            ),
            Self::DeclaredSizeMismatch { declared, actual } => write!(
                f,
                "decompressed size ({actual} bytes) does not match the declared uncompressed \
                 size ({declared} bytes)"
            ),
            Self::HardlinkTargetChanged => {
                f.write_str("hardlink target changed while it was being copied")
            }
            Self::DestinationChanged => {
                f.write_str("the destination changed while it was being replaced")
            }
            Self::TarMetadataBudget { limit } => fmt_tar_read_budget(f, *limit),
            Self::TarSyntheticBudget { limit } => fmt_tar_synthetic_budget(f, *limit),
            Self::SymlinksUnsupported => f.write_str("symlinks are not supported on this platform"),
            Self::ConflictUnlessSkipped { rel, cause } => write!(
                f,
                "extraction can fail at {rel} unless duplicates are skipped: {cause}"
            ),
            Self::ConflictFails { rel, cause } => {
                write!(f, "extraction fails at {rel}: {cause}")
            }
            Self::HardlinkTargetNotExtracted { link, target } => write!(
                f,
                "hardlink {link} points at {target}, which the selection does not extract"
            ),
            Self::LinkUnderFlatten { kind, name } => {
                write!(f, "flattening refuses {kind} entries: {name}")
            }
            Self::SourceOutsideRoot { path, root } => {
                write!(f, "path {path} is not under root directory: {root}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> Box<str> {
        s.into()
    }

    #[expect(
        clippy::too_many_lines,
        reason = "a table with one row per Violation kind"
    )]
    fn one_of_each() -> Vec<(Violation, SecurityViolationSubCode, Option<PolicySetting>)> {
        use SecurityViolationSubCode as C;
        let link = LinkKind::Symlink;
        vec![
            (Violation::EmptyPath, C::PathName, None),
            (Violation::NulInPath { path: text("p") }, C::PathName, None),
            (Violation::NulInPathArgument, C::PathName, None),
            (Violation::PathTooLong { len: 2, max: 1 }, C::PathName, None),
            (
                Violation::BannedComponent {
                    component: text("c"),
                },
                C::PathName,
                Some(PolicySetting::BannedComponents),
            ),
            (
                Violation::UnsafeComponent {
                    hazard: PortableHazard::Backslash,
                    model: PathModel::Portable,
                    component: text("c"),
                },
                C::PathName,
                None,
            ),
            (
                Violation::ReservedDeviceName {
                    component: text("c"),
                },
                C::PathName,
                Some(PolicySetting::WindowsReservedNames),
            ),
            (
                Violation::TrailingDotOrSpace {
                    component: text("c"),
                },
                C::PathName,
                None,
            ),
            (
                Violation::StreamSeparator {
                    component: text("c"),
                },
                C::PathName,
                None,
            ),
            (
                Violation::PathDepth { depth: 2, max: 1 },
                C::PathDepth,
                Some(PolicySetting::MaxPathDepth),
            ),
            (
                Violation::SymlinkTargetDepth { depth: 2, max: 1 },
                C::PathDepth,
                Some(PolicySetting::MaxPathDepth),
            ),
            (Violation::LinkTargetEmpty(link), C::LinkTarget, None),
            (Violation::LinkTargetNul(link), C::LinkTarget, None),
            (
                Violation::LinkTargetBannedComponent {
                    component: text("c"),
                },
                C::LinkTarget,
                Some(PolicySetting::BannedComponents),
            ),
            (
                Violation::LinkTargetTooLarge { size: 2, max: 1 },
                C::LinkTarget,
                None,
            ),
            (Violation::LinkTargetMissing(link), C::LinkTarget, None),
            (Violation::LinkTargetUnread(link), C::LinkTarget, None),
            (Violation::LinkTargetUnreadable(link), C::LinkTarget, None),
            (
                Violation::ReparsePointTarget { name: text("n") },
                C::LinkTarget,
                None,
            ),
            (
                Violation::LinksNotAllowed(LinkKind::Symlink),
                C::LinkPolicy,
                Some(PolicySetting::Symlinks),
            ),
            (
                Violation::LinksNotAllowed(LinkKind::Hardlink),
                C::LinkPolicy,
                Some(PolicySetting::Hardlinks),
            ),
            (
                Violation::SymlinkComponent { walked: text("w") },
                C::ExistingSymlink,
                Some(PolicySetting::Symlinks),
            ),
            (
                Violation::SymlinkParent {
                    entry: text("e"),
                    parent: text("p"),
                },
                C::ExistingSymlink,
                None,
            ),
            (
                Violation::ReplacesSymlink { rel: text("r") },
                C::ExistingSymlink,
                None,
            ),
            (
                Violation::SpecialEntry {
                    kind: SpecialFile::Fifo,
                    name: None,
                },
                C::EntryType,
                None,
            ),
            (
                Violation::UnsupportedTarType { kind: text("k") },
                C::EntryType,
                None,
            ),
            (
                Violation::UndefinedUnixType {
                    bits: 1,
                    name: text("n"),
                },
                C::EntryType,
                None,
            ),
            (
                Violation::KindContradiction {
                    native: NativeKind::File,
                    claimed_by: KindSource::UnixMode,
                    name: text("n"),
                },
                C::EntryType,
                None,
            ),
            (Violation::RootEntryNotDirectory, C::RootEntry, None),
            (
                Violation::RootEntryNotDirectoryOrEmptyFile,
                C::RootEntry,
                None,
            ),
            (Violation::EncryptedArchive, C::Encrypted, None),
            (
                Violation::EncryptedEntry { name: text("n") },
                C::Encrypted,
                None,
            ),
            (
                Violation::UnsupportedCompressionMethod { method: text("m") },
                C::CompressionMethod,
                None,
            ),
            (
                Violation::SolidArchive,
                C::SolidArchive,
                Some(PolicySetting::SolidArchives),
            ),
            (
                Violation::DeclaredSizeExceeded { declared: 1 },
                C::DeclaredSize,
                None,
            ),
            (
                Violation::DeclaredSizeMismatch {
                    declared: 1,
                    actual: 2,
                },
                C::DeclaredSize,
                None,
            ),
            (Violation::HardlinkTargetChanged, C::ConcurrentChange, None),
            (Violation::DestinationChanged, C::ConcurrentChange, None),
            (
                Violation::TarMetadataBudget { limit: 1 },
                C::TarMetadata,
                Some(PolicySetting::MaxTarMetadataBytes),
            ),
            (
                Violation::TarSyntheticBudget { limit: 1 },
                C::TarMetadata,
                None,
            ),
            (Violation::SymlinksUnsupported, C::Platform, None),
            (
                Violation::ConflictUnlessSkipped {
                    rel: text("r"),
                    cause: text("c"),
                },
                C::OutputConflict,
                None,
            ),
            (
                Violation::ConflictFails {
                    rel: text("r"),
                    cause: text("c"),
                },
                C::OutputConflict,
                None,
            ),
            (
                Violation::HardlinkTargetNotExtracted {
                    link: text("l"),
                    target: text("t"),
                },
                C::LinkTarget,
                None,
            ),
            (
                Violation::LinkUnderFlatten {
                    kind: link,
                    name: text("n"),
                },
                C::LinkPolicy,
                None,
            ),
            (
                Violation::SourceOutsideRoot {
                    path: text("p"),
                    root: text("r"),
                },
                C::SourcePath,
                None,
            ),
        ]
    }

    #[test]
    fn test_every_kind_has_family_setting_and_text() {
        for (kind, code, setting) in one_of_each() {
            assert_eq!(kind.sub_code(), code, "{kind:?}");
            assert_eq!(kind.relaxable_by(), setting, "{kind:?}");
            assert!(!kind.to_string().is_empty(), "{kind:?}");
        }
    }

    /// The text of each `one_of_each` row, in order; byte-identical to the
    /// pre-typing messages (verified by the security audit), and callers match
    /// on them, so a wording change must be a deliberate edit here.
    const EXPECTED_TEXT: [&str; 46] = [
        "empty path not allowed",
        "path contains null bytes: p",
        "path contains null bytes - potential security issue",
        "path exceeds maximum length of 1 bytes (got 2 bytes)",
        "banned path component: c",
        "path component is not portable (contains a backslash): c",
        "Windows reserved device name: c",
        "path component ends with '.' or ' ': c",
        "path component contains ':': c",
        "path depth 2 exceeds maximum 1",
        "symlink target depth 2 exceeds maximum 1",
        "symlink target is empty",
        "symlink target contains null bytes",
        "symlink target contains banned component: c",
        "symlink target too large: 2 bytes (max 1)",
        "symlink target is missing",
        "symlink target was not read, so it cannot be validated",
        "symlink target could not be read, so it cannot be validated",
        "symlink detected in 7z archive: n (Windows reparse point attribute set). Its target cannot be read due to sevenz-rust2 API limitations.",
        "symlinks not allowed",
        "hardlinks not allowed",
        "path component is a symlink: w",
        "refusing to create e under the existing symlink at p",
        "refusing to replace the existing symlink at r",
        "FIFO entries not supported",
        "unsupported entry type: k",
        "7z entry has an undefined Unix file type (0x1): n",
        "7z entry is a file but its Unix mode says directory: n",
        "archive root entry '.' must be a directory",
        "archive root entry '.' must be a directory or an empty regular file",
        "archive is encrypted (password-protected). Encrypted archives are not supported; decrypt the archive externally and try again.",
        "encrypted entry detected: n",
        "unsupported compression method: m",
        "solid 7z archives are not allowed (enable allow_solid_archives)",
        "decompressed size exceeded the declared uncompressed size of 1 bytes",
        "decompressed size (2 bytes) does not match the declared uncompressed size (1 bytes)",
        "hardlink target changed while it was being copied",
        "the destination changed while it was being replaced",
        "TAR metadata read budget exceeded: more than 1 bytes read while searching for the next archive entry (long-name/long-link/PAX headers, or a run of GNU sparse extension blocks)",
        "TAR cumulative synthetic-byte drain budget exceeded: more than 1 bytes of synthesized (unbacked) padding drained from unread entries across this archive",
        "symlinks are not supported on this platform",
        "extraction can fail at r unless duplicates are skipped: c",
        "extraction fails at r: c",
        "hardlink l points at t, which the selection does not extract",
        "flattening refuses symlink entries: n",
        "path p is not under root directory: r",
    ];

    #[test]
    fn test_every_kind_renders_its_pinned_text() {
        let kinds = one_of_each();
        assert_eq!(kinds.len(), EXPECTED_TEXT.len());
        for ((kind, ..), expected) in kinds.iter().zip(EXPECTED_TEXT) {
            assert_eq!(kind.to_string(), expected, "{kind:?}");
        }
    }

    #[test]
    fn test_every_family_has_a_kind() {
        let seen: Vec<_> = one_of_each().iter().map(|(k, ..)| k.sub_code()).collect();
        for code in SecurityViolationSubCode::ALL {
            assert!(
                *code == SecurityViolationSubCode::TarTrailer || seen.contains(code),
                "{code} has no Violation kind"
            );
        }
    }

    #[test]
    fn test_link_policy_text_names_the_link_kind() {
        assert_eq!(
            Violation::LinksNotAllowed(LinkKind::Symlink).to_string(),
            "symlinks not allowed"
        );
        assert_eq!(
            Violation::LinksNotAllowed(LinkKind::Hardlink).to_string(),
            "hardlinks not allowed"
        );
    }
}
