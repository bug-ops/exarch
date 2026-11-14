//! Error conversion for Node.js bindings.
//!
//! Every failure that reaches JavaScript is built by one env-taking builder,
//! [`IntoJsError::into_js_error`]. The rejection or exception is a real JS
//! `Error` whose `message` is the human-readable description only; the
//! machine-readable data lives in typed properties:
//!
//! - `code`: an [`ErrorCode`] string. Core errors keep their core code
//!   (`SECURITY_VIOLATION` for a rejected boundary path,
//!   `INVALID_CONFIGURATION` for a rejected setter value);
//!   `PROGRESS_CALLBACK_ERROR`, `STREAM_ERROR`, `ENTRY_CALLBACK_ERROR` and
//!   `ABORT_ERR` (an `AbortError`) are Node-only.
//! - `relaxableBy`: the [`PolicySetting`] that relaxes a refusal, when one
//!   does.
//! - `subCode`: an [`InvalidArchiveSubCode`] on an `INVALID_ARCHIVE`, when the
//!   failure has a finer classification, a [`SecurityViolationSubCode`] on
//!   every core `SECURITY_VIOLATION`, a [`QuotaSubCode`] on every
//!   `QUOTA_EXCEEDED` and a [`ZipBombSubCode`] on every `ZIP_BOMB`.
//! - `setting`: the [`ConfigSetting`] an `INVALID_CONFIGURATION` refused.
//! - `ioKind`: the [`IoKind`] of an `IO_ERROR`.
//! - `errno`, `strerror`, `path`: the OS failure behind a
//!   `SOURCE_NOT_ACCESSIBLE` and the source it names, redacted like the
//!   message.
//! - `restore`, `backupPath`, `leftoverPath`: what a failed `'atomic_replace'`
//!   (or a left-behind output reservation) left on disk, redacted like paths.
//! - `conflicts`, `by`: the entries that stopped a `'refuse'` extraction, or an
//!   `'overwrite'` extraction that met a directory occupant or a hardlink over
//!   a file, each as `{ path, occupant? }` with the kind of occupant, and who
//!   made the occupant (`'existing'` or `'archive'`). `by` is also set on an
//!   `EXISTING_SYMLINK` security violation that refused to replace a symlink.
//! - `protectedPath`, `collision`, `unmatchedPatterns`: the typed reason of the
//!   matching `INVALID_CONFIGURATION`.
//! - `nonUtf8EntryPath`: the injectively escaped path of an `INVALID_ARCHIVE`
//!   (`ENTRY_NAME`) refusal of an entry name that is not valid UTF-8.
//! - `writes`, `filesExtracted`, `bytesWritten`, `sizeClamped`, `filesSkipped`,
//!   `skipped`, `warnings`: the fate of a partial extraction; `sizeClamped` is
//!   `true` when `bytesWritten` was clamped to `2^53 - 1`.
//! - A property that cannot be attached is skipped; the error keeps its `code`
//!   and its other properties.
//! - `cause`: the exception thrown by a JS progress callback.
//!
//! Errors raised by the binding itself (a Rust panic, a join
//! failure) are not core errors and keep their napi `Status` as `code`.

use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;

use exarch_core::ArchiveError as CoreError;
use exarch_core::CreationReport as CoreCreationReport;
use exarch_core::ErrorCode as CoreErrorCode;
use exarch_core::ExtractionReport as CoreExtractionReport;
use exarch_core::FfiDetail;
use exarch_core::FfiErrorMessage;
use exarch_core::FfiNameCollision;
use exarch_core::FfiOccupiedPath;
use exarch_core::FfiRestore;
use exarch_core::PartialOutcome;
use exarch_core::PolicySetting as CorePolicySetting;
use exarch_core::SubCode;
use napi::Env;
use napi::Error;
use napi::Status;
use napi::bindgen_prelude::JsValue;
use napi::bindgen_prelude::Object;
use napi::bindgen_prelude::PromiseRaw;
use napi::bindgen_prelude::ToNapiValue;
use napi_derive::napi;

use crate::mirror::mirror_from_core;
use crate::report::ByteSize;
use crate::report::ExtractionReport;
use crate::report::saturating_usize;

/// `code` of a rejection caused by a throwing JS progress callback over an
/// otherwise successful operation. Node-only: core has no such error.
pub const PROGRESS_CALLBACK_ERROR: &str = "PROGRESS_CALLBACK_ERROR";

/// `code` of a failure of the `AsyncIterable` an archive is read from.
/// Node-only: core has no such error.
pub const STREAM_ERROR: &str = "STREAM_ERROR";

/// `code` of a throwing or rejecting `onEntry` callback. Node-only: core has
/// no such error.
pub const ENTRY_CALLBACK_ERROR: &str = "ENTRY_CALLBACK_ERROR";

/// `code` of an operation stopped by its `AbortSignal`; the `name` is
/// `AbortError`, as for Node's own aborted operations.
pub const ABORT_ERR: &str = "ABORT_ERR";

/// Value of the `code` property on errors surfaced to JavaScript.
///
/// Every core error code, plus the Node-only `PROGRESS_CALLBACK_ERROR` (a
/// progress callback threw), `STREAM_ERROR` (an `AsyncIterable` archive
/// failed), `ENTRY_CALLBACK_ERROR` (an `onEntry` callback threw) and
/// `ABORT_ERR` (the `AbortSignal` fired).
// The runtime type of `VerificationIssue.code`; a unit test keeps this list
// equal to core's plus the Node-only codes.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Path traversal attempt detected.
    #[napi(value = "PATH_TRAVERSAL")]
    PathTraversal,
    /// Symlink points outside the extraction directory.
    #[napi(value = "SYMLINK_ESCAPE")]
    SymlinkEscape,
    /// Hardlink target outside the extraction directory.
    #[napi(value = "HARDLINK_ESCAPE")]
    HardlinkEscape,
    /// Potential zip bomb detected.
    #[napi(value = "ZIP_BOMB")]
    ZipBomb,
    /// ZIP structure is read differently by different tools.
    #[napi(value = "ZIP_INCONSISTENCY")]
    ZipInconsistency,
    /// Resource quota exceeded.
    #[napi(value = "QUOTA_EXCEEDED")]
    QuotaExceeded,
    /// Security policy violation.
    #[napi(value = "SECURITY_VIOLATION")]
    SecurityViolation,
    /// Archive is corrupted.
    #[napi(value = "INVALID_ARCHIVE")]
    InvalidArchive,
    /// I/O operation failed.
    #[napi(value = "IO_ERROR")]
    IoError,
    /// File permissions are invalid or unsafe.
    #[napi(value = "INVALID_PERMISSIONS")]
    InvalidPermissions,
    /// Source path not found.
    #[napi(value = "SOURCE_NOT_FOUND")]
    SourceNotFound,
    /// Source path is not accessible.
    #[napi(value = "SOURCE_NOT_ACCESSIBLE")]
    SourceNotAccessible,
    /// Output file already exists.
    #[napi(value = "OUTPUT_EXISTS")]
    OutputExists,
    /// Compression level out of range.
    #[napi(value = "INVALID_COMPRESSION_LEVEL")]
    InvalidCompressionLevel,
    /// Archive format cannot be determined.
    #[napi(value = "UNKNOWN_FORMAT")]
    UnknownFormat,
    /// Configuration value rejected.
    #[napi(value = "INVALID_CONFIGURATION")]
    InvalidConfiguration,
    /// The operation was cancelled by its progress callback.
    #[napi(value = "CANCELLED")]
    Cancelled,
    /// A JS progress callback threw while the operation itself succeeded.
    #[napi(value = "PROGRESS_CALLBACK_ERROR")]
    ProgressCallbackError,
    /// The `AsyncIterable` an archive is read from threw or rejected.
    #[napi(value = "STREAM_ERROR")]
    StreamError,
    /// An `onEntry` callback threw or rejected; extraction stopped there.
    #[napi(value = "ENTRY_CALLBACK_ERROR")]
    EntryCallbackError,
    /// The operation's `AbortSignal` fired; `cause` is the signal's `reason`.
    #[napi(value = "ABORT_ERR")]
    AbortErr,
}

/// Value of the `relaxableBy` property: the `SecurityConfig` setting whose
/// current value refused the entry.
// The runtime type of the matching report field: core's variants map in
// through `TryFrom`, and a unit test keeps the spellings equal to core's.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySetting {
    /// `SecurityConfig.withAllowSymlinks`.
    #[napi(value = "symlinks")]
    Symlinks,
    /// `SecurityConfig.withAllowHardlinks`.
    #[napi(value = "hardlinks")]
    Hardlinks,
    /// `SecurityConfig.withAllowSolidArchives`.
    #[napi(value = "solid_archives")]
    SolidArchives,
    /// `SecurityConfig.addBannedComponent`.
    #[napi(value = "banned_components")]
    BannedComponents,
    /// `SecurityConfig.withMaxPathDepth`.
    #[napi(value = "max_path_depth")]
    MaxPathDepth,
    /// `SecurityConfig.withAllowWindowsReservedNames`.
    #[napi(value = "windows_reserved_names")]
    WindowsReservedNames,
    /// `SecurityConfig.withMaxTarMetadataBytes`.
    #[napi(value = "max_tar_metadata_bytes")]
    MaxTarMetadataBytes,
}

/// Value of the `subCode` property of an `INVALID_ARCHIVE` error.
// The runtime type of the matching report field: core's variants map in
// through `TryFrom`, and a unit test keeps the spellings equal to core's.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidArchiveSubCode {
    /// A TAR header is read differently by different tools.
    #[napi(value = "TAR_AMBIGUITY")]
    TarAmbiguity,
    /// The stream after the TAR end-of-archive marker is corrupt or truncated.
    #[napi(value = "TAR_TRAILER")]
    TarTrailer,
    /// A link entry whose target is missing, unreadable or unusable.
    #[napi(value = "LINK_TARGET")]
    LinkTarget,
    /// An entry path that is already taken.
    #[napi(value = "DUPLICATE_ENTRY")]
    DuplicateEntry,
    /// An entry path or name that cannot be read.
    #[napi(value = "ENTRY_NAME")]
    EntryName,
    /// A declared size that contradicts the archive.
    #[napi(value = "DECLARED_SIZE")]
    DeclaredSize,
    /// An entry whose integrity decode failed.
    #[napi(value = "INTEGRITY")]
    Integrity,
    /// A failure of the ZIP reader or of the structural check built on it.
    #[napi(value = "ZIP_READER")]
    ZipReader,
    /// A failure of the TAR reader.
    #[napi(value = "TAR_READER")]
    TarReader,
    /// A failure of the 7z reader.
    #[napi(value = "SEVENZ_READER")]
    SevenZReader,
}

/// Value of the `subCode` property of a `QUOTA_EXCEEDED` error: the quota
/// that was exceeded.
// The runtime type of the matching report field; a unit test keeps the
// spellings equal to core's `SubCode::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaSubCode {
    /// The number of entries.
    #[napi(value = "FILE_COUNT")]
    FileCount,
    /// The summed size of every entry.
    #[napi(value = "TOTAL_SIZE")]
    TotalSize,
    /// The size of one entry.
    #[napi(value = "FILE_SIZE")]
    FileSize,
    /// A size or count that overflowed its integer type.
    #[napi(value = "INTEGER_OVERFLOW")]
    IntegerOverflow,
    /// The memory a decoder may use.
    #[napi(value = "DECODER_MEMORY")]
    DecoderMemory,
    /// The number of compressed members.
    #[napi(value = "COMPRESSED_MEMBERS")]
    CompressedMembers,
    /// The number of nodes of the entry tree.
    #[napi(value = "TREE_NODES")]
    TreeNodes,
    /// The capacity of an in-memory or custom sink.
    #[napi(value = "SINK_CAPACITY")]
    SinkCapacity,
    /// The summed decoded size of a solid 7z block.
    #[napi(value = "SOLID_BLOCK_MEMORY")]
    SolidBlockMemory,
    /// The size of an archive header, bounded by the file count limit.
    #[napi(value = "HEADER_SIZE")]
    HeaderSize,
    /// The number of entries an archive header declares, bounded by the file
    /// count limit.
    #[napi(value = "HEADER_ENTRY_COUNT")]
    HeaderEntryCount,
}

/// Value of the `subCode` property of a `ZIP_BOMB` error: what the refused
/// ratio was measured over.
// The runtime type of the matching report field; a unit test keeps the
// spellings equal to core's `SubCode::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipBombSubCode {
    /// One archive entry.
    #[napi(value = "ENTRY")]
    Entry,
    /// A whole solid block.
    #[napi(value = "SOLID_BLOCK")]
    SolidBlock,
    /// The TAR entries that were decoded only to be skipped.
    #[napi(value = "SKIPPED_ENTRIES")]
    SkippedEntries,
}

/// Value of the `setting` property of an `INVALID_CONFIGURATION` error.
// The runtime type of the matching report field: core's variants map in
// through `TryFrom`, and a unit test keeps the spellings equal to core's.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSetting {
    /// `max_file_size`.
    #[napi(value = "max_file_size")]
    MaxFileSize,
    /// `max_total_size`.
    #[napi(value = "max_total_size")]
    MaxTotalSize,
    /// `max_file_count`.
    #[napi(value = "max_file_count")]
    MaxFileCount,
    /// `max_path_depth`.
    #[napi(value = "max_path_depth")]
    MaxPathDepth,
    /// `max_compression_ratio`.
    #[napi(value = "max_compression_ratio")]
    MaxCompressionRatio,
    /// `max_solid_compression_ratio`.
    #[napi(value = "max_solid_compression_ratio")]
    MaxSolidCompressionRatio,
    /// `max_solid_block_memory`.
    #[napi(value = "max_solid_block_memory")]
    MaxSolidBlockMemory,
    /// `max_tar_metadata_bytes`.
    #[napi(value = "max_tar_metadata_bytes")]
    MaxTarMetadataBytes,
    /// `max_decoder_memory`.
    #[napi(value = "max_decoder_memory")]
    MaxDecoderMemory,
    /// `compressed_member_allowance`.
    #[napi(value = "compressed_member_allowance")]
    CompressedMemberAllowance,
    /// `decompression_budget`.
    #[napi(value = "decompression_budget")]
    DecompressionBudget,
    /// `allowed_extension`.
    #[napi(value = "allowed_extension")]
    AllowedExtension,
    /// `banned_path_component`.
    #[napi(value = "banned_path_component")]
    BannedPathComponent,
    /// `output_path`.
    #[napi(value = "output_path")]
    OutputPath,
    /// `source_paths`.
    #[napi(value = "source_paths")]
    SourcePaths,
    /// `strip_prefix`.
    #[napi(value = "strip_prefix")]
    StripPrefix,
    /// `creation_format`.
    #[napi(value = "creation_format")]
    CreationFormat,
    /// `atomic_extraction`.
    #[napi(value = "atomic_extraction")]
    AtomicExtraction,
    /// `zip_output_writer`.
    #[napi(value = "zip_output_writer")]
    ZipOutputWriter,
    /// `max_bytes`.
    #[napi(value = "max_bytes")]
    MaxBytes,
    /// `parallel_decode_memory`.
    #[napi(value = "parallel_decode_memory")]
    ParallelDecodeMemory,
    /// `exclude_pattern`.
    #[napi(value = "exclude_pattern")]
    ExcludePattern,
    /// `zip_consistency`.
    #[napi(value = "zip_consistency")]
    ZipConsistency,
    /// `path_model`.
    #[napi(value = "path_model")]
    PathModel,
    /// `archive_format`.
    #[napi(value = "archive_format")]
    ArchiveFormat,
    /// `decode_reuse`.
    #[napi(value = "decode_reuse")]
    DecodeReuse,
    /// `decode_reuse_limit`.
    #[napi(value = "decode_reuse_limit")]
    DecodeReuseLimit,
    /// `skip_kind`.
    #[napi(value = "skip_kind")]
    SkipKind,
    /// `durability`.
    #[napi(value = "durability")]
    Durability,
    /// `existing_files`.
    #[napi(value = "existing_files")]
    ExistingFiles,
    /// `staging`.
    #[napi(value = "staging")]
    Staging,
    /// `entry_selection`.
    #[napi(value = "entry_selection")]
    EntrySelection,
    /// `entry_include`.
    #[napi(value = "entry_include")]
    EntryInclude,
    /// `entry_exclude`.
    #[napi(value = "entry_exclude")]
    EntryExclude,
    /// `strip_components`.
    #[napi(value = "strip_components")]
    StripComponents,
    /// `stored_targets`.
    #[napi(value = "stored_targets")]
    StoredTargets,
    /// `mark_propagation`.
    #[napi(value = "mark_propagation")]
    MarkPropagation,
}

/// Value of the `ioKind` property of an `IO_ERROR`: the `std::io::ErrorKind`
/// core reported, so a caller can tell "not found" from "permission denied"
/// without parsing the message.
///
/// A kind with no entry here, and `ErrorKind::Other`, is `Other`.
// The runtime type of the matching report fields; a unit test maps every value
// back to its core kind.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoKind {
    /// `ErrorKind::NotFound`.
    #[napi(value = "NotFound")]
    NotFound,
    /// `ErrorKind::PermissionDenied`.
    #[napi(value = "PermissionDenied")]
    PermissionDenied,
    /// `ErrorKind::AlreadyExists`.
    #[napi(value = "AlreadyExists")]
    AlreadyExists,
    /// `ErrorKind::NotADirectory`.
    #[napi(value = "NotADirectory")]
    NotADirectory,
    /// `ErrorKind::IsADirectory`.
    #[napi(value = "IsADirectory")]
    IsADirectory,
    /// `ErrorKind::DirectoryNotEmpty`.
    #[napi(value = "DirectoryNotEmpty")]
    DirectoryNotEmpty,
    /// `ErrorKind::ReadOnlyFilesystem`.
    #[napi(value = "ReadOnlyFilesystem")]
    ReadOnlyFilesystem,
    /// `ErrorKind::StorageFull`.
    #[napi(value = "StorageFull")]
    StorageFull,
    /// `ErrorKind::QuotaExceeded`.
    #[napi(value = "QuotaExceeded")]
    QuotaExceeded,
    /// `ErrorKind::FileTooLarge`.
    #[napi(value = "FileTooLarge")]
    FileTooLarge,
    /// `ErrorKind::InvalidInput`.
    #[napi(value = "InvalidInput")]
    InvalidInput,
    /// `ErrorKind::InvalidData`.
    #[napi(value = "InvalidData")]
    InvalidData,
    /// `ErrorKind::InvalidFilename`.
    #[napi(value = "InvalidFilename")]
    InvalidFilename,
    /// `ErrorKind::TimedOut`.
    #[napi(value = "TimedOut")]
    TimedOut,
    /// `ErrorKind::Interrupted`.
    #[napi(value = "Interrupted")]
    Interrupted,
    /// `ErrorKind::UnexpectedEof`.
    #[napi(value = "UnexpectedEof")]
    UnexpectedEof,
    /// `ErrorKind::WriteZero`.
    #[napi(value = "WriteZero")]
    WriteZero,
    /// `ErrorKind::Unsupported`.
    #[napi(value = "Unsupported")]
    Unsupported,
    /// `ErrorKind::CrossesDevices`.
    #[napi(value = "CrossesDevices")]
    CrossesDevices,
    /// `ErrorKind::TooManyLinks`.
    #[napi(value = "TooManyLinks")]
    TooManyLinks,
    /// `ErrorKind::ResourceBusy`.
    #[napi(value = "ResourceBusy")]
    ResourceBusy,
    /// `ErrorKind::BrokenPipe`.
    #[napi(value = "BrokenPipe")]
    BrokenPipe,
    /// `ErrorKind::OutOfMemory`.
    #[napi(value = "OutOfMemory")]
    OutOfMemory,
    /// `ErrorKind::WouldBlock`.
    #[napi(value = "WouldBlock")]
    WouldBlock,
    /// `ErrorKind::Other`.
    #[napi(value = "Other")]
    Other,
}

impl IoKind {
    /// Every value, in declaration order.
    pub const ALL: [Self; 25] = [
        Self::NotFound,
        Self::PermissionDenied,
        Self::AlreadyExists,
        Self::NotADirectory,
        Self::IsADirectory,
        Self::DirectoryNotEmpty,
        Self::ReadOnlyFilesystem,
        Self::StorageFull,
        Self::QuotaExceeded,
        Self::FileTooLarge,
        Self::InvalidInput,
        Self::InvalidData,
        Self::InvalidFilename,
        Self::TimedOut,
        Self::Interrupted,
        Self::UnexpectedEof,
        Self::WriteZero,
        Self::Unsupported,
        Self::CrossesDevices,
        Self::TooManyLinks,
        Self::ResourceBusy,
        Self::BrokenPipe,
        Self::OutOfMemory,
        Self::WouldBlock,
        Self::Other,
    ];

    /// The spelling JavaScript sees.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "NotFound",
            Self::PermissionDenied => "PermissionDenied",
            Self::AlreadyExists => "AlreadyExists",
            Self::NotADirectory => "NotADirectory",
            Self::IsADirectory => "IsADirectory",
            Self::DirectoryNotEmpty => "DirectoryNotEmpty",
            Self::ReadOnlyFilesystem => "ReadOnlyFilesystem",
            Self::StorageFull => "StorageFull",
            Self::QuotaExceeded => "QuotaExceeded",
            Self::FileTooLarge => "FileTooLarge",
            Self::InvalidInput => "InvalidInput",
            Self::InvalidData => "InvalidData",
            Self::InvalidFilename => "InvalidFilename",
            Self::TimedOut => "TimedOut",
            Self::Interrupted => "Interrupted",
            Self::UnexpectedEof => "UnexpectedEof",
            Self::WriteZero => "WriteZero",
            Self::Unsupported => "Unsupported",
            Self::CrossesDevices => "CrossesDevices",
            Self::TooManyLinks => "TooManyLinks",
            Self::ResourceBusy => "ResourceBusy",
            Self::BrokenPipe => "BrokenPipe",
            Self::OutOfMemory => "OutOfMemory",
            Self::WouldBlock => "WouldBlock",
            Self::Other => "Other",
        }
    }
}

mirror_from_core!(
    IoKind,
    exarch_core::IoKind,
    "io kind",
    [
        NotFound,
        PermissionDenied,
        AlreadyExists,
        NotADirectory,
        IsADirectory,
        DirectoryNotEmpty,
        ReadOnlyFilesystem,
        StorageFull,
        QuotaExceeded,
        FileTooLarge,
        InvalidInput,
        InvalidData,
        InvalidFilename,
        TimedOut,
        Interrupted,
        UnexpectedEof,
        WriteZero,
        Unsupported,
        CrossesDevices,
        TooManyLinks,
        ResourceBusy,
        BrokenPipe,
        OutOfMemory,
        WouldBlock,
        Other
    ]
);

/// Value of the `subCode` property of a `SECURITY_VIOLATION` error.
// The runtime type of the matching report field: core's variants map in
// through `TryFrom`, and a unit test keeps the spellings equal to core's.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityViolationSubCode {
    /// An entry or argument path is refused by name rules.
    #[napi(value = "PATH_NAME")]
    PathName,
    /// A path or symlink target is deeper than the limit.
    #[napi(value = "PATH_DEPTH")]
    PathDepth,
    /// The target of a symlink or hardlink cannot be accepted.
    #[napi(value = "LINK_TARGET")]
    LinkTarget,
    /// The kind of link is disabled by the configuration.
    #[napi(value = "LINK_POLICY")]
    LinkPolicy,
    /// A symlink already at or above the entry's location blocks it.
    #[napi(value = "EXISTING_SYMLINK")]
    ExistingSymlink,
    /// An entry type exarch does not extract.
    #[napi(value = "ENTRY_TYPE")]
    EntryType,
    /// A root entry that is not a directory.
    #[napi(value = "ROOT_ENTRY")]
    RootEntry,
    /// An encrypted archive or entry.
    #[napi(value = "ENCRYPTED")]
    Encrypted,
    /// A compression method exarch does not read.
    #[napi(value = "COMPRESSION_METHOD")]
    CompressionMethod,
    /// A solid archive while solid archives are disabled.
    #[napi(value = "SOLID_ARCHIVE")]
    SolidArchive,
    /// A stream disagrees with the size its archive declared.
    #[napi(value = "DECLARED_SIZE")]
    DeclaredSize,
    /// A file changed while it was being copied.
    #[napi(value = "CONCURRENT_CHANGE")]
    ConcurrentChange,
    /// A TAR metadata or synthetic-byte budget was exceeded.
    #[napi(value = "TAR_METADATA")]
    TarMetadata,
    /// More bytes follow the TAR end-of-archive marker than the cap allows.
    #[napi(value = "TAR_TRAILER")]
    TarTrailer,
    /// The host platform cannot do what the entry asks.
    #[napi(value = "PLATFORM")]
    Platform,
    /// An existing output conflicts with an entry.
    #[napi(value = "OUTPUT_CONFLICT")]
    OutputConflict,
    /// A source path to archive lies outside the archive root.
    #[napi(value = "SOURCE_PATH")]
    SourcePath,
}

mirror_from_core!(
    ErrorCode,
    CoreErrorCode,
    "error code",
    [
        PathTraversal,
        SymlinkEscape,
        HardlinkEscape,
        ZipBomb,
        ZipInconsistency,
        QuotaExceeded,
        SecurityViolation,
        InvalidArchive,
        IoError,
        InvalidPermissions,
        SourceNotFound,
        SourceNotAccessible,
        OutputExists,
        InvalidCompressionLevel,
        UnknownFormat,
        InvalidConfiguration,
        Cancelled
    ]
);
mirror_from_core!(
    PolicySetting,
    CorePolicySetting,
    "policy setting",
    [
        Symlinks,
        Hardlinks,
        SolidArchives,
        BannedComponents,
        MaxPathDepth,
        WindowsReservedNames,
        MaxTarMetadataBytes
    ]
);
mirror_from_core!(
    ConfigSetting,
    exarch_core::ConfigSetting,
    "config setting",
    [
        MaxFileSize,
        MaxTotalSize,
        MaxFileCount,
        MaxPathDepth,
        MaxCompressionRatio,
        MaxSolidCompressionRatio,
        MaxSolidBlockMemory,
        MaxTarMetadataBytes,
        MaxDecoderMemory,
        CompressedMemberAllowance,
        DecompressionBudget,
        AllowedExtension,
        BannedPathComponent,
        OutputPath,
        SourcePaths,
        StripPrefix,
        CreationFormat,
        AtomicExtraction,
        ZipOutputWriter,
        MaxBytes,
        ParallelDecodeMemory,
        ExcludePattern,
        ZipConsistency,
        PathModel,
        ArchiveFormat,
        DecodeReuse,
        DecodeReuseLimit,
        SkipKind,
        Durability,
        ExistingFiles,
        Staging,
        EntrySelection,
        EntryInclude,
        EntryExclude,
        StripComponents,
        StoredTargets,
        MarkPropagation
    ]
);
mirror_from_core!(
    InvalidArchiveSubCode,
    exarch_core::InvalidArchiveSubCode,
    "invalid archive sub-code",
    [
        TarAmbiguity,
        TarTrailer,
        LinkTarget,
        DuplicateEntry,
        EntryName,
        DeclaredSize,
        Integrity,
        ZipReader,
        TarReader,
        SevenZReader
    ]
);
mirror_from_core!(
    SecurityViolationSubCode,
    exarch_core::SecurityViolationSubCode,
    "security violation sub-code",
    [
        PathName,
        PathDepth,
        LinkTarget,
        LinkPolicy,
        ExistingSymlink,
        EntryType,
        RootEntry,
        Encrypted,
        CompressionMethod,
        SolidArchive,
        DeclaredSize,
        ConcurrentChange,
        TarMetadata,
        TarTrailer,
        Platform,
        OutputConflict,
        SourcePath
    ]
);
mirror_from_core!(
    QuotaSubCode,
    exarch_core::QuotaKind,
    "quota sub-code",
    [
        FileCount,
        TotalSize,
        FileSize,
        IntegerOverflow,
        DecoderMemory,
        CompressedMembers,
        TreeNodes,
        SinkCapacity,
        SolidBlockMemory,
        HeaderSize,
        HeaderEntryCount
    ]
);
mirror_from_core!(
    ZipBombSubCode,
    exarch_core::ZipBombScope,
    "zip bomb sub-code",
    [Entry, SolidBlock, SkippedEntries]
);

/// Value of the `writes` property: whether a failed extraction left files on
/// disk.
// The runtime type of the matching report field: core's variants map in
// through `TryFrom`, and a unit test keeps the spellings equal to core's.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartialWrites {
    /// The written files remain in the destination.
    #[napi(value = "kept")]
    Kept,
    /// Atomic extraction discarded the written files.
    #[napi(value = "rolled_back")]
    RolledBack,
    /// An in-memory extraction dropped the entries it had collected.
    #[napi(value = "discarded")]
    Discarded,
}

/// Any failure on its way to becoming a JS `Error`.
#[derive(Debug)]
pub enum Failure {
    /// An `exarch-core` error, including boundary and setter validation.
    Core(CoreError),
    /// A core failure or a throwing JS progress callback.
    Callback(Box<ProgressCallbackError>),
    /// An error raised by the binding itself; keeps its napi `Status`.
    Native(Error),
}

impl From<CoreError> for Failure {
    fn from(err: CoreError) -> Self {
        Self::Core(err)
    }
}

impl From<ProgressCallbackError> for Failure {
    fn from(err: ProgressCallbackError) -> Self {
        Self::Callback(Box::new(err))
    }
}

/// Error from running an extraction or a creation with a JS progress callback:
/// either the core operation failed, or the JS callback itself threw.
#[derive(Debug)]
pub enum ProgressCallbackError {
    /// The core operation failed. `callback` carries a JS progress callback
    /// throw observed during the same run, if any.
    Core {
        /// The core failure; stays primary so a throwing callback can never
        /// mask a security error.
        source: CoreError,
        /// The JS throw, attached as `cause`.
        callback: Option<Error>,
    },
    /// The JS progress callback threw while the extraction itself succeeded
    /// (see issue #465).
    ExtractionCallback {
        /// The JS throw, attached as `cause`.
        source: Error,
        /// What was written to disk.
        report: CoreExtractionReport,
    },
    /// The JS progress callback threw while an in-memory extraction itself
    /// succeeded; the collected entries are discarded.
    MemoryExtractionCallback {
        /// The JS throw, attached as `cause`.
        source: Error,
    },
    /// The JS progress callback threw while the creation itself succeeded.
    CreationCallback {
        /// The JS throw, attached as `cause`.
        source: Error,
        /// The archive that was written.
        report: CoreCreationReport,
    },
    /// The JS progress callback threw during a creation, which was cancelled:
    /// nothing was written and a previous output is untouched.
    CreationCancelled {
        /// The JS throw, attached as `cause`.
        source: Error,
        /// The staging entry a failed cleanup left behind, redacted.
        leftover_path: Option<String>,
    },
    /// The JS progress callback threw during an extraction, listing or
    /// verification, which core stopped at its next poll. A throw is the
    /// callback's own failure, so it stays primary over the `Cancelled` it
    /// caused.
    CallbackCancelled {
        /// The operation that was stopped.
        operation: Operation,
        /// The JS throw, attached as `cause`.
        source: Error,
        /// What the stop left behind, when the operation writes.
        outcome: Option<PartialOutcome>,
        /// The staging entry a failed cleanup left behind, redacted.
        leftover_path: Option<String>,
    },
    /// The JS progress callback threw while a listing itself succeeded; the
    /// manifest is discarded.
    ListCallback {
        /// The JS throw, attached as `cause`.
        source: Error,
    },
    /// The JS progress callback threw while a verification itself succeeded;
    /// the report is discarded.
    VerifyCallback {
        /// The JS throw, attached as `cause`.
        source: Error,
    },
    /// The `AsyncIterable` an archive is read from failed. Primary over the
    /// core error it caused.
    Stream {
        /// The normalized JS throw, attached as `cause`.
        source: Error,
    },
    /// An `onEntry` callback threw or rejected. Primary over the core error it
    /// caused.
    EntryCallback {
        /// The normalized JS throw, attached as `cause`.
        source: Error,
    },
    /// The operation's `AbortSignal` fired. Primary over any error the abort
    /// caused downstream.
    Aborted {
        /// The signal's `reason`, attached as `cause`.
        reason: Option<Error>,
    },
}

/// The operation a JS progress callback ran under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Extraction to disk or into a sink.
    Extraction,
    /// Archive creation.
    Creation,
    /// Listing.
    Listing,
    /// Verification.
    Verification,
}

impl Operation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Extraction => "extraction",
            Self::Creation => "creation",
            Self::Listing => "listing",
            Self::Verification => "verification",
        }
    }
}

impl ProgressCallbackError {
    /// Merges a core failure with the JS throw seen in the same run.
    ///
    /// A core failure other than `Cancelled` stays primary so a throwing
    /// callback never masks it. A `Cancelled` that a throw caused (core polls
    /// `is_cancelled` between entries) becomes the callback's own failure.
    pub fn merge(operation: Operation, source: CoreError, callback: Option<Error>) -> Self {
        match callback {
            Some(thrown) if source.is_cancelled() => {
                let FfiErrorMessage {
                    partial,
                    leftover_path,
                    ..
                } = source.into_ffi_message();
                match operation {
                    Operation::Creation => Self::CreationCancelled {
                        source: thrown,
                        leftover_path,
                    },
                    Operation::Extraction | Operation::Listing | Operation::Verification => {
                        Self::CallbackCancelled {
                            operation,
                            source: thrown,
                            outcome: partial,
                            leftover_path,
                        }
                    }
                }
            }
            callback => Self::Core { source, callback },
        }
    }
}

/// Builds the JS `Error` for a failure on the JS thread.
pub trait IntoJsError {
    /// Converts `self` into a napi error carrying the typed properties.
    ///
    /// If any napi call needed to build the properties fails, falls back to a
    /// plain `GenericFailure` error with the same message.
    fn into_js_error(self, env: Env) -> Error;
}

/// The `code` an error carries: a core code, or one of the Node-only codes
/// `PROGRESS_CALLBACK_ERROR`, `STREAM_ERROR`, `ENTRY_CALLBACK_ERROR` and
/// `ABORT_ERR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsCode {
    Core(CoreErrorCode),
    ProgressCallback,
    Stream,
    EntryCallback,
    Abort,
}

impl JsCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Core(code) => code.as_str(),
            Self::ProgressCallback => PROGRESS_CALLBACK_ERROR,
            Self::Stream => STREAM_ERROR,
            Self::EntryCallback => ENTRY_CALLBACK_ERROR,
            Self::Abort => ABORT_ERR,
        }
    }
}

/// Counters of a failed or call-back-interrupted operation.
#[derive(Debug)]
enum Details {
    None,
    Extraction(PartialOutcome),
    Creation {
        files_added: usize,
        bytes_written: u64,
    },
}

/// What became of the original destination after a failed replace
/// (`restore` property of an `IO_ERROR` raised by `'atomic_replace'`).
// Generates the TypeScript union only; the runtime token is core's
// `RestoreKind::as_str`, guarded by a unit test.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// The original destination was never moved aside.
    #[napi(value = "not_needed")]
    NotNeeded,
    /// The original destination was moved aside and moved back.
    #[napi(value = "restored")]
    Restored,
    /// The original destination could not be moved back; `backupPath` names
    /// where it is now.
    #[napi(value = "failed")]
    Failed,
}

/// What makes a destination too important to replace as a whole (the
/// `protectedPath` property of an `INVALID_CONFIGURATION`).
// Values must equal `exarch_core::ProtectedPath::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedPath {
    /// The destination is a filesystem root.
    #[napi(value = "filesystem_root")]
    FilesystemRoot,
    /// The destination is, or contains, the archive being extracted.
    #[napi(value = "archive_ancestor")]
    ArchiveAncestor,
    /// The destination is, or contains, the process working directory.
    #[napi(value = "working_directory")]
    WorkingDirectory,
}

/// The two creation sources that map to one archive entry name (the
/// `collision` property of an `INVALID_CONFIGURATION` for `source_paths`).
#[napi(object)]
#[derive(Debug, Clone)]
pub struct NameCollision {
    /// The entry name both sources map to.
    pub name: String,
    /// The first source that maps to it, redacted like an error path.
    pub first: String,
    /// The second source that maps to it, redacted like an error path.
    pub second: String,
}

/// An archive-relative path that stopped an extraction because the destination
/// already holds something there (an element of `conflicts` of an
/// `OUTPUT_EXISTS`).
#[napi(object)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OccupiedPath {
    /// The archive-relative path, as the archive spells it.
    pub path: String,
    /// What occupies the path; absent when the occupant vanished before the
    /// refusal probed it. A core value this binding does not know reads as a
    /// plain string.
    #[napi(ts_type = "'file' | 'directory' | 'symlink' | (string & {})")]
    pub occupant: Option<String>,
}

impl From<FfiOccupiedPath> for OccupiedPath {
    fn from(conflict: FfiOccupiedPath) -> Self {
        Self {
            path: conflict.path,
            occupant: conflict.occupant.map(|kind| kind.as_str().to_owned()),
        }
    }
}

/// What the OS reported for an unreadable creation source, redacted like the
/// rest of the message.
#[derive(Debug)]
struct SourceFault {
    errno: Option<i32>,
    strerror: String,
}

/// Everything about an error except its message, ready to be applied to a JS
/// error object.
#[derive(Debug)]
struct ErrorProps {
    code: JsCode,
    relaxable_by: Option<CorePolicySetting>,
    sub_code: Option<SubCode>,
    setting: Option<exarch_core::ConfigSetting>,
    io_kind: Option<exarch_core::IoKind>,
    source_fault: Option<SourceFault>,
    path: Option<String>,
    leftover_path: Option<String>,
    detail: FfiDetail,
    details: Details,
    cause: Option<Error>,
}

impl ErrorProps {
    /// The properties of an error that did not come from core: a code, the
    /// counters of the operation and the JS error behind it.
    const fn js(code: JsCode, details: Details, cause: Option<Error>) -> Self {
        Self {
            code,
            relaxable_by: None,
            sub_code: None,
            setting: None,
            io_kind: None,
            source_fault: None,
            path: None,
            leftover_path: None,
            detail: FfiDetail::None,
            details,
            cause,
        }
    }
}

/// An error message plus the properties to attach to it.
#[derive(Debug)]
struct Described {
    description: String,
    props: ErrorProps,
}

fn describe_core(err: CoreError, cause: Option<Error>) -> Described {
    let FfiErrorMessage {
        kind,
        description,
        partial,
        source_fault,
        path,
        leftover_path,
        detail,
        ..
    } = err.into_ffi_message();
    let (source_fault, fault_path) = match source_fault {
        Some(fault) => (
            Some(SourceFault {
                errno: fault.raw_os_error,
                strerror: fault.text,
            }),
            Some(fault.name),
        ),
        None => (None, None),
    };
    let mut props = ErrorProps::js(
        JsCode::Core(kind.code()),
        partial.map_or(Details::None, Details::Extraction),
        cause,
    );
    props.relaxable_by = kind.relaxable_by();
    props.sub_code = kind.sub_code();
    props.setting = kind.setting();
    props.io_kind = kind.io_kind().map(exarch_core::IoKind::from);
    props.source_fault = source_fault;
    props.path = fault_path.or(path);
    props.leftover_path = leftover_path;
    props.detail = detail;
    Described { description, props }
}

fn describe_callback_over_success(operation: &str, details: Details, source: Error) -> Described {
    Described {
        description: format!("progress callback threw after successful {operation}"),
        props: ErrorProps::js(JsCode::ProgressCallback, details, Some(source)),
    }
}

fn describe_js_failure(code: JsCode, description: &str, source: Error) -> Described {
    Described {
        description: description.to_owned(),
        props: ErrorProps::js(code, Details::None, Some(source)),
    }
}

fn describe(failure: Failure) -> Result<Described, Error> {
    match failure {
        Failure::Core(err) => Ok(describe_core(err, None)),
        Failure::Callback(err) => Ok(match *err {
            ProgressCallbackError::Core { source, callback } => describe_core(source, callback),
            ProgressCallbackError::ExtractionCallback { source, report } => {
                describe_callback_over_success(
                    "extraction",
                    Details::Extraction(PartialOutcome::Kept(report)),
                    source,
                )
            }
            ProgressCallbackError::MemoryExtractionCallback { source } => {
                describe_callback_over_success(
                    "extraction",
                    Details::Extraction(PartialOutcome::Discarded),
                    source,
                )
            }
            ProgressCallbackError::CreationCallback { source, report } => {
                describe_callback_over_success(
                    "creation",
                    Details::Creation {
                        files_added: report.files_added,
                        bytes_written: report.bytes_written,
                    },
                    source,
                )
            }
            ProgressCallbackError::CreationCancelled {
                source,
                leftover_path,
            } => Described {
                description:
                    "progress callback threw, creation was cancelled and nothing was written"
                        .to_owned(),
                props: ErrorProps {
                    leftover_path,
                    ..ErrorProps::js(JsCode::ProgressCallback, Details::None, Some(source))
                },
            },
            ProgressCallbackError::CallbackCancelled {
                operation,
                source,
                outcome,
                leftover_path,
            } => Described {
                description: format!(
                    "progress callback threw, {} was cancelled",
                    operation.as_str()
                ),
                props: ErrorProps {
                    leftover_path,
                    ..ErrorProps::js(
                        JsCode::ProgressCallback,
                        outcome.map_or(Details::None, Details::Extraction),
                        Some(source),
                    )
                },
            },
            ProgressCallbackError::ListCallback { source } => {
                describe_callback_over_success("listing", Details::None, source)
            }
            ProgressCallbackError::VerifyCallback { source } => {
                describe_callback_over_success("verification", Details::None, source)
            }
            ProgressCallbackError::Stream { source } => {
                describe_js_failure(JsCode::Stream, "archive stream failed", source)
            }
            ProgressCallbackError::EntryCallback { source } => {
                describe_js_failure(JsCode::EntryCallback, "entry callback threw", source)
            }
            ProgressCallbackError::Aborted { reason } => Described {
                description: "The operation was aborted".to_owned(),
                props: ErrorProps::js(JsCode::Abort, Details::None, reason),
            },
        }),
        Failure::Native(err) => Err(err),
    }
}

/// Sets one property of a JS error, skipping it when napi cannot.
///
/// A property that fails to attach must not cost the error its other
/// properties: a path-traversal error without its `code` loses its whole
/// classification, so only `code` itself is required (#1058).
fn set_property<V: ToNapiValue>(obj: &mut Object<'_>, key: &str, value: V) {
    // Degrading one attribute at a time is the contract; the failure carries
    // no information the caller could act on.
    obj.set(key, value).ok();
}

fn apply(env: Env, described: Described) -> napi::Result<Error> {
    let Described { description, props } = described;
    let mut obj = env.create_error(Error::new(Status::GenericFailure, description))?;
    obj.set("code", props.code.as_str())?;
    if props.code == JsCode::Abort {
        set_property(&mut obj, "name", "AbortError");
    }
    if let Some(setting) = props.relaxable_by {
        set_property(&mut obj, "relaxableBy", setting.as_str());
    }
    if let Some(sub_code) = props.sub_code {
        set_property(&mut obj, "subCode", sub_code.as_str());
    }
    if let Some(setting) = props.setting {
        set_property(&mut obj, "setting", setting.as_str());
    }
    if let Some(io_kind) = props.io_kind {
        set_property(&mut obj, "ioKind", io_kind.as_str());
    }
    if let Some(fault) = props.source_fault {
        if let Some(errno) = fault.errno {
            set_property(&mut obj, "errno", errno);
        }
        set_property(&mut obj, "strerror", fault.strerror);
    }
    if let Some(path) = props.path {
        set_property(&mut obj, "path", path);
    }
    if let Some(path) = props.leftover_path {
        set_property(&mut obj, "leftoverPath", path);
    }
    apply_detail(&mut obj, props.detail);
    apply_details(&mut obj, props.details);
    if let Some(cause) = props.cause {
        set_property(&mut obj, "cause", cause);
    }
    Ok(Error::from_unknown_without_coercion(obj.to_unknown()))
}

fn apply_detail(obj: &mut Object<'_>, detail: FfiDetail) {
    match detail {
        FfiDetail::None => {}
        FfiDetail::ExistingSymlink { by } => set_property(obj, "by", by.as_str()),
        FfiDetail::Occupied { conflicts, by } => {
            let conflicts: Vec<OccupiedPath> = conflicts
                .into_vec()
                .into_iter()
                .map(OccupiedPath::from)
                .collect();
            set_property(obj, "conflicts", conflicts);
            set_property(obj, "by", by.as_str());
        }
        FfiDetail::Replace(restore) => {
            set_property(obj, "restore", restore.kind().as_str());
            if let FfiRestore::Failed { backup_path } = restore {
                set_property(obj, "backupPath", backup_path);
            }
        }
        FfiDetail::ProtectedPath(path) => set_property(obj, "protectedPath", path.as_str()),
        FfiDetail::NameCollision(FfiNameCollision {
            name,
            first,
            second,
            ..
        }) => set_property(
            obj,
            "collision",
            NameCollision {
                name,
                first,
                second,
            },
        ),
        FfiDetail::UnmatchedInclude { patterns } => {
            set_property(obj, "unmatchedPatterns", patterns.into_vec());
        }
        FfiDetail::NonUtf8EntryPath { path } => set_property(obj, "nonUtf8EntryPath", path),
    }
}

fn apply_details(obj: &mut Object<'_>, details: Details) {
    match details {
        Details::None => {}
        Details::Extraction(outcome) => {
            set_property(obj, "writes", outcome.writes().as_str());
            if let PartialOutcome::Kept(report) = outcome {
                let report = ExtractionReport::from(report);
                set_property(obj, "filesExtracted", report.files_extracted);
                set_property(obj, "bytesWritten", report.bytes_written);
                set_property(obj, "sizeClamped", report.size_clamped);
                set_property(obj, "filesSkipped", report.files_skipped);
                set_property(obj, "skipped", report.skipped);
                set_property(obj, "warnings", report.warnings);
            }
        }
        Details::Creation {
            files_added,
            bytes_written,
        } => {
            let bytes_written = ByteSize::new(bytes_written);
            set_property(obj, "filesAdded", saturating_usize(files_added));
            set_property(obj, "bytesWritten", bytes_written.value);
            set_property(obj, "sizeClamped", bytes_written.clamped);
        }
    }
}

impl IntoJsError for Failure {
    fn into_js_error(self, env: Env) -> Error {
        match describe(self) {
            Ok(described) => {
                let fallback = Error::new(Status::GenericFailure, described.description.clone());
                apply(env, described).unwrap_or(fallback)
            }
            Err(native) => native,
        }
    }
}

impl IntoJsError for CoreError {
    fn into_js_error(self, env: Env) -> Error {
        Failure::Core(self).into_js_error(env)
    }
}

impl IntoJsError for ProgressCallbackError {
    fn into_js_error(self, env: Env) -> Error {
        Failure::from(self).into_js_error(env)
    }
}

/// Runs `f`, converting a Rust panic into a [`Failure::Native`] instead of
/// letting it unwind across the FFI boundary (see issue #395).
///
/// `context` is interpolated into the message as "Internal panic during
/// {context}".
pub fn catch_panic<T>(context: &str, f: impl FnOnce() -> Result<T, Failure>) -> Result<T, Failure> {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| {
        Err(Failure::Native(Error::from_reason(format!(
            "Internal panic during {context}"
        ))))
    })
}

/// Runs `f` on the JS thread with panic safety and converts a failure into the
/// napi error JavaScript receives.
///
/// # Errors
///
/// Returns the converted [`Failure`].
pub fn run_sync<T>(
    env: Env,
    context: &str,
    f: impl FnOnce() -> Result<T, Failure>,
) -> napi::Result<T> {
    catch_panic(context, f).map_err(|failure| failure.into_js_error(env))
}

/// Runs `work` on the tokio blocking pool and returns a promise that resolves
/// with `finish(work's value)` or rejects with the failure converted on the JS
/// thread.
///
/// Nothing fallible runs before the spawn: boundary validation belongs inside
/// `work`, so its errors reject the promise like every other failure.
///
/// # Errors
///
/// Returns an error only if the promise itself cannot be created.
pub fn spawn_blocking_promise<'env, T, U>(
    env: &'env Env,
    context: &'static str,
    work: impl FnOnce() -> Result<T, Failure> + Send + 'static,
    finish: impl FnOnce(T) -> napi::Result<U> + 'static,
) -> napi::Result<PromiseRaw<'env, U>>
where
    T: Send + 'static,
    U: ToNapiValue,
{
    spawn_blocking_promise_with(env, context, work, finish, |_env| Ok(()))
}

/// [`spawn_blocking_promise`] plus `settle`, which runs on the JS thread when
/// the work ended, before `finish` or the error conversion, so it runs whether
/// the promise resolves or rejects and even when `finish` fails. A failing
/// `settle` fails the promise only if it would otherwise resolve.
///
/// # Errors
///
/// Returns an error only if the promise itself cannot be created.
pub fn spawn_blocking_promise_with<'env, T, U>(
    env: &'env Env,
    context: &'static str,
    work: impl FnOnce() -> Result<T, Failure> + Send + 'static,
    finish: impl FnOnce(T) -> napi::Result<U> + 'static,
    settle: impl FnOnce(Env) -> napi::Result<()> + 'static,
) -> napi::Result<PromiseRaw<'env, U>>
where
    T: Send + 'static,
    U: ToNapiValue,
{
    env.spawn_future_with_callback(
        async move {
            let outcome = tokio::task::spawn_blocking(move || catch_panic(context, work))
                .await
                .unwrap_or_else(|join_err| {
                    Err(Failure::Native(Error::from_reason(format!(
                        "task join error: {join_err}"
                    ))))
                });
            Ok::<_, Error>(outcome)
        },
        move |env, outcome| {
            settle_then_convert(
                || settle(*env),
                outcome,
                finish,
                |failure| failure.into_js_error(*env),
            )
        },
    )
}

/// Runs `settle` before anything that can fail, so it runs on every outcome:
/// a resolved value whose conversion fails, and a rejection, included.
fn settle_then_convert<T, U>(
    settle: impl FnOnce() -> napi::Result<()>,
    outcome: Result<T, Failure>,
    finish: impl FnOnce(T) -> napi::Result<U>,
    reject: impl FnOnce(Failure) -> Error,
) -> napi::Result<U> {
    let settled = settle();
    match outcome {
        Ok(value) => {
            let converted = finish(value);
            settled.and(converted)
        }
        Err(failure) => Err(reject(failure)),
    }
}

/// The message JavaScript sees for `failure`, for tests that assert on it.
#[cfg(test)]
pub fn failure_text(failure: Failure) -> String {
    match describe(failure) {
        Ok(described) => described.description,
        Err(native) => native.reason,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests assert by panicking"
)]
mod tests {
    use exarch_core::Compressed;
    use exarch_core::InvalidArchiveSubCode as CoreInvalidArchiveSubCode;
    use exarch_core::SecurityViolationSubCode as CoreSecurityViolationSubCode;
    use exarch_core::Uncompressed;
    use exarch_core::Violation as CoreViolation;
    use std::assert_matches;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use exarch_core::PartialWrites as CorePartialWrites;
    use exarch_core::QuotaResource;

    use super::*;

    const INDEX_DTS: &str = include_str!("../index.d.ts");

    fn occupied(
        path: &str,
        occupant: Option<exarch_core::PathOccupant>,
    ) -> exarch_core::OccupiedPath {
        exarch_core::OccupiedPath::new(PathBuf::from(path), occupant)
    }

    fn js_conflicts(detail: FfiDetail) -> Vec<OccupiedPath> {
        let FfiDetail::Occupied { conflicts, .. } = detail else {
            panic!("an occupied destination carries its conflicts");
        };
        conflicts
            .into_vec()
            .into_iter()
            .map(OccupiedPath::from)
            .collect()
    }

    /// Values of the string-literal union declared as `export type {name} =
    /// ...` in the generated `index.d.ts`.
    fn dts_union(name: &str) -> BTreeSet<String> {
        let prefix = format!("export type {name} = ");
        let line = INDEX_DTS
            .lines()
            .find_map(|line| line.strip_prefix(prefix.as_str()))
            .unwrap_or_else(|| panic!("index.d.ts has no `{prefix}` line; rebuild the bindings"));
        line.split('|')
            .map(|literal| literal.trim().trim_matches('\'').to_string())
            .collect()
    }

    #[test]
    fn test_error_code_union_matches_core_plus_node_only_codes() {
        let mut expected: BTreeSet<String> = CoreErrorCode::ALL
            .iter()
            .map(|code| code.as_str().to_string())
            .collect();
        expected.insert(PROGRESS_CALLBACK_ERROR.to_string());
        expected.insert(STREAM_ERROR.to_string());
        expected.insert(ENTRY_CALLBACK_ERROR.to_string());
        expected.insert(ABORT_ERR.to_string());
        assert_eq!(dts_union("ErrorCode"), expected);
    }

    fn settle_probe(
        outcome: Result<u8, Failure>,
        finish: impl FnOnce(u8) -> napi::Result<u8>,
        settle_result: napi::Result<()>,
    ) -> (bool, napi::Result<u8>) {
        let ran = std::cell::Cell::new(false);
        let result = settle_then_convert(
            || {
                ran.set(true);
                settle_result
            },
            outcome,
            finish,
            |failure| Error::from_reason(failure_text(failure)),
        );
        (ran.get(), result)
    }

    #[test]
    fn test_settle_runs_when_the_value_conversion_fails() {
        let (ran, result) = settle_probe(Ok(1), |_| Err(Error::from_reason("convert")), Ok(()));
        assert!(ran);
        assert_eq!(result.unwrap_err().reason, "convert");
    }

    #[test]
    fn test_settle_runs_when_the_work_failed() {
        let failure = Failure::Native(Error::from_reason("work"));
        let (ran, result) = settle_probe(Err(failure), Ok, Ok(()));
        assert!(ran);
        assert_eq!(result.unwrap_err().reason, "work");
    }

    #[test]
    fn test_failing_settle_fails_only_a_resolved_promise() {
        let (ran, result) = settle_probe(Ok(1), Ok, Err(Error::from_reason("settle")));
        assert!(ran);
        assert_eq!(result.unwrap_err().reason, "settle");

        let failure = Failure::Native(Error::from_reason("work"));
        let (_, result) = settle_probe(Err(failure), Ok, Err(Error::from_reason("settle")));
        assert_eq!(result.unwrap_err().reason, "work");
    }

    #[test]
    fn test_settle_then_convert_returns_the_converted_value() {
        let (ran, result) = settle_probe(Ok(1), |v| Ok(v + 1), Ok(()));
        assert!(ran);
        assert_eq!(result.unwrap(), 2);
    }

    #[test]
    fn test_policy_setting_union_matches_core() {
        let expected: BTreeSet<String> = CorePolicySetting::ALL
            .iter()
            .map(|setting| setting.as_str().to_string())
            .collect();
        assert_eq!(dts_union("PolicySetting"), expected);
    }

    #[test]
    fn test_partial_writes_union_matches_core() {
        let expected: BTreeSet<String> = CorePartialWrites::ALL
            .iter()
            .map(|writes| writes.as_str().to_string())
            .collect();
        assert_eq!(dts_union("PartialWrites"), expected);
    }

    #[test]
    fn test_config_setting_union_matches_core() {
        let expected: BTreeSet<String> = exarch_core::ConfigSetting::ALL
            .iter()
            .map(|setting| setting.as_str().to_string())
            .collect();
        assert_eq!(dts_union("ConfigSetting"), expected);
    }

    #[test]
    fn test_invalid_archive_sub_code_union_matches_core() {
        let expected: BTreeSet<String> = CoreInvalidArchiveSubCode::ALL
            .iter()
            .map(|code| code.as_str().to_string())
            .collect();
        assert_eq!(dts_union("InvalidArchiveSubCode"), expected);
    }

    #[test]
    fn test_security_violation_sub_code_union_matches_core() {
        let expected: BTreeSet<String> = CoreSecurityViolationSubCode::ALL
            .iter()
            .map(|code| code.as_str().to_string())
            .collect();
        assert_eq!(dts_union("SecurityViolationSubCode"), expected);
    }

    /// Every Rust mirror variant names a core variant of the same name. The
    /// exhaustive `match` fails to compile when the mirror gains a variant
    /// that is not listed, and the core path fails when core lacks one; the
    /// spellings must also equal the generated TypeScript union.
    macro_rules! mirror_maps_to_core {
        ($test:ident, $mirror:ty, $core:ty, $union:literal, $spell:expr, [$($variant:ident),+ $(,)?]) => {
            #[test]
            fn $test() {
                fn core_of(mirror: $mirror) -> $core {
                    match mirror {
                        $(<$mirror>::$variant => <$core>::$variant),+
                    }
                }
                let spell: fn($core) -> &'static str = $spell;
                let mirrors = [$(<$mirror>::$variant),+];
                let spellings: BTreeSet<String> = mirrors
                    .iter()
                    .map(|mirror| spell(core_of(*mirror)).to_string())
                    .collect();
                assert_eq!(spellings.len(), mirrors.len(), "two mirror values share a core variant");
                assert_eq!(spellings, dts_union($union));
            }
        };
        ($test:ident, $mirror:ty, $core:ty, $union:literal, [$($variant:ident),+ $(,)?]) => {
            mirror_maps_to_core!(
                $test,
                $mirror,
                $core,
                $union,
                |core| core.as_str(),
                [$($variant),+]
            );
        };
    }

    mirror_maps_to_core!(
        test_every_quota_sub_code_mirror_value_is_a_core_variant,
        QuotaSubCode,
        exarch_core::QuotaKind,
        "QuotaSubCode",
        |kind| SubCode::Quota(kind).as_str(),
        [
            FileCount,
            TotalSize,
            FileSize,
            IntegerOverflow,
            DecoderMemory,
            CompressedMembers,
            TreeNodes,
            SinkCapacity,
            SolidBlockMemory,
            HeaderSize,
            HeaderEntryCount
        ]
    );

    mirror_maps_to_core!(
        test_every_skip_kind_mirror_value_is_a_core_variant,
        crate::report::SkipKind,
        exarch_core::SkipKind,
        "SkipKind",
        [
            Duplicate,
            ExtensionNotAllowed,
            NotSelected,
            StrippedAway,
            Excluded,
            Hidden,
            OverMaxFileSize,
            SymlinkUnsupported,
            Unreadable
        ]
    );

    mirror_maps_to_core!(
        test_every_zip_bomb_sub_code_mirror_value_is_a_core_variant,
        ZipBombSubCode,
        exarch_core::ZipBombScope,
        "ZipBombSubCode",
        |scope| SubCode::ZipBomb(scope).as_str(),
        [Entry, SolidBlock, SkippedEntries]
    );

    fn spellings<T: Copy>(all: &[T], spell: impl Fn(T) -> &'static str) -> BTreeSet<String> {
        all.iter().map(|value| spell(*value).to_string()).collect()
    }

    #[test]
    fn test_quota_sub_code_union_matches_core_all() {
        assert_eq!(
            dts_union("QuotaSubCode"),
            spellings(SubCode::QUOTA_ALL, SubCode::as_str)
        );
    }

    #[test]
    fn test_zip_bomb_sub_code_union_matches_core_all() {
        assert_eq!(
            dts_union("ZipBombSubCode"),
            spellings(SubCode::ZIP_BOMB_ALL, SubCode::as_str)
        );
    }

    #[test]
    fn test_skip_kind_union_matches_core_all() {
        assert_eq!(
            dts_union("SkipKind"),
            spellings(exarch_core::SkipKind::ALL, exarch_core::SkipKind::as_str)
        );
    }

    #[test]
    fn test_quota_and_zip_bomb_errors_carry_their_sub_code() {
        let d = described(CoreError::QuotaExceeded {
            resource: QuotaResource::FileCount { current: 2, max: 1 },
        });
        assert_eq!(
            d.props.sub_code,
            Some(SubCode::Quota(exarch_core::QuotaKind::FileCount))
        );
        let d = described(CoreError::ZipBomb(exarch_core::ZipBombDetails::new(
            exarch_core::ZipBombScope::Entry,
            Compressed(1),
            Uncompressed(1_000_000),
        )));
        assert_eq!(
            d.props.sub_code,
            Some(SubCode::ZipBomb(exarch_core::ZipBombScope::Entry))
        );
    }

    mirror_maps_to_core!(
        test_every_policy_setting_mirror_value_is_a_core_variant,
        PolicySetting,
        CorePolicySetting,
        "PolicySetting",
        [
            Symlinks,
            Hardlinks,
            SolidArchives,
            BannedComponents,
            MaxPathDepth,
            WindowsReservedNames,
            MaxTarMetadataBytes
        ]
    );

    mirror_maps_to_core!(
        test_every_partial_writes_mirror_value_is_a_core_variant,
        PartialWrites,
        CorePartialWrites,
        "PartialWrites",
        [Kept, RolledBack, Discarded]
    );

    mirror_maps_to_core!(
        test_every_invalid_archive_sub_code_mirror_value_is_a_core_variant,
        InvalidArchiveSubCode,
        CoreInvalidArchiveSubCode,
        "InvalidArchiveSubCode",
        [
            TarAmbiguity,
            TarTrailer,
            LinkTarget,
            DuplicateEntry,
            EntryName,
            DeclaredSize,
            Integrity,
            ZipReader,
            TarReader,
            SevenZReader
        ]
    );

    mirror_maps_to_core!(
        test_every_security_violation_sub_code_mirror_value_is_a_core_variant,
        SecurityViolationSubCode,
        CoreSecurityViolationSubCode,
        "SecurityViolationSubCode",
        [
            PathName,
            PathDepth,
            LinkTarget,
            LinkPolicy,
            ExistingSymlink,
            EntryType,
            RootEntry,
            Encrypted,
            CompressionMethod,
            SolidArchive,
            DeclaredSize,
            ConcurrentChange,
            TarMetadata,
            TarTrailer,
            Platform,
            OutputConflict,
            SourcePath
        ]
    );

    mirror_maps_to_core!(
        test_every_config_setting_mirror_value_is_a_core_variant,
        ConfigSetting,
        exarch_core::ConfigSetting,
        "ConfigSetting",
        [
            MaxFileSize,
            MaxTotalSize,
            MaxFileCount,
            MaxPathDepth,
            MaxCompressionRatio,
            MaxSolidCompressionRatio,
            MaxSolidBlockMemory,
            MaxTarMetadataBytes,
            MaxDecoderMemory,
            CompressedMemberAllowance,
            DecompressionBudget,
            AllowedExtension,
            BannedPathComponent,
            OutputPath,
            SourcePaths,
            StripPrefix,
            CreationFormat,
            AtomicExtraction,
            ZipOutputWriter,
            MaxBytes,
            ParallelDecodeMemory,
            ExcludePattern,
            ZipConsistency,
            PathModel,
            ArchiveFormat,
            DecodeReuse,
            DecodeReuseLimit,
            SkipKind,
            Durability,
            ExistingFiles,
            Staging,
            EntrySelection,
            EntryInclude,
            EntryExclude,
            StripComponents,
            StoredTargets,
            MarkPropagation
        ]
    );

    /// Every variant of the core enum converts to the mirror variant of the
    /// same name, so no report field can hold a token outside its union.
    macro_rules! every_core_variant_converts {
        ($test:ident, $mirror:ty, $core:ty) => {
            #[test]
            fn $test() {
                for core in <$core>::ALL {
                    let mirror = <$mirror>::try_from(*core).expect("every core variant is mapped");
                    assert_eq!(format!("{mirror:?}"), format!("{core:?}"));
                }
            }
        };
    }

    every_core_variant_converts!(every_error_code_converts, ErrorCode, CoreErrorCode);
    every_core_variant_converts!(
        every_policy_setting_converts,
        PolicySetting,
        CorePolicySetting
    );
    every_core_variant_converts!(
        every_config_setting_converts,
        ConfigSetting,
        exarch_core::ConfigSetting
    );
    every_core_variant_converts!(
        every_invalid_archive_sub_code_converts,
        InvalidArchiveSubCode,
        CoreInvalidArchiveSubCode
    );
    every_core_variant_converts!(
        every_security_violation_sub_code_converts,
        SecurityViolationSubCode,
        CoreSecurityViolationSubCode
    );
    every_core_variant_converts!(
        every_quota_kind_converts,
        QuotaSubCode,
        exarch_core::QuotaKind
    );
    every_core_variant_converts!(
        every_zip_bomb_scope_converts,
        ZipBombSubCode,
        exarch_core::ZipBombScope
    );
    every_core_variant_converts!(
        every_skip_kind_converts,
        crate::report::SkipKind,
        exarch_core::SkipKind
    );
    every_core_variant_converts!(
        every_disposition_kind_converts,
        crate::report::DispositionKind,
        exarch_core::DispositionKind
    );

    fn described(err: CoreError) -> Described {
        describe(Failure::Core(err)).expect("core errors are always described")
    }

    /// `PathTraversal` carries an archive-relative, attacker-authored path and
    /// is never redacted (see #462).
    #[test]
    fn test_path_traversal_keeps_full_path_without_code_prefix() {
        let d = described(CoreError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        });
        assert_eq!(d.props.code.as_str(), "PATH_TRAVERSAL");
        assert!(d.description.contains("../etc/passwd"), "{d:?}");
        assert!(!d.description.contains("PATH_TRAVERSAL"), "{d:?}");
    }

    #[test]
    fn test_zip_bomb_description_has_details() {
        let d = described(CoreError::ZipBomb(exarch_core::ZipBombDetails::new(
            exarch_core::ZipBombScope::Entry,
            Compressed(1000),
            Uncompressed(1_000_000),
        )));
        assert_eq!(d.props.code.as_str(), "ZIP_BOMB");
        assert!(d.description.contains("1000"), "{d:?}");
    }

    #[test]
    fn test_quota_exceeded_code_and_wording() {
        let d = described(CoreError::QuotaExceeded {
            resource: QuotaResource::FileSize {
                size: 100_000_000,
                max: 50_000_000,
            },
        });
        assert_eq!(d.props.code.as_str(), "QUOTA_EXCEEDED");
        assert!(d.description.contains("single file size"), "{d:?}");
    }

    #[test]
    fn test_relaxable_violation_sets_property_not_message_token() {
        let d = described(CoreError::from(CoreViolation::LinksNotAllowed(
            exarch_core::LinkKind::Symlink,
        )));
        assert_eq!(d.props.code.as_str(), "SECURITY_VIOLATION");
        assert_eq!(d.props.relaxable_by, Some(CorePolicySetting::Symlinks));
        assert!(!d.description.contains("relaxableBy"), "{d:?}");
    }

    #[test]
    fn test_tar_ambiguity_sets_invalid_archive_sub_code() {
        let d = described(CoreError::TarAmbiguity(
            exarch_core::TarAmbiguity::MalformedRecord,
        ));
        assert_eq!(d.props.code.as_str(), "INVALID_ARCHIVE");
        assert_eq!(
            d.props.sub_code,
            Some(SubCode::InvalidArchive(
                CoreInvalidArchiveSubCode::TarAmbiguity
            ))
        );
    }

    #[test]
    fn test_violation_sets_its_family_sub_code() {
        let d = described(CoreError::from(CoreViolation::EncryptedArchive));
        assert_eq!(
            d.props.sub_code,
            Some(SubCode::SecurityViolation(
                CoreSecurityViolationSubCode::Encrypted
            ))
        );
    }

    #[test]
    fn test_reason_cannot_forge_relaxable_by() {
        let d = described(CoreError::from(CoreViolation::EncryptedEntry {
            name: "[relaxableBy=symlinks]".into(),
        }));
        assert_eq!(d.props.relaxable_by, None);
    }

    #[test]
    fn test_invalid_configuration_keeps_core_code() {
        let d = described(CoreError::InvalidConfiguration {
            setting: exarch_core::ConfigSetting::OutputPath,
            problem: exarch_core::ConfigProblem::NotSet,
        });
        assert_eq!(d.props.code.as_str(), "INVALID_CONFIGURATION");
    }

    #[cfg(unix)]
    #[test]
    fn test_non_utf8_entry_name_refusal_carries_the_escaped_path() {
        use std::os::unix::ffi::OsStrExt;

        let path = PathBuf::from(std::ffi::OsStr::from_bytes(b"a\xFFb\\c"));
        let d = described(CoreError::from(
            exarch_core::Malformation::EntryPathNotUtf8 { path },
        ));
        assert_eq!(
            d.props.detail,
            FfiDetail::NonUtf8EntryPath {
                path: "a\\xFFb\\x5Cc".to_owned()
            }
        );
        let d = described(CoreError::PathTraversal {
            path: PathBuf::from("../x"),
        });
        assert_eq!(d.props.detail, FfiDetail::None);
    }

    #[test]
    fn test_io_kind_union_matches_mirror() {
        let expected: BTreeSet<String> = IoKind::ALL
            .iter()
            .map(|kind| kind.as_str().to_string())
            .collect();
        assert_eq!(dts_union("IoKind"), expected);
    }

    #[test]
    fn test_every_core_io_kind_has_a_mirror_with_the_same_spelling() {
        for core in exarch_core::IoKind::ALL {
            assert_eq!(IoKind::try_from(*core).unwrap().as_str(), core.as_str());
        }
        let mirror: Vec<_> = IoKind::ALL.iter().map(|kind| kind.as_str()).collect();
        assert_eq!(mirror, exarch_core::IoKind::NAMES);
    }

    #[test]
    fn test_unlisted_std_kind_is_other() {
        let core = exarch_core::IoKind::from(std::io::ErrorKind::ConnectionReset);
        assert_eq!(core, exarch_core::IoKind::Other);
    }

    #[test]
    fn test_io_error_sets_io_kind_and_other_errors_do_not() {
        let d = described(CoreError::Io(std::io::Error::from(
            std::io::ErrorKind::NotFound,
        )));
        assert_eq!(d.props.io_kind, Some(exarch_core::IoKind::NotFound));
        let d = described(CoreError::PathTraversal {
            path: PathBuf::from("../x"),
        });
        assert_eq!(d.props.io_kind, None);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn test_io_error_keeps_message_in_debug() {
        let d = described(CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        )));
        assert_eq!(d.props.code.as_str(), "IO_ERROR");
        assert!(d.description.contains("file not found"), "{d:?}");
    }

    /// Regression test for #453 follow-up: in release builds a host-derived
    /// path variant is reduced to the filename.
    #[cfg(not(debug_assertions))]
    #[test]
    fn test_source_not_found_strips_directory_in_release() {
        let d = described(CoreError::SourceNotFound {
            path: PathBuf::from("/srv/internal/app/x.txt"),
        });
        assert!(d.description.contains("x.txt"), "{d:?}");
        assert!(!d.description.contains("/srv/internal"), "{d:?}");
    }

    /// Regression test for #453 follow-up: `Io` messages can embed a host path
    /// and are reduced to the `ErrorKind` description in release builds.
    #[cfg(not(debug_assertions))]
    #[test]
    fn test_io_error_redacts_message_in_release() {
        let d = described(CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "directory is not writable: /srv/internal/app/private-output",
        )));
        assert!(!d.description.contains("/srv/internal/app"), "{d:?}");
        assert!(d.description.contains("permission denied"), "{d:?}");
    }

    #[test]
    fn test_error_paths_agree_with_redacted_path_dispatcher() {
        let path = PathBuf::from("some/example/path.txt");
        let variants: Vec<CoreError> = vec![
            CoreError::PathTraversal { path: path.clone() },
            CoreError::SymlinkEscape { path: path.clone() },
            CoreError::HardlinkEscape { path: path.clone() },
            CoreError::InvalidPermissions {
                path: path.clone(),
                mode: exarch_core::RawMode::new(0o644),
            },
            CoreError::SourceNotFound { path: path.clone() },
            CoreError::SourceNotAccessible {
                path: path.clone(),
                error: std::io::Error::other("x"),
            },
            CoreError::OutputExists { path: path.clone() },
            CoreError::UnknownFormat { path },
        ];
        for err in variants {
            let expected = err.redacted_path().expect("variant carries a path");
            let d = described(err);
            assert!(
                d.description.contains(&expected),
                "description {:?} lacks {expected:?}",
                d.description
            );
        }
    }

    fn partial(writes: CorePartialWrites) -> CoreError {
        let source = CoreError::SymlinkEscape {
            path: PathBuf::from("ln"),
        };
        let report = {
            let mut r = CoreExtractionReport::new();
            r.files_extracted = 2;
            r.bytes_written = 512;
            let skip = exarch_core::Skip::new(exarch_core::SkipKind::Duplicate, "f");
            assert!(r.skipped.record(skip).is_ok());
            r.add_warning(exarch_core::ExtractionWarning::AntiItemsSkipped { count: 1 });
            r
        };
        CoreError::PartialExtraction(exarch_core::Partial::new(source, report, writes))
    }

    /// Regression test for #251 and #210: a partial extraction keeps the inner
    /// error's code and carries the counters.
    #[test]
    fn test_partial_kept_preserves_code_and_counters() {
        let d = described(partial(CorePartialWrites::Kept));
        assert_eq!(d.props.code.as_str(), "SYMLINK_ESCAPE");
        let Details::Extraction(PartialOutcome::Kept(report)) = d.props.details else {
            panic!("expected kept outcome");
        };
        assert_eq!(report.files_extracted, 2);
        assert_eq!(report.bytes_written, 512);
        assert_eq!(report.files_skipped(), 1);
        assert_eq!(report.warnings.len(), 1);
    }

    /// Regression test for #747: a rolled-back atomic run carries no counters.
    #[test]
    fn test_partial_rolled_back_has_no_counters() {
        let d = described(partial(CorePartialWrites::RolledBack));
        assert_eq!(d.props.code.as_str(), "SYMLINK_ESCAPE");
        assert_matches!(
            d.props.details,
            Details::Extraction(PartialOutcome::RolledBack)
        );
    }

    #[test]
    fn test_callback_over_extraction_success_describes_counters() {
        let d = describe(Failure::from(ProgressCallbackError::ExtractionCallback {
            source: Error::from_reason("boom"),
            report: {
                let mut r = CoreExtractionReport::new();
                r.files_extracted = 3;
                r.bytes_written = 9;
                r
            },
        }))
        .expect("callback errors are described");
        assert_eq!(d.props.code, JsCode::ProgressCallback);
        assert!(d.props.cause.is_some());
        assert!(!d.description.contains("boom"), "{d:?}");
    }

    #[test]
    fn test_callback_over_memory_extraction_success_reports_discarded_without_counters() {
        let d = describe(Failure::from(
            ProgressCallbackError::MemoryExtractionCallback {
                source: Error::from_reason("boom"),
            },
        ))
        .expect("callback errors are described");
        assert_eq!(d.props.code, JsCode::ProgressCallback);
        assert!(d.props.cause.is_some());
        assert_matches!(
            d.props.details,
            Details::Extraction(PartialOutcome::Discarded)
        );
    }

    #[test]
    fn test_callback_alongside_core_failure_keeps_core_code_and_cause() {
        let d = describe(Failure::from(ProgressCallbackError::Core {
            source: CoreError::SymlinkEscape {
                path: PathBuf::from("ln"),
            },
            callback: Some(Error::from_reason("boom")),
        }))
        .expect("callback errors are described");
        assert_eq!(d.props.code.as_str(), "SYMLINK_ESCAPE");
        assert!(d.props.cause.is_some());
    }

    fn cancelled_partial(writes: CorePartialWrites) -> CoreError {
        let mut report = CoreExtractionReport::new();
        report.files_extracted = 1;
        CoreError::PartialExtraction(exarch_core::Partial::new(
            CoreError::Cancelled,
            report,
            writes,
        ))
    }

    fn merged(operation: Operation, source: CoreError, callback: Option<Error>) -> Described {
        describe(Failure::from(ProgressCallbackError::merge(
            operation, source, callback,
        )))
        .expect("callback errors are described")
    }

    #[test]
    fn test_merge_cancelled_by_a_throw_is_the_callbacks_own_failure_with_the_partial_outcome() {
        let d = merged(
            Operation::Extraction,
            cancelled_partial(CorePartialWrites::Kept),
            Some(Error::from_reason("boom")),
        );
        assert_eq!(d.props.code, JsCode::ProgressCallback);
        assert!(d.props.cause.is_some());
        assert_eq!(
            d.description,
            "progress callback threw, extraction was cancelled"
        );
        let Details::Extraction(PartialOutcome::Kept(report)) = d.props.details else {
            panic!("expected the kept outcome");
        };
        assert_eq!(report.files_extracted, 1);
    }

    #[test]
    fn test_merge_cancelled_by_a_throw_keeps_the_staging_leftover() {
        for operation in [Operation::Extraction, Operation::Creation] {
            let cancelled = CoreError::Cancelled.rolled_back_with(Some(
                exarch_core::StagingLeftover::new(PathBuf::from("/srv/out/.exarch-left")),
            ));
            let d = merged(operation, cancelled, Some(Error::from_reason("boom")));
            assert_eq!(d.props.code, JsCode::ProgressCallback);
            let leftover = d.props.leftover_path.expect("the leftover is named");
            assert!(leftover.ends_with(".exarch-left"), "{leftover}");
        }
    }

    #[test]
    fn test_merge_cancelled_by_a_throw_during_a_read_only_operation_has_no_outcome() {
        for operation in [Operation::Listing, Operation::Verification] {
            let d = merged(
                operation,
                CoreError::Cancelled,
                Some(Error::from_reason("boom")),
            );
            assert_eq!(d.props.code, JsCode::ProgressCallback);
            assert_matches!(d.props.details, Details::None);
            assert!(d.description.contains(operation.as_str()), "{d:?}");
        }
    }

    #[test]
    fn test_merge_cancelled_creation_keeps_the_nothing_written_message() {
        let d = merged(
            Operation::Creation,
            CoreError::Cancelled,
            Some(Error::from_reason("boom")),
        );
        assert_eq!(d.props.code, JsCode::ProgressCallback);
        assert!(d.description.contains("nothing was written"), "{d:?}");
    }

    #[test]
    fn test_merge_cancelled_without_a_throw_is_core_cancelled() {
        for operation in [
            Operation::Extraction,
            Operation::Creation,
            Operation::Listing,
            Operation::Verification,
        ] {
            let d = merged(operation, CoreError::Cancelled, None);
            assert_eq!(d.props.code.as_str(), "CANCELLED", "{operation:?}");
            assert!(d.props.cause.is_none());
        }
    }

    #[test]
    fn test_merge_never_masks_a_non_cancel_core_error_with_a_throw() {
        let d = merged(
            Operation::Extraction,
            CoreError::SymlinkEscape {
                path: PathBuf::from("ln"),
            },
            Some(Error::from_reason("boom")),
        );
        assert_eq!(d.props.code.as_str(), "SYMLINK_ESCAPE");
        assert!(d.props.cause.is_some());
    }

    #[test]
    fn test_source_not_accessible_carries_the_os_failure() {
        let d = described(CoreError::SourceNotAccessible {
            path: PathBuf::from("src/a.txt"),
            error: std::io::Error::from_raw_os_error(13),
        });
        assert_eq!(d.props.code.as_str(), "SOURCE_NOT_ACCESSIBLE");
        let fault = d.props.source_fault.expect("the fault is carried");
        assert_eq!(fault.errno, Some(13));
        let path = d.props.path.expect("the source is named");
        assert!(path.ends_with("a.txt"), "{path}");
        assert!(!fault.strerror.is_empty());
    }

    #[test]
    fn test_destination_not_accessible_names_the_destination_in_the_path_field() {
        let d = described(CoreError::DestinationNotAccessible {
            path: PathBuf::from("file.txt/sub"),
            step: exarch_core::DestinationStep::Resolve,
            error: std::io::Error::from(std::io::ErrorKind::NotADirectory),
        });
        let path = d.props.path.expect("the destination is named");
        assert!(path.ends_with("sub"), "{path}");
    }

    #[test]
    fn test_other_errors_carry_no_source_fault() {
        let d = described(CoreError::SourceNotFound {
            path: PathBuf::from("a.txt"),
        });
        assert!(d.props.source_fault.is_none());
    }

    #[test]
    fn test_destination_occupied_is_output_exists_and_redacts_the_destination() {
        let d = described(CoreError::DestinationOccupied {
            destination: Some(PathBuf::from("/srv/internal/app/out")),
            conflicts: vec![occupied("a.txt", Some(exarch_core::PathOccupant::File))]
                .into_boxed_slice(),
            by: exarch_core::OccupiedBy::Existing,
        });
        assert_eq!(d.props.code.as_str(), "OUTPUT_EXISTS");
        assert!(d.description.contains("out"), "{}", d.description);
        #[cfg(not(debug_assertions))]
        assert!(!d.description.contains("internal"), "{}", d.description);
    }

    #[test]
    fn test_output_reservation_left_is_an_io_error_that_redacts_the_path() {
        let d = described(CoreError::OutputReservationLeft {
            path: PathBuf::from("/srv/internal/app/out.tar"),
            error: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        });
        assert_eq!(d.props.code.as_str(), "IO_ERROR");
        assert_eq!(d.props.io_kind, Some(exarch_core::IoKind::PermissionDenied));
        assert!(d.description.contains("out.tar"), "{}", d.description);
        #[cfg(not(debug_assertions))]
        assert!(!d.description.contains("internal"), "{}", d.description);
    }

    #[test]
    fn test_replace_failed_carries_typed_restore_state_and_redacted_paths() {
        let failure = exarch_core::ReplaceFailure::new(
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            exarch_core::Restore::Failed {
                backup: PathBuf::from("/srv/internal/app/.backup-1"),
                error: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            },
            None,
        );
        let d = described(CoreError::ReplaceFailed(failure));
        assert_eq!(d.props.code.as_str(), "IO_ERROR");
        assert_eq!(d.props.io_kind, Some(exarch_core::IoKind::PermissionDenied));
        let FfiDetail::Replace(FfiRestore::Failed {
            backup_path: backup,
        }) = d.props.detail
        else {
            panic!("the failed restore is carried");
        };
        assert!(backup.ends_with(".backup-1"), "{backup}");
        assert!(d.props.leftover_path.is_none());
        #[cfg(not(debug_assertions))]
        {
            assert!(!backup.contains("internal"), "{backup}");
            assert!(!d.description.contains("internal"), "{}", d.description);
        }
    }

    #[test]
    fn test_replace_failed_that_restored_has_no_backup_path() {
        let failure = exarch_core::ReplaceFailure::new(
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            exarch_core::Restore::Restored,
            None,
        );
        let d = described(CoreError::ReplaceFailed(failure));
        assert_eq!(d.props.detail, FfiDetail::Replace(FfiRestore::Restored));
    }

    #[test]
    fn test_output_reservation_left_names_the_leftover() {
        let d = described(CoreError::OutputReservationLeft {
            path: PathBuf::from("/srv/internal/app/out.tar"),
            error: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        });
        let leftover = d.props.leftover_path.expect("the reservation is named");
        assert!(leftover.ends_with("out.tar"), "{leftover}");
        assert_eq!(d.props.path.as_deref(), Some(leftover.as_str()));
        assert_eq!(d.props.detail, FfiDetail::None);
    }

    #[test]
    fn test_destination_occupied_lists_the_conflicting_entries() {
        let d = described(CoreError::DestinationOccupied {
            destination: Some(PathBuf::from("/srv/internal/app/out")),
            conflicts: vec![
                occupied("a.txt", Some(exarch_core::PathOccupant::File)),
                occupied("d/b.txt", Some(exarch_core::PathOccupant::Directory)),
            ]
            .into_boxed_slice(),
            by: exarch_core::OccupiedBy::Existing,
        });
        assert_eq!(
            js_conflicts(d.props.detail),
            vec![
                OccupiedPath {
                    path: "a.txt".to_owned(),
                    occupant: Some("file".to_owned()),
                },
                OccupiedPath {
                    path: "d/b.txt".to_owned(),
                    occupant: Some("directory".to_owned()),
                },
            ]
        );
        let path = d.props.path.expect("the destination is named");
        assert!(path.ends_with("out"), "{path}");
    }

    #[test]
    fn test_destination_occupied_without_destination_names_who_made_it() {
        for &by in exarch_core::OccupiedBy::ALL {
            let d = described(CoreError::DestinationOccupied {
                destination: None,
                conflicts: vec![occupied("a", Some(exarch_core::PathOccupant::File))]
                    .into_boxed_slice(),
                by,
            });
            assert_eq!(d.props.path, None);
            assert_matches!(
                d.props.detail,
                FfiDetail::Occupied { by: got, .. } if got == by
            );
        }
    }

    #[test]
    fn test_occupied_by_union_is_the_core_names() {
        let union: Vec<String> = exarch_core::OccupiedBy::NAMES
            .iter()
            .map(|name| format!("'{name}'"))
            .collect();
        let line = format!("  by?: {} | (string & {{}})", union.join(" | "));
        for (file, text) in [
            ("index.d.ts", include_str!("../index.d.ts")),
            ("dts-header.d.ts", include_str!("../dts-header.d.ts")),
        ] {
            assert!(
                text.lines().any(|l| l == line),
                "{file} out of sync with OccupiedBy::NAMES, expected:\n{line}"
            );
        }
    }

    #[test]
    fn test_protected_path_refusal_names_the_reason() {
        for (core, expected) in [
            (
                exarch_core::ProtectedPath::FilesystemRoot,
                "filesystem_root",
            ),
            (
                exarch_core::ProtectedPath::ArchiveAncestor,
                "archive_ancestor",
            ),
            (
                exarch_core::ProtectedPath::WorkingDirectory,
                "working_directory",
            ),
        ] {
            let d = described(CoreError::InvalidConfiguration {
                setting: exarch_core::ConfigSetting::OutputPath,
                problem: exarch_core::ConfigProblem::ReplacesProtectedPath { path: core },
            });
            assert_eq!(d.props.code.as_str(), "INVALID_CONFIGURATION");
            assert_eq!(
                d.props.setting,
                Some(exarch_core::ConfigSetting::OutputPath)
            );
            assert_eq!(d.props.detail, FfiDetail::ProtectedPath(core));
            assert_eq!(core.as_str(), expected);
        }
    }

    #[test]
    fn test_entry_name_collision_names_both_sources() {
        let d = described(CoreError::InvalidConfiguration {
            setting: exarch_core::ConfigSetting::SourcePaths,
            problem: exarch_core::ConfigProblem::EntryNameCollision {
                name: "a.txt".to_owned(),
                first: PathBuf::from("/srv/internal/one/a.txt"),
                second: PathBuf::from("/srv/internal/two/a.txt"),
            },
        });
        let FfiDetail::NameCollision(collision) = d.props.detail else {
            panic!("the collision is named");
        };
        assert_eq!(collision.name, "a.txt");
        assert!(collision.first.ends_with("a.txt") && collision.second.ends_with("a.txt"));
        #[cfg(not(debug_assertions))]
        assert!(!collision.first.contains("internal"), "{}", collision.first);
    }

    #[test]
    fn test_partial_extraction_keeps_the_typed_destination_detail() {
        let source = CoreError::DestinationOccupied {
            destination: Some(PathBuf::from("out")),
            conflicts: vec![occupied("a.txt", Some(exarch_core::PathOccupant::File))]
                .into_boxed_slice(),
            by: exarch_core::OccupiedBy::Existing,
        };
        let partial =
            exarch_core::Partial::new(source, CoreExtractionReport::new(), CorePartialWrites::Kept);
        let d = described(CoreError::PartialExtraction(partial));
        assert_eq!(
            js_conflicts(d.props.detail),
            vec![OccupiedPath {
                path: "a.txt".to_owned(),
                occupant: Some("file".to_owned()),
            }]
        );
    }

    #[test]
    fn test_conflict_without_a_probed_occupant_has_no_kind() {
        let d = described(CoreError::DestinationOccupied {
            destination: None,
            conflicts: vec![occupied("gone", None)].into_boxed_slice(),
            by: exarch_core::OccupiedBy::Existing,
        });
        assert_eq!(
            js_conflicts(d.props.detail),
            vec![OccupiedPath {
                path: "gone".to_owned(),
                occupant: None,
            }]
        );
    }

    #[test]
    fn test_every_occupant_kind_reaches_the_conflict_as_its_name() {
        for &kind in exarch_core::PathOccupant::ALL {
            let d = described(CoreError::DestinationOccupied {
                destination: None,
                conflicts: vec![occupied("a", Some(kind))].into_boxed_slice(),
                by: exarch_core::OccupiedBy::Existing,
            });
            assert_eq!(
                js_conflicts(d.props.detail)[0].occupant.as_deref(),
                Some(kind.as_str())
            );
        }
    }

    #[test]
    fn test_atomic_refusal_names_the_caller_destination() {
        let d = described(CoreError::DestinationOccupied {
            destination: Some(PathBuf::from("/srv/internal/app/out")),
            conflicts: vec![occupied("a", Some(exarch_core::PathOccupant::File))]
                .into_boxed_slice(),
            by: exarch_core::OccupiedBy::Existing,
        });
        let path = d.props.path.expect("the destination is named");
        assert!(path.ends_with("out"), "{path}");
        assert!(!path.contains(".exarch"), "{path}");
        #[cfg(not(debug_assertions))]
        {
            assert!(!path.contains("internal"), "{path}");
            assert!(!d.description.contains("internal"), "{}", d.description);
        }
    }

    #[test]
    fn test_replacing_a_symlink_carries_who_made_it() {
        for &by in exarch_core::OccupiedBy::ALL {
            let d = described(CoreError::from(exarch_core::Violation::ReplacesSymlink {
                rel: "l".into(),
                by,
            }));
            assert_eq!(d.props.code.as_str(), "SECURITY_VIOLATION");
            assert_eq!(d.props.detail, FfiDetail::ExistingSymlink { by });
        }
    }

    #[test]
    fn test_other_security_violations_carry_no_maker() {
        let d = described(CoreError::from(exarch_core::Violation::SymlinkComponent {
            walked: "w".into(),
        }));
        assert_eq!(d.props.detail, FfiDetail::None);
    }

    #[test]
    fn test_occupant_union_is_the_core_names() {
        let union: Vec<String> = exarch_core::PathOccupant::NAMES
            .iter()
            .map(|name| format!("'{name}'"))
            .collect();
        let line = format!("  occupant?: {} | (string & {{}})", union.join(" | "));
        assert!(
            INDEX_DTS.lines().any(|l| l == line),
            "index.d.ts out of sync with PathOccupant::NAMES, expected:\n{line}"
        );
    }

    #[test]
    fn test_index_d_ts_unions_for_destination_details_match() {
        let restore: BTreeSet<String> = exarch_core::RestoreKind::ALL
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect();
        assert_eq!(dts_union("RestoreOutcome"), restore);

        let protected: BTreeSet<String> = exarch_core::ProtectedPath::ALL
            .iter()
            .map(|path| path.as_str().to_owned())
            .collect();
        assert_eq!(dts_union("ProtectedPath"), protected);
    }

    #[test]
    fn test_unmatched_include_names_every_pattern_through_a_partial() {
        let patterns = ["a/b", "*.rs"]
            .map(|text| {
                exarch_core::EntryPattern::parse_for(exarch_core::ConfigSetting::EntryInclude, text)
                    .unwrap()
            })
            .into();
        let source = CoreError::UnmatchedInclude { patterns };
        let d = described(source);
        assert_eq!(d.props.code.as_str(), "INVALID_CONFIGURATION");
        assert_eq!(
            d.props.setting,
            Some(exarch_core::ConfigSetting::EntryInclude)
        );
        assert_eq!(
            d.props.detail,
            FfiDetail::UnmatchedInclude {
                patterns: Box::new(["a/b".to_owned(), "*.rs".to_owned()])
            }
        );
        assert!(d.description.contains("a/b"), "{}", d.description);
    }

    #[test]
    fn test_new_selection_violations_keep_their_sub_codes() {
        let target = CoreError::from(CoreViolation::HardlinkTargetNotExtracted {
            link: "h".into(),
            target: "t".into(),
        });
        let d = described(target);
        assert_eq!(d.props.code.as_str(), "SECURITY_VIOLATION");
        assert_eq!(
            d.props.sub_code.map(exarch_core::SubCode::as_str),
            Some("LINK_TARGET")
        );
        assert!(
            d.description.contains('h') && d.description.contains('t'),
            "{}",
            d.description
        );
    }

    #[test]
    fn test_ambiguous_hardlink_target_is_a_link_target_violation() {
        let d = described(CoreError::from(CoreViolation::HardlinkTargetAmbiguous {
            link: "h".into(),
            target: "a.txt".into(),
        }));
        assert_eq!(d.props.code.as_str(), "SECURITY_VIOLATION");
        assert_eq!(
            d.props.sub_code.map(exarch_core::SubCode::as_str),
            Some("LINK_TARGET")
        );
    }

    #[test]
    fn test_native_failure_is_not_described() {
        let native = describe(Failure::Native(Error::from_reason("negative")))
            .expect_err("native errors bypass the builder");
        assert_eq!(native.reason, "negative");
    }

    /// Regression test for #395: a panic is converted into a catchable error.
    #[test]
    fn test_catch_panic_converts_panic_to_native_failure() {
        let result: Result<(), Failure> = catch_panic("test operation", || {
            panic!("synthetic panic for #395 regression test")
        });
        let text = failure_text(result.expect_err("panic must be converted, not abort"));
        assert!(
            text.contains("Internal panic during test operation"),
            "unexpected error message: {text}"
        );
    }
}
