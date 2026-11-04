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
//!   failure has a finer classification, and a [`SecurityViolationSubCode`] on
//!   every core `SECURITY_VIOLATION`.
//! - `writes`, `filesExtracted`, `bytesWritten`, `filesSkipped`, `warnings`:
//!   the fate of a partial extraction.
//! - `cause`: the exception thrown by a JS progress callback.
//!
//! Errors raised by the binding itself (a Rust panic, a join
//! failure) are not core errors and keep their napi `Status` as `code`.

use std::fmt;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;

use exarch_core::ArchiveError as CoreError;
use exarch_core::ErrorCode as CoreErrorCode;
use exarch_core::ExtractionReport as CoreExtractionReport;
use exarch_core::FfiErrorMessage;
use exarch_core::PartialOutcome;
use exarch_core::PolicySetting as CorePolicySetting;
use exarch_core::SubCode;
use exarch_core::creation::CreationReport as CoreCreationReport;
use napi::Env;
use napi::Error;
use napi::Status;
use napi::bindgen_prelude::JsValue;
use napi::bindgen_prelude::PromiseRaw;
use napi::bindgen_prelude::ToNapiValue;
use napi_derive::napi;

use crate::report::saturating_i64;
use crate::report::saturating_u32;

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
/// Every core error code, plus `PROGRESS_CALLBACK_ERROR` for a progress
/// callback that threw over a successful operation.
// Generates the TypeScript union only: runtime values come from core's
// `as_str`, and a unit test keeps this list equal to core's plus
// `PROGRESS_CALLBACK_ERROR`.
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
// Generates the TypeScript union only; runtime values come from core's
// `as_str`, guarded by a unit test.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySetting {
    /// `SecurityConfig.setAllowSymlinks`.
    #[napi(value = "symlinks")]
    Symlinks,
    /// `SecurityConfig.setAllowHardlinks`.
    #[napi(value = "hardlinks")]
    Hardlinks,
    /// `SecurityConfig.setAllowSolidArchives`.
    #[napi(value = "solid_archives")]
    SolidArchives,
    /// `SecurityConfig.addBannedComponent`.
    #[napi(value = "banned_components")]
    BannedComponents,
    /// `SecurityConfig.setMaxPathDepth`.
    #[napi(value = "max_path_depth")]
    MaxPathDepth,
    /// Rust API only: no setter in this binding.
    #[napi(value = "windows_reserved_names")]
    WindowsReservedNames,
    /// Rust API only: no setter in this binding.
    #[napi(value = "max_tar_metadata_bytes")]
    MaxTarMetadataBytes,
}

/// Value of the `subCode` property of an `INVALID_ARCHIVE` error.
// Generates the TypeScript union only; runtime values come from core's
// `as_str`, guarded by a unit test.
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
}

/// Value of the `setting` property of an `INVALID_CONFIGURATION` error.
// Generates the TypeScript union only; runtime values come from core's
// `as_str`, guarded by a unit test.
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
    /// `decompression_budget`.
    #[napi(value = "decompression_budget")]
    DecompressionBudget,
    /// `allowed_extension`.
    #[napi(value = "allowed_extension")]
    AllowedExtension,
    /// `banned_path_component`.
    #[napi(value = "banned_path_component")]
    BannedPathComponent,
    /// `archive_path`.
    #[napi(value = "archive_path")]
    ArchivePath,
    /// `output_directory`.
    #[napi(value = "output_directory")]
    OutputDirectory,
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
    /// `zip_archive`.
    #[napi(value = "zip_archive")]
    ZipArchive,
    /// `zip_output_writer`.
    #[napi(value = "zip_output_writer")]
    ZipOutputWriter,
    /// `max_bytes`.
    #[napi(value = "max_bytes")]
    MaxBytes,
}

/// Value of the `subCode` property of a `SECURITY_VIOLATION` error.
// Generates the TypeScript union only; runtime values come from core's
// `as_str`, guarded by a unit test.
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

/// Value of the `writes` property: whether a failed extraction left files on
/// disk.
// Generates the TypeScript union only; runtime values come from core's
// `as_str`, guarded by a unit test.
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

/// Builds the JS `Error` for a failure on the JS thread.
pub trait IntoJsError {
    /// Converts `self` into a napi error carrying the typed properties.
    ///
    /// If any napi call needed to build the properties fails, falls back to a
    /// plain `GenericFailure` error with the same message.
    fn into_js_error(self, env: Env) -> Error;
}

/// The `code` an error carries: a core code, or the Node-only
/// `PROGRESS_CALLBACK_ERROR`.
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

/// Everything about an error except its message, ready to be applied to a JS
/// error object.
#[derive(Debug)]
struct ErrorProps {
    code: JsCode,
    relaxable_by: Option<CorePolicySetting>,
    sub_code: Option<SubCode>,
    setting: Option<exarch_core::ConfigSetting>,
    details: Details,
    cause: Option<Error>,
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
        ..
    } = err.into_ffi_message();
    Described {
        description,
        props: ErrorProps {
            code: JsCode::Core(kind.code()),
            relaxable_by: kind.relaxable_by(),
            sub_code: kind.sub_code(),
            setting: kind.setting(),
            details: partial.map_or(Details::None, Details::Extraction),
            cause,
        },
    }
}

fn describe_callback_over_success(operation: &str, details: Details, source: Error) -> Described {
    Described {
        description: format!("progress callback threw after successful {operation}"),
        props: ErrorProps {
            code: JsCode::ProgressCallback,
            relaxable_by: None,
            sub_code: None,
            setting: None,
            details,
            cause: Some(source),
        },
    }
}

fn describe_js_failure(code: JsCode, description: &str, source: Error) -> Described {
    Described {
        description: description.to_owned(),
        props: ErrorProps {
            code,
            relaxable_by: None,
            sub_code: None,
            setting: None,
            details: Details::None,
            cause: Some(source),
        },
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
                props: ErrorProps {
                    code: JsCode::Abort,
                    relaxable_by: None,
                    sub_code: None,
                    setting: None,
                    details: Details::None,
                    cause: reason,
                },
            },
        }),
        Failure::Native(err) => Err(err),
    }
}

fn apply(env: Env, described: Described) -> napi::Result<Error> {
    let Described { description, props } = described;
    let mut obj = env.create_error(Error::new(Status::GenericFailure, description))?;
    obj.set("code", props.code.as_str())?;
    if props.code == JsCode::Abort {
        obj.set("name", "AbortError")?;
    }
    if let Some(setting) = props.relaxable_by {
        obj.set("relaxableBy", setting.as_str())?;
    }
    if let Some(sub_code) = props.sub_code {
        obj.set("subCode", sub_code.as_str())?;
    }
    if let Some(setting) = props.setting {
        obj.set("setting", setting.as_str())?;
    }
    match props.details {
        Details::None => {}
        Details::Extraction(outcome) => {
            obj.set("writes", outcome.writes().as_str())?;
            if let PartialOutcome::Kept(report) = outcome {
                obj.set("filesExtracted", saturating_u32(report.files_extracted))?;
                obj.set("bytesWritten", saturating_i64(report.bytes_written))?;
                obj.set("filesSkipped", saturating_u32(report.files_skipped()))?;
                obj.set(
                    "warnings",
                    report
                        .warnings
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<String>>(),
                )?;
            }
        }
        Details::Creation {
            files_added,
            bytes_written,
        } => {
            obj.set("filesAdded", saturating_u32(files_added))?;
            obj.set("bytesWritten", saturating_i64(bytes_written))?;
        }
    }
    if let Some(cause) = props.cause {
        obj.set("cause", cause)?;
    }
    Ok(Error::from_unknown_without_coercion(obj.to_unknown()))
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

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(err) => write!(f, "{err}"),
            Self::Callback(err) => match err.as_ref() {
                ProgressCallbackError::Core { source, .. } => write!(f, "{source}"),
                ProgressCallbackError::ExtractionCallback { .. }
                | ProgressCallbackError::MemoryExtractionCallback { .. } => {
                    f.write_str("progress callback threw after successful extraction")
                }
                ProgressCallbackError::CreationCallback { .. } => {
                    f.write_str("progress callback threw after successful creation")
                }
                ProgressCallbackError::ListCallback { .. } => {
                    f.write_str("progress callback threw after successful listing")
                }
                ProgressCallbackError::VerifyCallback { .. } => {
                    f.write_str("progress callback threw after successful verification")
                }
                ProgressCallbackError::Stream { .. } => f.write_str("archive stream failed"),
                ProgressCallbackError::EntryCallback { .. } => f.write_str("entry callback threw"),
                ProgressCallbackError::Aborted { .. } => f.write_str("The operation was aborted"),
            },
            Self::Native(err) => write!(f, "{}", err.reason),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
            |failure| Error::from_reason(failure.to_string()),
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
            path: PathBuf::from("/srv/secret/app/x.txt"),
        });
        assert!(d.description.contains("x.txt"), "{d:?}");
        assert!(!d.description.contains("/srv/secret"), "{d:?}");
    }

    /// Regression test for #453 follow-up: `Io` messages can embed a host path
    /// and are reduced to the `ErrorKind` description in release builds.
    #[cfg(not(debug_assertions))]
    #[test]
    fn test_io_error_redacts_message_in_release() {
        let d = described(CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "directory is not writable: /srv/secret/app/private-output",
        )));
        assert!(!d.description.contains("/srv/secret/app"), "{d:?}");
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
            CoreError::SourceNotAccessible { path: path.clone() },
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
        let err = result.expect_err("panic must be converted, not abort");
        assert!(
            err.to_string()
                .contains("Internal panic during test operation"),
            "unexpected error message: {err}"
        );
    }
}
