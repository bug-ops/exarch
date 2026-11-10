//! Node.js bindings for exarch-core.
//!
//! This crate provides a JavaScript/TypeScript API for secure archive
//! extraction with built-in protection against path traversal, zip bombs,
//! symlink attacks, and other common vulnerabilities.
//!
//! # Installation
//!
//! ```bash
//! npm install @exarch/node
//! ```
//!
//! # Quick Start
//!
//! ```javascript
//! const { extractArchive, SecurityConfig } = require('@exarch/node');
//!
//! // Use secure defaults
//! const report = await extractArchive('archive.tar.gz', '/tmp/output');
//! console.log(`Extracted ${report.filesExtracted} files`);
//!
//! // Customize security settings
//! const config = new SecurityConfig()
//!   .maxFileSize(100 * 1024 * 1024)
//!   .allowSymlinks(true);
//! const report = await extractArchive('archive.tar.gz', '/tmp/output', config);
//! ```
//!
//! # Security
//!
//! This library uses a secure-by-default approach. All potentially dangerous
//! features are disabled by default and must be explicitly enabled. See
//! `SecurityConfig` for configuration options.
//!
//! # Repository
//!
//! <https://github.com/rabax/exarch>
//!
//! # License
//!
//! MIT OR Apache-2.0

#![allow(
    clippy::needless_pass_by_value,
    reason = "napi passes JavaScript arguments by value and cannot take them by reference"
)]

use napi::bindgen_prelude::*;
use napi::threadsafe_function::ThreadsafeFunction;
use napi::threadsafe_function::ThreadsafeFunctionCallMode;
use napi_derive::napi;

/// Wraps a JavaScript shim `$body` (an expression) in an IIFE that defines
/// `normalizeThrown(what, thrown)`: an object or function passes through
/// unchanged, any other value becomes an `Error` named after `what` whose
/// `cause` is the value (a Symbol stringified, because napi-rs coerces `cause`
/// to a string when it reads it back, which throws for a raw Symbol).
///
/// One definition serves every shim that catches a throw before napi-rs sees
/// it: a primitive crossing that boundary can crash the host process.
macro_rules! js_with_normalizer {
    ($body:literal) => {
        concat!(
            "(() => {\n",
            "const normalizeThrown = (what, thrown) => {\n",
            "  if (thrown !== null && (typeof thrown === \"object\" || typeof thrown === \"function\")) {\n",
            "    return thrown;\n",
            "  }\n",
            "  const wrapped = new Error(what + \" threw a non-object value: \" + String(thrown));\n",
            "  wrapped.cause = typeof thrown === \"symbol\" ? String(thrown) : thrown;\n",
            "  return wrapped;\n",
            "};\n",
            "return ",
            $body,
            ";\n",
            "})()"
        )
    };
}

mod abort;
#[cfg_attr(
    test,
    allow(dead_code, reason = "napi registers its functions outside test builds")
)]
mod buffer;
#[cfg_attr(
    test,
    allow(dead_code, reason = "napi registers its functions outside test builds")
)]
mod callback;
mod config;
mod error;
#[cfg_attr(
    test,
    allow(dead_code, reason = "napi registers its functions outside test builds")
)]
mod memory;
mod mirror;
mod report;
mod stream;
mod utils;

use abort::AbortHandle;
use config::CreationConfig;
use config::ExtractionOptions;
use config::ListOptions;
use config::SecurityConfig;
use config::VerificationOptions;
use error::Failure;
use error::Operation;
use error::ProgressCallbackError;
use error::run_sync;
use error::spawn_blocking_promise;
use exarch_core::BoundaryPath;
use report::ArchiveManifest;
use report::CreatableFormat;
use report::CreationReport;
use report::Durability;
use report::ExtractionReport;
use report::VerificationReport;
use report::saturating_usize;
use utils::boundary_path;
use utils::boundary_paths;
use utils::path_text;

/// Result of the binding-internal operations, before conversion to a JS error.
type CoreResult<T> = std::result::Result<T, Failure>;

// The `catch_unwind` guards throughout this module only convert Rust panics
// into a catchable `Error` when the crate is built with `panic = "unwind"`;
// under `panic = "abort"` they are dead code and the whole Node.js process
// aborts on any panic. Fail the build loudly instead of silently
// reintroducing that vulnerability (see issue #395).
const _: () = assert!(
    cfg!(panic = "unwind"),
    "exarch-node must be built with panic=unwind so catch_unwind can convert Rust panics into catchable JS errors; see issue #395"
);

/// Extract an archive to the specified directory (async).
///
/// This function provides secure archive extraction with configurable
/// security policies. By default, it uses a restrictive security
/// configuration that blocks symlinks, hardlinks, absolute paths, and
/// enforces resource quotas.
///
/// # Security Considerations
///
/// ## Thread Safety and TOCTOU
///
/// The archive is opened once and read as a stream, so validation and
/// extraction see the same file contents. Another process can still replace
/// or modify the file on disk while it is read, whether the call is sync or
/// async: blocking the calling thread does not prevent that. For untrusted
/// archives that other processes can write to, copy the archive to a private
/// location or hold an exclusive lock on it for the duration of the call.
///
/// ## Input Validation
///
/// - Paths containing null bytes are rejected (security)
/// - Paths longer than core's `MAX_PATH_LENGTH` are rejected (`DoS` prevention)
/// - Boundary validation runs before the core call; a rejection is a
///   `SECURITY_VIOLATION`
///
/// # Arguments
///
/// * `archive_path` - Path to the archive file
/// * `output_dir` - Directory where files will be extracted
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
///
/// # Returns
///
/// Promise resolving to `ExtractionReport` with extraction statistics
///
/// # Errors
///
/// Rejects for security violations or I/O errors. The rejection is an `Error`
/// (see `ExarchError`) whose `message` is the description only; discriminate
/// on its properties instead of parsing text:
///
/// - `code`: an `ErrorCode`: `PATH_TRAVERSAL`, `SYMLINK_ESCAPE`,
///   `HARDLINK_ESCAPE`, `ZIP_BOMB`, `ZIP_INCONSISTENCY`, `QUOTA_EXCEEDED`,
///   `SECURITY_VIOLATION`, `INVALID_ARCHIVE`, `IO_ERROR`,
///   `INVALID_PERMISSIONS`, `SOURCE_NOT_FOUND`, `SOURCE_NOT_ACCESSIBLE`,
///   `OUTPUT_EXISTS`, `INVALID_COMPRESSION_LEVEL`, `UNKNOWN_FORMAT`,
///   `INVALID_CONFIGURATION` or `PROGRESS_CALLBACK_ERROR`. A path rejected at
///   the boundary (null byte, too long) is a `SECURITY_VIOLATION` and a
///   rejected setter value an `INVALID_CONFIGURATION`. Errors raised by the
///   binding itself (an internal panic, a failed argument conversion) keep
///   napi's status (`GenericFailure`) as `code`.
/// - `relaxableBy`: set on a `SECURITY_VIOLATION` that a `SecurityConfig`
///   setting relaxes, one of `symlinks`, `hardlinks`, `solid_archives`,
///   `banned_components`, `max_path_depth`, `windows_reserved_names` or
///   `max_tar_metadata_bytes`; absent when no setting relaxes the refusal.
///   Changing the setting removes that refusal only; the entry can still fail a
///   later check. Every one of these settings has a `SecurityConfig` setter.
/// - `subCode`: the finer classification of an `INVALID_ARCHIVE` (when it has
///   one), the family of every `SECURITY_VIOLATION`, the quota of every
///   `QUOTA_EXCEEDED` and the scope of every `ZIP_BOMB`.
/// - `ioKind`: the kind of an `IO_ERROR`, such as `NotFound`.
/// - `setting`: set on an `INVALID_CONFIGURATION` that names the refused
///   setting or input, as a `snake_case` id such as `max_file_count`.
/// - `writes`, `filesExtracted`, `bytesWritten`, `filesSkipped`, `warnings`:
///   set when extraction fails after some files were already written. `writes`
///   is `'kept'` (files remain; the counters and the typed `warnings` array
///   follow) or, with `'atomic'` or `'atomic_replace'` staging, `'rolled_back'`
///   (the destination was discarded; no counters).
///
/// # Examples
///
/// ```javascript
/// // Use secure defaults
/// const report = await extractArchive('archive.tar.gz', '/tmp/output');
/// console.log(`Extracted ${report.filesExtracted} files`);
///
/// // Customize security settings
/// const config = new SecurityConfig().withMaxFileSize(100 * 1024 * 1024);
/// const report = await extractArchive('archive.tar.gz', '/tmp/output', config);
///
/// // Customize extraction options
/// const opts = new ExtractionOptions().withExistingFiles('overwrite');
/// const report = await extractArchive('archive.tar.gz', '/tmp/output', null, opts);
/// ```
#[napi]
pub fn extract_archive<'env>(
    env: &'env Env,
    archive_path: String,
    output_dir: String,
    config: Option<&SecurityConfig>,
    options: Option<&ExtractionOptions>,
) -> Result<PromiseRaw<'env, ExtractionReport>> {
    // Owned copies: the work outlives this call on the blocking pool.
    let config_owned: exarch_core::SecurityConfig = config.map_or_default(|c| c.as_core().clone());
    let options_owned: exarch_core::ExtractionOptions =
        options.map_or_default(|o| o.as_core().clone());

    // NOTE: another process can modify the archive file while it is read;
    // sync and async calls are equally exposed (see the TOCTOU notes above).
    spawn_blocking_promise(
        env,
        "archive extraction",
        move || extract_core(&archive_path, &output_dir, &config_owned, &options_owned),
        |report| Ok(ExtractionReport::from(report)),
    )
}

/// Validates the boundary paths, then extracts.
///
/// Defense-in-depth: paths are validated here and again in core. Boundary
/// validation catches issues early; it runs inside the work so its error
/// rejects like every other failure.
fn extract_core(
    archive_path: &str,
    output_dir: &str,
    config: &exarch_core::SecurityConfig,
    options: &exarch_core::ExtractionOptions,
) -> CoreResult<exarch_core::ExtractionReport> {
    let archive_path = boundary_path(archive_path)?;
    let output_dir = boundary_path(output_dir)?;
    Ok(exarch_core::ExtractRequest::new(config)
        .with_options(options.clone())
        .extract(&archive_path, &output_dir)?)
}

/// Extract an archive to the specified directory (sync).
///
/// Synchronous version of `extractArchive`. Blocks the event loop until
/// extraction completes. Prefer the async version for most use cases.
///
/// # Arguments
///
/// * `archive_path` - Path to the archive file
/// * `output_dir` - Directory where files will be extracted
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
///
/// # Returns
///
/// `ExtractionReport` with extraction statistics
///
/// # Errors
///
/// Returns error for security violations or I/O errors. See `extract_archive`
/// for error code documentation.
///
/// # Examples
///
/// ```javascript
/// // Use secure defaults
/// const report = extractArchiveSync('archive.tar.gz', '/tmp/output');
/// console.log(`Extracted ${report.filesExtracted} files`);
///
/// // Customize security settings
/// const config = new SecurityConfig().withMaxFileSize(100 * 1024 * 1024);
/// const report = extractArchiveSync('archive.tar.gz', '/tmp/output', config);
/// ```
#[napi]
pub fn extract_archive_sync(
    env: Env,
    archive_path: String,
    output_dir: String,
    config: Option<&SecurityConfig>,
    options: Option<&ExtractionOptions>,
) -> Result<ExtractionReport> {
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    let default_options = exarch_core::ExtractionOptions::default();
    let options_ref = options.map_or(&default_options, |o| o.as_core());

    // CRITICAL: Never panic across FFI boundary
    run_sync(env, "archive extraction", || {
        extract_core(&archive_path, &output_dir, config_ref, options_ref)
    })
    .map(ExtractionReport::from)
}

/// Options of `createArchive` and its variants.
///
/// `overwrite` follows the same default as the Python binding: `true`
/// replaces an existing output when creation succeeds (a failed creation
/// leaves the previous output untouched); `false` refuses an existing output
/// with `OUTPUT_EXISTS`.
#[napi(object)]
#[derive(Debug, Clone, Default)]
pub struct CreateOptions {
    /// The archive format, instead of the one the output extension names (how
    /// a `.apk` or `.whl` is written as a plain ZIP). `'SevenZ'` cannot be
    /// created and is not part of the type.
    pub format: Option<CreatableFormat>,
    /// Whether an existing output may be replaced. Defaults to `true`.
    pub overwrite: Option<bool>,
    /// Whether the archive is flushed to stable storage before success is
    /// reported: `'synced'` (the default) or `'unsynced'`. See `Durability`
    /// for the crash and write-back hazards of `'unsynced'`.
    pub durability: Option<Durability>,
}

/// The output of a creation as the core request takes it.
fn output_file(output_path: &BoundaryPath, options: &CreateOptions) -> exarch_core::OutputFile {
    let file = if options.overwrite.unwrap_or(true) {
        exarch_core::OutputFile::replace(output_path.as_path())
    } else {
        exarch_core::OutputFile::create_new(output_path.as_path())
    };
    let file = match options.format {
        Some(format) => file.with_format(format.into()),
        None => file,
    };
    file.with_durability(
        options
            .durability
            .map_or_default(exarch_core::Durability::from),
    )
}

/// Create an archive from source files and directories (async).
///
/// # Arguments
///
/// * `output_path` - Path to output archive file
/// * `sources` - Array of source files/directories to include
/// * `config` - Optional `CreationConfig` (uses defaults if omitted)
///
/// # Returns
///
/// Promise resolving to `CreationReport` with creation statistics
///
/// # Errors
///
/// Returns error if path validation fails, archive creation fails, or I/O
/// errors occur.
///
/// # Examples
///
/// ```javascript
/// // Use defaults
/// const report = await createArchive('output.tar.gz', ['source_dir/']);
/// console.log(`Created archive with ${report.filesAdded} files`);
///
/// // Customize configuration
/// const config = new CreationConfig().withCompressionLevel(9);
/// const report = await createArchive('output.tar.gz', ['src/'], config);
/// ```
#[napi]
pub fn create_archive<'env>(
    env: &'env Env,
    output_path: String,
    sources: Vec<String>,
    config: Option<&CreationConfig>,
    options: Option<CreateOptions>,
) -> Result<PromiseRaw<'env, CreationReport>> {
    let config_owned: exarch_core::CreationConfig = config.map_or_default(|c| c.as_core().clone());
    let options = options.unwrap_or_default();

    spawn_blocking_promise(
        env,
        "archive creation",
        move || create_core(&output_path, &sources, &config_owned, &options),
        |report| Ok(CreationReport::from(report)),
    )
}

fn boundary_create_paths(
    output_path: &str,
    sources: &[String],
) -> CoreResult<(BoundaryPath, Vec<BoundaryPath>)> {
    Ok((boundary_path(output_path)?, boundary_paths(sources)?))
}

fn create_core(
    output_path: &str,
    sources: &[String],
    config: &exarch_core::CreationConfig,
    options: &CreateOptions,
) -> CoreResult<exarch_core::CreationReport> {
    let (output_path, sources) = boundary_create_paths(output_path, sources)?;
    let output = output_file(&output_path, options);
    Ok(exarch_core::CreateRequest::new(config).create(&output, &sources)?)
}

/// Create an archive from source files and directories (sync).
///
/// Synchronous version of `createArchive`. Blocks the event loop until
/// creation completes. Prefer the async version for most use cases.
///
/// # Arguments
///
/// * `output_path` - Path to output archive file
/// * `sources` - Array of source files/directories to include
/// * `config` - Optional `CreationConfig` (uses defaults if omitted)
///
/// # Returns
///
/// `CreationReport` with creation statistics
///
/// # Errors
///
/// Returns error if path validation fails, archive creation fails, or I/O
/// errors occur.
///
/// # Examples
///
/// ```javascript
/// // Use defaults
/// const report = createArchiveSync('output.tar.gz', ['source_dir/']);
/// console.log(`Created archive with ${report.filesAdded} files`);
/// ```
#[napi]
pub fn create_archive_sync(
    env: Env,
    output_path: String,
    sources: Vec<String>,
    config: Option<&CreationConfig>,
    options: Option<CreateOptions>,
) -> Result<CreationReport> {
    let default_config = exarch_core::CreationConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());
    let options = options.unwrap_or_default();

    run_sync(env, "archive creation", || {
        create_core(&output_path, &sources, config_ref, &options)
    })
    .map(CreationReport::from)
}

/// JavaScript source for a factory that wraps a progress callback so any
/// primitive value it throws is normalized to a proper `Error` before
/// napi-rs's threadsafe function dispatcher ever observes it (see issue
/// #473).
///
/// `napi_create_reference()` cannot create a weak reference to a thrown
/// primitive (string/number/boolean/`undefined`/`BigInt`/`null`); napi-rs
/// 3.12.0's `call_async_catch` dispatcher (`threadsafe_function.rs`) still
/// escalates that failure to `napi_fatal_exception`, crashing the host
/// process, even though the error was already delivered correctly to the
/// Rust side. Catching the throw in real JavaScript, ahead of that
/// dispatcher, sidesteps the defect entirely: napi-rs never sees a primitive
/// cross the callback boundary.
///
/// The guard only rewraps values `napi_create_reference()` actually can't
/// reference — any object or function (plain objects, custom `Error`
/// subclasses, cross-realm `Error`s, arrays) passes through unchanged, so the
/// original thrown value stays directly under the rejection's `cause` rather
/// than being demoted to `cause.cause`.
///
/// A thrown `Symbol` is stringified before being attached as `cause`, rather
/// than attached as-is like every other primitive: napi-rs's own
/// `extract_error_cause` (used when the *rejection* value's `.cause` is later
/// read back out) coerces `.cause` to a string via `napi_coerce_to_string`,
/// which throws `TypeError: Cannot convert a Symbol value to a string` for a
/// raw `Symbol` — reproducing this fix's own target crash one layer further
/// in, uncatchably under `--force-node-api-uncaught-exceptions-policy=true`.
const WRAP_PROGRESS_CALLBACK_JS: &str = js_with_normalizer!(
    r#"(callback) => function progressCallbackWrapper(err, arg) {
  try {
    return callback(err, arg);
  } catch (thrown) {
    throw normalizeThrown("progress callback", thrown);
  }
}"#
);

/// Argument type for a progress callback that wraps the JS value with
/// `WRAP_PROGRESS_CALLBACK_JS` before building the [`ThreadsafeFunction`].
///
/// Shared by `createArchiveWithProgress` and `extractArchiveWithProgress` —
/// the two entry points that dispatch through `ProgressDispatch::Awaited`
/// (`call_async_catch`) and therefore share the primitive-throw crash this
/// type exists to prevent. The sync variants that dispatch through
/// `ProgressDispatch::Deferred` (plain `ThreadsafeFunction::call`) never enter
/// the buggy code path in the first place, so they take a raw
/// `ThreadsafeFunction` unchanged.
///
/// The wrapping must happen inside [`FromNapiValue::from_napi_value`] rather
/// than in the body of an `async fn` like `extract_archive_with_progress`:
/// `Env` and `Function` wrap raw, thread-affine JS engine pointers and are
/// not `Send`, so neither can be a parameter of that `async fn` — its future
/// is later driven by `tokio::task::spawn_blocking`, which requires `Send`.
/// Argument extraction, by contrast, always runs synchronously on the JS
/// thread before the future is constructed, which is exactly where
/// `Env`/`Function` access is valid.
pub struct ProgressCallback(ThreadsafeFunction<ProgressArgs>);

impl TypeName for ProgressCallback {
    fn type_name() -> &'static str {
        "Function"
    }

    fn value_type() -> ValueType {
        ValueType::Function
    }
}

impl ValidateNapiValue for ProgressCallback {}

impl FromNapiValue for ProgressCallback {
    // SAFETY: `from_napi_value` is unsafe only because the trait contract
    // requires `env`/`napi_val` to be a valid, currently-active napi
    // environment and value, which is guaranteed here: napi-rs's generated
    // argument-extraction code calls this exclusively from inside the JS
    // callback that receives the corresponding `#[napi]` function's raw
    // arguments, on the JS thread, before either pointer can be invalidated.
    #[expect(unsafe_code, reason = "napi's FromNapiValue is an unsafe trait method")]
    unsafe fn from_napi_value(env: sys::napi_env, napi_val: sys::napi_value) -> Result<Self> {
        // `Function::from_napi_value` wraps any value with zero type
        // checking, unlike `ThreadsafeFunction::from_napi_value` (which fails
        // fast via `napi_create_reference`). Without this check, a
        // non-function `progress` argument would run the whole operation to
        // completion and only fail when the shim's `callback(...)` call
        // throws `TypeError: callback is not a function` — surfaced as a
        // misleading post-hoc `PROGRESS_CALLBACK_ERROR` instead of an
        // upfront rejection.
        assert_type_of!(env, napi_val, ValueType::Function)?;
        // SAFETY: same guarantee as above — `env`/`napi_val` come from the
        // trait caller and are valid for the duration of this call.
        let callback = unsafe { Function::<Unknown, Unknown>::from_napi_value(env, napi_val)? };
        let factory: Function<'_, Unknown<'_>, Function<'_, Unknown<'_>, Unknown<'_>>> =
            Env::from_raw(env).run_script(WRAP_PROGRESS_CALLBACK_JS)?;
        let wrapped = factory.call(callback.to_unknown())?;
        let tsfn = wrapped
            .build_threadsafe_function::<ProgressArgs>()
            .callee_handled::<true>()
            .build_callback(|ctx| Ok(ctx.value))?;
        Ok(Self(tsfn))
    }
}

/// Create an archive from source files and directories with a progress
/// callback (async).
///
/// The `progress` callback is called once per entry, receiving `(err,
/// [path, total, current, bytesWritten])` (napi's standard threadsafe
/// function calling convention: `err` is always `null`, the entry data
/// arrives as a single array argument) where:
/// - `path` — entry path being added to the archive
/// - `total` — total number of entries as `number`, or `null` while the count
///   is not known
/// - `current` — 1-based index of the current entry as `number`
/// - `bytesWritten` — always `0`. The callback only fires from the entry-start
///   event, which resets the running per-entry byte counter immediately before
///   dispatching; the separate byte-accumulation event never triggers a
///   dispatch of its own, so no call ever observes a nonzero value.
///
/// Creation runs on the tokio blocking thread pool. The progress callback is
/// dispatched back to the JavaScript thread via a threadsafe function.
///
/// A callback that throws cancels the creation: nothing is published and a
/// previous output stays untouched, and the promise rejects with
/// `PROGRESS_CALLBACK_ERROR` and the throw as `cause`. Cancellation is noticed
/// at the start of the next entry, so a failure of the entry whose callback
/// threw is an independent core error and wins (the throw is then its
/// `cause`).
///
/// # Arguments
///
/// * `output_path` - Path to output archive file
/// * `sources` - Array of source files/directories to include
/// * `config` - Optional `CreationConfig` (uses defaults if omitted)
/// * `options` - Optional `CreateOptions` (format, overwrite, durability)
/// * `progress` - Optional progress callback `(err: Error | null, arg: [path:
///   string, total: number | null, current: number, bytesWritten: number]) =>
///   void`
///
/// # Returns
///
/// Promise resolving to `CreationReport` with creation statistics
///
/// # Errors
///
/// Returns error if path validation fails, archive creation fails, or I/O
/// errors occur. See `createArchive` for the full list of error codes.
///
/// If `progress` throws, the returned promise rejects instead of crashing the
/// process (see issue #465), and the creation stops at the start of the next
/// entry. The rejection reports both signals:
///
/// - The callback's throw stopped the creation, or the last entry's callback
///   threw after the creation succeeded: `code` is `PROGRESS_CALLBACK_ERROR`.
///   After a stop nothing was published; after a success `filesAdded` and
///   `bytesWritten` are set, so the caller can still see that an archive was
///   written and needs cleaning up.
/// - Creation also failed on its own: the core error stays primary and keeps
///   its `code`; the callback's throw is attached as `cause`. A throwing
///   callback can never mask a core error.
///
/// In both cases the original JS exception is available as the `cause`
/// property of the rejection value. The throw's own text and stack are never
/// copied into the message — read `cause` for the callback's error detail
/// rather than parsing it out of `message`.
///
/// This holds regardless of what the callback *synchronously throws*,
/// including a bare primitive (`throw 'oops'`, `throw 42`, `throw true`):
/// `progress` is wrapped in a small JavaScript shim before it is ever handed
/// to napi-rs's threadsafe function dispatcher (see issue #473; identical
/// mechanism to `extractArchiveWithProgress`, which shares more detail on
/// why this is necessary). This does **not** cover an `async` progress
/// callback whose returned `Promise` rejects with a primitive — a
/// `try`/`catch` only observes synchronous throws. Keep `progress`
/// synchronous.
///
/// # Examples
///
/// ```javascript
/// const report = await createArchiveWithProgress(
///   'output.tar.gz',
///   ['source_dir/'],
///   null,
///   null,
///   (err, [path, total, current, bytesWritten]) => {
///     console.log(`${current}/${total}: ${path}`);
///   },
/// );
/// console.log(`Created archive with ${report.filesAdded} files`);
/// ```
#[napi]
pub fn create_archive_with_progress<'env>(
    env: &'env Env,
    output_path: String,
    sources: Vec<String>,
    config: Option<&CreationConfig>,
    options: Option<CreateOptions>,
    #[napi(ts_arg_type = "(((err: Error | null, arg: ProgressArgs) => any)) | undefined | null")]
    progress: Option<ProgressCallback>,
) -> Result<PromiseRaw<'env, CreationReport>> {
    let config_owned: exarch_core::CreationConfig = config.map_or_default(|c| c.as_core().clone());
    let progress = progress.map(|ProgressCallback(tsfn)| tsfn);
    let options = options.unwrap_or_default();

    spawn_blocking_promise(
        env,
        "archive creation with progress",
        move || {
            create_with_progress_core(
                &output_path,
                &sources,
                &config_owned,
                &options,
                progress,
                ProgressDispatch::Awaited,
            )
        },
        |report| Ok(CreationReport::from(report)),
    )
}

fn create_with_progress_core(
    output_path: &str,
    sources: &[String],
    config: &exarch_core::CreationConfig,
    options: &CreateOptions,
    progress: Option<ThreadsafeFunction<ProgressArgs>>,
    dispatch: ProgressDispatch,
) -> CoreResult<exarch_core::CreationReport> {
    let (output_path, sources) = boundary_create_paths(output_path, sources)?;
    let output = output_file(&output_path, options);
    run_with_optional_progress(
        Operation::Creation,
        progress,
        dispatch,
        AbortHandle::NONE,
        |progress| {
            Ok(exarch_core::CreateRequest::new(config)
                .with_progress(progress)
                .create(&output, &sources)?)
        },
        |source, report| ProgressCallbackError::CreationCallback { source, report },
    )
}

/// List archive contents without extracting (async).
///
/// # Arguments
///
/// * `archive_path` - Path to archive file
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
/// * `options` - Optional `ListOptions`; `new
///   ListOptions().withStoredTargets('read')` reads the link targets a 7z
///   archive keeps in entry data (default: left `'unread'`)
/// * `destination` - Optional directory `extractArchive` would write to. Its
///   volume decides whether a repeated name is listed as a `duplicate` skip or
///   as refused in `dispositions`; nothing is created
///
/// # Returns
///
/// Promise resolving to `ArchiveManifest` with entry metadata
///
/// # Errors
///
/// Returns error if path validation fails, archive is invalid, or I/O errors
/// occur.
///
/// # Examples
///
/// ```javascript
/// const manifest = await listArchive('archive.tar.gz');
/// for (const entry of manifest.entries) {
///     console.log(`${entry.path}: ${entry.size} bytes`);
/// }
/// ```
#[napi]
pub fn list_archive<'env>(
    env: &'env Env,
    archive_path: String,
    config: Option<&SecurityConfig>,
    options: Option<&ListOptions>,
    destination: Option<String>,
) -> Result<PromiseRaw<'env, ArchiveManifest>> {
    let config_owned: exarch_core::SecurityConfig = config.map_or_default(|c| c.as_core().clone());
    let options = options.map_or_default(ListOptions::to_core);

    spawn_blocking_promise(
        env,
        "archive listing",
        move || {
            list_core(
                &archive_path,
                &config_owned,
                options,
                destination.as_deref(),
            )
        },
        Ok,
    )
}

fn list_core(
    archive_path: &str,
    config: &exarch_core::SecurityConfig,
    options: exarch_core::ListOptions,
    destination: Option<&str>,
) -> CoreResult<ArchiveManifest> {
    let archive_path = boundary_path(archive_path)?;
    let volume = destination.map(boundary_path).transpose()?.map_or_else(
        || Ok(exarch_core::VolumeIdentity::default()),
        |destination| exarch_core::VolumeIdentity::of_destination(destination.as_ref()),
    )?;
    ArchiveManifest::from_core(
        exarch_core::ListRequest::new(config)
            .with_options(options)
            .list(&archive_path)?,
        config,
        volume,
    )
}

/// List archive contents without extracting (sync).
///
/// Synchronous version of `listArchive`. Blocks the event loop until
/// listing completes. Prefer the async version for most use cases.
///
/// # Arguments
///
/// * `archive_path` - Path to archive file
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
/// * `options` - Optional `ListOptions`, as in `listArchive`
/// * `destination` - Optional destination directory, as in `listArchive`
///
/// # Returns
///
/// `ArchiveManifest` with entry metadata
///
/// # Errors
///
/// Returns error if path validation fails, archive is invalid, or I/O errors
/// occur.
///
/// # Examples
///
/// ```javascript
/// const manifest = listArchiveSync('archive.tar.gz');
/// for (const entry of manifest.entries) {
///     console.log(`${entry.path}: ${entry.size} bytes`);
/// }
/// ```
#[napi]
pub fn list_archive_sync(
    env: Env,
    archive_path: String,
    config: Option<&SecurityConfig>,
    options: Option<&ListOptions>,
    destination: Option<String>,
) -> Result<ArchiveManifest> {
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());
    let options = options.map_or_default(ListOptions::to_core);

    run_sync(env, "archive listing", || {
        list_core(&archive_path, config_ref, options, destination.as_deref())
    })
}

/// Verify archive security (async).
///
/// # Arguments
///
/// * `archive_path` - Path to archive file
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
/// * `options` - Optional `VerificationOptions`; use `new
///   VerificationOptions().withIntegrityCheck()` to decode the payload and
///   verify checksums (default: metadata only, `integrityStatus` is
///   `'SKIPPED'`)
///
/// # Returns
///
/// Promise resolving to `VerificationReport` with validation results
///
/// # Errors
///
/// Returns error if path validation fails, archive is invalid, or I/O errors
/// occur. With the integrity check on, a TAR entry whose content fails to
/// decode is also an error.
///
/// # Examples
///
/// ```javascript
/// const report = await verifyArchive('archive.tar.gz');
/// if (report.status === 'PASS') {
///     console.log('Archive is safe to extract');
/// } else {
///     for (const issue of report.issues) {
///         console.log(`[${issue.severity}] ${issue.message}`);
///     }
/// }
/// ```
#[napi]
pub fn verify_archive<'env>(
    env: &'env Env,
    archive_path: String,
    config: Option<&SecurityConfig>,
    options: Option<&VerificationOptions>,
) -> Result<PromiseRaw<'env, VerificationReport>> {
    let config_owned: exarch_core::SecurityConfig = config.map_or_default(|c| c.as_core().clone());
    let options_owned: exarch_core::VerificationOptions = options.map_or_default(|o| *o.as_core());

    spawn_blocking_promise(
        env,
        "archive verification",
        move || verify_core(&archive_path, &config_owned, options_owned),
        Ok,
    )
}

fn verify_core(
    archive_path: &str,
    config: &exarch_core::SecurityConfig,
    options: exarch_core::VerificationOptions,
) -> CoreResult<VerificationReport> {
    let archive_path = boundary_path(archive_path)?;
    Ok(VerificationReport::from(
        exarch_core::VerifyRequest::new(config)
            .with_options(options)
            .verify(&archive_path)?,
    ))
}

/// Verify archive security (sync).
///
/// Synchronous version of `verifyArchive`. Blocks the event loop until
/// verification completes. Prefer the async version for most use cases.
///
/// # Arguments
///
/// * `archive_path` - Path to archive file
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
/// * `options` - Optional `VerificationOptions` (see `verifyArchive`)
///
/// # Returns
///
/// `VerificationReport` with validation results
///
/// # Errors
///
/// Returns error if path validation fails, archive is invalid, or I/O errors
/// occur.
///
/// # Examples
///
/// ```javascript
/// const report = verifyArchiveSync('archive.tar.gz');
/// if (report.status === 'PASS') {
///     console.log('Archive is safe to extract');
/// }
/// ```
#[napi]
pub fn verify_archive_sync(
    env: Env,
    archive_path: String,
    config: Option<&SecurityConfig>,
    options: Option<&VerificationOptions>,
) -> Result<VerificationReport> {
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());
    let default_options = exarch_core::VerificationOptions::default();
    let options_ref = options.map_or(&default_options, |o| o.as_core());

    run_sync(env, "archive verification", || {
        verify_core(&archive_path, config_ref, *options_ref)
    })
}

/// Extract an archive to the specified directory with a progress callback
/// (async).
///
/// The `progress` callback is called once per entry, receiving `(err,
/// [path, total, current, bytesWritten])` (napi's standard threadsafe
/// function calling convention: `err` is always `null`, the entry data
/// arrives as a single array argument) where:
/// - `path` — entry path inside the archive
/// - `total` — total number of entries as `number`, or `null` for TAR-family
///   formats because the entry count is unknown until the stream is fully read
/// - `current` — 1-based index of the current entry as `number`
/// - `bytesWritten` — always `0`. The callback only fires from the entry-start
///   event, which resets the running per-entry byte counter immediately before
///   dispatching; the separate byte-accumulation event never triggers a
///   dispatch of its own, so no call ever observes a nonzero value.
///
/// Extraction runs on the tokio blocking thread pool. The progress callback is
/// dispatched back to the JavaScript thread via a threadsafe function.
///
/// # Arguments
///
/// * `archive_path` - Path to the archive file
/// * `output_dir` - Directory where files will be extracted
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
/// * `options` - Optional `ExtractionOptions` (uses defaults if omitted)
/// * `progress` - Optional progress callback `(err: Error | null, arg: [path:
///   string, total: number | null, current: number, bytesWritten: number]) =>
///   void`
///
/// # Returns
///
/// Promise resolving to `ExtractionReport` with extraction statistics
///
/// # Errors
///
/// Rejects for security violations or I/O errors. See `extractArchive` for the
/// error properties (`code`, `relaxableBy`, `writes`, ...).
///
/// If `progress` throws, the returned promise rejects instead of crashing the
/// process (see issue #465), and the extraction stops before the next entry
/// (an atomic extraction is rolled back). The rejection reports both signals:
///
/// - The callback's throw stopped the extraction, or the last entry's callback
///   threw after it succeeded: `code` is `PROGRESS_CALLBACK_ERROR`, `writes` is
///   `'kept'` (or `'rolled_back'` for an atomic extraction) and, when kept,
///   `filesExtracted`, `bytesWritten`, `filesSkipped`, `skipped` and `warnings`
///   are set, so the caller can still see what was written to disk.
/// - Extraction also failed on its own: the core error stays primary and keeps
///   its `code`; the callback's throw is attached as `cause`. A throwing
///   callback can never mask a security error such as `SYMLINK_ESCAPE`.
///
/// In both cases the original JS exception is available as the `cause`
/// property of the rejection value. The throw's own text and stack are never
/// copied into the message — read `cause` for the callback's error detail.
///
/// This holds regardless of what the callback *synchronously throws*,
/// including a bare primitive (`throw 'oops'`, `throw 42`, `throw true`):
/// `progress` is wrapped in a small JavaScript shim before it is ever handed
/// to napi-rs's threadsafe function dispatcher (see issue #473). The shim's
/// `try`/`catch` catches any synchronous throw and, unless the thrown value
/// is already an object or function `napi_create_reference()` can reference,
/// re-throws a new `Error` carrying the original value as `cause`. napi-rs
/// 3.12.0's `call_async_catch` dispatcher crashes the host process
/// uncatchably when the JS value it observes crossing the callback boundary
/// is a primitive — `napi_create_reference()` cannot create a weak reference
/// to one, and the resulting non-ok status is escalated to
/// `napi_fatal_exception` regardless of the exception having already been
/// delivered to the channel — so the shim guarantees napi-rs never observes
/// a primitive throw in the first place, rather than relying on a fix inside
/// the upstream dispatcher.
///
/// This does **not** cover an `async` progress callback whose returned
/// `Promise` rejects with a primitive: a `try`/`catch` only observes
/// synchronous throws, so a rejected `Promise` passes through the shim as an
/// ordinary (fulfilled, from the shim's point of view) return value, napi-rs
/// never awaits it, and Node terminates the process with
/// `ERR_UNHANDLED_REJECTION` once the rejection goes unhandled — a
/// pre-existing gap (present since before #465) that this fix does not
/// address. Keep `progress` synchronous.
///
/// # Examples
///
/// ```javascript
/// const report = await extractArchiveWithProgress(
///   'archive.tar.gz',
///   '/tmp/output',
///   null,
///   null,
///   (err, [path, total, current, bytesWritten]) => {
///     console.log(`${current}/${total}: ${path}`);
///   },
/// );
/// console.log(`Extracted ${report.filesExtracted} files`);
/// ```
#[napi]
pub fn extract_archive_with_progress<'env>(
    env: &'env Env,
    archive_path: String,
    output_dir: String,
    config: Option<&SecurityConfig>,
    options: Option<&ExtractionOptions>,
    #[napi(ts_arg_type = "(((err: Error | null, arg: ProgressArgs) => any)) | undefined | null")]
    progress: Option<ProgressCallback>,
) -> Result<PromiseRaw<'env, ExtractionReport>> {
    let config_owned: exarch_core::SecurityConfig = config.map_or_default(|c| c.as_core().clone());
    let options_owned: exarch_core::ExtractionOptions =
        options.map_or_default(|o| o.as_core().clone());
    let progress = progress.map(|ProgressCallback(tsfn)| tsfn);

    spawn_blocking_promise(
        env,
        "archive extraction with progress",
        move || {
            let archive_path = boundary_path(&archive_path)?;
            let output_dir = boundary_path(&output_dir)?;
            run_with_optional_progress(
                Operation::Extraction,
                progress,
                ProgressDispatch::Awaited,
                AbortHandle::NONE,
                |progress| {
                    Ok(exarch_core::ExtractRequest::new(&config_owned)
                        .with_options(options_owned.clone())
                        .with_progress(progress)
                        .extract(&archive_path, &output_dir)?)
                },
                |source, report| ProgressCallbackError::ExtractionCallback { source, report },
            )
        },
        |report| Ok(ExtractionReport::from(report)),
    )
}

/// The value a progress callback receives: path, entry count (`None` while the
/// archive's entry count is unknown, as for a TAR stream), 1-based index and
/// bytes written for the entry.
pub(crate) type ProgressArgs = (String, Option<i64>, i64, i64);

/// Adapter that calls a JavaScript progress callback from a Rust worker thread.
///
/// Shared by extraction and creation. The JavaScript callback receives `(err:
/// Error | null, [path, total, current, bytesWritten])`. `bytesWritten` is
/// always `0`: only `on_entry_start` dispatches a call, and no byte of that
/// entry has been written yet. Reporting the bytes of the preceding entry
/// instead would be the stale value #285 removed from the Python binding.
///
/// If the JavaScript callback throws, the exception is captured into
/// `callback_error` instead of being routed through `napi_fatal_exception`
/// (which would otherwise crash the host process uncatchably, see issue
/// #465). Once a throw has been captured, further dispatches are skipped and
/// [`exarch_core::ProgressCallback::is_cancelled`] answers `true`, so the
/// operation stops at its next poll. A fired `AbortSignal` cancels the same
/// way.
struct NodeProgressAdapter {
    tsfn: ThreadsafeFunction<ProgressArgs>,
    dispatch: ProgressDispatch,
    callback_error: Option<Error>,
    abort: AbortHandle,
}

/// Runs `run` with the JS callback `progress` (or a no-op reporter when absent)
/// on a worker thread, merging a core failure and a callback throw the way
/// `extractArchiveWithProgress` does.
///
/// A throw after a successful run becomes the error built by `over_success`,
/// which receives the successful value so it can keep its counters; the value
/// itself is discarded.
fn run_with_optional_progress<T>(
    operation: Operation,
    progress: Option<ThreadsafeFunction<ProgressArgs>>,
    dispatch: ProgressDispatch,
    abort: AbortHandle,
    run: impl FnOnce(&mut dyn exarch_core::ProgressCallback) -> CoreResult<T>,
    over_success: impl FnOnce(Error, T) -> ProgressCallbackError,
) -> CoreResult<T> {
    let Some(tsfn) = progress else {
        return run(&mut exarch_core::NoopProgress);
    };
    let mut adapter = NodeProgressAdapter::new(tsfn, dispatch, abort);
    let result = run(&mut adapter);
    match (result, adapter.into_callback_error()) {
        (Ok(value), None) => Ok(value),
        (Ok(value), Some(source)) => Err(Failure::Callback(Box::new(over_success(source, value)))),
        (Err(Failure::Core(source)), callback) => Err(Failure::Callback(Box::new(
            ProgressCallbackError::merge(operation, source, callback),
        ))),
        (Err(other), _) => Err(other),
    }
}

/// How a progress dispatch reaches the JavaScript thread, which decides whether
/// a callback throw can be reported through the operation's own result.
#[derive(Clone, Copy)]
enum ProgressDispatch {
    /// The operation runs on a worker thread while the JavaScript event loop
    /// keeps turning, so each dispatch can be awaited and a throw captured into
    /// `callback_error` before the operation returns.
    Awaited,
    /// The operation runs on the JavaScript thread itself (a `*Sync` entry
    /// point), so the event loop cannot turn until it returns and awaiting a
    /// dispatch would deadlock. Calls are queued and delivered afterwards,
    /// which also means a throw cannot be routed back into the return value.
    Deferred,
}

impl NodeProgressAdapter {
    fn new(
        tsfn: ThreadsafeFunction<ProgressArgs>,
        dispatch: ProgressDispatch,
        abort: AbortHandle,
    ) -> Self {
        Self {
            abort,
            tsfn,
            dispatch,
            callback_error: None,
        }
    }

    /// Consumes the adapter, returning the error captured from a throwing JS
    /// progress callback, if one occurred.
    fn into_callback_error(self) -> Option<Error> {
        self.callback_error
    }
}

impl exarch_core::ProgressCallback for NodeProgressAdapter {
    fn on_entry_start(&mut self, path: &std::path::Path, position: exarch_core::EntryPosition) {
        let total = position.total.known();
        let current = position.current.get();
        if self.callback_error.is_some() || self.abort.check().is_err() {
            return;
        }
        let path_str = path_text(path);
        let total_i64 = total.map(saturating_usize);
        let current_i64 = saturating_usize(current);
        let value = Ok((path_str, total_i64, current_i64, 0));
        match self.dispatch {
            // `call_async_catch` clears and captures a JS throw into `Err`
            // rather than routing it through `napi_fatal_exception`. `block_on`
            // is sound here because an `Awaited` adapter runs only on a
            // `spawn_blocking` worker thread, never inside an async
            // task-polling context and never on the JS thread.
            ProgressDispatch::Awaited => {
                if let Err(err) =
                    tokio::runtime::Handle::current().block_on(self.tsfn.call_async_catch(value))
                {
                    self.callback_error = Some(err);
                }
            }
            // No runtime is entered on the JS thread and the event loop is
            // blocked, so the dispatch is queued unawaited. A throw surfaces as
            // an ordinary Node.js `uncaughtException` on the delivering turn.
            ProgressDispatch::Deferred => {
                self.tsfn
                    .call(value, ThreadsafeFunctionCallMode::NonBlocking);
            }
        }
    }

    fn on_bytes_written(&mut self, _bytes: u64) {}

    fn on_entry_complete(&mut self, _path: &std::path::Path) {}

    fn on_complete(&mut self) {}

    fn is_cancelled(&mut self) -> bool {
        self.callback_error.is_some() || self.abort.check().is_err()
    }
}

#[cfg(test)]
mod tests {
    use exarch_core::ArchiveError as CoreError;

    use super::*;

    fn long_path() -> String {
        "x".repeat(5000)
    }

    /// Asserts `result` is the core `SecurityViolation` the boundary check
    /// raises, with `needle` in its message.
    fn assert_boundary_violation<T: std::fmt::Debug>(result: CoreResult<T>, needle: &str) {
        match result {
            Err(Failure::Core(err @ CoreError::SecurityViolation { .. })) => {
                assert!(err.to_string().contains(needle), "got: {err}");
            }
            other => panic!("expected a boundary SecurityViolation, got {other:?}"),
        }
    }

    /// Asserts `result` did not fail at the boundary: empty and valid paths
    /// pass boundary validation, and core handles the rest.
    fn assert_not_boundary_error<T>(result: CoreResult<T>) {
        if let Err(err) = result {
            let msg = error::failure_text(err);
            assert!(
                !msg.contains("null bytes") && !msg.contains("maximum length"),
                "should not fail on boundary path validation, got: {msg}"
            );
        }
    }

    fn security() -> exarch_core::SecurityConfig {
        exarch_core::SecurityConfig::default()
    }

    fn extraction() -> exarch_core::ExtractionOptions {
        exarch_core::ExtractionOptions::default()
    }

    fn creation() -> exarch_core::CreationConfig {
        exarch_core::CreationConfig::default()
    }

    #[test]
    fn test_extract_rejects_null_byte_in_archive_path() {
        let result = extract_core("/tmp/test\0x.tar", "/tmp/out", &security(), &extraction());
        assert_boundary_violation(result, "null bytes");
    }

    #[test]
    fn test_extract_rejects_null_byte_in_output_dir() {
        let result = extract_core("/tmp/test.tar", "/tmp/out\0x", &security(), &extraction());
        assert_boundary_violation(result, "null bytes");
    }

    #[test]
    fn test_extract_rejects_excessively_long_paths() {
        let long = long_path();
        let archive = extract_core(&long, "/tmp/out", &security(), &extraction());
        assert_boundary_violation(archive, "maximum length");
        let output = extract_core("/tmp/test.tar", &long, &security(), &extraction());
        assert_boundary_violation(output, "maximum length");
    }

    #[test]
    fn test_extract_accepts_empty_and_relative_paths() {
        assert_not_boundary_error(extract_core("", "", &security(), &extraction()));
        assert_not_boundary_error(extract_core(
            "relative_test.tar",
            "relative_output",
            &security(),
            &extraction(),
        ));
    }

    #[test]
    fn test_create_rejects_null_byte_in_output_and_sources() {
        let sources = vec!["source/".to_string()];
        assert_boundary_violation(
            create_core(
                "/tmp/out\0x.tar",
                &sources,
                &creation(),
                &CreateOptions::default(),
            ),
            "null bytes",
        );
        let bad_sources = vec!["ok/".to_string(), "src\0x".to_string()];
        assert_boundary_violation(
            create_core(
                "/tmp/out.tar",
                &bad_sources,
                &creation(),
                &CreateOptions::default(),
            ),
            "null bytes",
        );
    }

    #[test]
    fn test_create_rejects_excessively_long_paths() {
        let long = long_path();
        assert_boundary_violation(
            create_core(
                &long,
                &["source/".to_string()],
                &creation(),
                &CreateOptions::default(),
            ),
            "maximum length",
        );
        assert_boundary_violation(
            create_core(
                "/tmp/out.tar",
                &[long],
                &creation(),
                &CreateOptions::default(),
            ),
            "maximum length",
        );
    }

    #[test]
    fn test_create_accepts_empty_sources() {
        assert_not_boundary_error(create_core(
            "/tmp/exarch-empty-sources.tar",
            &[],
            &creation(),
            &CreateOptions::default(),
        ));
    }

    #[test]
    fn test_create_with_progress_rejects_null_byte() {
        let result = create_with_progress_core(
            "/tmp/out\0x.tar",
            &[],
            &creation(),
            &CreateOptions::default(),
            None,
            ProgressDispatch::Deferred,
        );
        assert_boundary_violation(result, "null bytes");
    }

    #[test]
    fn test_list_rejects_invalid_archive_path() {
        let options = exarch_core::ListOptions::default();
        assert_boundary_violation(
            list_core("/tmp/test\0x.tar", &security(), options, None),
            "null bytes",
        );
        assert_boundary_violation(
            list_core(&long_path(), &security(), options, None),
            "maximum length",
        );
    }

    #[test]
    fn test_verify_rejects_invalid_archive_path() {
        let options = exarch_core::VerificationOptions::default();
        assert_boundary_violation(
            verify_core("/tmp/test\0x.tar", &security(), options),
            "null bytes",
        );
        assert_boundary_violation(
            verify_core(&long_path(), &security(), options),
            "maximum length",
        );
    }
}
