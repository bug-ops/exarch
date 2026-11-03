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
mod report;
mod stream;
mod utils;

use abort::AbortHandle;
use config::CreationConfig;
use config::ExtractionOptions;
use config::SecurityConfig;
use config::VerificationOptions;
use error::Failure;
use error::ProgressCallbackError;
use error::run_sync;
use error::spawn_blocking_promise;
use report::ArchiveManifest;
use report::CreationReport;
use report::ExtractionReport;
use report::VerificationReport;
use utils::validate_path;

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
/// The extraction runs on a tokio blocking-pool worker thread. This creates
/// a Time-Of-Check-Time-Of-Use (TOCTOU) race condition where the archive
/// file could be modified between validation and extraction. This is an
/// accepted tradeoff for async performance. For untrusted archives, ensure
/// exclusive access to the archive file during extraction.
///
/// ## Input Validation
///
/// - Paths containing null bytes are rejected (security)
/// - Paths exceeding 4096 bytes are rejected (`DoS` prevention)
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
///   binding itself (a negative size, an internal panic) keep napi's status
///   (`GenericFailure`) as `code`.
/// - `relaxableBy`: set on a `SECURITY_VIOLATION` that a `SecurityConfig`
///   setting relaxes, one of `symlinks`, `hardlinks`, `solid_archives`,
///   `banned_components`, `max_path_depth`, `windows_reserved_names` or
///   `max_tar_metadata_bytes`; absent when no setting relaxes the refusal.
///   Changing the setting removes that refusal only; the entry can still fail a
///   later check. `windows_reserved_names` and `max_tar_metadata_bytes` have no
///   setter in this binding (Rust API only).
/// - `writes`, `filesExtracted`, `bytesWritten`, `filesSkipped`, `warnings`:
///   set when extraction fails after some files were already written. `writes`
///   is `'kept'` (files remain; the counters and the `warnings` string array
///   follow) or, with `atomic`, `'rolled_back'` (the destination was discarded;
///   no counters).
///
/// # Examples
///
/// ```javascript
/// // Use secure defaults
/// const report = await extractArchive('archive.tar.gz', '/tmp/output');
/// console.log(`Extracted ${report.filesExtracted} files`);
///
/// // Customize security settings
/// const config = new SecurityConfig().setMaxFileSize(100 * 1024 * 1024);
/// const report = await extractArchive('archive.tar.gz', '/tmp/output', config);
///
/// // Customize extraction options
/// const opts = new ExtractionOptions().withSkipDuplicates(false);
/// const report = await extractArchive('archive.tar.gz', '/tmp/output', null, opts);
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
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

    // NOTE: TOCTOU race condition - archive contents can change between
    // validation and extraction. This is an accepted limitation for async I/O.
    // For maximum security with untrusted archives, use extractArchiveSync()
    // or ensure exclusive file access (e.g., flock) during extraction.
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
    validate_path(archive_path)?;
    validate_path(output_dir)?;
    Ok(exarch_core::extract_archive_with_options(
        archive_path,
        output_dir,
        config,
        options,
    )?)
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
/// const config = new SecurityConfig().setMaxFileSize(100 * 1024 * 1024);
/// const report = extractArchiveSync('archive.tar.gz', '/tmp/output', config);
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
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
/// const config = new CreationConfig().compressionLevel(9);
/// const report = await createArchive('output.tar.gz', ['src/'], config);
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn create_archive<'env>(
    env: &'env Env,
    output_path: String,
    sources: Vec<String>,
    config: Option<&CreationConfig>,
) -> Result<PromiseRaw<'env, CreationReport>> {
    let config_owned: exarch_core::creation::CreationConfig =
        config.map_or_default(|c| c.as_core().clone());

    spawn_blocking_promise(
        env,
        "archive creation",
        move || create_core(&output_path, &sources, &config_owned),
        |report| Ok(CreationReport::from(report)),
    )
}

fn validate_create_paths(output_path: &str, sources: &[String]) -> CoreResult<()> {
    validate_path(output_path)?;
    sources
        .iter()
        .try_for_each(|source| validate_path(source))?;
    Ok(())
}

fn create_core(
    output_path: &str,
    sources: &[String],
    config: &exarch_core::creation::CreationConfig,
) -> CoreResult<exarch_core::creation::CreationReport> {
    validate_create_paths(output_path, sources)?;
    let sources_refs: Vec<&str> = sources.iter().map(String::as_str).collect();
    Ok(exarch_core::create_archive(
        output_path,
        &sources_refs,
        config,
    )?)
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
#[allow(clippy::needless_pass_by_value)]
pub fn create_archive_sync(
    env: Env,
    output_path: String,
    sources: Vec<String>,
    config: Option<&CreationConfig>,
) -> Result<CreationReport> {
    let default_config = exarch_core::creation::CreationConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    run_sync(env, "archive creation", || {
        create_core(&output_path, &sources, config_ref)
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
/// type exists to prevent. `createArchiveWithProgressSync` dispatches
/// through `ProgressDispatch::Deferred` (plain `ThreadsafeFunction::call`)
/// instead, which never enters the buggy code path in the first place — see
/// its own doc comment — so it takes a raw `ThreadsafeFunction` unchanged.
///
/// The wrapping must happen inside [`FromNapiValue::from_napi_value`] rather
/// than in the body of an `async fn` like `extract_archive_with_progress`:
/// `Env` and `Function` wrap raw, thread-affine JS engine pointers and are
/// not `Send`, so neither can be a parameter of that `async fn` — its future
/// is later driven by `tokio::task::spawn_blocking`, which requires `Send`.
/// Argument extraction, by contrast, always runs synchronously on the JS
/// thread before the future is constructed, which is exactly where
/// `Env`/`Function` access is valid.
pub struct ProgressCallback(ThreadsafeFunction<(String, i64, i64, i64)>);

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
            .build_threadsafe_function::<(String, i64, i64, i64)>()
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
/// - `total` — total number of entries as `number`
/// - `current` — 1-based index of the current entry as `number`
/// - `bytesWritten` — always `0`. The callback only fires from the entry-start
///   event, which resets the running per-entry byte counter immediately before
///   dispatching; the separate byte-accumulation event never triggers a
///   dispatch of its own, so no call ever observes a nonzero value.
///
/// Creation runs on the tokio blocking thread pool. The progress callback is
/// dispatched back to the JavaScript thread via a threadsafe function.
///
/// # Arguments
///
/// * `output_path` - Path to output archive file
/// * `sources` - Array of source files/directories to include
/// * `config` - Optional `CreationConfig` (uses defaults if omitted)
/// * `progress` - Optional progress callback `(err: Error | null, arg: [path:
///   string, total: number, current: number, bytesWritten: number]) => void`
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
/// process (see issue #465). Creation has already run to completion (or
/// failure) by the time the rejection is observed — a throwing callback cannot
/// abort creation early, since the progress callback contract has no
/// cancellation signal. The rejection therefore reports both signals:
///
/// - Creation succeeded: `code` is `PROGRESS_CALLBACK_ERROR` and `filesAdded`
///   and `bytesWritten` are set, so the caller can still see that an archive
///   was written and needs cleaning up.
/// - Creation also failed: the core error stays primary and keeps its `code`;
///   the callback's throw is attached as `cause`. A throwing callback can never
///   mask a core error.
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
/// `try`/`catch` only observes synchronous throws — nor
/// `createArchiveWithProgressSync`'s deferred dispatch, which never enters
/// the affected code path to begin with (see its own doc comment). Keep
/// `progress` synchronous.
///
/// # Examples
///
/// ```javascript
/// const report = await createArchiveWithProgress(
///   'output.tar.gz',
///   ['source_dir/'],
///   null,
///   (err, [path, total, current, bytesWritten]) => {
///     console.log(`${current}/${total}: ${path}`);
///   },
/// );
/// console.log(`Created archive with ${report.filesAdded} files`);
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn create_archive_with_progress<'env>(
    env: &'env Env,
    output_path: String,
    sources: Vec<String>,
    config: Option<&CreationConfig>,
    #[napi(
        ts_arg_type = "(((err: Error | null, arg: [string, number, number, number]) => any)) | undefined | null"
    )]
    progress: Option<ProgressCallback>,
) -> Result<PromiseRaw<'env, CreationReport>> {
    let config_owned: exarch_core::creation::CreationConfig =
        config.map_or_default(|c| c.as_core().clone());
    let progress = progress.map(|ProgressCallback(tsfn)| tsfn);

    spawn_blocking_promise(
        env,
        "archive creation with progress",
        move || {
            create_with_progress_core(
                &output_path,
                &sources,
                &config_owned,
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
    config: &exarch_core::creation::CreationConfig,
    progress: Option<ThreadsafeFunction<(String, i64, i64, i64)>>,
    dispatch: ProgressDispatch,
) -> CoreResult<exarch_core::creation::CreationReport> {
    validate_create_paths(output_path, sources)?;
    let sources_refs: Vec<&str> = sources.iter().map(String::as_str).collect();
    run_create_with_optional_progress(output_path, &sources_refs, config, progress, dispatch)
        .map_err(Failure::Callback)
}

/// Create an archive from source files and directories with a progress
/// callback (sync).
///
/// Synchronous version of `createArchiveWithProgress`. Blocks the event loop
/// until creation completes. Prefer the async version for most use cases.
///
/// # `progress` does not report live during this call
///
/// `progress` is dispatched through the same threadsafe-function mechanism as
/// the async variant, which only ever delivers calls on a turn of the Node.js
/// event loop. Because this function blocks that same event loop until it
/// returns, **every queued call is delivered only after
/// `createArchiveWithProgressSync` has already returned** — none of them fire
/// during the call, so `progress` cannot be used to report *live* progress
/// here. Use `createArchiveWithProgress` instead if you need progress updates
/// while creation is still running.
///
/// ## A throwing `progress` surfaces as an `uncaughtException`
///
/// Because every call is delivered after this function has already returned,
/// there is no return value left to carry a callback throw: this function has
/// resolved with its `CreationReport` by then. A throw therefore propagates the
/// way any throw from a deferred callback does — as a process-level
/// `uncaughtException` on the turn that delivered the call, observable via
/// `process.on('uncaughtException', ...)`. It is never merged into a
/// `PROGRESS_CALLBACK_ERROR` result the way `createArchiveWithProgress` merges
/// it, and it cannot be caught by wrapping this call in `try`/`catch`.
///
/// The primitive-throw crash documented on `createArchiveWithProgress` does
/// **not** apply here: that defect lives in the await-the-result dispatch path,
/// which this function cannot use (awaiting a call that only the blocked event
/// loop can deliver would deadlock). Queued calls take the plain dispatch path
/// instead, where a thrown primitive reaches `uncaughtException` intact just
/// like a thrown `Error`.
///
/// # Arguments
///
/// * `output_path` - Path to output archive file
/// * `sources` - Array of source files/directories to include
/// * `config` - Optional `CreationConfig` (uses defaults if omitted)
/// * `progress` - Optional progress callback `(err: Error | null, arg: [path:
///   string, total: number, current: number, bytesWritten: number]) => void`.
///   See the sections above: calls arrive only after this function returns, and
///   a throw becomes an `uncaughtException` rather than an error from here.
///
/// # Returns
///
/// `CreationReport` with creation statistics
///
/// # Errors
///
/// Returns error if path validation fails, archive creation fails, or I/O
/// errors occur. See `createArchive` for the full list of error codes.
///
/// # Examples
///
/// ```javascript
/// const report = createArchiveWithProgressSync(
///   'output.tar.gz',
///   ['source_dir/'],
///   null,
///   (err, [path, total, current, bytesWritten]) => {
///     // Fires only after createArchiveWithProgressSync has already returned.
///     console.log(`${current}/${total}: ${path}`);
///   },
/// );
/// console.log(`Created archive with ${report.filesAdded} files`);
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn create_archive_with_progress_sync(
    env: Env,
    output_path: String,
    sources: Vec<String>,
    config: Option<&CreationConfig>,
    progress: Option<ThreadsafeFunction<(String, i64, i64, i64)>>,
) -> Result<CreationReport> {
    let default_config = exarch_core::creation::CreationConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    run_sync(env, "archive creation with progress", || {
        create_with_progress_core(
            &output_path,
            &sources,
            config_ref,
            progress,
            ProgressDispatch::Deferred,
        )
    })
    .map(CreationReport::from)
}

/// Runs `create_archive_with_progress` routing to the JS callback when
/// present or to [`exarch_core::NoopProgress`] when absent.
///
/// A core creation failure and a JS callback throw can occur in the same run;
/// both are carried out of here so neither is silently dropped, mirroring
/// [`run_extract_with_optional_progress`]. Under
/// [`ProgressDispatch::Deferred`] no throw is ever observable here — the
/// callback runs only after the caller has returned.
fn run_create_with_optional_progress(
    output_path: &str,
    sources: &[&str],
    config: &exarch_core::creation::CreationConfig,
    progress: Option<ThreadsafeFunction<(String, i64, i64, i64)>>,
    dispatch: ProgressDispatch,
) -> std::result::Result<exarch_core::creation::CreationReport, Box<ProgressCallbackError>> {
    progress.map_or_else(
        || {
            let mut noop = exarch_core::NoopProgress;
            exarch_core::create_archive_with_progress(output_path, sources, config, &mut noop)
                .map_err(|source| {
                    Box::new(ProgressCallbackError::Core {
                        source,
                        callback: None,
                    })
                })
        },
        |tsfn| {
            let mut callback = NodeProgressAdapter::new(tsfn, dispatch, AbortHandle::NONE);
            let result = exarch_core::create_archive_with_progress(
                output_path,
                sources,
                config,
                &mut callback,
            );
            match (result, callback.into_callback_error()) {
                (Ok(report), None) => Ok(report),
                (Ok(report), Some(source)) => {
                    Err(Box::new(ProgressCallbackError::CreationCallback {
                        source,
                        report,
                    }))
                }
                (Err(source), callback) => {
                    Err(Box::new(ProgressCallbackError::Core { source, callback }))
                }
            }
        },
    )
}

/// List archive contents without extracting (async).
///
/// # Arguments
///
/// * `archive_path` - Path to archive file
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
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
#[allow(clippy::needless_pass_by_value)]
pub fn list_archive<'env>(
    env: &'env Env,
    archive_path: String,
    config: Option<&SecurityConfig>,
) -> Result<PromiseRaw<'env, ArchiveManifest>> {
    let config_owned: exarch_core::SecurityConfig = config.map_or_default(|c| c.as_core().clone());

    spawn_blocking_promise(
        env,
        "archive listing",
        move || list_core(&archive_path, &config_owned),
        ArchiveManifest::try_from,
    )
}

fn list_core(
    archive_path: &str,
    config: &exarch_core::SecurityConfig,
) -> CoreResult<exarch_core::inspection::ArchiveManifest> {
    validate_path(archive_path)?;
    Ok(exarch_core::list_archive(archive_path, config)?)
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
#[allow(clippy::needless_pass_by_value)]
pub fn list_archive_sync(
    env: Env,
    archive_path: String,
    config: Option<&SecurityConfig>,
) -> Result<ArchiveManifest> {
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    let manifest = run_sync(env, "archive listing", || {
        list_core(&archive_path, config_ref)
    })?;

    ArchiveManifest::try_from(manifest)
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
#[allow(clippy::needless_pass_by_value)]
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
        VerificationReport::try_from,
    )
}

fn verify_core(
    archive_path: &str,
    config: &exarch_core::SecurityConfig,
    options: exarch_core::VerificationOptions,
) -> CoreResult<exarch_core::inspection::VerificationReport> {
    validate_path(archive_path)?;
    Ok(exarch_core::verify_archive_with_options(
        archive_path,
        config,
        &options,
    )?)
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
#[allow(clippy::needless_pass_by_value)]
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

    let report = run_sync(env, "archive verification", || {
        verify_core(&archive_path, config_ref, *options_ref)
    })?;

    VerificationReport::try_from(report)
}

/// Extract an archive to the specified directory with a progress callback
/// (async).
///
/// The `progress` callback is called once per entry, receiving `(err,
/// [path, total, current, bytesWritten])` (napi's standard threadsafe
/// function calling convention: `err` is always `null`, the entry data
/// arrives as a single array argument) where:
/// - `path` — entry path inside the archive
/// - `total` — total number of entries as `number` (0 for TAR-family formats
///   because the entry count is unknown until the stream is fully read)
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
///   string, total: number, current: number, bytesWritten: number]) => void`
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
/// process (see issue #465). Extraction has already run to completion (or
/// failure) by the time the rejection is observed — a throwing callback cannot
/// abort the extraction early, since the progress callback contract has no
/// cancellation signal. The rejection therefore reports both signals:
///
/// - Extraction succeeded: `code` is `PROGRESS_CALLBACK_ERROR`, `writes` is
///   `'kept'` and `filesExtracted`, `bytesWritten`, `filesSkipped` and
///   `warnings` are set, so the caller can still see what was written to disk.
/// - Extraction also failed: the core error stays primary and keeps its `code`;
///   the callback's throw is attached as `cause`. A throwing callback can never
///   mask a security error such as `SYMLINK_ESCAPE`.
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
#[allow(clippy::needless_pass_by_value)]
pub fn extract_archive_with_progress<'env>(
    env: &'env Env,
    archive_path: String,
    output_dir: String,
    config: Option<&SecurityConfig>,
    options: Option<&ExtractionOptions>,
    #[napi(
        ts_arg_type = "(((err: Error | null, arg: [string, number, number, number]) => any)) | undefined | null"
    )]
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
            validate_path(&archive_path)?;
            validate_path(&output_dir)?;
            run_extract_with_optional_progress(
                &archive_path,
                &output_dir,
                &config_owned,
                &options_owned,
                progress,
            )
            .map_err(Failure::Callback)
        },
        |report| Ok(ExtractionReport::from(report)),
    )
}

/// Runs `extract_archive_with_options_and_progress` routing to the JS callback
/// when present or to [`exarch_core::NoopProgress`] when absent.
///
/// A core extraction failure and a JS callback throw can occur in the same
/// run; both are carried out of here so neither is silently dropped (see the
/// `From<ProgressCallbackError>` impl for how they merge into one rejection).
fn run_extract_with_optional_progress(
    archive_path: &str,
    output_dir: &str,
    config: &exarch_core::SecurityConfig,
    options: &exarch_core::ExtractionOptions,
    progress: Option<ThreadsafeFunction<(String, i64, i64, i64)>>,
) -> std::result::Result<exarch_core::ExtractionReport, Box<ProgressCallbackError>> {
    progress.map_or_else(
        || {
            let mut noop = exarch_core::NoopProgress;
            exarch_core::extract_archive_with_options_and_progress(
                archive_path,
                output_dir,
                config,
                options,
                &mut noop,
            )
            .map_err(|source| {
                Box::new(ProgressCallbackError::Core {
                    source,
                    callback: None,
                })
            })
        },
        |tsfn| {
            let mut callback =
                NodeProgressAdapter::new(tsfn, ProgressDispatch::Awaited, AbortHandle::NONE);
            let result = exarch_core::extract_archive_with_options_and_progress(
                archive_path,
                output_dir,
                config,
                options,
                &mut callback,
            );
            match (result, callback.into_callback_error()) {
                (Ok(report), None) => Ok(report),
                (Ok(report), Some(source)) => {
                    Err(Box::new(ProgressCallbackError::ExtractionCallback {
                        source,
                        report,
                    }))
                }
                (Err(source), callback) => {
                    Err(Box::new(ProgressCallbackError::Core { source, callback }))
                }
            }
        },
    )
}

/// Adapter that calls a JavaScript progress callback from a Rust worker thread.
///
/// Shared by extraction and creation. The JavaScript callback receives `(err:
/// Error | null, [path, total, current, bytesWritten])`. `bytesWritten` is
/// always `0`: only `on_entry_start` dispatches a call, and it resets
/// `current_entry_bytes` to `0` immediately before doing so. `on_bytes_written`
/// does accumulate per-chunk writes (during creation; extraction also emits
/// these events for some formats), but never triggers a dispatch of its own.
///
/// If the JavaScript callback throws, the exception is captured into
/// `callback_error` instead of being routed through `napi_fatal_exception`
/// (which would otherwise crash the host process uncatchably, see issue
/// #465). Once a throw has been captured, further dispatches are skipped:
/// the [`exarch_core::ProgressCallback`] contract has no cancellation signal,
/// so extraction/creation keeps running, but there is no value in repeatedly
/// invoking a callback already known to be broken.
struct NodeProgressAdapter {
    tsfn: ThreadsafeFunction<(String, i64, i64, i64)>,
    dispatch: ProgressDispatch,
    current_entry_bytes: i64,
    total: usize,
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
    progress: Option<ThreadsafeFunction<(String, i64, i64, i64)>>,
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
        (Err(Failure::Core(source)), callback) => {
            Err(Failure::Callback(Box::new(ProgressCallbackError::Core {
                source,
                callback,
            })))
        }
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
        tsfn: ThreadsafeFunction<(String, i64, i64, i64)>,
        dispatch: ProgressDispatch,
        abort: AbortHandle,
    ) -> Self {
        Self {
            abort,
            tsfn,
            dispatch,
            current_entry_bytes: 0,
            total: 0,
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
    fn on_entry_start(&mut self, path: &std::path::Path, total: usize, current: usize) {
        if self.callback_error.is_some() || self.abort.check().is_err() {
            return;
        }
        self.current_entry_bytes = 0;
        self.total = total;
        let path_str = path.to_string_lossy().into_owned();
        let total_i64 = i64::try_from(total).unwrap_or(i64::MAX);
        let current_i64 = i64::try_from(current).unwrap_or(i64::MAX);
        let value = Ok((path_str, total_i64, current_i64, self.current_entry_bytes));
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

    fn on_bytes_written(&mut self, bytes: u64) {
        self.current_entry_bytes = self.current_entry_bytes.saturating_add(bytes.cast_signed());
    }

    fn on_entry_complete(&mut self, _path: &std::path::Path) {}

    fn on_complete(&mut self) {}
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
            let msg = err.to_string();
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

    fn creation() -> exarch_core::creation::CreationConfig {
        exarch_core::creation::CreationConfig::default()
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
            create_core("/tmp/out\0x.tar", &sources, &creation()),
            "null bytes",
        );
        let bad_sources = vec!["ok/".to_string(), "src\0x".to_string()];
        assert_boundary_violation(
            create_core("/tmp/out.tar", &bad_sources, &creation()),
            "null bytes",
        );
    }

    #[test]
    fn test_create_rejects_excessively_long_paths() {
        let long = long_path();
        assert_boundary_violation(
            create_core(&long, &["source/".to_string()], &creation()),
            "maximum length",
        );
        assert_boundary_violation(
            create_core("/tmp/out.tar", &[long], &creation()),
            "maximum length",
        );
    }

    #[test]
    fn test_create_accepts_empty_sources() {
        assert_not_boundary_error(create_core(
            "/tmp/exarch-empty-sources.tar",
            &[],
            &creation(),
        ));
    }

    #[test]
    fn test_create_with_progress_rejects_null_byte() {
        let result = create_with_progress_core(
            "/tmp/out\0x.tar",
            &[],
            &creation(),
            None,
            ProgressDispatch::Deferred,
        );
        assert_boundary_violation(result, "null bytes");
    }

    #[test]
    fn test_list_rejects_invalid_archive_path() {
        assert_boundary_violation(list_core("/tmp/test\0x.tar", &security()), "null bytes");
        assert_boundary_violation(list_core(&long_path(), &security()), "maximum length");
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
