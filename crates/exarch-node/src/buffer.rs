//! Archives held in memory instead of on disk.

use napi::Env;
use napi::bindgen_prelude::PromiseRaw;
use napi::bindgen_prelude::Result;
use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;

use crate::CoreResult;
use crate::ProgressArgs;
use crate::ProgressCallback;
use crate::ProgressDispatch;
use crate::abort::AbortBinding;
use crate::config::ListOptions;
use crate::config::SecurityConfig;
use crate::config::VerificationOptions;
use crate::error::Operation;
use crate::error::ProgressCallbackError;
use crate::error::run_sync;
use crate::error::spawn_blocking_promise_with;
use crate::report::ArchiveManifest;
use crate::report::ArchiveType;
use crate::report::VerificationReport;
use crate::run_with_optional_progress;
use crate::stream::AbortableSource;
use crate::stream::ArchiveSource;
use crate::stream::IntoSource;
use napi::threadsafe_function::ThreadsafeFunction;

fn list_core(
    data: impl IntoSource,
    config: &exarch_core::SecurityConfig,
    format: Option<ArchiveType>,
    options: exarch_core::ListOptions,
) -> CoreResult<ArchiveManifest> {
    data.run(format, |reader| {
        ArchiveManifest::from_core(
            exarch_core::ListRequest::new(config)
                .with_options(options)
                .list_reader(reader)?,
            config,
        )
    })
}

fn verify_core(
    data: impl IntoSource,
    config: &exarch_core::SecurityConfig,
    options: exarch_core::VerificationOptions,
    format: Option<ArchiveType>,
) -> CoreResult<VerificationReport> {
    data.run(format, |reader| {
        Ok(VerificationReport::from(
            exarch_core::VerifyRequest::new(config)
                .with_options(options)
                .verify_reader(reader)?,
        ))
    })
}

fn list_with_progress_core(
    data: impl IntoSource,
    config: &exarch_core::SecurityConfig,
    format: Option<ArchiveType>,
    options: exarch_core::ListOptions,
    progress: Option<ThreadsafeFunction<ProgressArgs>>,
    dispatch: ProgressDispatch,
) -> CoreResult<ArchiveManifest> {
    run_with_optional_progress(
        Operation::Listing,
        progress,
        dispatch,
        data.abort_handle(),
        |progress| {
            data.run(format, |reader| {
                ArchiveManifest::from_core(
                    exarch_core::ListRequest::new(config)
                        .with_options(options)
                        .with_progress(progress)
                        .list_reader(reader)?,
                    config,
                )
            })
        },
        |source, _| ProgressCallbackError::ListCallback { source },
    )
}

fn verify_with_progress_core(
    data: impl IntoSource,
    config: &exarch_core::SecurityConfig,
    options: exarch_core::VerificationOptions,
    format: Option<ArchiveType>,
    progress: Option<ThreadsafeFunction<ProgressArgs>>,
    dispatch: ProgressDispatch,
) -> CoreResult<VerificationReport> {
    run_with_optional_progress(
        Operation::Verification,
        progress,
        dispatch,
        data.abort_handle(),
        |progress| {
            data.run(format, |reader| {
                Ok(VerificationReport::from(
                    exarch_core::VerifyRequest::new(config)
                        .with_options(options)
                        .with_progress(progress)
                        .verify_reader(reader)?,
                ))
            })
        },
        |source, _| ProgressCallbackError::VerifyCallback { source },
    )
}

/// List the contents of an archive held in memory, without extracting (async).
///
/// # Arguments
///
/// * `data` - The archive bytes (a `Buffer` or any `Uint8Array`), copied before
///   the call returns, or an `AsyncIterable<Uint8Array>` (TAR family only) read
///   from a worker thread and closed (`return()`) however the call ends
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
/// * `format` - The archive format; detected from the leading bytes if omitted
/// * `signal` - Optional `AbortSignal`. Aborting rejects with `ABORT_ERR` (an
///   `AbortError`, `cause` is `signal.reason`) and frees the worker. The abort
///   is noticed when the job starts, while it waits for JavaScript (an
///   `AsyncIterable` chunk or its close), at every read of a `Uint8Array`
///   archive and, for the `WithProgress` variants, at every progress callback
///
/// # Returns
///
/// Promise resolving to `ArchiveManifest` with entry metadata
///
/// # Errors
///
/// Rejects with `UNKNOWN_FORMAT` if the format cannot be detected, with
/// `ABORT_ERR` if `signal` fired, and with the errors of `listArchive`
/// otherwise. A `signal` that is not an `AbortSignal` throws a `TypeError`
/// synchronously.
///
/// # Examples
///
/// ```javascript
/// const manifest = await listArchiveBytes(fs.readFileSync('archive.tar.gz'));
/// ```
#[napi]
pub fn list_archive_bytes<'env>(
    env: &'env Env,
    #[napi(ts_arg_type = "Uint8Array | AsyncIterable<Uint8Array>")] data: ArchiveSource,
    config: Option<&SecurityConfig>,
    format: Option<ArchiveType>,
    #[napi(ts_arg_type = "AbortSignalLike | undefined | null")] signal: Option<AbortBinding>,
    options: Option<&ListOptions>,
) -> Result<PromiseRaw<'env, ArchiveManifest>> {
    let config_owned: exarch_core::SecurityConfig = config.map_or_default(|c| c.as_core().clone());
    let options = options.map_or_default(ListOptions::to_core);
    let (data, detach) = AbortableSource::bind(data, signal);

    spawn_blocking_promise_with(
        env,
        "archive listing",
        move || list_core(data, &config_owned, format, options),
        Ok,
        move |env| detach.run(env),
    )
}

/// List the contents of an archive held in memory, without extracting (sync).
///
/// Blocks the event loop until listing completes. Prefer `listArchiveBytes`.
///
/// # Arguments
///
/// * `data` - The archive bytes
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
/// * `format` - The archive format; detected from the leading bytes if omitted
///
/// # Returns
///
/// `ArchiveManifest` with entry metadata
///
/// # Errors
///
/// The errors of `listArchiveBytes`.
///
/// # Examples
///
/// ```javascript
/// const manifest = listArchiveBytesSync(fs.readFileSync('archive.zip'));
/// ```
#[napi]
pub fn list_archive_bytes_sync(
    env: Env,
    data: Uint8Array,
    config: Option<&SecurityConfig>,
    format: Option<ArchiveType>,
    options: Option<&ListOptions>,
) -> Result<ArchiveManifest> {
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());
    let options = options.map_or_default(ListOptions::to_core);

    run_sync(env, "archive listing", || {
        list_core(&*data, config_ref, format, options)
    })
}

/// Verify the security of an archive held in memory (async).
///
/// # Arguments
///
/// * `data` - The archive bytes (copied before the call returns)
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
/// * `options` - Optional `VerificationOptions`
/// * `format` - The archive format; detected from the leading bytes if omitted
/// * `signal` - Optional `AbortSignal`, observed as in `listArchiveBytes`
///
/// # Returns
///
/// Promise resolving to `VerificationReport` with validation results
///
/// # Errors
///
/// The errors of `listArchiveBytes`.
///
/// # Examples
///
/// ```javascript
/// const report = await verifyArchiveBytes(fs.readFileSync('archive.zip'));
/// ```
#[napi]
pub fn verify_archive_bytes<'env>(
    env: &'env Env,
    #[napi(ts_arg_type = "Uint8Array | AsyncIterable<Uint8Array>")] data: ArchiveSource,
    config: Option<&SecurityConfig>,
    options: Option<&VerificationOptions>,
    format: Option<ArchiveType>,
    #[napi(ts_arg_type = "AbortSignalLike | undefined | null")] signal: Option<AbortBinding>,
) -> Result<PromiseRaw<'env, VerificationReport>> {
    let config_owned: exarch_core::SecurityConfig = config.map_or_default(|c| c.as_core().clone());
    let options_owned: exarch_core::VerificationOptions = options.map_or_default(|o| *o.as_core());
    let (data, detach) = AbortableSource::bind(data, signal);

    spawn_blocking_promise_with(
        env,
        "archive verification",
        move || verify_core(data, &config_owned, options_owned, format),
        Ok,
        move |env| detach.run(env),
    )
}

/// Verify the security of an archive held in memory (sync).
///
/// Blocks the event loop until verification completes. Prefer
/// `verifyArchiveBytes`.
///
/// # Arguments
///
/// * `data` - The archive bytes
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
/// * `options` - Optional `VerificationOptions`
/// * `format` - The archive format; detected from the leading bytes if omitted
///
/// # Returns
///
/// `VerificationReport` with validation results
///
/// # Errors
///
/// The errors of `listArchiveBytes`.
///
/// # Examples
///
/// ```javascript
/// const report = verifyArchiveBytesSync(fs.readFileSync('archive.zip'));
/// ```
#[napi]
pub fn verify_archive_bytes_sync(
    env: Env,
    data: Uint8Array,
    config: Option<&SecurityConfig>,
    options: Option<&VerificationOptions>,
    format: Option<ArchiveType>,
) -> Result<VerificationReport> {
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());
    let default_options = exarch_core::VerificationOptions::default();
    let options_ref = options.map_or(&default_options, |o| o.as_core());

    run_sync(env, "archive verification", || {
        verify_core(&*data, config_ref, *options_ref, format)
    })
}

/// List the contents of an archive held in memory with a progress callback
/// (async).
///
/// Same as `listArchiveBytes`, plus `progress`, called once per entry with
/// `(err, [path, total, current, bytesWritten])` (`total` is `0` for TAR,
/// `bytesWritten` always `0`).
///
/// # Arguments
///
/// The arguments of `listArchiveBytes` up to `format`, then:
///
/// * `progress` - Optional progress callback
/// * `signal` - Optional `AbortSignal`, as in `listArchiveBytes`
///
/// # Returns
///
/// Promise resolving to `ArchiveManifest` with entry metadata
///
/// # Errors
///
/// The errors of `listArchiveBytes`. If `progress` throws, the run still
/// completes. When listing succeeded, the promise rejects with
/// `PROGRESS_CALLBACK_ERROR` and the throw as `cause`; the manifest is
/// discarded. When listing failed, the core error keeps its `code` and the
/// throw is attached as `cause`.
///
/// # Examples
///
/// ```javascript
/// const manifest = await listArchiveBytesWithProgress(
///   fs.readFileSync('archive.zip'),
///   null,
///   null,
///   (err, [path, total, current]) => console.log(`${current}/${total}: ${path}`),
/// );
/// ```
#[napi]
pub fn list_archive_bytes_with_progress<'env>(
    env: &'env Env,
    #[napi(ts_arg_type = "Uint8Array | AsyncIterable<Uint8Array>")] data: ArchiveSource,
    config: Option<&SecurityConfig>,
    format: Option<ArchiveType>,
    #[napi(ts_arg_type = "(((err: Error | null, arg: ProgressArgs) => any)) | undefined | null")]
    progress: Option<ProgressCallback>,
    #[napi(ts_arg_type = "AbortSignalLike | undefined | null")] signal: Option<AbortBinding>,
    options: Option<&ListOptions>,
) -> Result<PromiseRaw<'env, ArchiveManifest>> {
    let config_owned: exarch_core::SecurityConfig = config.map_or_default(|c| c.as_core().clone());
    let options = options.map_or_default(ListOptions::to_core);
    let progress = progress.map(|ProgressCallback(tsfn)| tsfn);
    let (data, detach) = AbortableSource::bind(data, signal);

    spawn_blocking_promise_with(
        env,
        "archive listing with progress",
        move || {
            list_with_progress_core(
                data,
                &config_owned,
                format,
                options,
                progress,
                ProgressDispatch::Awaited,
            )
        },
        Ok,
        move |env| detach.run(env),
    )
}

/// Verify the security of an archive held in memory with a progress callback
/// (async).
///
/// Same as `verifyArchiveBytes`, plus `progress`, called once per entry with
/// `(err, [path, total, current, bytesWritten])` (`total` is `0` for TAR,
/// `bytesWritten` always `0`).
///
/// # Arguments
///
/// The arguments of `verifyArchiveBytes` up to `format`, then:
///
/// * `progress` - Optional progress callback
/// * `signal` - Optional `AbortSignal`, as in `listArchiveBytes`
///
/// # Returns
///
/// Promise resolving to `VerificationReport` with validation results
///
/// # Errors
///
/// The errors of `verifyArchiveBytes`. If `progress` throws, the run still
/// completes. When verification returned a report (including one with status
/// `FAIL`), the promise rejects with `PROGRESS_CALLBACK_ERROR` and the throw as
/// `cause`; the report is discarded. When it errored, the core error keeps its
/// `code` and the throw is attached as `cause`.
///
/// # Examples
///
/// ```javascript
/// const report = await verifyArchiveBytesWithProgress(
///   fs.readFileSync('archive.zip'),
///   null,
///   null,
///   null,
///   (err, [path, total, current]) => console.log(`${current}/${total}: ${path}`),
/// );
/// ```
#[napi]
pub fn verify_archive_bytes_with_progress<'env>(
    env: &'env Env,
    #[napi(ts_arg_type = "Uint8Array | AsyncIterable<Uint8Array>")] data: ArchiveSource,
    config: Option<&SecurityConfig>,
    options: Option<&VerificationOptions>,
    format: Option<ArchiveType>,
    #[napi(ts_arg_type = "(((err: Error | null, arg: ProgressArgs) => any)) | undefined | null")]
    progress: Option<ProgressCallback>,
    #[napi(ts_arg_type = "AbortSignalLike | undefined | null")] signal: Option<AbortBinding>,
) -> Result<PromiseRaw<'env, VerificationReport>> {
    let config_owned: exarch_core::SecurityConfig = config.map_or_default(|c| c.as_core().clone());
    let options_owned: exarch_core::VerificationOptions = options.map_or_default(|o| *o.as_core());
    let progress = progress.map(|ProgressCallback(tsfn)| tsfn);
    let (data, detach) = AbortableSource::bind(data, signal);

    spawn_blocking_promise_with(
        env,
        "archive verification with progress",
        move || {
            verify_with_progress_core(
                data,
                &config_owned,
                options_owned,
                format,
                progress,
                ProgressDispatch::Awaited,
            )
        },
        Ok,
        move |env| detach.run(env),
    )
}

/// List the contents of an archive held in memory with a progress callback
/// (sync).
///
/// Blocks the event loop until listing completes. Same as
/// `listArchiveBytesWithProgress`, except that the calls to `progress` are
/// queued and arrive only after this function has returned; a throw there
/// becomes an `uncaughtException`, not an error from here.
///
/// # Arguments
///
/// The arguments of `listArchiveBytesSync`, then:
///
/// * `progress` - Optional progress callback
///
/// # Returns
///
/// `ArchiveManifest` with entry metadata
///
/// # Errors
///
/// The errors of `listArchiveBytesSync`.
///
/// # Examples
///
/// ```javascript
/// const manifest = listArchiveBytesWithProgressSync(
///   fs.readFileSync('archive.zip'),
///   null,
///   null,
///   (err, [path, total, current]) => console.log(`${current}/${total}: ${path}`),
/// );
/// ```
#[napi]
pub fn list_archive_bytes_with_progress_sync(
    env: Env,
    data: Uint8Array,
    config: Option<&SecurityConfig>,
    format: Option<ArchiveType>,
    progress: Option<ThreadsafeFunction<ProgressArgs>>,
    options: Option<&ListOptions>,
) -> Result<ArchiveManifest> {
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());
    let options = options.map_or_default(ListOptions::to_core);

    run_sync(env, "archive listing with progress", move || {
        list_with_progress_core(
            &*data,
            config_ref,
            format,
            options,
            progress,
            ProgressDispatch::Deferred,
        )
    })
}

/// Verify the security of an archive held in memory with a progress callback
/// (sync).
///
/// Blocks the event loop until verification completes. Same as
/// `verifyArchiveBytesWithProgress`, except that the calls to `progress` are
/// queued and arrive only after this function has returned; a throw there
/// becomes an `uncaughtException`, not an error from here.
///
/// # Arguments
///
/// The arguments of `verifyArchiveBytesSync`, then:
///
/// * `progress` - Optional progress callback
///
/// # Returns
///
/// `VerificationReport` with validation results
///
/// # Errors
///
/// The errors of `verifyArchiveBytesSync`.
///
/// # Examples
///
/// ```javascript
/// const report = verifyArchiveBytesWithProgressSync(
///   fs.readFileSync('archive.zip'),
///   null,
///   null,
///   null,
///   (err, [path, total, current]) => console.log(`${current}/${total}: ${path}`),
/// );
/// ```
#[napi]
pub fn verify_archive_bytes_with_progress_sync(
    env: Env,
    data: Uint8Array,
    config: Option<&SecurityConfig>,
    options: Option<&VerificationOptions>,
    format: Option<ArchiveType>,
    progress: Option<ThreadsafeFunction<ProgressArgs>>,
) -> Result<VerificationReport> {
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());
    let default_options = exarch_core::VerificationOptions::default();
    let options_ref = options.map_or(&default_options, |o| o.as_core());

    run_sync(env, "archive verification with progress", move || {
        verify_with_progress_core(
            &*data,
            config_ref,
            *options_ref,
            format,
            progress,
            ProgressDispatch::Deferred,
        )
    })
}
