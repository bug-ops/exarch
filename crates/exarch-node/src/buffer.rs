//! Archives held in memory instead of on disk.

use exarch_core::ArchiveReader;
use napi::Env;
use napi::bindgen_prelude::PromiseRaw;
use napi::bindgen_prelude::Result;
use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;

use crate::CoreResult;
use crate::config::SecurityConfig;
use crate::config::VerificationOptions;
use crate::error::run_sync;
use crate::error::spawn_blocking_promise;
use crate::report::ArchiveManifest;
use crate::report::ArchiveType;
use crate::report::VerificationReport;

fn list_core(
    data: impl AsRef<[u8]> + Send,
    config: &exarch_core::SecurityConfig,
    format: Option<ArchiveType>,
) -> CoreResult<exarch_core::inspection::ArchiveManifest> {
    let reader = ArchiveReader::from_bytes(data, format.map(Into::into))?;
    Ok(exarch_core::list_reader(
        reader,
        config,
        &exarch_core::ListOptions::default(),
    )?)
}

fn verify_core(
    data: impl AsRef<[u8]> + Send,
    config: &exarch_core::SecurityConfig,
    options: exarch_core::VerificationOptions,
    format: Option<ArchiveType>,
) -> CoreResult<exarch_core::inspection::VerificationReport> {
    let reader = ArchiveReader::from_bytes(data, format.map(Into::into))?;
    Ok(exarch_core::verify_reader(reader, config, &options)?)
}

/// List the contents of an archive held in memory, without extracting (async).
///
/// # Arguments
///
/// * `data` - The archive bytes (a `Buffer` or any `Uint8Array`); copied before
///   the call returns
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
/// * `format` - The archive format; detected from the leading bytes if omitted
///
/// # Returns
///
/// Promise resolving to `ArchiveManifest` with entry metadata
///
/// # Errors
///
/// Rejects with `UNKNOWN_FORMAT` if the format cannot be detected, and with
/// the errors of `listArchive` otherwise.
///
/// # Examples
///
/// ```javascript
/// const manifest = await listArchiveBytes(fs.readFileSync('archive.tar.gz'));
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn list_archive_bytes<'env>(
    env: &'env Env,
    data: Uint8Array,
    config: Option<&SecurityConfig>,
    format: Option<ArchiveType>,
) -> Result<PromiseRaw<'env, ArchiveManifest>> {
    let config_owned: exarch_core::SecurityConfig = config.map_or_default(|c| c.as_core().clone());
    let bytes = data.to_vec();

    spawn_blocking_promise(
        env,
        "archive listing",
        move || list_core(bytes, &config_owned, format),
        ArchiveManifest::try_from,
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
#[allow(clippy::needless_pass_by_value)]
pub fn list_archive_bytes_sync(
    env: Env,
    data: Uint8Array,
    config: Option<&SecurityConfig>,
    format: Option<ArchiveType>,
) -> Result<ArchiveManifest> {
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    let manifest = run_sync(env, "archive listing", || {
        list_core(&*data, config_ref, format)
    })?;

    ArchiveManifest::try_from(manifest)
}

/// Verify the security of an archive held in memory (async).
///
/// # Arguments
///
/// * `data` - The archive bytes (copied before the call returns)
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
/// * `options` - Optional `VerificationOptions`
/// * `format` - The archive format; detected from the leading bytes if omitted
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
#[allow(clippy::needless_pass_by_value)]
pub fn verify_archive_bytes<'env>(
    env: &'env Env,
    data: Uint8Array,
    config: Option<&SecurityConfig>,
    options: Option<&VerificationOptions>,
    format: Option<ArchiveType>,
) -> Result<PromiseRaw<'env, VerificationReport>> {
    let config_owned: exarch_core::SecurityConfig = config.map_or_default(|c| c.as_core().clone());
    let options_owned: exarch_core::VerificationOptions = options.map_or_default(|o| *o.as_core());
    let bytes = data.to_vec();

    spawn_blocking_promise(
        env,
        "archive verification",
        move || verify_core(bytes, &config_owned, options_owned, format),
        VerificationReport::try_from,
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
#[allow(clippy::needless_pass_by_value)]
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

    let report = run_sync(env, "archive verification", || {
        verify_core(&*data, config_ref, *options_ref, format)
    })?;

    VerificationReport::try_from(report)
}
