//! Extraction of an archive held in memory into memory.

use std::path::Path;
use std::path::PathBuf;

use exarch_core::MemoryEntry as CoreMemoryEntry;
use exarch_core::MemoryLimit;
use exarch_core::MemorySink;
use exarch_core::PathModel as CorePathModel;
use exarch_core::SanitizedMode;
use exarch_core::SinkOptions;
use exarch_core::extract_bytes_to_memory;
use exarch_core::formats::detect::ArchiveType as CoreArchiveType;
use exarch_core::formats::detect::CreatableFormat;
use exarch_core::utf8_entry_path;
use napi::Env;
use napi::bindgen_prelude::PromiseRaw;
use napi::bindgen_prelude::Result;
use napi::bindgen_prelude::Uint8Array;
use napi::threadsafe_function::ThreadsafeFunction;
use napi_derive::napi;

use crate::CoreResult;
use crate::ProgressCallback;
use crate::config::CreationConfig;
use crate::config::ExtractionOptions;
use crate::config::SecurityConfig;
use crate::config::exact_positive_bytes;
use crate::error::Failure;
use crate::error::ProgressCallbackError;
use crate::error::run_sync;
use crate::error::spawn_blocking_promise;
use crate::report::ArchiveType;
use crate::report::CreationReport;
use crate::report::ExtractionReport;
use crate::report::unknown_variant;
use crate::run_with_optional_progress;
use crate::utils::validate_path;

/// The path semantics extraction validates names against.
// Values must equal `exarch_core::PathModel::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathModel {
    /// The rules of the platform running the extraction.
    #[napi(value = "host")]
    Host,
    /// The strictest rules of every supported platform.
    #[napi(value = "portable")]
    Portable,
}

impl From<PathModel> for CorePathModel {
    fn from(value: PathModel) -> Self {
        match value {
            PathModel::Host => Self::Host,
            PathModel::Portable => Self::Portable,
        }
    }
}

/// What a `MemoryEntry` holds.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryEntryKind {
    /// A regular file.
    #[napi(value = "file")]
    File,
    /// A directory the archive names explicitly.
    #[napi(value = "directory")]
    Directory,
    /// A symbolic link, stored as data.
    #[napi(value = "symlink")]
    Symlink,
}

/// An entry extracted into memory.
#[napi(object)]
pub struct MemoryEntry {
    /// Entry path, relative, as delivered by extraction.
    pub path: String,
    /// What the entry is.
    pub kind: MemoryEntryKind,
    /// The file's bytes as a `Uint8Array` (a plain `Uint8Array`, not a
    /// `Buffer`; input parameters accept both); only for a file.
    pub data: Option<Uint8Array>,
    /// Permission bits after setuid and setgid were stripped; only for a file
    /// whose archive carries a mode.
    pub mode: Option<u32>,
    /// Symlink target as the archive spells it; only for a symlink.
    pub target: Option<String>,
}

/// The text of `path`, or an error: a lossy conversion could merge two
/// distinct entries into one name.
fn utf8(path: &Path) -> CoreResult<String> {
    Ok(utf8_entry_path(path).map(str::to_owned)?)
}

impl TryFrom<(PathBuf, CoreMemoryEntry)> for MemoryEntry {
    type Error = Failure;

    fn try_from((path, entry): (PathBuf, CoreMemoryEntry)) -> CoreResult<Self> {
        let path = utf8(&path)?;
        Ok(match entry {
            CoreMemoryEntry::File { data, mode } => Self {
                path,
                kind: MemoryEntryKind::File,
                data: Some(Uint8Array::from(data)),
                mode: mode.map(SanitizedMode::as_u32),
                target: None,
            },
            CoreMemoryEntry::Symlink { target } => Self {
                path,
                kind: MemoryEntryKind::Symlink,
                data: None,
                mode: None,
                target: Some(utf8(&target)?),
            },
            CoreMemoryEntry::Directory => Self {
                path,
                kind: MemoryEntryKind::Directory,
                data: None,
                mode: None,
                target: None,
            },
            _ => return Err(Failure::Native(unknown_variant("memory entry", "unknown"))),
        })
    }
}

/// The result of `extractArchiveToMemory`.
#[napi(object)]
pub struct MemoryExtraction {
    /// Extraction statistics.
    pub report: ExtractionReport,
    /// The extracted entries in path order.
    pub entries: Vec<MemoryEntry>,
}

/// The inputs of an extraction into memory, owned so they can cross threads.
struct MemoryJob<B> {
    data: B,
    config: exarch_core::SecurityConfig,
    options: exarch_core::ExtractionOptions,
    max_bytes: Option<f64>,
    path_model: CorePathModel,
    format: Option<ArchiveType>,
}

fn invalid_max_bytes() -> Failure {
    Failure::Core(exarch_core::ArchiveError::InvalidConfiguration {
        reason: "maxBytes must be a positive whole number of bytes".into(),
    })
}

impl<B: AsRef<[u8]> + Send> MemoryJob<B> {
    fn new(
        data: B,
        config: Option<&SecurityConfig>,
        options: Option<&ExtractionOptions>,
        max_bytes: Option<f64>,
        path_model: Option<PathModel>,
        format: Option<ArchiveType>,
    ) -> Self {
        Self {
            data,
            config: config.map_or_default(|c| c.as_core().clone()),
            options: options.map_or_default(|o| o.as_core().clone()),
            max_bytes,
            path_model: path_model.map_or(CorePathModel::Host, Into::into),
            format,
        }
    }

    fn run(self) -> CoreResult<MemoryExtraction> {
        let (report, sink) = self.extract(&mut exarch_core::NoopProgress)?;
        into_memory_extraction(report, sink)
    }

    /// Runs with the JS callback `progress`, merging a core failure and a
    /// callback throw the way `extractArchiveWithProgress` does. A throw after
    /// a successful run discards the entries: the rejection carries only the
    /// report counters.
    fn run_with_progress(
        self,
        progress: Option<ThreadsafeFunction<(String, i64, i64, i64)>>,
    ) -> CoreResult<MemoryExtraction> {
        let (report, sink) = run_with_optional_progress(
            progress,
            |progress| self.extract(progress),
            |source, _| ProgressCallbackError::MemoryExtractionCallback { source },
        )?;
        into_memory_extraction(report, sink)
    }

    fn extract(
        self,
        progress: &mut dyn exarch_core::ProgressCallback,
    ) -> CoreResult<(exarch_core::ExtractionReport, MemorySink)> {
        let limit = self
            .max_bytes
            .map(|bytes| {
                exact_positive_bytes(bytes)
                    .map(MemoryLimit::new)
                    .ok_or_else(invalid_max_bytes)
            })
            .transpose()?;
        let options = SinkOptions::try_from(&self.options)?;
        Ok(extract_bytes_to_memory(
            self.data,
            self.format.map(Into::into),
            &self.config,
            &options,
            limit,
            self.path_model,
            progress,
        )?)
    }
}

fn into_memory_extraction(
    report: exarch_core::ExtractionReport,
    sink: MemorySink,
) -> CoreResult<MemoryExtraction> {
    Ok(MemoryExtraction {
        report: ExtractionReport::from(report),
        entries: sink
            .into_entries()
            .into_iter()
            .map(MemoryEntry::try_from)
            .collect::<CoreResult<_>>()?,
    })
}

/// Extract an archive held in memory into memory with a progress callback
/// (async).
///
/// Same as `extractArchiveToMemory`, plus `progress`, called once per entry
/// with `(err, [path, total, current, bytesWritten])` (see
/// `extractArchiveWithProgress`; `bytesWritten` is always `0`).
///
/// # Arguments
///
/// The arguments of `extractArchiveToMemory`, then:
///
/// * `progress` - Optional progress callback
///
/// # Returns
///
/// Promise resolving to `MemoryExtraction` with the report and the entries
///
/// # Errors
///
/// The errors of `extractArchiveToMemory`. If `progress` throws, the run
/// still completes:
///
/// - When extraction succeeded, the promise rejects with
///   `PROGRESS_CALLBACK_ERROR`, the throw as `cause`, and the report counters;
///   the extracted entries are discarded, as nothing was written to disk.
/// - When extraction failed, the core error keeps its `code` and the throw is
///   attached as `cause`.
///
/// # Examples
///
/// ```javascript
/// const { entries } = await extractArchiveToMemoryWithProgress(
///   fs.readFileSync('a.tar.gz'),
///   null, null, null, null, null,
///   (err, [path, total, current]) => console.log(`${current}/${total}: ${path}`),
/// );
/// ```
#[napi]
// The JS signature is positional: `extractArchiveToMemory`'s arguments plus `progress`.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn extract_archive_to_memory_with_progress<'env>(
    env: &'env Env,
    data: Uint8Array,
    config: Option<&SecurityConfig>,
    options: Option<&ExtractionOptions>,
    max_bytes: Option<f64>,
    path_model: Option<PathModel>,
    format: Option<ArchiveType>,
    #[napi(
        ts_arg_type = "(((err: Error | null, arg: [string, number, number, number]) => any)) | undefined | null"
    )]
    progress: Option<ProgressCallback>,
) -> Result<PromiseRaw<'env, MemoryExtraction>> {
    let job = MemoryJob::new(
        data.to_vec(),
        config,
        options,
        max_bytes,
        path_model,
        format,
    );
    let progress = progress.map(|ProgressCallback(tsfn)| tsfn);

    spawn_blocking_promise(
        env,
        "archive extraction with progress",
        move || job.run_with_progress(progress),
        Ok,
    )
}

/// An archive created in memory.
#[napi(object)]
pub struct CreatedArchive {
    /// The archive bytes as a `Uint8Array`.
    pub data: Uint8Array,
    /// Creation statistics.
    pub report: CreationReport,
}

fn create_to_bytes_core(
    sources: &[String],
    format: ArchiveType,
    config: &exarch_core::creation::CreationConfig,
) -> CoreResult<CreatedArchive> {
    sources
        .iter()
        .try_for_each(|source| validate_path(source))?;
    let format = CreatableFormat::try_from(CoreArchiveType::from(format))?;
    let (bytes, report) = exarch_core::create_to_bytes(sources, format, config)?;
    Ok(CreatedArchive {
        data: Uint8Array::from(bytes),
        report: CreationReport::from(report),
    })
}

/// Create an archive from source files and directories into memory (async).
///
/// The whole archive is held in memory (about 2-3x its size at the peak) with
/// no size cap, so use `createArchive` for large archives. Sources must be
/// regular files and directories; FIFOs and device files are not supported.
///
/// # Arguments
///
/// * `sources` - Array of source files/directories to include
/// * `format` - The archive format; `'SevenZ'` cannot be created
/// * `config` - Optional `CreationConfig` (uses defaults if omitted)
///
/// # Returns
///
/// Promise resolving to `CreatedArchive` with the archive bytes and the report
///
/// # Errors
///
/// Rejects with `INVALID_CONFIGURATION` for `'SevenZ'`, and with the errors of
/// `createArchive` otherwise.
///
/// # Examples
///
/// ```javascript
/// const { data, report } = await createArchiveToBytes(['src/'], 'TarGz');
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn create_archive_to_bytes<'env>(
    env: &'env Env,
    sources: Vec<String>,
    format: ArchiveType,
    config: Option<&CreationConfig>,
) -> Result<PromiseRaw<'env, CreatedArchive>> {
    let config_owned: exarch_core::creation::CreationConfig =
        config.map_or_default(|c| c.as_core().clone());

    spawn_blocking_promise(
        env,
        "archive creation",
        move || create_to_bytes_core(&sources, format, &config_owned),
        Ok,
    )
}

/// Create an archive from source files and directories into memory (sync).
///
/// Blocks the event loop until creation completes. Prefer
/// `createArchiveToBytes`.
///
/// # Arguments
///
/// The arguments of `createArchiveToBytes`.
///
/// # Returns
///
/// `CreatedArchive` with the archive bytes and the report
///
/// # Errors
///
/// The errors of `createArchiveToBytes`.
///
/// # Examples
///
/// ```javascript
/// const { data } = createArchiveToBytesSync(['src/'], 'Zip');
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn create_archive_to_bytes_sync(
    env: Env,
    sources: Vec<String>,
    format: ArchiveType,
    config: Option<&CreationConfig>,
) -> Result<CreatedArchive> {
    let default_config = exarch_core::creation::CreationConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    run_sync(env, "archive creation", || {
        create_to_bytes_core(&sources, format, config_ref)
    })
}

/// Extract an archive held in memory into memory (async).
///
/// The archive passes the same validation as `extractArchive`; nothing is
/// written to disk.
///
/// # Arguments
///
/// * `data` - The archive bytes (copied before the call returns)
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
/// * `options` - Optional `ExtractionOptions` (`atomic` is not supported)
/// * `maxBytes` - The most bytes to keep: payload (file data, hardlink copies
///   and symlink targets) plus path bytes plus 256 per entry; defaults to the
///   config's `maxTotalSize`
/// * `pathModel` - `'host'` (default) or `'portable'`
/// * `format` - The archive format; detected from the leading bytes if omitted
///
/// # Returns
///
/// Promise resolving to `MemoryExtraction` with the report and the entries
///
/// # Errors
///
/// Rejects with `INVALID_CONFIGURATION` for a `maxBytes` that is not a positive
/// whole number, `QUOTA_EXCEEDED` when a quota or `maxBytes` is exceeded, and
/// the errors of `extractArchive` otherwise.
///
/// # Examples
///
/// ```javascript
/// const { entries } = await extractArchiveToMemory(fs.readFileSync('a.tar.gz'));
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn extract_archive_to_memory<'env>(
    env: &'env Env,
    data: Uint8Array,
    config: Option<&SecurityConfig>,
    options: Option<&ExtractionOptions>,
    max_bytes: Option<f64>,
    path_model: Option<PathModel>,
    format: Option<ArchiveType>,
) -> Result<PromiseRaw<'env, MemoryExtraction>> {
    let job = MemoryJob::new(
        data.to_vec(),
        config,
        options,
        max_bytes,
        path_model,
        format,
    );

    spawn_blocking_promise(env, "archive extraction", move || job.run(), Ok)
}

/// Extract an archive held in memory into memory (sync).
///
/// Blocks the event loop until extraction completes. Prefer
/// `extractArchiveToMemory`.
///
/// # Arguments
///
/// The arguments of `extractArchiveToMemory`.
///
/// # Returns
///
/// `MemoryExtraction` with the report and the entries
///
/// # Errors
///
/// The errors of `extractArchiveToMemory`.
///
/// # Examples
///
/// ```javascript
/// const { entries } = extractArchiveToMemorySync(fs.readFileSync('a.zip'));
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn extract_archive_to_memory_sync(
    env: Env,
    data: Uint8Array,
    config: Option<&SecurityConfig>,
    options: Option<&ExtractionOptions>,
    max_bytes: Option<f64>,
    path_model: Option<PathModel>,
    format: Option<ArchiveType>,
) -> Result<MemoryExtraction> {
    let job = MemoryJob::new(&*data, config, options, max_bytes, path_model, format);

    run_sync(env, "archive extraction", move || job.run())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn union_line<T: Copy>(name: &str, all: &[T], as_str: fn(T) -> &'static str) -> String {
        let values: Vec<String> = all.iter().map(|v| format!("'{}'", as_str(*v))).collect();
        format!("export type {name} = {}", values.join(" | "))
    }

    #[test]
    fn index_d_ts_path_model_matches_core() {
        let dts = include_str!("../index.d.ts");
        let line = union_line("PathModel", CorePathModel::ALL, CorePathModel::as_str);
        assert!(
            dts.lines().any(|l| l == line),
            "index.d.ts out of sync with exarch-core, expected line:\n{line}"
        );
    }

    #[test]
    fn path_model_maps_every_core_variant() {
        assert_eq!(CorePathModel::from(PathModel::Host), CorePathModel::Host);
        assert_eq!(
            CorePathModel::from(PathModel::Portable),
            CorePathModel::Portable
        );
    }
}
