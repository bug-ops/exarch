//! Extraction of an archive into an `onEntry` callback.

use std::io;

use exarch_core::CallbackSink;
use exarch_core::MemoryEntry as CoreMemoryEntry;
use exarch_core::PathModel as CorePathModel;
use exarch_core::SafePath;
use exarch_core::SinkOptions;
use napi::Env;
use napi::JsValue;
use napi::Status;
use napi::bindgen_prelude::FromNapiValue;
use napi::bindgen_prelude::Function;
use napi::bindgen_prelude::Promise;
use napi::bindgen_prelude::PromiseRaw;
use napi::bindgen_prelude::Result;
use napi::bindgen_prelude::TypeName;
use napi::bindgen_prelude::Uint8Array;
use napi::bindgen_prelude::Unknown;
use napi::bindgen_prelude::ValidateNapiValue;
use napi::sys;
use napi::threadsafe_function::ThreadsafeFunction;
use napi_derive::napi;
use tokio::runtime::Handle;

use crate::CoreResult;
use crate::config::ExtractionOptions;
use crate::config::SecurityConfig;
use crate::error::Failure;
use crate::error::ProgressCallbackError;
use crate::error::run_sync;
use crate::error::spawn_blocking_promise;
use crate::memory::MemoryEntry;
use crate::memory::PathModel;
use crate::report::ArchiveType;
use crate::report::ExtractionReport;
use crate::stream::ArchiveSource;
use crate::stream::IntoSource;

/// `onEntry` for the async function: awaits the callback, so a slow consumer
/// holds the extraction back, and rejects with a normalized `Error`.
///
/// A thrown or rejected non-object is wrapped in an `Error` whose `cause` is
/// the primitive (a Symbol stringified, see `stream.rs`).
const WRAP_ENTRY_CALLBACK_JS: &str = js_with_normalizer!(
    r#"(callback) => async function entryCallback(entry) {
  try {
    await callback(entry);
  } catch (thrown) {
    throw normalizeThrown("onEntry", thrown);
  }
}"#
);

/// `onEntry` for the sync function: returns what went wrong instead of
/// throwing, so no exception is left pending in the JS environment. A callback
/// that returns a thenable is refused: the extraction cannot wait for it, and
/// its rejection is silenced so it cannot become an unhandled rejection.
const WRAP_ENTRY_CALLBACK_SYNC_JS: &str = js_with_normalizer!(
    r#"(callback) => function entryCallbackSync(entry) {
  let result;
  try {
    result = callback(entry);
  } catch (thrown) {
    return normalizeThrown("onEntry", thrown);
  }
  try {
    if (result !== null && result !== undefined && typeof result.then === "function") {
      try {
        result.then(undefined, () => {});
      } catch (_) {}
      return new TypeError("onEntry returned a promise; use extractArchiveToCallback");
    }
  } catch (thrown) {
    return normalizeThrown("onEntry", thrown);
  }
  return undefined;
}"#
);

type EntryFn = ThreadsafeFunction<MemoryEntry, Promise<()>, MemoryEntry, Status, false>;

/// The `onEntry` argument of `extractArchiveToCallback`.
pub struct EntryCallback(EntryFn);

impl TypeName for EntryCallback {
    fn type_name() -> &'static str {
        "Function"
    }

    fn value_type() -> napi::ValueType {
        napi::ValueType::Function
    }
}

impl ValidateNapiValue for EntryCallback {}

impl FromNapiValue for EntryCallback {
    // SAFETY: napi-rs calls this only from the generated argument-extraction
    // code, on the JS thread, with a live `env` and `napi_val`.
    #[expect(unsafe_code, reason = "napi's FromNapiValue is an unsafe trait method")]
    unsafe fn from_napi_value(env: sys::napi_env, napi_val: sys::napi_value) -> Result<Self> {
        napi::assert_type_of!(env, napi_val, napi::ValueType::Function)?;
        // SAFETY: same guarantee as above.
        let callback = unsafe { Function::<Unknown, Unknown>::from_napi_value(env, napi_val)? };
        let factory: Function<'_, Unknown<'_>, Function<'_, MemoryEntry, Promise<()>>> =
            Env::from_raw(env).run_script(WRAP_ENTRY_CALLBACK_JS)?;
        let wrapped = factory.call(callback.to_unknown())?;
        let tsfn = wrapped
            .build_threadsafe_function::<MemoryEntry>()
            .callee_handled::<false>()
            .build_callback(|ctx| Ok(ctx.value))?;
        Ok(Self(tsfn))
    }
}

/// The inputs of an extraction into a callback, owned so they can cross
/// threads.
struct CallbackJob {
    config: exarch_core::SecurityConfig,
    options: exarch_core::ExtractionOptions,
    path_model: CorePathModel,
    format: Option<ArchiveType>,
}

impl CallbackJob {
    fn new(
        config: Option<&SecurityConfig>,
        options: Option<&ExtractionOptions>,
        path_model: Option<PathModel>,
        format: Option<ArchiveType>,
    ) -> Self {
        Self {
            config: config.map_or_default(|c| c.as_core().clone()),
            options: options.map_or_default(|o| o.as_core().clone()),
            path_model: path_model.map_or(CorePathModel::Host, Into::into),
            format,
        }
    }

    /// Extracts `source`, handing every entry to `deliver`. The first failure
    /// `deliver` reports ends the extraction and is the primary error.
    fn run(
        self,
        source: impl IntoSource,
        mut deliver: impl FnMut(MemoryEntry) -> std::result::Result<(), Failure>,
    ) -> CoreResult<exarch_core::ExtractionReport> {
        let options = match SinkOptions::try_from(&self.options) {
            Ok(options) => options,
            Err(err) => {
                source.abandon();
                return Err(err.into());
            }
        };
        let mut failure: Option<Failure> = None;
        let result = source.run(self.format, |reader| {
            let mut sink = CallbackSink::new(|path: &SafePath, entry: CoreMemoryEntry| {
                let delivered = MemoryEntry::try_from((path.as_path().to_path_buf(), entry))
                    .and_then(&mut deliver);
                delivered.map_err(|err| {
                    failure.get_or_insert(err);
                    io::Error::other("entry callback failed")
                })
            })
            .with_path_model(self.path_model);
            Ok(exarch_core::extract_to_sink(
                reader,
                &mut sink,
                &self.config,
                &options,
            )?)
        });
        failure.map_or(result, Err)
    }
}

/// Extract an archive held in memory, handing every verified entry to a
/// callback (async).
///
/// Nothing is written to disk and nothing is kept. `onEntry` receives a
/// `MemoryEntry` per entry in extraction order, after the entry was verified;
/// a file arrives whole, so memory use is one file, bounded by the config's
/// `maxFileSize`. The extraction waits for each call, and for the promise it
/// returns, before it reads on, so a slow consumer holds it back.
///
/// Entries are provisional: each is delivered as soon as it is verified, so a
/// later failure refuses the archive after earlier entries were already
/// delivered. Treat the results as final only once the promise resolved. The
/// gzip CRC of a `.tar.gz` is never checked on extraction, so a corrupt
/// compressed stream can deliver altered data without an error.
///
/// A `'symlink'` entry's `target` is spelled as the archive stores it,
/// relative to the link. A `'hardlink'` entry is delivered by reference after
/// every other entry: its `target` is the root-relative resolved path of an
/// entry already delivered, a file or an earlier hardlink (a chain is
/// delivered link by link). With `skipDuplicates` off one path can be delivered
/// more than once and a hardlink refers to the latest delivery. Implicit
/// parent directories are not delivered.
///
/// # Arguments
///
/// * `data` - The archive bytes (copied before the call returns), or an
///   `AsyncIterable<Uint8Array>` (TAR family only), read from a worker thread
///   and closed (`return()`) however the call ends
/// * `onEntry` - Called with each entry; may return a promise
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
/// * `options` - Optional `ExtractionOptions` (`atomic` is not supported)
/// * `pathModel` - `'host'` (default) or `'portable'`
/// * `format` - The archive format; detected from the leading bytes if omitted
///
/// # Returns
///
/// Promise resolving to the `ExtractionReport`
///
/// # Errors
///
/// Rejects with `ENTRY_CALLBACK_ERROR` and the thrown value as `cause` when
/// `onEntry` throws or rejects (a non-object is wrapped in an `Error` whose
/// `cause` is the primitive), with `STREAM_ERROR` when the iterable throws,
/// and with the errors of `extractArchive` otherwise.
///
/// # Examples
///
/// ```javascript
/// const sizes = new Map();
/// await extractArchiveToCallback(fs.readFileSync('a.tar.gz'), (entry) => {
///   if (entry.kind === 'file') sizes.set(entry.path, entry.data.length);
/// });
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn extract_archive_to_callback<'env>(
    env: &'env Env,
    #[napi(ts_arg_type = "Uint8Array | AsyncIterable<Uint8Array>")] data: ArchiveSource,
    #[napi(ts_arg_type = "(entry: MemoryEntry) => void | Promise<void>")] on_entry: EntryCallback,
    config: Option<&SecurityConfig>,
    options: Option<&ExtractionOptions>,
    path_model: Option<PathModel>,
    format: Option<ArchiveType>,
) -> Result<PromiseRaw<'env, ExtractionReport>> {
    let job = CallbackJob::new(config, options, path_model, format);
    let EntryCallback(tsfn) = on_entry;

    spawn_blocking_promise(
        env,
        "archive extraction to a callback",
        move || {
            job.run(data, |entry| {
                Handle::current()
                    .block_on(async { tsfn.call_async_catch(entry).await?.await })
                    .map_err(|source| ProgressCallbackError::EntryCallback { source }.into())
            })
        },
        |report| Ok(ExtractionReport::from(report)),
    )
}

/// Extract an archive held in memory, handing every verified entry to a
/// callback (sync).
///
/// Blocks the event loop until extraction completes. `onEntry` runs on the
/// JavaScript thread and must be synchronous: a callback that returns a
/// promise is refused, because the extraction cannot wait for it. Its
/// rejection is silenced and the call fails with `ENTRY_CALLBACK_ERROR` and a
/// `TypeError` as `cause`. Prefer `extractArchiveToCallback`.
///
/// # Arguments
///
/// The arguments of `extractArchiveToCallback`, except that `data` must be a
/// `Uint8Array`, which is copied before `onEntry` first runs.
///
/// # Returns
///
/// The `ExtractionReport`
///
/// # Errors
///
/// The errors of `extractArchiveToCallback`.
///
/// # Examples
///
/// ```javascript
/// const names = [];
/// extractArchiveToCallbackSync(fs.readFileSync('a.zip'), (entry) => names.push(entry.path));
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn extract_archive_to_callback_sync<'env>(
    env: Env,
    data: Uint8Array,
    #[napi(ts_arg_type = "(entry: MemoryEntry) => void")] on_entry: Function<
        'env,
        MemoryEntry,
        Unknown<'env>,
    >,
    config: Option<&SecurityConfig>,
    options: Option<&ExtractionOptions>,
    path_model: Option<PathModel>,
    format: Option<ArchiveType>,
) -> Result<ExtractionReport> {
    let job = CallbackJob::new(config, options, path_model, format);
    let factory: Function<'_, Unknown<'_>, Function<'_, MemoryEntry, Unknown<'_>>> =
        env.run_script(WRAP_ENTRY_CALLBACK_SYNC_JS)?;
    let wrapped = factory.call(on_entry.to_unknown())?;

    run_sync(env, "archive extraction to a callback", || {
        // Copied: `onEntry` runs JS while the archive is parsed, and JS can
        // mutate or detach the caller's buffer under a borrowed slice.
        job.run(data.to_vec(), |entry| {
            let outcome = wrapped
                .call(entry)
                .map_err(|source| ProgressCallbackError::EntryCallback { source })?;
            if outcome.get_type().map_err(Failure::Native)? == napi::ValueType::Undefined {
                return Ok(());
            }
            Err(ProgressCallbackError::EntryCallback {
                source: napi::Error::from_unknown_without_coercion(outcome),
            }
            .into())
        })
    })
    .map(ExtractionReport::from)
}
