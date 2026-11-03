//! Archive input that is bytes or an `AsyncIterable<Uint8Array>`.
//!
//! A stream is pulled from the blocking worker: every chunk is requested from
//! the JavaScript thread through a threadsafe function and awaited, so the
//! event loop keeps turning and the stream's own backpressure applies. The
//! iterator is closed (`return()`) on every exit of the job, including a
//! refusal that never reads the whole archive.

use std::io;
use std::io::Read;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::PoisonError;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use exarch_core::ArchiveReader;
use napi::Env;
use napi::JsValue;
use napi::Status;
use napi::bindgen_prelude::FromNapiValue;
use napi::bindgen_prelude::Function;
use napi::bindgen_prelude::JsObjectValue;
use napi::bindgen_prelude::Promise;
use napi::bindgen_prelude::Result;
use napi::bindgen_prelude::TypeName;
use napi::bindgen_prelude::Uint8Array;
use napi::bindgen_prelude::Unknown;
use napi::bindgen_prelude::ValidateNapiValue;
use napi::sys;
use napi::threadsafe_function::ThreadsafeFunction;
use napi::threadsafe_function::ThreadsafeFunctionCallMode;
use tokio::runtime::Handle;

use crate::CoreResult;
use crate::abort::AbortBinding;
use crate::abort::AbortHandle;
use crate::abort::Aborted;
use crate::abort::Detach;
use crate::error::Failure;
use crate::error::ProgressCallbackError;
use crate::report::ArchiveType;

/// Turns the `data` argument into `undefined` (bytes) or `{ next, close }`.
///
/// A thrown or rejected non-object is wrapped in an `Error` whose `cause` is
/// the primitive (a Symbol stringified: napi-rs coerces `cause` to a string
/// when it reads it back, which throws for a raw Symbol).
const CLASSIFY_SOURCE_JS: &str = js_with_normalizer!(
    r#"(source) => {
  if (ArrayBuffer.isView(source)) {
    return undefined;
  }
  const factory = source === null || source === undefined ? undefined : source[Symbol.asyncIterator];
  if (typeof factory !== "function") {
    throw new TypeError("data must be a Uint8Array or an AsyncIterable<Uint8Array>");
  }
  let iterator;
  const start = () => {
    if (iterator === undefined) {
      iterator = factory.call(source);
    }
    return iterator;
  };
  return {
    next: async () => {
      try {
        const step = await start().next();
        if (step.done) {
          return null;
        }
        if (!(step.value instanceof Uint8Array)) {
          throw new TypeError("stream chunks must be Uint8Array");
        }
        return new Uint8Array(step.value);
      } catch (thrown) {
        throw normalizeThrown("stream", thrown);
      }
    },
    close: async () => {
      try {
        const it = start();
        if (typeof it.return === "function") {
          await it.return();
        }
      } catch (_) {}
    },
  };
}"#
);

type NextFn = ThreadsafeFunction<(), Promise<Option<Uint8Array>>, (), Status, false>;
type CloseFn = ThreadsafeFunction<(), Promise<()>, (), Status, false>;

/// Why a pull produced no chunk.
enum PullStop {
    Aborted,
    Failed(napi::Error),
}

/// The two functions that drive an `AsyncIterable`, and what went wrong.
///
/// Every wait on JavaScript races the operation's `AbortSignal`, so a stalled
/// iterable cannot pin the worker once the signal fires.
struct StreamShared {
    next: NextFn,
    close: CloseFn,
    failure: Mutex<Option<napi::Error>>,
    closed: AtomicBool,
    abort: OnceLock<AbortHandle>,
}

impl StreamShared {
    fn abort(&self) -> &AbortHandle {
        self.abort.get().unwrap_or(&AbortHandle::NONE)
    }

    fn pull(&self) -> std::result::Result<Option<Vec<u8>>, PullStop> {
        let pulled = Handle::current().block_on(self.abort().race(async {
            let promise = self.next.call_async_catch(()).await?;
            Ok::<_, napi::Error>(promise.await?.map(|chunk| chunk.to_vec()))
        }));
        match pulled {
            Ok(Ok(chunk)) => Ok(chunk),
            Ok(Err(err)) => Err(PullStop::Failed(err)),
            Err(Aborted) => Err(PullStop::Aborted),
        }
    }

    fn record(&self, err: napi::Error) {
        self.failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert(err);
    }

    fn take_failure(&self) -> Option<napi::Error> {
        self.failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// Closes the iterator once and waits for it, unless the signal fires
    /// first: a generator whose `finally` never settles must not pin the
    /// worker. An error from `return()` is swallowed by the JavaScript side.
    fn close_blocking(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let _ = Handle::current().block_on(
                self.abort()
                    .race(async { self.close.call_async_catch(()).await?.await }),
            );
        }
    }

    /// Queues the close without waiting: after an abort `return()` would sit
    /// behind the `next()` that is still pending.
    fn abort_close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.close.call((), ThreadsafeFunctionCallMode::NonBlocking);
        }
    }
}

impl Drop for StreamShared {
    /// Fallback for a job that never reached its own close, such as a panic:
    /// queue the close without waiting.
    fn drop(&mut self) {
        self.abort_close();
    }
}

/// A [`Read`] over an `AsyncIterable<Uint8Array>`, for a blocking worker.
struct NodeStreamReader {
    shared: Arc<StreamShared>,
    chunk: Vec<u8>,
    pos: usize,
    done: bool,
}

impl Read for NodeStreamReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.chunk.len() {
            if self.done {
                return Ok(0);
            }
            match self.shared.pull() {
                Ok(Some(chunk)) => {
                    self.chunk = chunk;
                    self.pos = 0;
                }
                Ok(None) => {
                    self.done = true;
                    return Ok(0);
                }
                Err(PullStop::Failed(err)) => {
                    self.done = true;
                    self.shared.record(err);
                    return Err(io::Error::other("archive stream failed"));
                }
                Err(PullStop::Aborted) => {
                    self.done = true;
                    return Err(io::Error::other("archive read aborted"));
                }
            }
        }
        let n = buf.len().min(self.chunk.len() - self.pos);
        buf[..n].copy_from_slice(&self.chunk[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// An `AsyncIterable<Uint8Array>` argument, not yet read.
pub struct StreamSource {
    shared: Arc<StreamShared>,
}

/// The `data` argument of the async in-memory functions.
pub enum ArchiveSource {
    /// The archive bytes, copied before the call returns.
    Bytes(Vec<u8>),
    /// An `AsyncIterable<Uint8Array>`, TAR family only.
    Stream(StreamSource),
}

impl TypeName for ArchiveSource {
    fn type_name() -> &'static str {
        "ArchiveSource"
    }

    fn value_type() -> napi::ValueType {
        napi::ValueType::Object
    }
}

impl ValidateNapiValue for ArchiveSource {}

impl FromNapiValue for ArchiveSource {
    // SAFETY: napi-rs calls this only from the generated argument-extraction
    // code, on the JS thread, with a live `env` and `napi_val`.
    #[expect(unsafe_code, reason = "napi's FromNapiValue is an unsafe trait method")]
    unsafe fn from_napi_value(env: sys::napi_env, napi_val: sys::napi_value) -> Result<Self> {
        // SAFETY: same guarantee as above.
        let source = unsafe { Unknown::from_napi_value(env, napi_val)? };
        let classify: Function<'_, Unknown<'_>, Unknown<'_>> =
            Env::from_raw(env).run_script(CLASSIFY_SOURCE_JS)?;
        let classified = classify.call(source)?;
        if classified.get_type()? == napi::ValueType::Undefined {
            // SAFETY: same guarantee as above.
            let bytes = unsafe { Uint8Array::from_napi_value(env, napi_val)? };
            return Ok(Self::Bytes(bytes.to_vec()));
        }
        // SAFETY: `classified` is a live value of this environment.
        let driver =
            unsafe { napi::bindgen_prelude::Object::from_napi_value(env, classified.raw())? };
        let next: Function<'_, (), Promise<Option<Uint8Array>>> =
            driver.get_named_property("next")?;
        let close: Function<'_, (), Promise<()>> = driver.get_named_property("close")?;
        let next = next
            .build_threadsafe_function::<()>()
            .callee_handled::<false>()
            .build_callback(|_| Ok(()))?;
        let close = close
            .build_threadsafe_function::<()>()
            .callee_handled::<false>()
            .build_callback(|_| Ok(()))?;
        Ok(Self::Stream(StreamSource {
            shared: Arc::new(StreamShared {
                next,
                close,
                failure: Mutex::new(None),
                closed: AtomicBool::new(false),
                abort: OnceLock::new(),
            }),
        }))
    }
}

/// Where an archive comes from, for the code that opens it.
pub trait IntoSource: Send + Sized {
    /// Releases the source of a job that failed before it was opened. A
    /// stream is closed and awaited, as after a run.
    fn abandon(self) {}

    /// Opens the archive and runs `f` on it. A stream is closed afterwards on
    /// every outcome, and a failure of the stream is the primary error.
    ///
    /// # Errors
    ///
    /// The errors of opening the archive and of `f`.
    fn run<T>(
        self,
        format: Option<ArchiveType>,
        f: impl FnOnce(ArchiveReader<'_>) -> CoreResult<T>,
    ) -> CoreResult<T>;
}

impl<B: AsRef<[u8]> + Send> IntoSource for B {
    fn run<T>(
        self,
        format: Option<ArchiveType>,
        f: impl FnOnce(ArchiveReader<'_>) -> CoreResult<T>,
    ) -> CoreResult<T> {
        f(ArchiveReader::from_bytes(self, format.map(Into::into))?)
    }
}

impl ArchiveSource {
    /// Queues the close of a stream without waiting, for a job the signal
    /// stopped.
    fn abort_abandon(self) {
        if let Self::Stream(StreamSource { shared }) = self {
            shared.abort_close();
        }
    }

    fn bind_abort(&self, abort: &AbortHandle) {
        if let Self::Stream(StreamSource { shared }) = self {
            shared.abort.get_or_init(|| abort.clone());
        }
    }
}

impl IntoSource for ArchiveSource {
    fn abandon(self) {
        if let Self::Stream(StreamSource { shared }) = self {
            shared.close_blocking();
        }
    }

    fn run<T>(
        self,
        format: Option<ArchiveType>,
        f: impl FnOnce(ArchiveReader<'_>) -> CoreResult<T>,
    ) -> CoreResult<T> {
        match self {
            Self::Bytes(bytes) => bytes.run(format, f),
            Self::Stream(StreamSource { shared }) => {
                let reader = NodeStreamReader {
                    shared: Arc::clone(&shared),
                    chunk: Vec::new(),
                    pos: 0,
                    done: false,
                };
                let opened = match format {
                    Some(format) => ArchiveReader::of_stream(reader, format.into()),
                    None => ArchiveReader::detect_stream(reader),
                };
                let result = opened.map_err(Failure::from).and_then(f);
                if shared.abort().is_observed() {
                    shared.abort_close();
                } else {
                    shared.close_blocking();
                }
                shared.take_failure().map_or(result, |source| {
                    Err(ProgressCallbackError::Stream { source }.into())
                })
            }
        }
    }
}

/// An [`ArchiveSource`] tied to the operation's `AbortSignal`.
///
/// The signal is checked before anything is opened. When it stopped the job
/// at any point, the stream is closed without waiting and the result is the
/// abort, whatever error the stopped read caused downstream.
pub struct AbortableSource {
    source: ArchiveSource,
    abort: AbortHandle,
}

impl AbortableSource {
    /// Binds `source` to the optional `signal`; also returns the cleanup to run
    /// on the JS thread once the operation settled.
    #[must_use]
    pub fn bind(source: ArchiveSource, signal: Option<AbortBinding>) -> (Self, Detach) {
        let (abort, detach) = AbortBinding::split(signal);
        source.bind_abort(&abort);
        (Self { source, abort }, detach)
    }

    /// The handle for waits that happen outside the source, such as `onEntry`.
    #[must_use]
    pub fn abort(&self) -> AbortHandle {
        self.abort.clone()
    }
}

impl IntoSource for AbortableSource {
    fn abandon(self) {
        if self.abort.is_observed() {
            self.source.abort_abandon();
        } else {
            self.source.abandon();
        }
    }

    fn run<T>(
        self,
        format: Option<ArchiveType>,
        f: impl FnOnce(ArchiveReader<'_>) -> CoreResult<T>,
    ) -> CoreResult<T> {
        if self.abort.check().is_err() {
            self.source.abort_abandon();
            return Err(self.abort.failure());
        }
        let result = self.source.run(format, f);
        if self.abort.is_observed() {
            return Err(self.abort.failure());
        }
        result
    }
}
