//! `AbortSignal` support for the async in-memory functions.
//!
//! The signal is bound while the arguments are extracted, so a value that is
//! not a signal throws a `TypeError` before anything starts. The binding shares
//! an [`AbortWatch`] with the blocking worker: an abort sets a sticky flag and
//! wakes whatever the worker is awaiting, which is a pull of the archive
//! stream, an `onEntry` promise or the close of the stream.
//!
//! An abort is noticed only at those points and when the worker starts.
//! Parsing or extracting bytes that are already in memory is not interrupted.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Poll;

use napi::Env;
use napi::Error;
use napi::bindgen_prelude::FnArgs;
use napi::bindgen_prelude::FromNapiValue;
use napi::bindgen_prelude::Function;
use napi::bindgen_prelude::FunctionRef;
use napi::bindgen_prelude::Result;
use napi::bindgen_prelude::TypeName;
use napi::bindgen_prelude::Unknown;
use napi::bindgen_prelude::ValidateNapiValue;
use napi::sys;
use tokio::sync::Notify;

use crate::error::Failure;
use crate::error::ProgressCallbackError;

/// Checks that the argument looks like an `AbortSignal` and subscribes
/// `onAbort(reason)` to it; returns the function that unsubscribes.
///
/// The check is duck-typed, like Node's own `validateAbortSignal`, so a signal
/// from another realm is accepted.
const BIND_SIGNAL_JS: &str = r#"(signal, onAbort) => {
  if (
    typeof signal !== "object" ||
    signal === null ||
    !("aborted" in signal) ||
    typeof signal.addEventListener !== "function"
  ) {
    throw new TypeError("signal must be an AbortSignal");
  }
  if (signal.aborted) {
    onAbort(signal.reason);
    return () => {};
  }
  const listener = () => onAbort(signal.reason);
  signal.addEventListener("abort", listener, { once: true });
  return () => {
    try {
      if (typeof signal.removeEventListener === "function") {
        signal.removeEventListener("abort", listener);
      }
    } catch (_) {}
  };
}"#;

/// Returned by the waits of an [`AbortHandle`] when the signal fired first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aborted;

/// State shared between the JS listener and the blocking worker.
#[derive(Debug)]
struct AbortWatch {
    aborted: AtomicBool,
    observed: AtomicBool,
    reason: Mutex<Option<Error>>,
    notify: Notify,
}

impl AbortWatch {
    fn new() -> Self {
        Self {
            aborted: AtomicBool::new(false),
            observed: AtomicBool::new(false),
            reason: Mutex::new(None),
            notify: Notify::new(),
        }
    }

    fn fire(&self, reason: Error) {
        self.reason
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert(reason);
        self.aborted.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    fn observe(&self) -> Aborted {
        self.observed.store(true, Ordering::Release);
        Aborted
    }
}

/// The worker's view of an optional `AbortSignal`. Without a signal every wait
/// completes normally.
#[derive(Debug, Clone, Default)]
pub struct AbortHandle(Option<Arc<AbortWatch>>);

impl AbortHandle {
    /// A handle that never aborts.
    pub const NONE: Self = Self(None);

    /// Records and reports whether the signal already fired.
    ///
    /// # Errors
    ///
    /// [`Aborted`] when it did.
    pub fn check(&self) -> std::result::Result<(), Aborted> {
        match &self.0 {
            Some(watch) if watch.aborted.load(Ordering::Acquire) => Err(watch.observe()),
            _ => Ok(()),
        }
    }

    /// Whether the worker saw the abort and stopped because of it.
    #[must_use]
    pub fn is_observed(&self) -> bool {
        self.0
            .as_ref()
            .is_some_and(|watch| watch.observed.load(Ordering::Acquire))
    }

    /// Awaits `fut` unless the signal fires first.
    ///
    /// `fut` is polled once before the flag is read, so a call it enqueues on
    /// its first poll (such as the close of an iterable) is issued even when
    /// the signal already fired. The wakeup is registered before the flag is
    /// read, so an abort between the two cannot be lost.
    ///
    /// # Errors
    ///
    /// [`Aborted`] when the signal fired before `fut` completed.
    pub async fn race<F: Future>(&self, fut: F) -> std::result::Result<F::Output, Aborted> {
        let Some(watch) = &self.0 else {
            return Ok(fut.await);
        };
        let mut notified = pin!(watch.notify.notified());
        notified.as_mut().enable();
        let mut fut = pin!(fut);
        std::future::poll_fn(|cx| {
            if let Poll::Ready(output) = fut.as_mut().poll(cx) {
                return Poll::Ready(Ok(output));
            }
            if watch.aborted.load(Ordering::Acquire) || notified.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(watch.observe()));
            }
            Poll::Pending
        })
        .await
    }

    /// The failure that rejects the operation, carrying the signal's reason the
    /// first time it is taken.
    #[must_use]
    pub fn failure(&self) -> Failure {
        let reason = self.0.as_ref().and_then(|watch| {
            watch
                .reason
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
        });
        ProgressCallbackError::Aborted { reason }.into()
    }
}

type Unsubscribe = FunctionRef<(), Unknown<'static>>;
type OnAbortFn<'env> = Function<'env, Unknown<'env>, ()>;
type BindFn<'env> =
    Function<'env, FnArgs<(Unknown<'env>, OnAbortFn<'env>)>, Function<'env, (), Unknown<'env>>>;

/// The `signal` argument: an `AbortSignal` the worker is subscribed to.
pub struct AbortBinding {
    handle: AbortHandle,
    unsubscribe: Unsubscribe,
}

/// Unsubscribes from the signal on the JS thread once the operation settled.
pub struct Detach(Option<Unsubscribe>);

impl Detach {
    /// Removes the abort listener. Must run on the JS thread.
    ///
    /// # Errors
    ///
    /// Returns the error of calling into JavaScript.
    pub fn run(self, env: Env) -> Result<()> {
        if let Some(unsubscribe) = self.0 {
            unsubscribe.borrow_back(&env)?.call(())?;
        }
        Ok(())
    }
}

impl AbortBinding {
    /// Splits the optional argument into the worker's handle and the JS-thread
    /// cleanup.
    #[must_use]
    pub fn split(binding: Option<Self>) -> (AbortHandle, Detach) {
        match binding {
            Some(Self {
                handle,
                unsubscribe,
            }) => (handle, Detach(Some(unsubscribe))),
            None => (AbortHandle::NONE, Detach(None)),
        }
    }
}

impl TypeName for AbortBinding {
    fn type_name() -> &'static str {
        "AbortSignal"
    }

    fn value_type() -> napi::ValueType {
        napi::ValueType::Object
    }
}

impl ValidateNapiValue for AbortBinding {}

impl FromNapiValue for AbortBinding {
    // SAFETY: napi-rs calls this only from the generated argument-extraction
    // code, on the JS thread, with a live `env` and `napi_val`.
    #[expect(unsafe_code, reason = "napi's FromNapiValue is an unsafe trait method")]
    unsafe fn from_napi_value(env: sys::napi_env, napi_val: sys::napi_value) -> Result<Self> {
        // SAFETY: same guarantee as above.
        let signal = unsafe { Unknown::from_napi_value(env, napi_val)? };
        let env = Env::from_raw(env);
        let watch = Arc::new(AbortWatch::new());
        let listener_watch = Arc::clone(&watch);
        let on_abort: OnAbortFn<'_> = env.create_function_from_closure("onAbort", move |ctx| {
            let reason: Unknown = ctx.get(0)?;
            listener_watch.fire(Error::from_unknown_without_coercion(reason));
            Ok(())
        })?;
        let bind: BindFn<'_> = env.run_script(BIND_SIGNAL_JS)?;
        let unsubscribe = bind.call(FnArgs::from((signal, on_abort)))?.create_ref()?;
        Ok(Self {
            handle: AbortHandle(Some(watch)),
            unsubscribe,
        })
    }
}
