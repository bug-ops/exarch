//! Structured context for `std::io::Error::other` call sites.

use std::error::Error as StdError;
use std::fmt;

/// Pairs a static, non-path-bearing summary with the dynamic detail of an
/// I/O failure constructed via [`std::io::Error::other`].
///
/// FFI bindings redact `ArchiveError::Io` messages down to their
/// [`std::io::ErrorKind`] description in release builds, since free-form
/// messages have no structured path field to sanitize. For errors built
/// from `ErrorKind::Other`, that redaction collapses to the fixed string
/// "other error", discarding all diagnostic value. Wrapping the detail in
/// `IoContext` lets bindings recognize the error (via
/// [`std::io::Error::get_ref`] and downcasting) and surface `context`
/// instead — safe to show even in release builds because it is always a
/// `&'static str` fixed at the call site, never built from path or archive
/// entry data.
///
/// # Examples
///
/// ```
/// use exarch_core::IoContext;
/// use std::io;
///
/// let err = io::Error::other(IoContext::new(
///     "failed to read entry metadata",
///     "/tmp/x: denied",
/// ));
/// assert_eq!(
///     err.to_string(),
///     "failed to read entry metadata: /tmp/x: denied"
/// );
///
/// let ctx = err
///     .get_ref()
///     .and_then(|inner| inner.downcast_ref::<IoContext>())
///     .expect("IoContext downcast");
/// assert_eq!(ctx.context, "failed to read entry metadata");
/// ```
#[derive(Debug)]
pub struct IoContext {
    /// Static summary of the failure. Never carries path or archive entry
    /// data — safe to surface in release builds.
    pub context: &'static str,
    /// Full dynamic detail (may embed a host path). Shown only in debug
    /// builds via `ArchiveError::Io`'s `Display`.
    pub detail: String,
}

impl IoContext {
    /// Creates a new `IoContext` pairing a static summary with dynamic
    /// detail.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::IoContext;
    ///
    /// let ctx = IoContext::new("failed to start file in zip archive", "boom");
    /// assert_eq!(ctx.context, "failed to start file in zip archive");
    /// assert_eq!(ctx.detail, "boom");
    /// ```
    #[must_use]
    pub fn new(context: &'static str, detail: impl Into<String>) -> Self {
        Self {
            context,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for IoContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.context, self.detail)
    }
}

impl StdError for IoContext {}

#[cfg(test)]
#[allow(clippy::expect_used)] // Allow expect in tests for brevity
mod tests {
    use super::IoContext;
    use std::io;

    #[test]
    fn display_includes_context_and_detail() {
        let ctx = IoContext::new("failed to read entry metadata", "/tmp/x: denied");
        assert_eq!(
            ctx.to_string(),
            "failed to read entry metadata: /tmp/x: denied"
        );
    }

    #[test]
    fn roundtrips_through_io_error_other() {
        let err = io::Error::other(IoContext::new("failed to finish zip archive", "disk full"));
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "failed to finish zip archive: disk full");

        let ctx = err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<IoContext>())
            .expect("IoContext should be downcastable from io::Error");
        assert_eq!(ctx.context, "failed to finish zip archive");
        assert_eq!(ctx.detail, "disk full");
    }
}
