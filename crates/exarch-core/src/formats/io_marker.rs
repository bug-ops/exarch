//! Typed errors carried inside an [`io::Error`] across a `Read` boundary.
//!
//! A decoder or wrapper that can only return [`io::Error`] smuggles a typed
//! marker through it, and the caller recovers the marker by downcast instead
//! of matching message text.

use std::io;

/// A typed error carried inside an [`io::Error`].
///
/// Implementors guarantee that [`into_io`](Self::into_io) wraps `self` as the
/// error's source with kind [`KIND`](Self::KIND); callers may assume that
/// [`find`](Self::find) recovers exactly the markers built that way.
pub(crate) trait IoMarker: std::error::Error + Send + Sync + Sized + 'static {
    /// The kind the wrapping [`io::Error`] reports.
    const KIND: io::ErrorKind = io::ErrorKind::InvalidData;

    /// Wraps the marker in an [`io::Error`] of kind [`KIND`](Self::KIND).
    fn into_io(self) -> io::Error {
        io::Error::new(Self::KIND, self)
    }

    /// The marker carried directly by `error`, if it is one.
    fn find(error: &io::Error) -> Option<&Self> {
        error.get_ref()?.downcast_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("probe")]
    struct Probe;

    impl IoMarker for Probe {}

    #[derive(Debug, thiserror::Error)]
    #[error("other probe")]
    struct OtherProbe;

    impl IoMarker for OtherProbe {
        const KIND: io::ErrorKind = io::ErrorKind::Other;
    }

    #[test]
    fn round_trips_through_io_error_with_its_kind() {
        let error = Probe.into_io();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(Probe::find(&error).is_some());
        assert_eq!(OtherProbe.into_io().kind(), io::ErrorKind::Other);
    }

    #[test]
    fn find_ignores_other_markers_and_plain_errors() {
        assert!(Probe::find(&OtherProbe.into_io()).is_none());
        assert!(Probe::find(&io::Error::from(io::ErrorKind::InvalidData)).is_none());
    }
}
