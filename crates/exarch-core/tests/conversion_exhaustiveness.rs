//! Conversions over core enums are written so that adding a variant fails
//! loudly: `CallbackError` is closed, so a match without a wildcard breaks the
//! build of any front end that handles it.

use std::io;

use exarch_core::ArchiveError;
use exarch_core::CallbackError;

/// A wildcard-free match: adding a `CallbackError` variant fails to compile.
fn describe(error: &CallbackError<io::Error>) -> &'static str {
    match error {
        CallbackError::Callback(_) => "callback",
        CallbackError::Archive(_) => "archive",
    }
}

#[test]
fn every_callback_error_variant_is_handled_and_keeps_its_cause() {
    let callback = CallbackError::Callback(io::Error::other("stop"));
    assert_eq!(describe(&callback), "callback");
    assert_eq!(callback.to_string(), "entry callback failed");

    let archive: CallbackError<io::Error> =
        CallbackError::from(ArchiveError::Io(io::Error::other("disk")));
    assert_eq!(describe(&archive), "archive");
    assert!(archive.to_string().contains("disk"));
}
