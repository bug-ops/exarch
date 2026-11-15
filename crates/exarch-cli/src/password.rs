//! Password input for encrypted archives.
//!
//! The password reaches the process only through a file, a file descriptor or
//! an interactive prompt, never through argv or the environment. [`read`] runs
//! before the sandbox confines the process, because every source opens
//! something outside the destination (a file, a descriptor, `/dev/tty`).

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use exarch_core::Password;

/// Where the password is read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordSource {
    /// The first line of a regular file.
    File(PathBuf),
    /// The first line read from an inherited file descriptor.
    #[cfg(unix)]
    Fd(std::os::fd::RawFd),
    /// A no-echo prompt on the terminal.
    Prompt,
}

/// Reads the password from `source`, or returns `None` when no source was
/// given.
///
/// # Errors
///
/// A source that cannot be read, or whose content is not a valid password.
pub fn read(source: Option<&PasswordSource>) -> Result<Option<Arc<Password>>> {
    source
        .map(|source| {
            Err::<Arc<Password>, _>(anyhow::anyhow!(
                "password input from {source:?} is not available yet"
            ))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_source_means_no_password() {
        assert!(matches!(read(None), Ok(None)));
    }
}
