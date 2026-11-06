//! The failure of replacing an existing destination as a whole.

use std::fmt;
use std::io;
use std::path::PathBuf;

use crate::closed_enum::closed_enum;

closed_enum! {
    /// The outcome of [`Restore`] without its payload.
    ///
    /// The string form is stable and shared by every front end.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::Restore;
    /// use exarch_core::RestoreKind;
    ///
    /// assert_eq!(Restore::Restored.kind(), RestoreKind::Restored);
    /// assert_eq!(RestoreKind::Failed.as_str(), "failed");
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[non_exhaustive]
    pub enum RestoreKind {
        /// The original destination was never moved aside
        NotNeeded => "not_needed",
        /// The original destination was moved aside and moved back
        Restored => "restored",
        /// The original destination was moved aside and could not be moved back
        Failed => "failed",
    }
}

/// What became of the original destination after a failed replace.
///
/// # Examples
///
/// ```
/// use exarch_core::Restore;
///
/// assert!(Restore::Restored.original_is_intact());
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub enum Restore {
    /// The original destination was never moved aside.
    NotNeeded,
    /// The original destination was moved aside and moved back.
    Restored,
    /// The original destination was moved aside and could not be moved back; it
    /// still sits at `backup`.
    Failed {
        /// Where the original destination is now.
        backup: PathBuf,
        /// Why moving it back failed.
        error: io::Error,
    },
}

impl Restore {
    /// Whether the original destination is still where it was.
    #[must_use]
    pub const fn original_is_intact(&self) -> bool {
        matches!(self, Self::NotNeeded | Self::Restored)
    }

    /// Which outcome this is, without the backup path and error.
    #[must_use]
    pub const fn kind(&self) -> RestoreKind {
        match self {
            Self::NotNeeded => RestoreKind::NotNeeded,
            Self::Restored => RestoreKind::Restored,
            Self::Failed { .. } => RestoreKind::Failed,
        }
    }
}

/// A staging directory that a failed replace left on disk.
#[derive(Debug)]
#[non_exhaustive]
pub struct StagingLeftover {
    /// The path of the leftover directory.
    pub path: PathBuf,
}

impl StagingLeftover {
    /// Records a staging directory left at `path`.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::StagingLeftover;
    ///
    /// let leftover = StagingLeftover::new("out/.exarch-1".into());
    /// assert!(leftover.path.ends_with(".exarch-1"));
    /// ```
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

/// Why replacing an existing destination failed, and what is left behind.
///
/// An I/O failure only: every refusal of the replace is a typed
/// [`ArchiveError`](crate::ArchiveError) of its own.
///
/// # Examples
///
/// ```
/// use exarch_core::ReplaceFailure;
/// use exarch_core::Restore;
///
/// let failure = ReplaceFailure::new(
///     std::io::Error::from(std::io::ErrorKind::PermissionDenied),
///     Restore::Restored,
///     None,
/// );
/// assert!(failure.restore.original_is_intact());
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub struct ReplaceFailure {
    /// The I/O error that stopped the replace.
    pub error: io::Error,
    /// What became of the original destination.
    pub restore: Restore,
    /// The staging directory left on disk, if any.
    pub leftover: Option<StagingLeftover>,
}

impl ReplaceFailure {
    /// Records a failed replace.
    #[must_use]
    pub const fn new(
        error: io::Error,
        restore: Restore,
        leftover: Option<StagingLeftover>,
    ) -> Self {
        Self {
            error,
            restore,
            leftover,
        }
    }
}

impl ReplaceFailure {
    /// The description a binding shows: the I/O text and every host path
    /// redacted like an [`ArchiveError::Io`](crate::ArchiveError::Io) path.
    pub(crate) fn redacted_description(&self) -> String {
        use super::redaction::sanitize_io_error_for_error;
        use super::redaction::sanitize_path_for_error;

        let head = format!(
            "failed to replace the destination: {}",
            sanitize_io_error_for_error(&self.error)
        );
        let restore = match &self.restore {
            Restore::NotNeeded => format!("{head}; the original destination is unchanged"),
            Restore::Restored => format!("{head}; the original destination was restored"),
            Restore::Failed { backup, error } => format!(
                "{head}; restoring the original destination failed ({}), it remains at {}",
                sanitize_io_error_for_error(error),
                sanitize_path_for_error(backup)
            ),
        };
        match &self.leftover {
            Some(leftover) => format!(
                "{restore}; a staging directory remains at {}",
                sanitize_path_for_error(&leftover.path)
            ),
            None => restore,
        }
    }
}

impl fmt::Display for ReplaceFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to replace the destination: {}", self.error)?;
        match &self.restore {
            Restore::NotNeeded => f.write_str("; the original destination is unchanged")?,
            Restore::Restored => f.write_str("; the original destination was restored")?,
            Restore::Failed { backup, error } => write!(
                f,
                "; restoring the original destination failed ({error}), it remains at {}",
                backup.display()
            )?,
        }
        self.leftover.as_ref().map_or(Ok(()), |leftover| {
            write!(
                f,
                "; a staging directory remains at {}",
                leftover.path.display()
            )
        })
    }
}

impl std::error::Error for ReplaceFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
