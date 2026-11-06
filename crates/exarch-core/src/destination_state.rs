//! Whether an extraction destination can hold anything yet.

use std::io;
use std::path::Path;

/// Whether a destination is fresh: nothing exists at its final name and the
/// directory that would hold it exists.
///
/// A fresh destination has no conflicts to look for and no pre-existing
/// content a failed run could damage, so a front end can skip a conflict
/// pre-check and extract atomically. A missing parent directory is not
/// fresh: extraction would have to create it, and a refusal could not undo
/// that.
///
/// # Examples
///
/// ```
/// use exarch_core::DestinationState;
///
/// let dir = std::env::temp_dir();
/// assert_eq!(
///     DestinationState::probe(&dir.join("exarch-doc-never-created")),
///     DestinationState::Fresh
/// );
/// assert_eq!(DestinationState::probe(&dir), DestinationState::NotFresh);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DestinationState {
    /// The final name is free and its parent directory exists.
    Fresh,
    /// Something is at the final name (a dangling symlink counts), the
    /// parent directory is missing, or either cannot be inspected.
    NotFresh,
}

impl DestinationState {
    /// Classifies `destination` without following a symlink at its final
    /// name. An empty parent (`out/`) means the current directory.
    #[must_use]
    pub fn probe(destination: &Path) -> Self {
        let parent = destination
            .parent()
            .filter(|parent| !parent.is_empty())
            .unwrap_or_else(|| Path::new("."));
        let absent = matches!(
            destination.symlink_metadata(),
            Err(ref error) if error.kind() == io::ErrorKind::NotFound
        );
        if absent && parent.is_dir() {
            Self::Fresh
        } else {
            Self::NotFresh
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::DestinationState;

    #[test]
    fn an_absent_name_in_an_existing_parent_is_fresh() {
        let temp = tempfile::tempdir().unwrap();

        assert_eq!(
            DestinationState::probe(&temp.path().join("out")),
            DestinationState::Fresh
        );
    }

    #[test]
    fn an_existing_name_or_a_missing_parent_is_not_fresh() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("out")).unwrap();

        assert_eq!(
            DestinationState::probe(&temp.path().join("out")),
            DestinationState::NotFresh
        );
        assert_eq!(
            DestinationState::probe(&temp.path().join("missing").join("out")),
            DestinationState::NotFresh
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_is_not_fresh() {
        let temp = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("nowhere", temp.path().join("out")).unwrap();

        assert_eq!(
            DestinationState::probe(&temp.path().join("out")),
            DestinationState::NotFresh
        );
    }

    #[test]
    fn a_bare_name_resolves_its_parent_to_the_working_directory() {
        assert_eq!(
            DestinationState::probe("exarch-test-never-created-name".as_ref()),
            DestinationState::Fresh
        );
    }
}
