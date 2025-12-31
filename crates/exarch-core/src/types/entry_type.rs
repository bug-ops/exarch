//! Archive entry type enumeration.

use std::path::PathBuf;

/// Type of entry in an archive.
///
/// This enum represents the different types of entries that can be found
/// in an archive file. Each variant contains the necessary metadata for
/// that specific type.
///
/// # Examples
///
/// ```
/// use exarch_core::types::EntryType;
/// use std::path::PathBuf;
///
/// let file = EntryType::File;
/// let directory = EntryType::Directory;
/// let symlink = EntryType::Symlink {
///     target: PathBuf::from("../target"),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EntryType {
    /// Regular file entry.
    File,

    /// Directory entry.
    Directory,

    /// Symbolic link entry.
    ///
    /// The `target` field contains the path the symlink points to.
    /// This target has NOT been validated and must be checked before use.
    Symlink {
        /// The symlink target path (not yet validated).
        target: PathBuf,
    },

    /// Hard link entry.
    ///
    /// The `target` field contains the path the hardlink points to.
    /// This target has NOT been validated and must be checked before use.
    Hardlink {
        /// The hardlink target path (not yet validated).
        target: PathBuf,
    },
}

impl EntryType {
    /// Returns `true` if this is a regular file.
    #[must_use]
    pub const fn is_file(&self) -> bool {
        matches!(self, Self::File)
    }

    /// Returns `true` if this is a directory.
    #[must_use]
    pub const fn is_directory(&self) -> bool {
        matches!(self, Self::Directory)
    }

    /// Returns `true` if this is a symlink.
    #[must_use]
    pub const fn is_symlink(&self) -> bool {
        matches!(self, Self::Symlink { .. })
    }

    /// Returns `true` if this is a hardlink.
    #[must_use]
    pub const fn is_hardlink(&self) -> bool {
        matches!(self, Self::Hardlink { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_type_file() {
        let entry = EntryType::File;
        assert!(entry.is_file());
        assert!(!entry.is_directory());
        assert!(!entry.is_symlink());
        assert!(!entry.is_hardlink());
    }

    #[test]
    fn test_entry_type_directory() {
        let entry = EntryType::Directory;
        assert!(!entry.is_file());
        assert!(entry.is_directory());
        assert!(!entry.is_symlink());
        assert!(!entry.is_hardlink());
    }

    #[test]
    fn test_entry_type_symlink() {
        let entry = EntryType::Symlink {
            target: PathBuf::from("../target"),
        };
        assert!(!entry.is_file());
        assert!(!entry.is_directory());
        assert!(entry.is_symlink());
        assert!(!entry.is_hardlink());
    }

    #[test]
    fn test_entry_type_hardlink() {
        let entry = EntryType::Hardlink {
            target: PathBuf::from("original"),
        };
        assert!(!entry.is_file());
        assert!(!entry.is_directory());
        assert!(!entry.is_symlink());
        assert!(entry.is_hardlink());
    }

    #[test]
    fn test_entry_type_equality() {
        let file1 = EntryType::File;
        let file2 = EntryType::File;
        assert_eq!(file1, file2);

        let symlink1 = EntryType::Symlink {
            target: PathBuf::from("target"),
        };
        let symlink2 = EntryType::Symlink {
            target: PathBuf::from("target"),
        };
        assert_eq!(symlink1, symlink2);
    }

    #[test]
    fn test_entry_type_clone() {
        let original = EntryType::Symlink {
            target: PathBuf::from("target"),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    // L-4: Debug format tests
    #[test]
    fn test_entry_type_debug_format() {
        let file = EntryType::File;
        let debug = format!("{file:?}");
        assert_eq!(debug, "File");

        let symlink = EntryType::Symlink {
            target: PathBuf::from("secret"),
        };
        let debug = format!("{symlink:?}");
        assert!(debug.contains("Symlink"));
        assert!(debug.contains("secret"));

        let directory = EntryType::Directory;
        let debug = format!("{directory:?}");
        assert_eq!(debug, "Directory");
    }

    // M-TEST-5: EntryType variant edge cases
    #[test]
    fn test_entry_type_symlink_empty_target() {
        let entry = EntryType::Symlink {
            target: PathBuf::from(""),
        };
        assert!(entry.is_symlink(), "empty target should still be symlink");
    }

    #[test]
    fn test_entry_type_hardlink_empty_target() {
        let entry = EntryType::Hardlink {
            target: PathBuf::from(""),
        };
        assert!(entry.is_hardlink(), "empty target should still be hardlink");
    }

    #[test]
    fn test_entry_type_symlink_with_special_chars() {
        let entry = EntryType::Symlink {
            target: PathBuf::from("../../../etc/passwd"),
        };
        assert!(
            entry.is_symlink(),
            "path traversal target should be recognized as symlink"
        );
    }

    #[test]
    fn test_entry_type_hardlink_absolute_target() {
        let entry = EntryType::Hardlink {
            target: PathBuf::from("/etc/passwd"),
        };
        assert!(
            entry.is_hardlink(),
            "absolute target should be recognized as hardlink"
        );
    }

    #[test]
    fn test_entry_type_inequality() {
        let file = EntryType::File;
        let dir = EntryType::Directory;
        assert_ne!(file, dir, "file should not equal directory");

        let symlink1 = EntryType::Symlink {
            target: PathBuf::from("a"),
        };
        let symlink2 = EntryType::Symlink {
            target: PathBuf::from("b"),
        };
        assert_ne!(symlink1, symlink2, "different targets should not be equal");
    }

    #[test]
    fn test_entry_type_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(EntryType::File);
        set.insert(EntryType::Directory);
        set.insert(EntryType::Symlink {
            target: PathBuf::from("target"),
        });
        set.insert(EntryType::Hardlink {
            target: PathBuf::from("original"),
        });

        assert_eq!(set.len(), 4, "all variants should hash uniquely");
    }
}
