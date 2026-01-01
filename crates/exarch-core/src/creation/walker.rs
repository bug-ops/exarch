//! Directory tree walking with filtering.
//!
//! This module provides efficient directory traversal with built-in filtering
//! based on configuration options like hidden files, exclude patterns, and size
//! limits.

use crate::ExtractionError;
use crate::Result;
use crate::creation::config::CreationConfig;
use crate::creation::filters;
use std::fs::Metadata;
use std::path::Path;
use std::path::PathBuf;
use walkdir::WalkDir;

/// Walks a directory tree with filtering based on `CreationConfig`.
///
/// This walker handles:
/// - Hidden file filtering
/// - Pattern-based exclusion
/// - Symlink handling (follow or store as-is)
/// - Size limit enforcement
/// - Archive path computation
///
/// # Examples
///
/// ```no_run
/// use exarch_core::creation::CreationConfig;
/// use exarch_core::creation::walker::FilteredWalker;
/// use std::path::Path;
///
/// let config = CreationConfig::default();
/// let root = Path::new("./project");
/// let walker = FilteredWalker::new(root, &config);
///
/// for entry in walker.walk() {
///     let entry = entry.unwrap();
///     println!("Would add: {}", entry.archive_path.display());
/// }
/// ```
pub struct FilteredWalker<'a> {
    root: &'a Path,
    config: &'a CreationConfig,
}

impl<'a> FilteredWalker<'a> {
    /// Creates a new filtered walker for the given root directory.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::CreationConfig;
    /// use exarch_core::creation::walker::FilteredWalker;
    /// use std::path::Path;
    ///
    /// let config = CreationConfig::default();
    /// let walker = FilteredWalker::new(Path::new("."), &config);
    /// ```
    #[must_use]
    pub fn new(root: &'a Path, config: &'a CreationConfig) -> Self {
        Self { root, config }
    }

    /// Returns an iterator over filtered directory entries.
    ///
    /// The iterator:
    /// - Skips entries based on configuration (hidden files, patterns, size)
    /// - Handles symlinks according to `follow_symlinks` setting
    /// - Computes archive paths using `strip_prefix` if configured
    /// - Returns errors for inaccessible files/directories
    ///
    /// # Errors
    ///
    /// Entries may error if:
    /// - File metadata cannot be read
    /// - Path is not valid UTF-8 (platform-specific)
    /// - Symlink target cannot be read
    pub fn walk(&self) -> impl Iterator<Item = Result<FilteredEntry>> + '_ {
        let walker = WalkDir::new(self.root)
            .follow_links(self.config.follow_symlinks)
            .into_iter();

        walker.filter_map(move |entry| {
            match entry {
                Ok(entry) => {
                    let path = entry.path();

                    // Skip if matches filter rules
                    if filters::should_skip(path, self.config) {
                        return None;
                    }

                    // Build FilteredEntry
                    match self.build_filtered_entry(&entry) {
                        Ok(Some(filtered)) => Some(Ok(filtered)),
                        Ok(None) => None, // Filtered out (e.g., size limit)
                        Err(e) => Some(Err(e)),
                    }
                }
                Err(e) => {
                    // Convert walkdir error to ExtractionError
                    Some(Err(ExtractionError::Io(std::io::Error::other(format!(
                        "walkdir error: {e}"
                    )))))
                }
            }
        })
    }

    /// Builds a `FilteredEntry` from a `walkdir::DirEntry`.
    ///
    /// Returns `Ok(None)` if the entry should be filtered out (e.g., exceeds
    /// size limit).
    fn build_filtered_entry(&self, entry: &walkdir::DirEntry) -> Result<Option<FilteredEntry>> {
        let path = entry.path().to_path_buf();
        let metadata = entry.metadata().map_err(|e| {
            ExtractionError::Io(std::io::Error::other(format!(
                "cannot read metadata for {}: {e}",
                path.display()
            )))
        })?;

        // Determine entry type
        let entry_type = if metadata.is_symlink() {
            let target = std::fs::read_link(&path).map_err(|e| {
                ExtractionError::Io(std::io::Error::other(format!(
                    "cannot read symlink target for {}: {e}",
                    path.display()
                )))
            })?;
            EntryType::Symlink { target }
        } else if metadata.is_dir() {
            EntryType::Directory
        } else {
            EntryType::File
        };

        // Check file size limit (only for regular files)
        let size = get_file_size(&metadata);
        if entry_type == EntryType::File
            && let Some(max_size) = self.config.max_file_size
            && size > max_size
        {
            return Ok(None); // Filter out
        }

        // Compute archive path
        let archive_path = filters::compute_archive_path(&path, self.root, self.config)?;

        Ok(Some(FilteredEntry {
            path,
            archive_path,
            entry_type,
            size,
        }))
    }
}

/// A filtered directory entry with computed archive path.
///
/// Represents a file, directory, or symlink that passed all filtering rules
/// and is ready to be added to an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilteredEntry {
    /// Full filesystem path to the entry.
    pub path: PathBuf,

    /// Path to use in the archive (relative, with `strip_prefix` applied).
    pub archive_path: PathBuf,

    /// Type of entry (file, directory, or symlink).
    pub entry_type: EntryType,

    /// Size in bytes (0 for directories).
    pub size: u64,
}

/// Type of directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryType {
    /// Regular file.
    File,

    /// Directory.
    Directory,

    /// Symbolic link with its target path.
    Symlink {
        /// Target of the symlink.
        target: PathBuf,
    },
}

/// Collects all entries from sources into a vector for single-pass processing.
///
/// This function performs a single directory traversal and collects all
/// filtered entries into memory, avoiding the need to traverse the directory
/// tree twice (once for counting, once for processing).
///
/// # Examples
///
/// ```no_run
/// use exarch_core::creation::CreationConfig;
/// use exarch_core::creation::walker::collect_entries;
/// use std::path::Path;
///
/// let config = CreationConfig::default();
/// let sources = [Path::new("./src")];
/// let entries = collect_entries(&sources, &config)?;
/// println!("Total entries: {}", entries.len());
/// # Ok::<(), exarch_core::ExtractionError>(())
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Source path does not exist
/// - Directory traversal fails
/// - File metadata cannot be read
pub fn collect_entries<P: AsRef<Path>>(
    sources: &[P],
    config: &CreationConfig,
) -> Result<Vec<FilteredEntry>> {
    let mut entries = Vec::new();

    for source in sources {
        let path = source.as_ref();

        if !path.exists() {
            return Err(ExtractionError::SourceNotFound {
                path: path.to_path_buf(),
            });
        }

        if path.is_dir() {
            let walker = FilteredWalker::new(path, config);
            for entry in walker.walk() {
                entries.push(entry?);
            }
        } else {
            // For single files, we need to create a FilteredEntry manually
            // This matches the behavior in tar.rs and zip.rs
            let metadata = std::fs::metadata(path)?;
            let size = if metadata.is_file() {
                metadata.len()
            } else {
                0
            };

            let entry_type = if metadata.is_symlink() {
                let target = std::fs::read_link(path)?;
                EntryType::Symlink { target }
            } else if metadata.is_dir() {
                EntryType::Directory
            } else {
                EntryType::File
            };

            // Compute archive path using the same logic as in the format modules
            let archive_path = if let Some(parent) = path.parent() {
                filters::compute_archive_path(path, parent, config)?
            } else {
                path.file_name()
                    .ok_or_else(|| {
                        ExtractionError::Io(std::io::Error::other(format!(
                            "cannot determine filename for {}",
                            path.display()
                        )))
                    })?
                    .into()
            };

            entries.push(FilteredEntry {
                path: path.to_path_buf(),
                archive_path,
                entry_type,
                size,
            });
        }
    }

    Ok(entries)
}

/// Gets the file size from metadata in a cross-platform way.
#[cfg(unix)]
fn get_file_size(metadata: &Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.size()
}

#[cfg(not(unix))]
fn get_file_size(metadata: &Metadata) -> u64 {
    metadata.len()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Allow unwrap in tests for brevity
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_walker_basic_directory() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Create test structure
        fs::write(root.join("file1.txt"), "content1").unwrap();
        fs::write(root.join("file2.rs"), "content2").unwrap();
        fs::create_dir(root.join("subdir")).unwrap();
        fs::write(root.join("subdir/file3.txt"), "content3").unwrap();

        let config = CreationConfig::default()
            .with_include_hidden(true)
            .with_exclude_patterns(vec![]);

        let walker = FilteredWalker::new(root, &config);
        let entries: Vec<_> = walker.walk().collect::<Result<Vec<_>>>().unwrap();

        // Should find exactly: root dir, file1, file2, subdir, file3 = 5 entries
        assert_eq!(entries.len(), 5, "expected exactly 5 entries");

        let paths: Vec<_> = entries
            .iter()
            .map(|e| e.archive_path.to_str().unwrap())
            .collect();

        assert!(paths.iter().any(|p| p.contains("file1.txt")));
        assert!(paths.iter().any(|p| p.contains("file2.rs")));
        assert!(paths.iter().any(|p| p.contains("subdir")));
        assert!(paths.iter().any(|p| p.contains("file3.txt")));
    }

    #[test]
    fn test_walker_skips_hidden_files() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("visible.txt"), "content").unwrap();
        fs::write(root.join(".hidden"), "secret").unwrap();

        let config = CreationConfig::default(); // include_hidden = false by default
        let walker = FilteredWalker::new(root, &config);
        let entries: Vec<_> = walker.walk().collect::<Result<Vec<_>>>().unwrap();

        let paths: Vec<_> = entries
            .iter()
            .map(|e| e.archive_path.to_str().unwrap())
            .collect();

        assert!(paths.iter().any(|p| p.contains("visible.txt")));
        assert!(!paths.iter().any(|p| p.contains(".hidden")));
    }

    #[test]
    fn test_walker_includes_hidden_when_configured() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("visible.txt"), "content").unwrap();
        fs::write(root.join(".hidden"), "secret").unwrap();

        let config = CreationConfig::default().with_include_hidden(true);
        let walker = FilteredWalker::new(root, &config);
        let entries: Vec<_> = walker.walk().collect::<Result<Vec<_>>>().unwrap();

        let paths: Vec<_> = entries
            .iter()
            .map(|e| e.archive_path.to_str().unwrap())
            .collect();

        assert!(paths.iter().any(|p| p.contains("visible.txt")));
        assert!(paths.iter().any(|p| p.contains(".hidden")));
    }

    #[test]
    fn test_walker_skips_excluded_patterns() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("keep.txt"), "keep").unwrap();
        fs::write(root.join("skip.tmp"), "skip").unwrap();
        fs::write(root.join("also.log"), "skip").unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec!["*.tmp".to_string(), "*.log".to_string()]);

        let walker = FilteredWalker::new(root, &config);
        let entries: Vec<_> = walker.walk().collect::<Result<Vec<_>>>().unwrap();

        let paths: Vec<_> = entries
            .iter()
            .map(|e| e.archive_path.to_str().unwrap())
            .collect();

        assert!(paths.iter().any(|p| p.contains("keep.txt")));
        assert!(!paths.iter().any(|p| p.contains("skip.tmp")));
        assert!(!paths.iter().any(|p| p.contains("also.log")));
    }

    #[cfg(unix)]
    #[test]
    fn test_walker_handles_symlinks() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("target.txt"), "content").unwrap();
        std::os::unix::fs::symlink(root.join("target.txt"), root.join("link.txt")).unwrap();

        // Don't follow symlinks (default)
        let config = CreationConfig::default();
        let walker = FilteredWalker::new(root, &config);
        let entries: Vec<_> = walker.walk().collect::<Result<Vec<_>>>().unwrap();

        let link_entry = entries
            .iter()
            .find(|e| e.archive_path.to_str().unwrap().contains("link.txt"));

        assert!(link_entry.is_some());
        if let Some(entry) = link_entry {
            assert!(matches!(entry.entry_type, EntryType::Symlink { .. }));
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_walker_detects_symlink_cycles() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::create_dir(root.join("dir1")).unwrap();
        fs::create_dir(root.join("dir1/dir2")).unwrap();

        // Create symlink cycle: dir1/dir2/link -> dir1
        std::os::unix::fs::symlink(root.join("dir1"), root.join("dir1/dir2/link")).unwrap();

        // Follow symlinks - walkdir handles cycle detection
        let config = CreationConfig::default().with_follow_symlinks(true);
        let walker = FilteredWalker::new(root, &config);

        // Collect all entries - should get an error for the cycle
        let results: Vec<_> = walker.walk().collect();

        // Should have some successful entries before hitting the cycle
        let successes = results.iter().filter(|r| r.is_ok()).count();
        assert!(successes > 0, "should have some entries before cycle");

        // Should detect the cycle and return an error
        let has_cycle_error = results.iter().any(|r| {
            if let Err(e) = r {
                e.to_string().contains("File system loop")
                    || e.to_string().contains("walkdir error")
            } else {
                false
            }
        });
        assert!(has_cycle_error, "should detect symlink cycle");
    }

    #[test]
    fn test_walker_respects_max_file_size() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("small.txt"), "tiny").unwrap(); // 4 bytes
        fs::write(root.join("large.txt"), "a".repeat(1000)).unwrap(); // 1000 bytes

        let config = CreationConfig::default().with_max_file_size(Some(100));

        let walker = FilteredWalker::new(root, &config);
        let entries: Vec<_> = walker.walk().collect::<Result<Vec<_>>>().unwrap();

        let paths: Vec<_> = entries
            .iter()
            .map(|e| e.archive_path.to_str().unwrap())
            .collect();

        assert!(paths.iter().any(|p| p.contains("small.txt")));
        assert!(!paths.iter().any(|p| p.contains("large.txt")));
    }

    #[test]
    fn test_walker_computes_archive_paths() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::create_dir(root.join("src")).unwrap();
        fs::write(root.join("src/main.rs"), "code").unwrap();

        let config = CreationConfig::default();
        let walker = FilteredWalker::new(root, &config);
        let entries: Vec<_> = walker.walk().collect::<Result<Vec<_>>>().unwrap();

        let main_entry = entries
            .iter()
            .find(|e| e.archive_path.to_str().unwrap().contains("main.rs"));

        assert!(main_entry.is_some());
        if let Some(entry) = main_entry {
            assert_eq!(entry.archive_path, Path::new("src/main.rs"));
        }
    }

    #[test]
    fn test_walker_strip_prefix() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::create_dir(root.join("project")).unwrap();
        fs::create_dir(root.join("project/src")).unwrap();
        fs::write(root.join("project/src/main.rs"), "code").unwrap();

        let config = CreationConfig::default().with_strip_prefix(Some(PathBuf::from("project")));

        let walker = FilteredWalker::new(root, &config);
        let entries: Vec<_> = walker.walk().collect::<Result<Vec<_>>>().unwrap();

        let main_entry = entries
            .iter()
            .find(|e| e.archive_path.to_str().unwrap().contains("main.rs"));

        assert!(main_entry.is_some());
        if let Some(entry) = main_entry {
            assert_eq!(entry.archive_path, Path::new("src/main.rs"));
        }
    }

    #[test]
    fn test_filtered_entry_file() {
        let entry = FilteredEntry {
            path: PathBuf::from("/tmp/file.txt"),
            archive_path: PathBuf::from("file.txt"),
            entry_type: EntryType::File,
            size: 1024,
        };

        assert_eq!(entry.path, Path::new("/tmp/file.txt"));
        assert_eq!(entry.archive_path, Path::new("file.txt"));
        assert!(matches!(entry.entry_type, EntryType::File));
        assert_eq!(entry.size, 1024);
    }

    #[test]
    fn test_filtered_entry_directory() {
        let entry = FilteredEntry {
            path: PathBuf::from("/tmp/dir"),
            archive_path: PathBuf::from("dir"),
            entry_type: EntryType::Directory,
            size: 0,
        };

        assert!(matches!(entry.entry_type, EntryType::Directory));
        assert_eq!(entry.size, 0);
    }

    #[test]
    fn test_filtered_entry_symlink() {
        let entry = FilteredEntry {
            path: PathBuf::from("/tmp/link"),
            archive_path: PathBuf::from("link"),
            entry_type: EntryType::Symlink {
                target: PathBuf::from("target.txt"),
            },
            size: 0,
        };

        match &entry.entry_type {
            EntryType::Symlink { target } => {
                assert_eq!(target, Path::new("target.txt"));
            }
            _ => panic!("expected symlink"),
        }
    }

    #[test]
    fn test_entry_type_equality() {
        assert_eq!(EntryType::File, EntryType::File);
        assert_eq!(EntryType::Directory, EntryType::Directory);
        assert_eq!(
            EntryType::Symlink {
                target: PathBuf::from("a")
            },
            EntryType::Symlink {
                target: PathBuf::from("a")
            }
        );
        assert_ne!(EntryType::File, EntryType::Directory);
        assert_ne!(
            EntryType::Symlink {
                target: PathBuf::from("a")
            },
            EntryType::Symlink {
                target: PathBuf::from("b")
            }
        );
    }

    #[test]
    fn test_collect_entries_empty_sources() {
        let config = CreationConfig::default();
        let sources: Vec<&Path> = vec![];

        let entries = collect_entries(&sources, &config).unwrap();

        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_collect_entries_nonexistent_source() {
        let config = CreationConfig::default();
        let sources = [Path::new("/nonexistent/path/that/does/not/exist")];

        let result = collect_entries(&sources, &config);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ExtractionError::SourceNotFound { .. }
        ));
    }

    #[test]
    fn test_collect_entries_mixed_files_and_directories() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Create mixed structure
        fs::write(root.join("single_file.txt"), "standalone").unwrap();
        fs::create_dir(root.join("dir1")).unwrap();
        fs::write(root.join("dir1/file1.txt"), "content1").unwrap();
        fs::write(root.join("dir1/file2.txt"), "content2").unwrap();
        fs::create_dir(root.join("dir2")).unwrap();
        fs::write(root.join("dir2/file3.txt"), "content3").unwrap();

        let config = CreationConfig::default().with_include_hidden(true);
        let sources = [
            root.join("single_file.txt"),
            root.join("dir1"),
            root.join("dir2"),
        ];

        let entries = collect_entries(&sources, &config).unwrap();

        // Should have: single_file.txt (1) + dir1 entries (2 files + 1 dir = 3) + dir2
        // entries (1 file + 1 dir = 2) = 6 total
        assert!(
            entries.len() >= 5,
            "Expected at least 5 entries (files and dirs), got {}",
            entries.len()
        );

        let paths: Vec<_> = entries
            .iter()
            .map(|e| e.archive_path.to_str().unwrap())
            .collect();

        assert!(paths.iter().any(|p| p.contains("single_file.txt")));
        assert!(paths.iter().any(|p| p.contains("file1.txt")));
        assert!(paths.iter().any(|p| p.contains("file2.txt")));
        assert!(paths.iter().any(|p| p.contains("file3.txt")));
    }

    #[test]
    fn test_collect_entries_large_directory_count() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Create a directory with known number of entries
        for i in 0..50 {
            fs::write(root.join(format!("file_{i}.txt")), format!("content {i}")).unwrap();
        }
        fs::create_dir(root.join("subdir")).unwrap();
        for i in 0..30 {
            fs::write(
                root.join(format!("subdir/file_{i}.txt")),
                format!("sub content {i}"),
            )
            .unwrap();
        }

        let config = CreationConfig::default().with_include_hidden(true);
        let sources = [root];

        let entries = collect_entries(&sources, &config).unwrap();

        // Should have: 50 files in root + 1 subdir + 1 root dir + 30 files in subdir =
        // 82
        assert!(
            entries.len() >= 80,
            "Expected at least 80 entries, got {}",
            entries.len()
        );
    }

    #[test]
    fn test_collect_entries_single_file() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("test.txt");
        fs::write(&file_path, "content").unwrap();

        let config = CreationConfig::default();
        let sources = [&file_path];

        let entries = collect_entries(&sources, &config).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_type, EntryType::File);
        assert!(
            entries[0]
                .archive_path
                .to_str()
                .unwrap()
                .contains("test.txt")
        );
    }

    #[test]
    fn test_collect_entries_respects_filters() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("keep.txt"), "keep").unwrap();
        fs::write(root.join("skip.tmp"), "skip").unwrap();
        fs::write(root.join(".hidden"), "hidden").unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec!["*.tmp".to_string()])
            .with_include_hidden(false);

        let sources = [root];
        let entries = collect_entries(&sources, &config).unwrap();

        let paths: Vec<_> = entries
            .iter()
            .map(|e| e.archive_path.to_str().unwrap())
            .collect();

        assert!(paths.iter().any(|p| p.contains("keep.txt")));
        assert!(!paths.iter().any(|p| p.contains("skip.tmp")));
        assert!(!paths.iter().any(|p| p.contains(".hidden")));
    }
}
