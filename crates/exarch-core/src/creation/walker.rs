//! Directory tree walking with filtering.
//!
//! This module provides efficient directory traversal with built-in filtering
//! based on configuration options like hidden files, exclude patterns, and size
//! limits.

use crate::ArchiveError;
use crate::IoContext;
use crate::Result;
use crate::Skip;
use crate::SkipKind;
use crate::Skips;
use crate::creation::config::CreationConfig;
use crate::creation::filters;
use crate::creation::source::source_error;
use crate::creation::source::walk_error;
use crate::creation::staged::ExcludedOutput;
use std::fs::Metadata;
use std::ops::Deref;
use std::path::Component;
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
/// ```ignore
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
    excluded: &'a ExcludedOutput,
}

static NOTHING_EXCLUDED: ExcludedOutput = ExcludedOutput::none();

impl<'a> FilteredWalker<'a> {
    /// Creates a new filtered walker for the given root directory.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use exarch_core::creation::CreationConfig;
    /// use exarch_core::creation::walker::FilteredWalker;
    /// use std::path::Path;
    ///
    /// let config = CreationConfig::default();
    /// let walker = FilteredWalker::new(Path::new("."), &config);
    /// ```
    #[must_use]
    pub fn new(root: &'a Path, config: &'a CreationConfig) -> Self {
        Self {
            root,
            config,
            excluded: &NOTHING_EXCLUDED,
        }
    }

    /// Leaves out the staged output file and its target before any filter
    /// rule sees them, so they are neither archived nor counted as skipped.
    #[must_use]
    pub const fn excluding(mut self, excluded: &'a ExcludedOutput) -> Self {
        self.excluded = excluded;
        self
    }

    /// Returns an iterator over filtered directory entries.
    ///
    /// The iterator:
    /// - Skips entries based on configuration (hidden files, patterns, size)
    /// - Never enters a hidden directory below the root unless hidden entries
    ///   are included: it is reported once as a skipped entry, so nothing
    ///   inside it (even a visible name) reaches the archive
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
    pub fn walk(&self) -> impl Iterator<Item = Result<WalkItem>> + '_ {
        let mut walker = WalkDir::new(self.root)
            .follow_links(self.config.follow_symlinks)
            .into_iter();

        std::iter::from_fn(move || {
            loop {
                let entry = match walker.next()? {
                    Ok(entry) => entry,
                    Err(e) => return Some(Err(walk_error(e, self.root))),
                };
                if self.is_hidden_directory(&entry) {
                    walker.skip_current_dir();
                    let shown = entry
                        .path()
                        .strip_prefix(self.root)
                        .unwrap_or_else(|_| entry.path());
                    return Some(Ok(WalkItem::Skipped(Skip::new(SkipKind::Hidden, shown))));
                }
                if let Some(item) = self.visit(&entry).transpose() {
                    return Some(item);
                }
            }
        })
    }

    /// Whether `entry` is a hidden directory below the walk root that is to be
    /// left out whole. The root itself is named by the caller, so it is walked.
    fn is_hidden_directory(&self, entry: &walkdir::DirEntry) -> bool {
        !self.config.include_hidden
            && entry.depth() > 0
            && entry.file_type().is_dir()
            && filters::is_hidden(entry.path())
    }

    /// Applies the filter rules to one walked entry.
    ///
    /// Returns `Ok(None)` for the walk root, which is no entry of the archive.
    fn visit(&self, entry: &walkdir::DirEntry) -> Result<Option<WalkItem>> {
        if self.excluded.excludes(entry.path()) {
            return Ok(None);
        }
        let relative = filters::compute_archive_path(entry.path(), self.root, self.config)?;
        match ArchiveEntryName::from_relative(&relative) {
            Some(name) => filters::skip_reason(&name, self.config).map_or_else(
                || self.build_filtered_entry(entry, relative),
                |kind| Ok(Some(WalkItem::Skipped(Skip::new(kind, name.to_path_buf())))),
            ),
            // No name left: the walk root, or an entry `strip_prefix` emptied.
            None if !self.config.include_hidden && filters::is_hidden(entry.path()) => Ok(None),
            None => self.build_filtered_entry(entry, relative),
        }
    }

    /// Builds a `WalkItem` from a `walkdir::DirEntry` that passed the filter
    /// rules.
    ///
    /// Returns `Ok(None)` for an entry with no name left, and a skip for a
    /// file over the size limit.
    fn build_filtered_entry(
        &self,
        entry: &walkdir::DirEntry,
        relative: PathBuf,
    ) -> Result<Option<WalkItem>> {
        let path = entry.path().to_path_buf();
        let metadata = entry.metadata().map_err(|e| walk_error(e, &path))?;

        // Determine entry type
        let entry_type = if metadata.is_symlink() {
            let target = std::fs::read_link(&path).map_err(|e| source_error(&path, e))?;
            EntryType::Symlink { target }
        } else if metadata.is_dir() {
            EntryType::Directory
        } else {
            EntryType::File
        };

        // Check file size limit (only for regular files)
        let size = get_file_size(&metadata);
        if entry_type == EntryType::File && !self.config.max_file_size.admits(size) {
            let shown = if relative.is_empty() { path } else { relative };
            return Ok(Some(WalkItem::Skipped(Skip::new(
                SkipKind::OverMaxFileSize,
                shown,
            ))));
        }

        let Some(archive_path) = entry_name(&path, &relative, entry_type == EntryType::Directory)?
        else {
            return Ok(None);
        };

        Ok(Some(WalkItem::Entry(FilteredEntry {
            path,
            archive_path,
            entry_type,
            size,
        })))
    }
}

/// What the walker decided about one walked entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkItem {
    /// The entry goes into the archive.
    Entry(FilteredEntry),

    /// The entry is left out, with the reason.
    Skipped(Skip),
}

/// The entries of a creation and what was left out on the way.
#[derive(Debug, Default)]
pub struct Collected {
    /// The entries to add, in walk order.
    pub entries: Vec<FilteredEntry>,

    /// The entries the filters left out.
    pub skipped: Skips,
}

/// Name of an entry inside a created archive: relative, normalized and
/// non-empty.
///
/// Built only by [`ArchiveEntryName::from_relative`], so a writer never has to
/// re-check for the empty name of the walk root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntryName(PathBuf);

impl ArchiveEntryName {
    /// Returns the name for `path`, or `None` if it is empty, absolute or
    /// holds anything other than plain components (`.`, `..`, a prefix).
    #[must_use]
    pub fn from_relative(path: &Path) -> Option<Self> {
        let mut components = path.components().peekable();
        components.peek()?;
        components
            .all(|component| matches!(component, Component::Normal(_)))
            .then(|| Self(path.to_path_buf()))
    }
}

impl Deref for ArchiveEntryName {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

/// Turns a computed relative path into an archive entry name.
///
/// A directory with no name left (the walk root, or one that `strip_prefix`
/// emptied) is dropped. A file or symlink with no name left is refused, since
/// it cannot be stored under any name.
fn entry_name(path: &Path, relative: &Path, is_dir: bool) -> Result<Option<ArchiveEntryName>> {
    match (ArchiveEntryName::from_relative(relative), is_dir) {
        (Some(name), _) => Ok(Some(name)),
        (None, true) => Ok(None),
        (None, false) => Err(ArchiveError::InvalidConfiguration {
            setting: crate::ConfigSetting::StripPrefix,
            problem: crate::ConfigProblem::RemovesWholeName {
                path: path.to_path_buf(),
            },
        }),
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
    pub archive_path: ArchiveEntryName,

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
/// ```ignore
/// use exarch_core::creation::CreationConfig;
/// use exarch_core::creation::walker::collect_entries;
/// use std::path::Path;
///
/// let config = CreationConfig::default();
/// let sources = [Path::new("./src")];
/// let entries = collect_entries(&sources, &config, &ExcludedOutput::none())?;
/// println!("Total entries: {}", entries.len());
/// # Ok::<(), exarch_core::ArchiveError>(())
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
    excluded: &ExcludedOutput,
) -> Result<Collected> {
    let mut collected = Collected::default();

    for source in sources {
        let path = source.as_ref();

        // `symlink_metadata` (lstat) is required here instead of
        // `exists`/`metadata` (stat) so that a dangling symlink (target
        // missing) is still treated as a present source; it is later
        // classified as EntryType::Symlink below. The result is reused
        // in the single-file branch to avoid a second lstat.
        let metadata = path.symlink_metadata().map_err(|e| source_error(path, e))?;

        // `metadata.is_dir()` (from the lstat above) is required here instead
        // of `path.is_dir()` (stat, follows symlinks), so that a
        // symlink pointing at a directory is not routed into
        // `FilteredWalker`/`WalkDir` by default — `WalkDir` always
        // dereferences its root regardless of `follow_links(false)` and
        // would produce an empty relative path for the root entry. Such a
        // symlink is instead classified as `EntryType::Symlink` in the
        // branch below, consistent with the symlink-to-file case. When
        // `follow_symlinks` is explicitly enabled, though, the symlink
        // must still be walked as a directory (via `path.is_dir()`,
        // stat) to preserve the pre-existing dereferencing behavior for
        // that config — otherwise the single-entry branch would try to
        // open the symlink as a regular file and fail with an I/O error.
        if metadata.is_dir() || (config.follow_symlinks && path.is_dir()) {
            let walker = FilteredWalker::new(path, config).excluding(excluded);
            for item in walker.walk() {
                match item? {
                    WalkItem::Entry(entry) => collected.entries.push(entry),
                    WalkItem::Skipped(skip) => collected.skipped.record(skip)?,
                }
            }
        } else {
            // For single files, we need to create a FilteredEntry manually.
            // `symlink_metadata` (lstat) is required here instead of `metadata`
            // (stat) so that a symlink passed directly as a
            // top-level source is classified as EntryType::Symlink
            // rather than silently dereferenced into its target.
            // `metadata.is_dir()` can no longer be true here (that case is
            // routed to the walk branch above), so only `File` and
            // `Symlink` remain.
            let size = if metadata.is_file() {
                metadata.len()
            } else {
                0
            };

            let entry_type = if metadata.is_symlink() {
                let target = std::fs::read_link(path).map_err(|e| source_error(path, e))?;
                EntryType::Symlink { target }
            } else {
                EntryType::File
            };

            let relative = if let Some(parent) = path.parent() {
                filters::compute_archive_path(path, parent, config)?
            } else {
                path.file_name()
                    .ok_or_else(|| {
                        ArchiveError::Io(std::io::Error::other(IoContext::new(
                            "cannot determine filename for source path",
                            path.display().to_string(),
                        )))
                    })?
                    .into()
            };

            if !excluded.excludes(path)
                && let Some(archive_path) = entry_name(path, &relative, false)?
            {
                collected.entries.push(FilteredEntry {
                    path: path.to_path_buf(),
                    archive_path,
                    entry_type,
                    size,
                });
            }
        }
    }

    Ok(collected)
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
    use crate::creation::ExcludePattern;
    use std::assert_matches;
    use std::fs;
    use tempfile::TempDir;

    fn walked_items(walker: &FilteredWalker<'_>) -> Vec<WalkItem> {
        walker.walk().collect::<Result<Vec<_>>>().unwrap()
    }

    fn walked_entries(walker: &FilteredWalker<'_>) -> Vec<FilteredEntry> {
        walked_items(walker)
            .into_iter()
            .filter_map(|item| match item {
                WalkItem::Entry(entry) => Some(entry),
                WalkItem::Skipped(_) => None,
            })
            .collect()
    }

    /// #916: the root's own ancestors used to match the exclude patterns, so
    /// the default `*.tmp` emptied an archive whose source sat under `job.tmp`.
    #[test]
    fn test_walker_ignores_patterns_matching_the_ancestors_of_the_root() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("job.tmp").join("src");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("a.txt"), "a").unwrap();
        fs::write(root.join("b.rs"), "b").unwrap();

        let config = CreationConfig::default();
        let collected =
            collect_entries(&[root.as_path()], &config, &ExcludedOutput::none()).unwrap();

        assert_eq!(collected.entries.len(), 2);
        assert!(collected.skipped.is_empty());
    }

    #[test]
    fn test_walker_counts_what_the_filters_leave_out() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        fs::write(root.join("keep.txt"), "keep").unwrap();
        fs::write(root.join("skip.tmp"), "x").unwrap();
        fs::write(root.join(".secret"), "x").unwrap();
        fs::write(root.join("big.bin"), "a".repeat(1000)).unwrap();

        let config = CreationConfig::default().with_max_file_size(crate::non_zero!(100));
        let collected = collect_entries(&[root], &config, &ExcludedOutput::none()).unwrap();

        assert_eq!(collected.entries.len(), 1);
        assert_eq!(collected.skipped.count(SkipKind::Excluded), 1);
        assert_eq!(collected.skipped.count(SkipKind::Hidden), 1);
        assert_eq!(collected.skipped.count(SkipKind::OverMaxFileSize), 1);
        let mut sample: Vec<_> = collected
            .skipped
            .sample()
            .iter()
            .map(|skip| skip.path.clone())
            .collect();
        sample.sort();
        assert_eq!(
            sample,
            [".secret", "big.bin", "skip.tmp"].map(PathBuf::from)
        );
    }

    #[test]
    fn test_walker_path_pattern_excludes_the_subtree_by_archive_path() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("build/out")).unwrap();
        fs::write(root.join("build/out/app"), "bin").unwrap();
        fs::write(root.join("build/keep.txt"), "k").unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![ExcludePattern::try_from("build/out").unwrap()]);
        let collected = collect_entries(&[root], &config, &ExcludedOutput::none()).unwrap();

        let paths: Vec<_> = collected
            .entries
            .iter()
            .map(|e| e.archive_path.to_path_buf())
            .collect();
        // Path comparison is by component, so the host separator does not
        // matter.
        assert!(paths.contains(&PathBuf::from("build/keep.txt")));
        assert!(!paths.iter().any(|p| p.starts_with("build/out")));
        assert_eq!(collected.skipped.count(SkipKind::Excluded), 2);
    }

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
        let entries = walked_entries(&walker);

        // Should find exactly: file1, file2, subdir, file3; the root is not
        // an entry.
        assert_eq!(entries.len(), 4, "expected exactly 4 entries");

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
        let entries = walked_entries(&walker);

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
        let entries = walked_entries(&walker);

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

        let config = CreationConfig::default().with_exclude_patterns(vec![
            ExcludePattern::try_from("*.tmp").unwrap(),
            ExcludePattern::try_from("*.log").unwrap(),
        ]);

        let walker = FilteredWalker::new(root, &config);
        let entries = walked_entries(&walker);

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
        let entries = walked_entries(&walker);

        let link_entry = entries
            .iter()
            .find(|e| e.archive_path.to_str().unwrap().contains("link.txt"));

        assert!(link_entry.is_some());
        if let Some(entry) = link_entry {
            assert_matches!(entry.entry_type, EntryType::Symlink { .. });
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

        let config = CreationConfig::default().with_max_file_size(crate::non_zero!(100));

        let walker = FilteredWalker::new(root, &config);
        let entries = walked_entries(&walker);

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
        let entries = walked_entries(&walker);

        let main_entry = entries
            .iter()
            .find(|e| e.archive_path.to_str().unwrap().contains("main.rs"));

        assert!(main_entry.is_some());
        if let Some(entry) = main_entry {
            assert_eq!(&*entry.archive_path, Path::new("src/main.rs"));
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
        let entries = walked_entries(&walker);

        let main_entry = entries
            .iter()
            .find(|e| e.archive_path.to_str().unwrap().contains("main.rs"));

        assert!(main_entry.is_some());
        if let Some(entry) = main_entry {
            assert_eq!(&*entry.archive_path, Path::new("src/main.rs"));
        }
    }

    #[test]
    fn test_filtered_entry_file() {
        let entry = FilteredEntry {
            path: PathBuf::from("/tmp/file.txt"),
            archive_path: ArchiveEntryName::from_relative(Path::new("file.txt")).unwrap(),
            entry_type: EntryType::File,
            size: 1024,
        };

        assert_eq!(entry.path, Path::new("/tmp/file.txt"));
        assert_eq!(&*entry.archive_path, Path::new("file.txt"));
        assert_matches!(entry.entry_type, EntryType::File);
        assert_eq!(entry.size, 1024);
    }

    #[test]
    fn test_filtered_entry_directory() {
        let entry = FilteredEntry {
            path: PathBuf::from("/tmp/dir"),
            archive_path: ArchiveEntryName::from_relative(Path::new("dir")).unwrap(),
            entry_type: EntryType::Directory,
            size: 0,
        };

        assert_matches!(entry.entry_type, EntryType::Directory);
        assert_eq!(entry.size, 0);
    }

    #[test]
    fn test_filtered_entry_symlink() {
        let entry = FilteredEntry {
            path: PathBuf::from("/tmp/link"),
            archive_path: ArchiveEntryName::from_relative(Path::new("link")).unwrap(),
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

        let entries = collect_entries(&sources, &config, &ExcludedOutput::none())
            .unwrap()
            .entries;

        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_collect_entries_nonexistent_source() {
        let config = CreationConfig::default();
        let sources = [Path::new("/nonexistent/path/that/does/not/exist")];

        let result = collect_entries(&sources, &config, &ExcludedOutput::none());

        assert!(result.is_err());
        assert_matches!(result.unwrap_err(), ArchiveError::SourceNotFound { .. });
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

        let entries = collect_entries(&sources, &config, &ExcludedOutput::none())
            .unwrap()
            .entries;

        // single_file.txt + 2 files of dir1 + 1 file of dir2; the source
        // directories themselves are walk roots and are not entries.
        assert_eq!(entries.len(), 4);

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

        let entries = collect_entries(&sources, &config, &ExcludedOutput::none())
            .unwrap()
            .entries;

        // Should have: 50 files in root + 1 subdir + 1 root dir + 30 files in
        // subdir = 82
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

        let entries = collect_entries(&sources, &config, &ExcludedOutput::none())
            .unwrap()
            .entries;

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

    #[cfg(unix)]
    #[test]
    fn test_collect_entries_single_file_symlink_not_dereferenced() {
        let temp = TempDir::new().unwrap();
        let target_path = temp.path().join("target.txt");
        let link_path = temp.path().join("evil_link");
        fs::write(&target_path, "content").unwrap();
        std::os::unix::fs::symlink(&target_path, &link_path).unwrap();

        let config = CreationConfig::default();
        let sources = [&link_path];

        let entries = collect_entries(&sources, &config, &ExcludedOutput::none())
            .unwrap()
            .entries;

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].entry_type,
            EntryType::Symlink {
                target: target_path,
            }
        );
        assert!(
            entries[0]
                .archive_path
                .to_str()
                .unwrap()
                .contains("evil_link")
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_collect_entries_dangling_symlink_source_not_rejected() {
        let temp = TempDir::new().unwrap();
        let missing_target = temp.path().join("nowhere.txt");
        let link_path = temp.path().join("dangling_link");
        std::os::unix::fs::symlink(&missing_target, &link_path).unwrap();

        let config = CreationConfig::default();
        let sources = [&link_path];

        let entries = collect_entries(&sources, &config, &ExcludedOutput::none())
            .unwrap()
            .entries;

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].entry_type,
            EntryType::Symlink {
                target: missing_target,
            }
        );
        assert!(
            entries[0]
                .archive_path
                .to_str()
                .unwrap()
                .contains("dangling_link")
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_collect_entries_dir_symlink_source_classified_as_symlink() {
        let temp = TempDir::new().unwrap();
        let target_dir = temp.path().join("target_dir");
        let link_path = temp.path().join("dirlink");
        fs::create_dir(&target_dir).unwrap();
        fs::write(target_dir.join("inner.txt"), "content").unwrap();
        std::os::unix::fs::symlink(&target_dir, &link_path).unwrap();

        let config = CreationConfig::default();
        let sources = [&link_path];

        let entries = collect_entries(&sources, &config, &ExcludedOutput::none())
            .unwrap()
            .entries;

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].entry_type,
            EntryType::Symlink { target: target_dir }
        );
        assert!(
            entries[0]
                .archive_path
                .to_str()
                .unwrap()
                .contains("dirlink")
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
            .with_exclude_patterns(vec![ExcludePattern::try_from("*.tmp").unwrap()])
            .with_include_hidden(false);

        let sources = [root];
        let entries = collect_entries(&sources, &config, &ExcludedOutput::none())
            .unwrap()
            .entries;

        let paths: Vec<_> = entries
            .iter()
            .map(|e| e.archive_path.to_str().unwrap())
            .collect();

        assert!(paths.iter().any(|p| p.contains("keep.txt")));
        assert!(!paths.iter().any(|p| p.contains("skip.tmp")));
        assert!(!paths.iter().any(|p| p.contains(".hidden")));
    }
}
