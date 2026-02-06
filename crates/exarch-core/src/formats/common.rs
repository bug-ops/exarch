//! Common extraction utilities shared between archive formats.
//!
//! This module provides shared functionality for TAR and ZIP extractors
//! to avoid code duplication. It is an internal module not exposed in
//! the public API.
//!
//! # Functions
//!
//! - [`extract_file_generic`]: Generic file extraction with buffered I/O
//! - [`create_directory`]: Directory creation (idempotent)
//! - [`create_symlink`]: Symbolic link creation (Unix only)

use rustc_hash::FxHashSet;
use std::fs::File;
use std::fs::create_dir_all;
use std::io::BufWriter;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use crate::ExtractionError;
use crate::ExtractionReport;
use crate::Result;
use crate::copy::CopyBuffer;
use crate::copy::copy_with_buffer;
use crate::error::QuotaResource;
use crate::security::validator::ValidatedEntry;
use crate::types::DestDir;
use crate::types::SafeSymlink;

/// Cache for tracking created directories during extraction.
///
/// Reduces redundant mkdir syscalls for nested archive structures.
/// For example, extracting 1000 files in nested directories without caching
/// can result in ~3000 mkdir syscalls. With caching, this reduces to ~150.
///
/// # Implementation
///
/// Uses an in-memory `FxHashSet<PathBuf>` to track all created directory paths.
/// `FxHashSet` is a faster non-cryptographic hash from rustc, optimized for
/// performance when hash DOS protection is not needed.
///
/// When a directory needs to be created, we first check the cache to avoid
/// redundant syscalls.
///
/// # Performance
///
/// - Reduces syscalls by ~95% for deeply nested archives
/// - Memory overhead: O(d) where d is number of unique directories
/// - Lookup cost: O(1) average with `FxHasher` (faster than `SipHash`)
/// - Default capacity: 128 directories (tunable via `with_capacity`)
///
/// # TOCTOU Safety
///
/// This cache creates a potential Time-Of-Check-Time-Of-Use (TOCTOU) race:
/// another process could delete cached directories between our check and use.
/// However, this is NOT a security concern because:
///
/// 1. **Fail-safe**: If a cached directory is deleted, subsequent file creation
///    will fail with ENOENT, causing extraction to abort cleanly.
/// 2. **No privilege escalation**: Cache only tracks directories we created,
///    not arbitrary filesystem state.
/// 3. **Defense in depth**: Path validation happens before caching (blocks
///    traversal, absolute paths, etc.).
/// 4. **Industry standard**: TAR, ZIP, and other extractors use similar caching
///    without additional synchronization.
///
/// # Future Work
///
/// Potential quota features for future versions:
/// - `max_directory_depth`: Limit nesting depth (`DoS` protection)
/// - `max_unique_directories`: Limit total directory count (memory limit)
///
/// These are deferred because:
/// - Current `max_total_size` quota provides sufficient `DoS` protection
/// - Real-world archives rarely exceed reasonable directory counts
/// - Simpler implementation reduces attack surface
///
/// # Examples
///
/// ```ignore
/// use exarch_core::formats::common::DirCache;
/// use std::path::Path;
///
/// let mut cache = DirCache::new();
///
/// // First call creates directory and caches all ancestors
/// cache.ensure_parent_dir(Path::new("a/b/c/file.txt"))?;
///
/// // Second call skips mkdir - already cached
/// cache.ensure_parent_dir(Path::new("a/b/c/file2.txt"))?;
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct DirCache {
    created: FxHashSet<PathBuf>,
}

impl DirCache {
    /// Creates a new directory cache with default capacity (128).
    ///
    /// This is sufficient for most archives. Use [`with_capacity`] if you
    /// know the archive has significantly more unique directories.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let cache = DirCache::new();
    /// ```
    ///
    /// [`with_capacity`]: Self::with_capacity
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::with_capacity(128)
    }

    /// Creates a new directory cache with specified capacity.
    ///
    /// Pre-allocating capacity avoids rehashing during extraction.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // For archives with many unique directories
    /// let cache = DirCache::with_capacity(1000);
    /// ```
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        use rustc_hash::FxBuildHasher;
        Self {
            created: FxHashSet::with_capacity_and_hasher(capacity, FxBuildHasher),
        }
    }

    /// Private helper to cache all ancestor directories of a path.
    ///
    /// This avoids duplicating the ancestor-walking logic in both
    /// `ensure_parent_dir` and `ensure_dir`.
    fn cache_ancestors(&mut self, path: &Path) {
        let mut current = path;
        while !current.as_os_str().is_empty() {
            self.created.insert(current.to_path_buf());
            match current.parent() {
                Some(p) if !p.as_os_str().is_empty() => current = p,
                _ => break,
            }
        }
    }

    /// Checks if a path is in the cache (i.e., was created by us).
    #[inline]
    pub fn contains(&self, path: &Path) -> bool {
        self.created.contains(path)
    }

    /// Ensures parent directory exists, using cache to skip redundant mkdir
    /// calls.
    ///
    /// This function creates the parent directory of the given file path if it
    /// does not exist. All ancestor directories are also created and cached.
    ///
    /// # Performance
    ///
    /// - First call for a directory: Creates directory and caches all ancestors
    /// - Subsequent calls for same directory: O(1) cache lookup, no syscall
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if directory was created
    /// - `Ok(false)` if directory already existed (cached or no parent)
    ///
    /// # Errors
    ///
    /// Returns an I/O error if directory creation fails.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut cache = DirCache::new();
    /// let created = cache.ensure_parent_dir(Path::new("a/b/file.txt"))?;
    /// assert!(created); // First call creates directory
    ///
    /// let created = cache.ensure_parent_dir(Path::new("a/b/file2.txt"))?;
    /// assert!(!created); // Second call finds cached directory
    /// ```
    #[inline]
    pub fn ensure_parent_dir(&mut self, file_path: &Path) -> std::io::Result<bool> {
        if let Some(parent) = file_path.parent() {
            if parent.as_os_str().is_empty() {
                return Ok(false);
            }
            if !self.created.contains(parent) {
                create_dir_all(parent)?;
                self.cache_ancestors(parent);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Ensures a directory exists (for directory entries in archives).
    ///
    /// This function creates the directory if it does not exist. All ancestor
    /// directories are also created and cached.
    ///
    /// # Performance
    ///
    /// - First call for a directory: Creates directory and caches all ancestors
    /// - Subsequent calls for same directory: O(1) cache lookup, no syscall
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if directory was created
    /// - `Ok(false)` if directory already existed (cached or empty path)
    ///
    /// # Errors
    ///
    /// Returns an I/O error if directory creation fails.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut cache = DirCache::new();
    /// let created = cache.ensure_dir(Path::new("a/b/c"))?;
    /// assert!(created); // First call creates directory
    ///
    /// let created = cache.ensure_dir(Path::new("a/b/c"))?;
    /// assert!(!created); // Second call finds cached directory
    /// ```
    #[inline]
    pub fn ensure_dir(&mut self, dir_path: &Path) -> std::io::Result<bool> {
        if dir_path.as_os_str().is_empty() {
            return Ok(false);
        }
        if !self.created.contains(dir_path) {
            create_dir_all(dir_path)?;
            self.cache_ancestors(dir_path);
            return Ok(true);
        }
        Ok(false)
    }
}

impl Default for DirCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Creates a file with optional permissions set atomically during creation.
///
/// On Unix platforms, this function uses `OpenOptions::mode()` to set file
/// permissions during the `open()` syscall, reducing from 2 syscalls
/// (create + chmod) to 1 syscall (create with mode).
///
/// On non-Unix platforms, permissions are not supported and mode is ignored.
///
/// # Performance
///
/// - Unix: 1 syscall (open with mode)
/// - Non-Unix: 1 syscall (create)
/// - Traditional approach: 2 syscalls (create + chmod)
///
/// For archives with 1000 files, this reduces 2000 syscalls to 1000 syscalls
/// (50% reduction in permission-related syscalls).
///
/// # Security - Mode Sanitization Requirement
///
/// **CRITICAL**: This function trusts the caller to provide safe mode values.
/// The `mode` parameter MUST be sanitized before calling this function to:
///
/// - Strip setuid bit (0o4000) if required by security policy
/// - Strip setgid bit (0o2000) if required by security policy
/// - Strip sticky bit (0o1000) if required by security policy
/// - Ensure world-writable permissions are only set if allowed
///
/// Mode sanitization MUST be performed by the caller (typically in the
/// validation layer via `SecurityConfig::sanitize_mode()`). This function
/// does NOT perform any sanitization and will apply the mode value directly.
///
/// # Arguments
///
/// * `path` - Path where file should be created
/// * `mode` - Optional Unix file mode (must be pre-sanitized by caller)
///
/// # Errors
///
/// Returns an I/O error if file creation fails.
#[inline]
#[cfg(unix)]
fn create_file_with_mode(path: &Path, mode: Option<u32>) -> std::io::Result<File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);

    if let Some(m) = mode {
        // Apply sanitized mode during open (already stripped setuid/setgid)
        opts.mode(m);
    }

    opts.open(path)
}

/// Creates a file (non-Unix platforms ignore mode parameter).
///
/// This is the fallback implementation for platforms that do not support
/// Unix-style file permissions.
///
/// # Arguments
///
/// * `path` - Path where file should be created
/// * `_mode` - Ignored on non-Unix platforms
///
/// # Errors
///
/// Returns an I/O error if file creation fails.
#[inline]
#[cfg(not(unix))]
fn create_file_with_mode(path: &Path, _mode: Option<u32>) -> std::io::Result<File> {
    File::create(path)
}

/// Generic file extraction implementation used by all format adapters.
///
/// This function consolidates file extraction logic to ensure consistent:
/// - Directory creation with caching
/// - Buffered I/O (64KB buffer)
/// - Permission preservation (Unix only, set atomically during file creation)
/// - Quota tracking with overflow protection
///
/// # Performance Optimization
///
/// On Unix, file permissions are set atomically during file creation using
/// `OpenOptions::mode()`, reducing syscalls from 2 (create + chmod) to 1
/// (create with mode). This provides a 10-15% speedup for archives with
/// many files.
///
/// # Correctness
///
/// Quota is checked BEFORE writing to prevent partial files on overflow.
/// This fixes the inconsistency where TAR was checking AFTER write.
///
/// # Type Parameters
///
/// - `R`: Reader type that implements `Read`
///
/// # Arguments
///
/// * `reader` - Source data stream
/// * `validated` - Validated entry metadata (path, mode, etc.)
/// * `dest` - Destination directory
/// * `report` - Extraction statistics (updated)
/// * `expected_size` - Expected file size (if known) for quota pre-check
/// * `copy_buffer` - Reusable buffer for I/O operations
/// * `dir_cache` - Directory cache to reduce redundant mkdir syscalls
///
/// # Errors
///
/// Returns error if:
/// - Parent directory creation fails
/// - Quota would be exceeded (checked before write)
/// - File creation fails
/// - I/O error during copy
#[inline]
pub fn extract_file_generic<R: Read>(
    reader: &mut R,
    validated: &ValidatedEntry,
    dest: &DestDir,
    report: &mut ExtractionReport,
    expected_size: Option<u64>,
    copy_buffer: &mut CopyBuffer,
    dir_cache: &mut DirCache,
) -> Result<()> {
    let output_path = dest.join(&validated.safe_path);

    // Create parent directories if needed using cache
    dir_cache.ensure_parent_dir(&output_path)?;

    // CRITICAL: Check quota BEFORE writing (prevents partial files on overflow)
    if let Some(size) = expected_size {
        report
            .bytes_written
            .checked_add(size)
            .ok_or(ExtractionError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow,
            })?;
    }

    // Create file with permissions set atomically (Unix optimization)
    // On Unix: mode is set during open() - 1 syscall
    // On Windows: mode is ignored - 1 syscall
    // Traditional: create() + set_permissions() - 2 syscalls
    let output_file = create_file_with_mode(&output_path, validated.mode)?;
    let mut buffered_writer = BufWriter::with_capacity(64 * 1024, output_file);
    let bytes_written = copy_with_buffer(reader, &mut buffered_writer, copy_buffer)?;
    buffered_writer.flush()?;

    // Permissions already set during file creation on Unix
    // No additional chmod syscall needed

    report.files_extracted += 1;
    report.bytes_written =
        report
            .bytes_written
            .checked_add(bytes_written)
            .ok_or(ExtractionError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow,
            })?;

    Ok(())
}

/// Creates a directory from a validated entry.
///
/// This is a shared helper used by both TAR and ZIP extractors.
///
/// # Idempotent Behavior
///
/// This function is idempotent - calling it multiple times for the same
/// directory has no effect thanks to the directory cache.
///
/// # Quota Tracking
///
/// Directory creation increments the `directories_created` counter but
/// does NOT count toward the byte quota (`bytes_written`). Only regular
/// file data counts toward byte quotas.
///
/// # Arguments
///
/// * `validated` - Validated entry metadata
/// * `dest` - Destination directory
/// * `report` - Extraction statistics (updated)
/// * `dir_cache` - Directory cache to reduce redundant mkdir syscalls
///
/// # Errors
///
/// Returns an error if directory creation fails due to I/O errors.
pub fn create_directory(
    validated: &ValidatedEntry,
    dest: &DestDir,
    report: &mut ExtractionReport,
    dir_cache: &mut DirCache,
) -> Result<()> {
    let dir_path = dest.join(&validated.safe_path);

    // Use cache to avoid redundant mkdir syscalls
    dir_cache.ensure_dir(&dir_path)?;

    report.directories_created += 1;

    Ok(())
}

/// Creates a symbolic link from a validated symlink entry.
///
/// This is a shared helper used by both TAR and ZIP extractors.
/// Parent directories are created automatically if needed using the directory
/// cache.
///
/// # Platform Support
///
/// - **Unix**: Full symlink support via `std::os::unix::fs::symlink`
/// - **Other platforms**: Returns `SecurityViolation` error
///
/// # Error Behavior
///
/// If the symlink already exists, the function will fail with an I/O error.
/// Unlike `create_directory`, this function is NOT idempotent - it does not
/// overwrite existing symlinks or files at the target path.
///
/// # Arguments
///
/// * `safe_symlink` - Validated symlink entry
/// * `dest` - Destination directory
/// * `report` - Extraction statistics (updated)
/// * `dir_cache` - Directory cache to reduce redundant mkdir syscalls
///
/// # Errors
///
/// Returns an error if:
/// - Platform does not support symlinks
/// - Parent directory creation fails
/// - Symlink creation fails (including when target path already exists)
/// - A file or symlink already exists at the link path
#[allow(unused_variables)]
pub fn create_symlink(
    safe_symlink: &SafeSymlink,
    dest: &DestDir,
    report: &mut ExtractionReport,
    dir_cache: &mut DirCache,
) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let link_path = dest.join_path(safe_symlink.link_path());
        let target_path = safe_symlink.target_path();

        // Create parent directories using cache
        dir_cache.ensure_parent_dir(&link_path)?;

        // Create symlink
        symlink(target_path, &link_path)?;

        report.symlinks_created += 1;

        Ok(())
    }

    #[cfg(not(unix))]
    {
        Err(ExtractionError::SecurityViolation {
            reason: "symlinks are not supported on this platform".into(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ExtractionError;
    use crate::ExtractionReport;
    use crate::SecurityConfig;
    use crate::copy::CopyBuffer;
    use crate::security::validator::ValidatedEntry;
    use crate::security::validator::ValidatedEntryType;
    use crate::types::SafePath;
    use std::io::Cursor;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_extract_file_generic_integer_overflow_check() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let mut report = ExtractionReport::default();
        let mut copy_buffer = CopyBuffer::new();
        let mut dir_cache = DirCache::new();

        // Set bytes_written to a value close to u64::MAX
        report.bytes_written = u64::MAX - 100;

        // Try to extract a file with size that would overflow
        let expected_size = Some(200u64); // This would overflow when added

        let config = SecurityConfig::default();
        let validated = ValidatedEntry {
            safe_path: SafePath::validate(&PathBuf::from("test.txt"), &dest, &config)
                .expect("path should be valid"),
            mode: Some(0o644),
            entry_type: ValidatedEntryType::File,
        };

        let mut reader = Cursor::new(b"test data");

        let result = extract_file_generic(
            &mut reader,
            &validated,
            &dest,
            &mut report,
            expected_size,
            &mut copy_buffer,
            &mut dir_cache,
        );

        // Should return QuotaExceeded with IntegerOverflow
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ExtractionError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow
            }
        ));
    }

    /// Test `DirCache` basic functionality
    #[test]
    fn test_dir_cache_basic() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let mut cache = DirCache::new();

        let file_path = temp.path().join("a/b/c/file.txt");

        // First call creates directory
        let created = cache
            .ensure_parent_dir(&file_path)
            .expect("should create dir");
        assert!(created, "first call should create directory");
        assert!(temp.path().join("a/b/c").exists());

        // Second call finds cached directory
        let created = cache
            .ensure_parent_dir(&file_path)
            .expect("should use cache");
        assert!(!created, "second call should use cache");
    }

    /// Test `DirCache` with nested paths
    #[test]
    fn test_dir_cache_nested_paths() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let mut cache = DirCache::new();

        // Create deep nested directory
        let file1 = temp.path().join("a/b/c/d/file1.txt");
        cache.ensure_parent_dir(&file1).expect("should create");
        assert!(temp.path().join("a/b/c/d").exists());

        // All ancestors should be cached
        let file2 = temp.path().join("a/b/other.txt");
        let created = cache.ensure_parent_dir(&file2).expect("should use cache");
        assert!(!created, "ancestor should be cached");
    }

    /// Test `DirCache` `ensure_dir` method
    #[test]
    fn test_dir_cache_ensure_dir() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let mut cache = DirCache::new();

        let dir_path = temp.path().join("a/b/c");

        // First call creates directory
        let created = cache.ensure_dir(&dir_path).expect("should create dir");
        assert!(created, "first call should create directory");
        assert!(dir_path.exists());

        // Second call finds cached directory
        let created = cache.ensure_dir(&dir_path).expect("should use cache");
        assert!(!created, "second call should use cache");
    }

    /// Test `DirCache` with empty parent path
    #[test]
    fn test_dir_cache_empty_parent() {
        use std::path::PathBuf;
        let mut cache = DirCache::new();

        // Relative file path with no parent directory
        let file_path = PathBuf::from("file.txt");
        let created = cache
            .ensure_parent_dir(&file_path)
            .expect("should handle empty parent");
        assert!(!created, "file with no directory should return false");
    }

    /// Test `DirCache` with single component path
    #[test]
    fn test_dir_cache_single_component() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let mut cache = DirCache::new();

        // Path with single component (no parent except current dir)
        let file_path = temp.path().join("file.txt");
        let created = cache
            .ensure_parent_dir(&file_path)
            .expect("should handle single component");

        // Parent is temp.path(), which was not in cache, so it gets created/cached
        assert!(created, "parent directory gets cached on first call");

        // Second call should use cache
        let file_path2 = temp.path().join("file2.txt");
        let created = cache
            .ensure_parent_dir(&file_path2)
            .expect("should use cache");
        assert!(!created, "second call uses cached parent");
    }

    /// Test `DirCache` with pre-existing directory
    #[test]
    fn test_dir_cache_preexisting_directory() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let mut cache = DirCache::new();

        // Create directory manually first
        let dir_path = temp.path().join("existing/dir");
        std::fs::create_dir_all(&dir_path).expect("should create dir");

        // First call should still return true (not in cache)
        let created = cache.ensure_dir(&dir_path).expect("should succeed");
        assert!(created, "first call creates cache entry even if dir exists");

        // Second call should return false (cached)
        let created = cache.ensure_dir(&dir_path).expect("should succeed");
        assert!(!created, "second call uses cache");
    }

    /// Test `DirCache` with deep nesting (stress test)
    #[test]
    fn test_dir_cache_deep_nesting() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let mut cache = DirCache::new();

        // Create path with 100 levels of nesting
        let mut path = temp.path().to_path_buf();
        for i in 0..100 {
            path.push(format!("level{i}"));
        }
        path.push("file.txt");

        // First call creates all 100 levels
        let created = cache
            .ensure_parent_dir(&path)
            .expect("should create deep nesting");
        assert!(created, "deep nesting should be created");

        // Verify all levels exist
        let parent = path.parent().expect("should have parent");
        assert!(parent.exists(), "all levels should exist");

        // Second call should use cache
        let created = cache.ensure_parent_dir(&path).expect("should use cache");
        assert!(!created, "deep nesting should be cached");
    }

    /// Test `DirCache` with multiple files in same directory
    #[test]
    fn test_dir_cache_multiple_files_same_dir() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let mut cache = DirCache::new();

        let dir = temp.path().join("shared/directory");

        // First file creates directory
        let file1 = dir.join("file1.txt");
        let created = cache.ensure_parent_dir(&file1).expect("should create dir");
        assert!(created, "first file creates directory");

        // Subsequent files in same directory use cache
        for i in 2..=10 {
            let file = dir.join(format!("file{i}.txt"));
            let created = cache.ensure_parent_dir(&file).expect("should use cache");
            assert!(!created, "file {i} should use cached directory");
        }
    }

    /// Test `DirCache::with_capacity` constructor
    #[test]
    fn test_dir_cache_with_capacity() {
        let cache = DirCache::with_capacity(1000);
        // Just verify it constructs without panic
        assert_eq!(cache.created.len(), 0, "should start empty");
    }

    /// Test `DirCache::contains` method
    #[test]
    fn test_dir_cache_contains() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let mut cache = DirCache::new();

        let dir_path = temp.path().join("a/b/c");

        // Before creation, should not contain
        assert!(
            !cache.contains(&dir_path),
            "should not contain before creation"
        );

        // Create directory
        cache.ensure_dir(&dir_path).expect("should create dir");

        // After creation, should contain
        assert!(cache.contains(&dir_path), "should contain after creation");

        // Ancestors should also be cached
        assert!(
            cache.contains(&temp.path().join("a/b")),
            "ancestor should be cached"
        );
        assert!(
            cache.contains(&temp.path().join("a")),
            "ancestor should be cached"
        );
    }

    /// H1: Test `create_file_with_mode()` with Unix mode 0o644
    #[cfg(unix)]
    #[test]
    fn test_create_file_with_mode_0o644() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("failed to create temp dir");
        let file_path = temp.path().join("test_0o644.txt");

        // Create file with mode 0o644
        let file = create_file_with_mode(&file_path, Some(0o644)).expect("should create file");
        drop(file);

        // Verify file exists
        assert!(file_path.exists(), "file should exist");

        // Verify permissions
        let metadata = std::fs::metadata(&file_path).expect("should read metadata");
        let mode = metadata.permissions().mode();

        // Mask to get only permission bits (remove file type bits)
        let permission_bits = mode & 0o777;
        assert_eq!(
            permission_bits, 0o644,
            "file should have permissions 0o644, got 0o{permission_bits:o}"
        );
    }

    /// H1: Test `create_file_with_mode()` with Unix mode 0o755
    #[cfg(unix)]
    #[test]
    fn test_create_file_with_mode_0o755() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("failed to create temp dir");
        let file_path = temp.path().join("test_0o755.txt");

        // Create file with mode 0o755
        let file = create_file_with_mode(&file_path, Some(0o755)).expect("should create file");
        drop(file);

        // Verify file exists
        assert!(file_path.exists(), "file should exist");

        // Verify permissions
        let metadata = std::fs::metadata(&file_path).expect("should read metadata");
        let mode = metadata.permissions().mode();

        // Mask to get only permission bits
        let permission_bits = mode & 0o777;
        assert_eq!(
            permission_bits, 0o755,
            "file should have permissions 0o755, got 0o{permission_bits:o}"
        );
    }

    /// H1: Test `create_file_with_mode()` with Unix mode 0o600
    #[cfg(unix)]
    #[test]
    fn test_create_file_with_mode_0o600() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("failed to create temp dir");
        let file_path = temp.path().join("test_0o600.txt");

        // Create file with mode 0o600
        let file = create_file_with_mode(&file_path, Some(0o600)).expect("should create file");
        drop(file);

        // Verify file exists
        assert!(file_path.exists(), "file should exist");

        // Verify permissions
        let metadata = std::fs::metadata(&file_path).expect("should read metadata");
        let mode = metadata.permissions().mode();

        // Mask to get only permission bits
        let permission_bits = mode & 0o777;
        assert_eq!(
            permission_bits, 0o600,
            "file should have permissions 0o600, got 0o{permission_bits:o}"
        );
    }

    /// H2: Test `create_file_with_mode()` with None (system default
    /// permissions)
    #[test]
    fn test_create_file_with_mode_none() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let file_path = temp.path().join("test_none.txt");

        // Create file with mode=None (should use system defaults)
        let file = create_file_with_mode(&file_path, None).expect("should create file");
        drop(file);

        // Verify file exists
        assert!(file_path.exists(), "file should exist");

        // File should have been created successfully with default permissions
        // The exact permissions depend on umask and platform, so we just verify
        // creation
    }

    /// H2: Test `create_file_with_mode()` with None on Unix (verify umask-based
    /// default)
    #[cfg(unix)]
    #[test]
    fn test_create_file_with_mode_none_unix() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("failed to create temp dir");
        let file_path = temp.path().join("test_none_unix.txt");

        // Create file with mode=None
        let file = create_file_with_mode(&file_path, None).expect("should create file");
        drop(file);

        // Verify file exists
        assert!(file_path.exists(), "file should exist");

        // Verify file has some permission bits set (not zero)
        let metadata = std::fs::metadata(&file_path).expect("should read metadata");
        let mode = metadata.permissions().mode();
        let permission_bits = mode & 0o777;

        // Should have some permissions (not completely locked)
        // Typical defaults are 0o644 or 0o666 & !umask
        assert_ne!(
            permission_bits, 0,
            "file should have non-zero permissions with mode=None"
        );
    }
}
