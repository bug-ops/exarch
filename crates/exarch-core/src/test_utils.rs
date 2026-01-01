//! Test utilities for archive creation and validation.
//!
//! This module provides reusable helpers for creating in-memory test archives,
//! reducing code duplication across format-specific tests.
//!
//! # Panics
//!
//! All functions in this module may panic on I/O errors since they are
//! designed for test use only where panics are acceptable.

#![allow(clippy::unwrap_used, clippy::missing_panics_doc)]

use std::io::Cursor;
use std::io::Write;

/// Creates an in-memory TAR archive from a list of entries.
///
/// Each entry is a tuple of (path, content). Files are created with mode 0o644.
///
/// # Examples
///
/// ```
/// use exarch_core::test_utils::create_test_tar;
///
/// let tar_data = create_test_tar(vec![("file.txt", b"hello"), ("dir/nested.txt", b"world")]);
/// ```
#[must_use]
pub fn create_test_tar(entries: Vec<(&str, &[u8])>) -> Vec<u8> {
    let mut ar = tar::Builder::new(Vec::new());
    for (path, data) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        ar.append_data(&mut header, path, data).unwrap();
    }
    ar.into_inner().unwrap()
}

/// Creates an in-memory ZIP archive from a list of entries.
///
/// Each entry is a tuple of (path, content). Files are stored uncompressed
/// with mode 0o644.
///
/// # Examples
///
/// ```
/// use exarch_core::test_utils::create_test_zip;
///
/// let zip_data = create_test_zip(vec![("file.txt", b"hello"), ("dir/nested.txt", b"world")]);
/// ```
#[must_use]
pub fn create_test_zip(entries: Vec<(&str, &[u8])>) -> Vec<u8> {
    use zip::write::SimpleFileOptions;
    use zip::write::ZipWriter;

    let buffer = Vec::new();
    let mut zip = ZipWriter::new(Cursor::new(buffer));

    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o644);

    for (path, data) in entries {
        zip.start_file(path, options).unwrap();
        zip.write_all(data).unwrap();
    }

    zip.finish().unwrap().into_inner()
}

/// Builder for creating TAR test archives with various entry types.
///
/// Supports files, directories, symlinks, and hardlinks.
///
/// # Examples
///
/// ```
/// use exarch_core::test_utils::TarTestBuilder;
///
/// let tar_data = TarTestBuilder::new()
///     .add_file("file.txt", b"content")
///     .add_directory("dir/")
///     .add_symlink("link", "file.txt")
///     .build();
/// ```
pub struct TarTestBuilder {
    builder: tar::Builder<Vec<u8>>,
}

impl TarTestBuilder {
    /// Creates a new TAR test builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            builder: tar::Builder::new(Vec::new()),
        }
    }

    /// Adds a regular file to the archive.
    #[must_use]
    pub fn add_file(mut self, path: &str, data: &[u8]) -> Self {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        self.builder.append_data(&mut header, path, data).unwrap();
        self
    }

    /// Adds a regular file with custom mode.
    #[must_use]
    pub fn add_file_with_mode(mut self, path: &str, data: &[u8], mode: u32) -> Self {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(mode);
        header.set_cksum();
        self.builder.append_data(&mut header, path, data).unwrap();
        self
    }

    /// Adds a directory to the archive.
    #[must_use]
    pub fn add_directory(mut self, path: &str) -> Self {
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        self.builder
            .append_data(&mut header, path, std::io::empty())
            .unwrap();
        self
    }

    /// Adds a symlink to the archive.
    #[must_use]
    pub fn add_symlink(mut self, path: &str, target: &str) -> Self {
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o777);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name(target).unwrap();
        header.set_cksum();
        self.builder
            .append_data(&mut header, path, std::io::empty())
            .unwrap();
        self
    }

    /// Adds a hardlink to the archive.
    #[must_use]
    pub fn add_hardlink(mut self, path: &str, target: &str) -> Self {
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Link);
        header.set_link_name(target).unwrap();
        header.set_cksum();
        self.builder
            .append_data(&mut header, path, std::io::empty())
            .unwrap();
        self
    }

    /// Builds and returns the TAR archive data.
    #[must_use]
    pub fn build(self) -> Vec<u8> {
        self.builder.into_inner().unwrap()
    }
}

impl Default for TarTestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating ZIP test archives with various entry types.
///
/// # Examples
///
/// ```
/// use exarch_core::test_utils::ZipTestBuilder;
///
/// let zip_data = ZipTestBuilder::new()
///     .add_file("file.txt", b"content")
///     .add_directory("dir/")
///     .build();
/// ```
pub struct ZipTestBuilder {
    zip: zip::ZipWriter<Cursor<Vec<u8>>>,
}

impl ZipTestBuilder {
    /// Creates a new ZIP test builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            zip: zip::ZipWriter::new(Cursor::new(Vec::new())),
        }
    }

    /// Adds a regular file to the archive.
    #[must_use]
    pub fn add_file(mut self, path: &str, data: &[u8]) -> Self {
        use zip::write::SimpleFileOptions;

        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .unix_permissions(0o644);

        self.zip.start_file(path, options).unwrap();
        self.zip.write_all(data).unwrap();
        self
    }

    /// Adds a regular file with custom mode.
    #[must_use]
    pub fn add_file_with_mode(mut self, path: &str, data: &[u8], mode: u32) -> Self {
        use zip::write::SimpleFileOptions;

        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .unix_permissions(mode);

        self.zip.start_file(path, options).unwrap();
        self.zip.write_all(data).unwrap();
        self
    }

    /// Adds a directory to the archive.
    #[must_use]
    pub fn add_directory(mut self, path: &str) -> Self {
        use zip::write::SimpleFileOptions;

        let options = SimpleFileOptions::default().unix_permissions(0o755);
        self.zip.add_directory(path, options).unwrap();
        self
    }

    /// Adds a symlink to the archive.
    #[cfg(unix)]
    #[must_use]
    pub fn add_symlink(mut self, path: &str, target: &str) -> Self {
        use zip::write::SimpleFileOptions;

        // ZIP stores symlinks as files with Unix mode bit set
        let options = SimpleFileOptions::default().unix_permissions(0o120_777);

        self.zip.start_file(path, options).unwrap();
        self.zip.write_all(target.as_bytes()).unwrap();
        self
    }

    /// Builds and returns the ZIP archive data.
    #[must_use]
    pub fn build(self) -> Vec<u8> {
        self.zip.finish().unwrap().into_inner()
    }
}

impl Default for ZipTestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_test_tar() {
        let tar_data = create_test_tar(vec![("file.txt", b"hello")]);
        assert!(!tar_data.is_empty());
    }

    #[test]
    fn test_create_test_zip() {
        let zip_data = create_test_zip(vec![("file.txt", b"hello")]);
        assert!(!zip_data.is_empty());
    }

    #[test]
    fn test_tar_builder() {
        let tar_data = TarTestBuilder::new()
            .add_file("file.txt", b"content")
            .add_directory("dir/")
            .build();
        assert!(!tar_data.is_empty());
    }

    #[test]
    fn test_zip_builder() {
        let zip_data = ZipTestBuilder::new()
            .add_file("file.txt", b"content")
            .add_directory("dir/")
            .build();
        assert!(!zip_data.is_empty());
    }
}
