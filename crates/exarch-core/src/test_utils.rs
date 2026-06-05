//! Test utilities for archive creation and validation.
//!
//! This module provides reusable helpers for creating in-memory test archives,
//! reducing code duplication across format-specific tests.
//!
//! # Panics
//!
//! All functions in this module may panic on I/O errors since they are
//! designed for test use only where panics are acceptable.

#![allow(clippy::unwrap_used, clippy::missing_panics_doc, dead_code)]

use std::io::Cursor;
use std::io::Write;

/// Creates an in-memory TAR archive from a list of `(path, content)` entries.
///
/// All files are created with mode `0o644`.
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

/// Creates an in-memory ZIP archive from a list of `(path, content)` entries.
///
/// Files are stored uncompressed with mode `0o644`.
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

/// Creates a raw in-memory ZIP with a single entry whose name is written
/// verbatim into the local file header and central directory, bypassing any
/// normalization that the `zip` crate applies via `start_file`. Use this to
/// craft entries with absolute paths or traversal sequences that
/// `enclosed_name()` returns `None` for.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn create_raw_zip_entry(entry_name: &str, content: &[u8]) -> Vec<u8> {
    let name_bytes = entry_name.as_bytes();
    let name_len = name_bytes.len() as u16;
    let content_len = content.len() as u32;
    let mut buf: Vec<u8> = Vec::new();

    let local_offset = buf.len() as u32;
    buf.extend_from_slice(b"PK\x03\x04");
    buf.extend_from_slice(&20u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // flags
    buf.extend_from_slice(&0u16.to_le_bytes()); // stored
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // CRC32
    buf.extend_from_slice(&content_len.to_le_bytes());
    buf.extend_from_slice(&content_len.to_le_bytes());
    buf.extend_from_slice(&name_len.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // extra length
    buf.extend_from_slice(name_bytes);
    buf.extend_from_slice(content);

    let central_offset = buf.len() as u32;
    buf.extend_from_slice(b"PK\x01\x02");
    buf.extend_from_slice(&0x031eu16.to_le_bytes());
    buf.extend_from_slice(&20u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&content_len.to_le_bytes());
    buf.extend_from_slice(&content_len.to_le_bytes());
    buf.extend_from_slice(&name_len.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // extra length
    buf.extend_from_slice(&0u16.to_le_bytes()); // comment length
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk start
    buf.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    buf.extend_from_slice(&(0o100_644u32 << 16).to_le_bytes());
    buf.extend_from_slice(&local_offset.to_le_bytes());
    buf.extend_from_slice(name_bytes);

    let central_size = (buf.len() as u32) - central_offset;
    buf.extend_from_slice(b"PK\x05\x06");
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&central_size.to_le_bytes());
    buf.extend_from_slice(&central_offset.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf
}

/// Builder for creating TAR test archives with files, directories, symlinks,
/// and hardlinks.
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

/// Creates a raw ZIP archive containing a single symlink entry.
///
/// The ZIP spec encodes symlink targets as uncompressed file data, with
/// `S_IFLNK` mode bits stored in the high 16 bits of the central directory's
/// external attributes field. This bypasses the zip crate writer's
/// `unix_permissions()` path, which does not set external attributes reliably.
#[must_use]
pub fn create_zip_with_symlink(link_path: &str, target: &str) -> Vec<u8> {
    let content = target.as_bytes();
    let crc = {
        let mut c: u32 = 0xFFFF_FFFF;
        for &b in content {
            c ^= u32::from(b);
            for _ in 0..8 {
                if c & 1 != 0 {
                    c = (c >> 1) ^ 0xEDB8_8320;
                } else {
                    c >>= 1;
                }
            }
        }
        c ^ 0xFFFF_FFFF
    };
    // S_IFLNK | rwxrwxrwx — encodes mode in high word of external attributes
    let external_attributes: u32 = 0o120_777 << 16;
    let name_bytes = link_path.as_bytes();
    let name_len = u16::try_from(name_bytes.len()).unwrap();
    let content_len = u32::try_from(content.len()).unwrap();

    let mut buf: Vec<u8> = Vec::new();

    let local_offset = u32::try_from(buf.len()).unwrap();
    buf.extend_from_slice(b"PK\x03\x04");
    buf.extend_from_slice(&20u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // flags
    buf.extend_from_slice(&0u16.to_le_bytes()); // compression: Stored
    buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
    buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
    buf.extend_from_slice(&crc.to_le_bytes());
    buf.extend_from_slice(&content_len.to_le_bytes());
    buf.extend_from_slice(&content_len.to_le_bytes());
    buf.extend_from_slice(&name_len.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // extra field length
    buf.extend_from_slice(name_bytes);
    buf.extend_from_slice(content);

    let central_offset = u32::try_from(buf.len()).unwrap();
    buf.extend_from_slice(b"PK\x01\x02");
    buf.extend_from_slice(&0x031eu16.to_le_bytes()); // version made by: Unix
    buf.extend_from_slice(&20u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // flags
    buf.extend_from_slice(&0u16.to_le_bytes()); // compression
    buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
    buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
    buf.extend_from_slice(&crc.to_le_bytes());
    buf.extend_from_slice(&content_len.to_le_bytes());
    buf.extend_from_slice(&content_len.to_le_bytes());
    buf.extend_from_slice(&name_len.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // extra length
    buf.extend_from_slice(&0u16.to_le_bytes()); // comment length
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk number start
    buf.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
    buf.extend_from_slice(&external_attributes.to_le_bytes());
    buf.extend_from_slice(&local_offset.to_le_bytes());
    buf.extend_from_slice(name_bytes);

    let central_size = u32::try_from(buf.len()).unwrap() - central_offset;
    buf.extend_from_slice(b"PK\x05\x06");
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk number
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk with central dir
    buf.extend_from_slice(&1u16.to_le_bytes()); // entries on this disk
    buf.extend_from_slice(&1u16.to_le_bytes()); // total entries
    buf.extend_from_slice(&central_size.to_le_bytes());
    buf.extend_from_slice(&central_offset.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // comment length

    buf
}

/// Builder for creating ZIP test archives with files, directories, and
/// symlinks.
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
