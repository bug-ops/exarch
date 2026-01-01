//! Compression codec support for archive formats.
//!
//! This module provides unified handling of compression codecs used with
//! TAR archives. The same compression codecs can be used for both reading
//! (decompression) and writing (compression).
//!
//! # Supported Codecs
//!
//! - **Gzip** (.tar.gz, .tgz): Fast compression with good compatibility
//! - **Bzip2** (.tar.bz2, .tbz2): Better compression ratio, slower
//! - **Xz** (.tar.xz, .txz): Best compression ratio, slowest
//! - **Zstd** (.tar.zst, .tzst): Modern codec with good speed/ratio balance

/// Compression codec for archive files.
///
/// Represents the compression algorithm used for compressed archives.
/// Each codec has different trade-offs between compression ratio,
/// speed, and compatibility.
///
/// # Performance Characteristics
///
/// | Codec | Compression | Decompression | Ratio | Compatibility |
/// |-------|-------------|---------------|-------|---------------|
/// | Gzip  | Fast        | Fast          | Good  | Excellent     |
/// | Bzip2 | Slow        | Medium        | Better| Good          |
/// | Xz    | Very Slow   | Medium        | Best  | Good          |
/// | Zstd  | Fast        | Very Fast     | Good  | Modern        |
///
/// # Examples
///
/// ```
/// use exarch_core::formats::compression::CompressionCodec;
///
/// // Choose codec based on requirements
/// let fast_codec = CompressionCodec::Gzip; // Fast compression
/// let best_codec = CompressionCodec::Xz; // Best compression ratio
/// let modern_codec = CompressionCodec::Zstd; // Modern balanced approach
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompressionCodec {
    /// Gzip compression (deflate algorithm).
    ///
    /// Fast compression and decompression with widespread support.
    /// Good default choice for most use cases.
    Gzip,

    /// Bzip2 compression (Burrows-Wheeler algorithm).
    ///
    /// Better compression ratio than gzip but slower.
    /// Good for archives that will be distributed.
    Bzip2,

    /// Xz compression (LZMA2 algorithm).
    ///
    /// Best compression ratio but slowest.
    /// Good for long-term storage or bandwidth-constrained transfers.
    Xz,

    /// Zstd compression (Zstandard algorithm).
    ///
    /// Modern codec with excellent speed and good compression ratio.
    /// Good for archives that need fast decompression.
    Zstd,
}

impl CompressionCodec {
    /// Returns the typical file extension for this codec when used with TAR.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::formats::compression::CompressionCodec;
    ///
    /// assert_eq!(CompressionCodec::Gzip.extension(), "tar.gz");
    /// assert_eq!(CompressionCodec::Bzip2.extension(), "tar.bz2");
    /// assert_eq!(CompressionCodec::Xz.extension(), "tar.xz");
    /// assert_eq!(CompressionCodec::Zstd.extension(), "tar.zst");
    /// ```
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Gzip => "tar.gz",
            Self::Bzip2 => "tar.bz2",
            Self::Xz => "tar.xz",
            Self::Zstd => "tar.zst",
        }
    }

    /// Returns a human-readable name for this codec.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::formats::compression::CompressionCodec;
    ///
    /// assert_eq!(CompressionCodec::Gzip.name(), "gzip");
    /// assert_eq!(CompressionCodec::Bzip2.name(), "bzip2");
    /// ```
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_extension() {
        assert_eq!(CompressionCodec::Gzip.extension(), "tar.gz");
        assert_eq!(CompressionCodec::Bzip2.extension(), "tar.bz2");
        assert_eq!(CompressionCodec::Xz.extension(), "tar.xz");
        assert_eq!(CompressionCodec::Zstd.extension(), "tar.zst");
    }

    #[test]
    fn test_codec_name() {
        assert_eq!(CompressionCodec::Gzip.name(), "gzip");
        assert_eq!(CompressionCodec::Bzip2.name(), "bzip2");
        assert_eq!(CompressionCodec::Xz.name(), "xz");
        assert_eq!(CompressionCodec::Zstd.name(), "zstd");
    }

    #[test]
    fn test_codec_equality() {
        assert_eq!(CompressionCodec::Gzip, CompressionCodec::Gzip);
        assert_ne!(CompressionCodec::Gzip, CompressionCodec::Bzip2);
    }

    #[test]
    fn test_codec_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(CompressionCodec::Gzip);
        set.insert(CompressionCodec::Bzip2);
        set.insert(CompressionCodec::Gzip); // Duplicate

        assert_eq!(set.len(), 2);
        assert!(set.contains(&CompressionCodec::Gzip));
        assert!(set.contains(&CompressionCodec::Bzip2));
    }
}
