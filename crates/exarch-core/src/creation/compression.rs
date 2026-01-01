//! Compression level conversion utilities.
//!
//! This module provides unified conversion from the user-friendly compression
//! level scale (1-9) to codec-specific compression level types.
//!
//! # Level Mapping
//!
//! User levels follow a consistent scale:
//!
//! - **1-3**: Fast compression (lower CPU usage, larger files)
//! - **6**: Default compression (balanced)
//! - **7-9**: Best compression (higher CPU usage, smaller files)
//!
//! Each codec maps these levels to its own internal scale.

use crate::formats::compression::CompressionCodec;

/// Converts user compression level (1-9) to flate2 compression level.
///
/// # Mapping
///
/// - `None` or `Some(6)`: Default compression
/// - `1-3`: Fast compression
/// - `7-9`: Best compression
/// - Other values: Literal level (clamped to valid range)
///
/// # Examples
///
/// ```
/// use exarch_core::creation::compression::compression_level_to_flate2;
///
/// let default_level = compression_level_to_flate2(None);
/// let fast_level = compression_level_to_flate2(Some(1));
/// let best_level = compression_level_to_flate2(Some(9));
/// ```
#[must_use]
pub fn compression_level_to_flate2(level: Option<u8>) -> flate2::Compression {
    match level {
        None | Some(6) => flate2::Compression::default(),
        Some(1..=3) => flate2::Compression::fast(),
        Some(7..=9) => flate2::Compression::best(),
        Some(n) => flate2::Compression::new(u32::from(n)),
    }
}

/// Converts user compression level (1-9) to bzip2 compression level.
///
/// # Mapping
///
/// - `None` or `Some(6)`: Default compression
/// - `1`: Fast compression
/// - `2-6`: Literal level
/// - `7-9`: Best compression
///
/// # Examples
///
/// ```
/// use exarch_core::creation::compression::compression_level_to_bzip2;
///
/// let default_level = compression_level_to_bzip2(None);
/// let fast_level = compression_level_to_bzip2(Some(1));
/// let best_level = compression_level_to_bzip2(Some(9));
/// ```
#[must_use]
pub fn compression_level_to_bzip2(level: Option<u8>) -> bzip2::Compression {
    match level {
        None | Some(6) => bzip2::Compression::default(),
        Some(1) => bzip2::Compression::fast(),
        Some(7..=9) => bzip2::Compression::best(),
        Some(n @ 2..=6) => bzip2::Compression::new(u32::from(n)),
        Some(n) => bzip2::Compression::new(u32::from(n.min(9))),
    }
}

/// Converts user compression level (1-9) to xz compression level.
///
/// # Mapping
///
/// - `None` or `Some(6)`: Level 6 (default)
/// - Other values: Literal level (0-9 range supported by xz)
///
/// # Examples
///
/// ```
/// use exarch_core::creation::compression::compression_level_to_xz;
///
/// let default_level = compression_level_to_xz(None);
/// let fast_level = compression_level_to_xz(Some(1));
/// let best_level = compression_level_to_xz(Some(9));
/// ```
#[must_use]
pub fn compression_level_to_xz(level: Option<u8>) -> u32 {
    match level {
        None | Some(6) => 6,
        Some(n) => u32::from(n),
    }
}

/// Converts user compression level (1-9) to zstd compression level.
///
/// # Mapping
///
/// Zstd has a wider range (1-22) than our user scale (1-9).
/// We map user levels to strategic zstd levels:
///
/// - `None` or `Some(6)`: Level 3 (default, fast with good compression)
/// - `1`: Level 1 (fastest)
/// - `2`: Level 2 (fast)
/// - `7`: Level 10 (good compression)
/// - `8`: Level 15 (better compression)
/// - `9`: Level 19 (best compression)
/// - Other values: Level 3 (default)
///
/// # Examples
///
/// ```
/// use exarch_core::creation::compression::compression_level_to_zstd;
///
/// let default_level = compression_level_to_zstd(None);
/// assert_eq!(default_level, 3);
///
/// let fast_level = compression_level_to_zstd(Some(1));
/// assert_eq!(fast_level, 1);
///
/// let best_level = compression_level_to_zstd(Some(9));
/// assert_eq!(best_level, 19);
/// ```
#[allow(clippy::match_same_arms)] // Different semantic meanings for each level
#[must_use]
pub fn compression_level_to_zstd(level: Option<u8>) -> i32 {
    match level {
        // Default compression level
        None | Some(6) => 3,
        Some(1) => 1,
        Some(2) => 2,
        Some(7) => 10,
        Some(8) => 15,
        Some(9) => 19,
        // All other levels (3-5, 0, 10+) map to default
        _ => 3,
    }
}

/// Converts compression codec and level to the appropriate compression type.
///
/// This is a convenience function that dispatches to the codec-specific
/// conversion functions.
///
/// # Type Parameters
///
/// The return type is an enum that wraps all possible compression types.
/// Use pattern matching to extract the specific type.
///
/// # Examples
///
/// ```
/// use exarch_core::creation::compression::CompressionLevel;
/// use exarch_core::creation::compression::convert_compression_level;
/// use exarch_core::formats::compression::CompressionCodec;
///
/// let level = convert_compression_level(CompressionCodec::Gzip, Some(9));
/// match level {
///     CompressionLevel::Flate2(c) => {
///         // Use flate2 compression
///     }
///     _ => unreachable!(),
/// }
/// ```
#[must_use]
pub fn convert_compression_level(codec: CompressionCodec, level: Option<u8>) -> CompressionLevel {
    match codec {
        CompressionCodec::Gzip => CompressionLevel::Flate2(compression_level_to_flate2(level)),
        CompressionCodec::Bzip2 => CompressionLevel::Bzip2(compression_level_to_bzip2(level)),
        CompressionCodec::Xz => CompressionLevel::Xz(compression_level_to_xz(level)),
        CompressionCodec::Zstd => CompressionLevel::Zstd(compression_level_to_zstd(level)),
    }
}

/// Unified compression level type.
///
/// This enum wraps codec-specific compression level types to provide
/// a unified interface for compression level conversion.
#[derive(Debug, Clone, Copy)]
pub enum CompressionLevel {
    /// Flate2 (gzip) compression level.
    Flate2(flate2::Compression),

    /// Bzip2 compression level.
    Bzip2(bzip2::Compression),

    /// Xz compression level (raw u32).
    Xz(u32),

    /// Zstd compression level (raw i32).
    Zstd(i32),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_level_to_flate2() {
        // Default
        let level = compression_level_to_flate2(None);
        assert_eq!(level, flate2::Compression::default());

        let level = compression_level_to_flate2(Some(6));
        assert_eq!(level, flate2::Compression::default());

        // Fast
        let level = compression_level_to_flate2(Some(1));
        assert_eq!(level, flate2::Compression::fast());

        // Best
        let level = compression_level_to_flate2(Some(9));
        assert_eq!(level, flate2::Compression::best());

        // Specific level
        let level = compression_level_to_flate2(Some(5));
        assert_eq!(level, flate2::Compression::new(5));
    }

    #[test]
    fn test_compression_level_to_bzip2() {
        // Default
        let level = compression_level_to_bzip2(None);
        assert_eq!(level, bzip2::Compression::default());

        // Fast
        let level = compression_level_to_bzip2(Some(1));
        assert_eq!(level, bzip2::Compression::fast());

        // Best
        let level = compression_level_to_bzip2(Some(9));
        assert_eq!(level, bzip2::Compression::best());

        // Specific level
        let level = compression_level_to_bzip2(Some(4));
        assert_eq!(level, bzip2::Compression::new(4));
    }

    #[test]
    fn test_compression_level_to_xz() {
        assert_eq!(compression_level_to_xz(None), 6);
        assert_eq!(compression_level_to_xz(Some(6)), 6);
        assert_eq!(compression_level_to_xz(Some(1)), 1);
        assert_eq!(compression_level_to_xz(Some(9)), 9);
    }

    #[test]
    fn test_compression_level_to_zstd() {
        assert_eq!(compression_level_to_zstd(None), 3);
        assert_eq!(compression_level_to_zstd(Some(6)), 3);
        assert_eq!(compression_level_to_zstd(Some(1)), 1);
        assert_eq!(compression_level_to_zstd(Some(2)), 2);
        assert_eq!(compression_level_to_zstd(Some(7)), 10);
        assert_eq!(compression_level_to_zstd(Some(8)), 15);
        assert_eq!(compression_level_to_zstd(Some(9)), 19);
    }

    #[test]
    fn test_convert_compression_level() {
        let level = convert_compression_level(CompressionCodec::Gzip, Some(9));
        match level {
            CompressionLevel::Flate2(c) => {
                assert_eq!(c, flate2::Compression::best());
            }
            _ => panic!("Expected Flate2 compression level"),
        }

        let level = convert_compression_level(CompressionCodec::Zstd, None);
        match level {
            CompressionLevel::Zstd(c) => {
                assert_eq!(c, 3);
            }
            _ => panic!("Expected Zstd compression level"),
        }
    }
}
