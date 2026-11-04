//! Compression level conversion utilities.
//!
//! This module maps the user-friendly [`CompressionLevel`] scale (1-9) to
//! codec-specific compression levels. The range is guaranteed by the type, so
//! no mapping has to handle an out-of-range value.
//!
//! # Level Mapping
//!
//! - **1-3**: Fast compression (lower CPU usage, larger files)
//! - **6**: Default compression (balanced)
//! - **7-9**: Best compression (higher CPU usage, smaller files)
//!
//! Each codec maps these levels to its own internal scale.

use crate::creation::CompressionLevel;

impl CompressionLevel {
    /// The flate2 level: fast for 1-3, best for 7-9, and `4..=6` map to flate2
    /// levels 4-6 as given.
    pub(crate) fn to_flate2(self) -> flate2::Compression {
        match self.get() {
            1..=3 => flate2::Compression::fast(),
            7..=9 => flate2::Compression::best(),
            n => flate2::Compression::new(u32::from(n)),
        }
    }

    /// The bzip2 level: fast for 1, best for 7-9, the literal level for 2-6.
    pub(crate) fn to_bzip2(self) -> bzip2::Compression {
        match self.get() {
            1 => bzip2::Compression::fast(),
            7..=9 => bzip2::Compression::best(),
            n => bzip2::Compression::new(u32::from(n)),
        }
    }

    /// The xz preset: the literal level.
    pub(crate) fn to_xz(self) -> u32 {
        u32::from(self.get())
    }

    /// The zstd level. Zstd spans 1-22, so the scale maps to strategic levels:
    /// 1 to 1, 2 to 2, 7 to 10, 8 to 15, 9 to 19, and 3-6 to the default 3.
    pub(crate) fn to_zstd(self) -> i32 {
        match self.get() {
            1 => 1,
            2 => 2,
            7 => 10,
            8 => 15,
            9 => 19,
            _ => 3,
        }
    }

    /// The deflate level the ZIP writer takes.
    pub(crate) fn to_zip_level(self) -> i64 {
        i64::from(self.get())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn level(n: u8) -> CompressionLevel {
        CompressionLevel::try_from(n).unwrap()
    }

    #[test]
    fn test_to_flate2() {
        assert_eq!(
            CompressionLevel::default().to_flate2(),
            flate2::Compression::new(6)
        );
        assert_eq!(level(1).to_flate2(), flate2::Compression::fast());
        assert_eq!(level(3).to_flate2(), flate2::Compression::fast());
        assert_eq!(level(5).to_flate2(), flate2::Compression::new(5));
        assert_eq!(level(9).to_flate2(), flate2::Compression::best());
    }

    #[test]
    fn test_to_bzip2() {
        assert_eq!(level(1).to_bzip2(), bzip2::Compression::fast());
        for n in 2..=6u8 {
            assert_eq!(level(n).to_bzip2(), bzip2::Compression::new(u32::from(n)));
        }
        for n in 7..=9u8 {
            assert_eq!(level(n).to_bzip2(), bzip2::Compression::best());
        }
    }

    #[test]
    fn test_to_xz_is_the_literal_level() {
        assert_eq!(CompressionLevel::default().to_xz(), 6);
        assert_eq!(level(1).to_xz(), 1);
        assert_eq!(level(9).to_xz(), 9);
    }

    #[test]
    fn test_to_zstd() {
        assert_eq!(CompressionLevel::default().to_zstd(), 3);
        assert_eq!(level(1).to_zstd(), 1);
        assert_eq!(level(2).to_zstd(), 2);
        assert_eq!(level(4).to_zstd(), 3);
        assert_eq!(level(7).to_zstd(), 10);
        assert_eq!(level(8).to_zstd(), 15);
        assert_eq!(level(9).to_zstd(), 19);
    }

    #[test]
    fn test_to_zip_level() {
        assert_eq!(level(9).to_zip_level(), 9);
        assert_eq!(CompressionLevel::default().to_zip_level(), 6);
    }
}
