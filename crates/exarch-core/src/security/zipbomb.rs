//! Zip bomb detection.

use crate::ArchiveError;
use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;

/// Validates compression ratio to detect potential zip bombs.
///
/// # Errors
///
/// Returns an error if the compression ratio exceeds the configured maximum.
pub fn validate_compression_ratio(
    compressed_size: u64,
    uncompressed_size: u64,
    config: &SecurityConfig<Validated>,
) -> Result<()> {
    // HIGH-001: Fix bypass for stored compression with compressed_size == 0
    // Reject invalid entries where compressed_size is 0 but uncompressed_size >
    // 0
    if compressed_size == 0 {
        if uncompressed_size > 0 {
            return Err(ArchiveError::InvalidArchive(
                "compressed_size is 0 but uncompressed_size > 0 (invalid archive metadata)".into(),
            ));
        }
        // Both zero is OK (empty file)
        return Ok(());
    }

    #[allow(clippy::cast_precision_loss)]
    let ratio = uncompressed_size as f64 / compressed_size as f64;

    if ratio > config.max_compression_ratio {
        return Err(ArchiveError::ZipBomb {
            compressed: compressed_size,
            uncompressed: uncompressed_size,
            ratio,
        });
    }

    Ok(())
}

/// Cumulative bound on the compressed sizes an archive declares in its
/// metadata.
///
/// Per-entry ratio checks trust declared compressed sizes; charging every
/// declared size against the bytes the archive really occupies caps the total
/// output at `max_compression_ratio` times the real archive size, and rejects
/// entries that claim overlapping or non-existent data.
#[derive(Debug)]
pub struct DeclaredCompressedBudget {
    remaining: u64,
}

impl DeclaredCompressedBudget {
    /// Creates a budget of `data_region` bytes, the archive space that can
    /// hold compressed entry data.
    pub const fn new(data_region: u64) -> Self {
        Self {
            remaining: data_region,
        }
    }

    /// Charges one declared compressed size against the budget.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidArchive`] when `declared` exceeds what
    /// is left of the budget.
    pub fn charge(&mut self, declared: u64) -> Result<()> {
        self.remaining = self.remaining.checked_sub(declared).ok_or_else(|| {
            ArchiveError::InvalidArchive("declared compressed size exceeds archive length".into())
        })?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn test_validate_compression_ratio_safe() {
        let config = SecurityConfig::default().validate().expect("valid config");
        let result = validate_compression_ratio(1000, 10_000, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_compression_ratio_bomb() {
        let config = SecurityConfig::default().validate().expect("valid config");
        let result = validate_compression_ratio(1000, 1_000_000, &config);
        assert_matches!(result, Err(ArchiveError::ZipBomb { .. }));
    }

    #[test]
    fn test_validate_compression_ratio_zero_compressed() {
        let config = SecurityConfig::default().validate().expect("valid config");

        // HIGH-001: Zero compressed with non-zero uncompressed is invalid
        let result = validate_compression_ratio(0, 1000, &config);
        assert_matches!(
            result,
            Err(ArchiveError::InvalidArchive(_)),
            "zero compressed with non-zero uncompressed should be rejected"
        );
    }

    #[test]
    fn test_declared_budget_accepts_sizes_within_region() {
        let mut budget = DeclaredCompressedBudget::new(100);
        budget.charge(60).expect("fits");
        budget.charge(40).expect("fits exactly");
        budget.charge(0).expect("zero is free");
    }

    #[test]
    fn test_declared_budget_rejects_cumulative_overrun() {
        let mut budget = DeclaredCompressedBudget::new(100);
        budget.charge(60).expect("fits");
        assert_matches!(budget.charge(41), Err(ArchiveError::InvalidArchive(_)));
    }

    #[test]
    fn test_declared_budget_rejects_u64_max() {
        let mut budget = DeclaredCompressedBudget::new(u64::MAX - 1);
        assert_matches!(
            budget.charge(u64::MAX),
            Err(ArchiveError::InvalidArchive(_))
        );
    }

    // H-TEST-3: Division by zero edge cases test
    #[test]
    fn test_compressed_size_zero_with_uncompressed_zero() {
        let config = SecurityConfig::default().validate().expect("valid config");

        // Both zero - should be OK (empty file)
        let result = validate_compression_ratio(0, 0, &config);
        assert!(result.is_ok(), "0/0 should be handled gracefully");
    }

    #[test]
    fn test_compressed_size_zero_with_large_uncompressed() {
        let config = SecurityConfig::default().validate().expect("valid config");

        // HIGH-001: Compressed size zero with uncompressed > 0 is INVALID
        // This prevents zip bomb bypass for stored compression
        let result = validate_compression_ratio(0, 1_000_000, &config);
        assert_matches!(
            result,
            Err(ArchiveError::InvalidArchive(_)),
            "compressed_size == 0 but uncompressed_size > 0 should be rejected (HIGH-001 fix)"
        );
    }

    #[test]
    fn test_very_small_compressed_large_uncompressed() {
        let config = SecurityConfig::default().validate().expect("valid config");

        // Very small compressed size (1 byte) with large uncompressed
        // This should trigger zip bomb detection
        let result = validate_compression_ratio(1, 1_000_000, &config);
        assert_matches!(
            result,
            Err(ArchiveError::ZipBomb { .. }),
            "extremely high compression ratio should be detected as zip bomb"
        );
    }

    #[test]
    fn test_equal_sizes() {
        let config = SecurityConfig::default().validate().expect("valid config");

        // No compression (ratio = 1.0)
        let result = validate_compression_ratio(1000, 1000, &config);
        assert!(result.is_ok(), "ratio of 1.0 should be safe");
    }

    #[test]
    fn test_negative_compression() {
        let config = SecurityConfig::default().validate().expect("valid config");

        // Compressed larger than uncompressed (poor compression)
        let result = validate_compression_ratio(2000, 1000, &config);
        assert!(
            result.is_ok(),
            "ratio < 1.0 should be safe (negative compression)"
        );
    }
}
