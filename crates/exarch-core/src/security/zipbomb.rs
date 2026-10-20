//! Zip bomb detection.

use crate::ArchiveError;
use crate::CompressionRatio;
use crate::Result;
use crate::SecurityConfig;
use crate::ZipBombDetails;
use crate::ZipBombScope;
use crate::config::Validated;
use crate::inspection::EntryCompression;
use crate::inspection::SolidBlock;

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
    check_ratio(
        ZipBombScope::Entry,
        compressed_size,
        uncompressed_size,
        config.max_compression_ratio,
    )
}

/// Validates the compression ratio of a whole solid block against
/// `max_solid_compression_ratio`.
///
/// A block without data (`uncompressed == 0`) is accepted.
///
/// # Errors
///
/// Returns [`ArchiveError::ZipBomb`] when the block claims data but no
/// compressed bytes, or when the ratio exceeds the configured maximum.
pub fn validate_solid_block_ratio(
    block: &SolidBlock,
    config: &SecurityConfig<Validated>,
) -> Result<()> {
    check_ratio(
        ZipBombScope::SolidBlock,
        block.compressed,
        block.uncompressed,
        config.max_solid_compression_ratio,
    )
}

/// Applies the ratio check that fits how `compression` attributes data to an
/// entry of `uncompressed_size` bytes: per file for
/// [`EntryCompression::Entry`], per block for a solid block start, none
/// otherwise.
///
/// # Errors
///
/// Returns the error of [`validate_compression_ratio`] or
/// [`validate_solid_block_ratio`].
pub fn validate_entry_compression(
    compression: &EntryCompression,
    uncompressed_size: u64,
    config: &SecurityConfig<Validated>,
) -> Result<()> {
    match compression {
        EntryCompression::Entry(compressed) => {
            validate_compression_ratio(*compressed, uncompressed_size, config)
        }
        EntryCompression::SolidBlockStart(block) => validate_solid_block_ratio(block, config),
        EntryCompression::Unknown | EntryCompression::SolidBlockMember => Ok(()),
    }
}

fn check_ratio(
    scope: ZipBombScope,
    compressed_size: u64,
    uncompressed_size: u64,
    max_ratio: f64,
) -> Result<()> {
    let details = ZipBombDetails::new(scope, compressed_size, uncompressed_size);
    match details.ratio() {
        // HIGH-001: data claimed from zero compressed bytes bypasses any finite limit
        CompressionRatio::Unbounded => Err(ArchiveError::ZipBomb(details)),
        CompressionRatio::Finite(ratio) if ratio > max_ratio => Err(ArchiveError::ZipBomb(details)),
        CompressionRatio::Finite(_) => Ok(()),
    }
}

/// Bounds the sum of declared compressed sizes by the archive's data region.
///
/// Each entry's declared compressed size is charged against the budget, so
/// the sizes of all entries together never exceed the space the archive can
/// actually hold. Entries that declare more data than remains are rejected,
/// which keeps per-entry compression-ratio checks anchored to real archive
/// bytes.
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
        assert_matches!(result, Err(ArchiveError::ZipBomb(_)));
    }

    #[test]
    fn test_validate_compression_ratio_zero_compressed() {
        let config = SecurityConfig::default().validate().expect("valid config");

        // HIGH-001: Zero compressed with non-zero uncompressed is an unbounded
        // ratio
        let result = validate_compression_ratio(0, 1000, &config);
        assert_matches!(
            result,
            Err(ArchiveError::ZipBomb(details))
                if details.ratio() == CompressionRatio::Unbounded
                    && details.scope() == ZipBombScope::Entry,
            "zero compressed with non-zero uncompressed should be rejected"
        );
    }

    #[test]
    fn test_solid_block_ratio_uses_solid_limit() {
        let config = SecurityConfig::default().validate().expect("valid config");
        // 138x passes the solid limit (1000) though it exceeds the per-file one
        // (100).
        assert!(validate_solid_block_ratio(&SolidBlock::new(1000, 138_000), &config).is_ok());
        assert_matches!(
            validate_solid_block_ratio(&SolidBlock::new(1000, 1_500_000), &config),
            Err(ArchiveError::ZipBomb(_))
        );
    }

    #[test]
    fn test_ratio_equal_to_limit_is_accepted_and_just_above_is_rejected() {
        let config = SecurityConfig::default().validate().expect("valid config");
        assert!(validate_solid_block_ratio(&SolidBlock::new(10, 10_000), &config).is_ok());
        assert_matches!(
            validate_solid_block_ratio(&SolidBlock::new(10, 10_001), &config),
            Err(ArchiveError::ZipBomb(_))
        );
        assert!(validate_compression_ratio(10, 1000, &config).is_ok());
        assert_matches!(
            validate_compression_ratio(10, 1001, &config),
            Err(ArchiveError::ZipBomb(_))
        );
    }

    #[test]
    fn test_solid_block_ratio_empty_and_zero_compressed() {
        let config = SecurityConfig::default().validate().expect("valid config");
        assert!(validate_solid_block_ratio(&SolidBlock::new(0, 0), &config).is_ok());
        assert_matches!(
            validate_solid_block_ratio(&SolidBlock::new(0, 10), &config),
            Err(ArchiveError::ZipBomb(details))
                if details.ratio() == CompressionRatio::Unbounded
                    && details.scope() == ZipBombScope::SolidBlock
        );
    }

    #[test]
    fn test_entry_compression_dispatch() {
        let config = SecurityConfig::default().validate().expect("valid config");
        let block = EntryCompression::SolidBlockStart(SolidBlock::new(1000, 138_000));
        assert!(validate_entry_compression(&block, 1, &config).is_ok());
        assert!(
            validate_entry_compression(&EntryCompression::SolidBlockMember, u64::MAX, &config)
                .is_ok()
        );
        assert!(validate_entry_compression(&EntryCompression::Unknown, u64::MAX, &config).is_ok());
        assert_matches!(
            validate_entry_compression(&EntryCompression::Entry(1000), 138_000, &config),
            Err(ArchiveError::ZipBomb(_))
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
            Err(ArchiveError::ZipBomb(details))
                if details.ratio() == CompressionRatio::Unbounded,
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
            Err(ArchiveError::ZipBomb(_)),
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
