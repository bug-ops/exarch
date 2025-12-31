//! Zip bomb detection.

use crate::ExtractionError;
use crate::Result;
use crate::SecurityConfig;

/// Validates compression ratio to detect potential zip bombs.
///
/// # Errors
///
/// Returns an error if the compression ratio exceeds the configured maximum.
pub fn validate_compression_ratio(
    compressed_size: u64,
    uncompressed_size: u64,
    config: &SecurityConfig,
) -> Result<()> {
    // HIGH-001: Fix bypass for stored compression with compressed_size == 0
    // Reject invalid entries where compressed_size is 0 but uncompressed_size > 0
    if compressed_size == 0 {
        if uncompressed_size > 0 {
            return Err(ExtractionError::InvalidArchive(
                "compressed_size is 0 but uncompressed_size > 0 (invalid archive metadata)".into(),
            ));
        }
        // Both zero is OK (empty file)
        return Ok(());
    }

    #[allow(clippy::cast_precision_loss)]
    let ratio = uncompressed_size as f64 / compressed_size as f64;

    if ratio > config.max_compression_ratio {
        return Err(ExtractionError::ZipBomb {
            compressed: compressed_size,
            uncompressed: uncompressed_size,
            ratio,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_compression_ratio_safe() {
        let config = SecurityConfig::default();
        let result = validate_compression_ratio(1000, 10_000, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_compression_ratio_bomb() {
        let config = SecurityConfig::default();
        let result = validate_compression_ratio(1000, 1_000_000, &config);
        assert!(matches!(result, Err(ExtractionError::ZipBomb { .. })));
    }

    #[test]
    fn test_validate_compression_ratio_zero_compressed() {
        let config = SecurityConfig::default();

        // HIGH-001: Zero compressed with non-zero uncompressed is invalid
        let result = validate_compression_ratio(0, 1000, &config);
        assert!(
            matches!(result, Err(ExtractionError::InvalidArchive(_))),
            "zero compressed with non-zero uncompressed should be rejected"
        );
    }

    // H-TEST-3: Division by zero edge cases test
    #[test]
    fn test_compressed_size_zero_with_uncompressed_zero() {
        let config = SecurityConfig::default();

        // Both zero - should be OK (empty file)
        let result = validate_compression_ratio(0, 0, &config);
        assert!(result.is_ok(), "0/0 should be handled gracefully");
    }

    #[test]
    fn test_compressed_size_zero_with_large_uncompressed() {
        let config = SecurityConfig::default();

        // HIGH-001: Compressed size zero with uncompressed > 0 is INVALID
        // This prevents zip bomb bypass for stored compression
        let result = validate_compression_ratio(0, 1_000_000, &config);
        assert!(
            matches!(result, Err(ExtractionError::InvalidArchive(_))),
            "compressed_size == 0 but uncompressed_size > 0 should be rejected (HIGH-001 fix)"
        );
    }

    #[test]
    fn test_very_small_compressed_large_uncompressed() {
        let config = SecurityConfig::default();

        // Very small compressed size (1 byte) with large uncompressed
        // This should trigger zip bomb detection
        let result = validate_compression_ratio(1, 1_000_000, &config);
        assert!(
            matches!(result, Err(ExtractionError::ZipBomb { .. })),
            "extremely high compression ratio should be detected as zip bomb"
        );
    }

    #[test]
    fn test_equal_sizes() {
        let config = SecurityConfig::default();

        // No compression (ratio = 1.0)
        let result = validate_compression_ratio(1000, 1000, &config);
        assert!(result.is_ok(), "ratio of 1.0 should be safe");
    }

    #[test]
    fn test_negative_compression() {
        let config = SecurityConfig::default();

        // Compressed larger than uncompressed (poor compression)
        let result = validate_compression_ratio(2000, 1000, &config);
        assert!(
            result.is_ok(),
            "ratio < 1.0 should be safe (negative compression)"
        );
    }
}
