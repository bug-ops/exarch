//! Zip bomb detection.

use crate::{ExtractionError, Result, SecurityConfig};

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
    if compressed_size == 0 {
        return Ok(());
    }

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
        let result = validate_compression_ratio(0, 1000, &config);
        assert!(result.is_ok());
    }
}
