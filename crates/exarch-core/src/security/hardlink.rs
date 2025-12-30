//! Hardlink security validation.

use std::path::Path;

use crate::Result;
use crate::SecurityConfig;

/// Validates that a hardlink target is safe.
///
/// # Errors
///
/// Returns an error if hardlinks are not allowed or if the target
/// is outside the extraction directory.
pub fn validate_hardlink(link_path: &Path, target: &Path, config: &SecurityConfig) -> Result<()> {
    let _link_path = link_path;
    let _target = target;
    let _config = config;
    // TODO: Implement hardlink validation
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_validate_hardlink_placeholder() {
        let config = SecurityConfig::default();
        let result = validate_hardlink(&PathBuf::from("link"), &PathBuf::from("target"), &config);
        assert!(result.is_ok());
    }
}
