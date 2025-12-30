//! Symlink security validation.

use std::path::Path;

use crate::{Result, SecurityConfig};

/// Validates that a symlink target is safe.
///
/// # Errors
///
/// Returns an error if symlinks are not allowed or if the target
/// escapes the extraction directory.
pub fn validate_symlink(link_path: &Path, target: &Path, config: &SecurityConfig) -> Result<()> {
    let _link_path = link_path;
    let _target = target;
    let _config = config;
    // TODO: Implement symlink validation
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_validate_symlink_placeholder() {
        let config = SecurityConfig::default();
        let result = validate_symlink(
            &PathBuf::from("link"),
            &PathBuf::from("target"),
            &config,
        );
        assert!(result.is_ok());
    }
}
