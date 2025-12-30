//! Path traversal validation.

use std::path::Path;

use crate::{Result, SecurityConfig};

/// Validates that a path does not contain traversal attempts.
///
/// # Errors
///
/// Returns an error if the path contains ".." components or
/// attempts to escape the extraction directory.
pub fn validate_path(path: &Path, config: &SecurityConfig) -> Result<()> {
    let _path = path;
    let _config = config;
    // TODO: Implement path validation
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_validate_path_valid() {
        let config = SecurityConfig::default();
        let path = PathBuf::from("foo/bar.txt");
        assert!(validate_path(&path, &config).is_ok());
    }
}
