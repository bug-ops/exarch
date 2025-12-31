//! File permission validation and sanitization.

use crate::ExtractionError;
use crate::Result;
use crate::SecurityConfig;

/// Sanitizes file permissions by stripping dangerous bits.
///
/// This function removes security-sensitive permission bits that could
/// lead to privilege escalation:
/// - Setuid bit (04000): Allows execution with file owner's privileges
/// - Setgid bit (02000): Allows execution with file group's privileges
///
/// World-writable files (0002) are rejected by default as they pose
/// security risks in multi-user environments.
///
/// # Performance
///
/// This is a pure computation with no I/O. Typical execution time: <10 ns.
///
/// # Errors
///
/// Returns `ExtractionError::InvalidPermissions` if world-writable files
/// are detected (mode has the world-writable bit set).
///
/// # Examples
///
/// ```
/// use exarch_core::SecurityConfig;
/// use exarch_core::security::sanitize_permissions;
/// use std::path::Path;
///
/// let config = SecurityConfig::default();
///
/// // Setuid bit is stripped
/// let sanitized = sanitize_permissions(Path::new("file.txt"), 0o4755, &config).unwrap();
/// assert_eq!(sanitized, 0o755);
///
/// // Setgid bit is stripped
/// let sanitized = sanitize_permissions(Path::new("file.txt"), 0o2755, &config).unwrap();
/// assert_eq!(sanitized, 0o755);
///
/// // Both bits stripped
/// let sanitized = sanitize_permissions(Path::new("file.txt"), 0o6755, &config).unwrap();
/// assert_eq!(sanitized, 0o755);
/// ```
pub fn sanitize_permissions(
    path: &std::path::Path,
    mode: u32,
    config: &SecurityConfig,
) -> Result<u32> {
    let mut sanitized = mode;

    // Strip setuid bit (04000)
    sanitized &= !0o4000;

    // Strip setgid bit (02000)
    sanitized &= !0o2000;

    // M-CODE-1: Check world-writable using config flag
    // Reject world-writable (0002) unless explicitly allowed
    // World-writable files pose security risks in multi-user environments
    if !config.allowed.world_writable && (sanitized & 0o002) != 0 {
        return Err(ExtractionError::InvalidPermissions {
            path: path.to_path_buf(),
            mode: sanitized,
        });
    }

    Ok(sanitized)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_permissions_normal() {
        let config = SecurityConfig::default();
        let result = sanitize_permissions(std::path::Path::new("file.txt"), 0o644, &config);
        assert_eq!(result.unwrap(), 0o644);
    }

    #[test]
    fn test_sanitize_permissions_executable() {
        let config = SecurityConfig::default();
        let result = sanitize_permissions(std::path::Path::new("file.txt"), 0o755, &config);
        assert_eq!(result.unwrap(), 0o755);
    }

    #[test]
    fn test_sanitize_permissions_strip_setuid() {
        let config = SecurityConfig::default();
        let result = sanitize_permissions(std::path::Path::new("file.txt"), 0o4755, &config);
        assert_eq!(result.unwrap(), 0o755);
    }

    #[test]
    fn test_sanitize_permissions_strip_setgid() {
        let config = SecurityConfig::default();
        let result = sanitize_permissions(std::path::Path::new("file.txt"), 0o2755, &config);
        assert_eq!(result.unwrap(), 0o755);
    }

    #[test]
    fn test_sanitize_permissions_strip_both() {
        let config = SecurityConfig::default();
        let result = sanitize_permissions(std::path::Path::new("file.txt"), 0o6755, &config);
        assert_eq!(result.unwrap(), 0o755);
    }

    #[test]
    fn test_sanitize_permissions_reject_world_writable() {
        let config = SecurityConfig::default();
        let result = sanitize_permissions(std::path::Path::new("file.txt"), 0o777, &config);
        assert!(matches!(
            result,
            Err(ExtractionError::InvalidPermissions { .. })
        ));
    }

    #[test]
    fn test_sanitize_permissions_world_readable_ok() {
        let config = SecurityConfig::default();
        let result = sanitize_permissions(std::path::Path::new("file.txt"), 0o644, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sanitize_permissions_owner_writable_ok() {
        let config = SecurityConfig::default();
        let result = sanitize_permissions(std::path::Path::new("file.txt"), 0o600, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sanitize_permissions_group_writable_ok() {
        let config = SecurityConfig::default();
        let result = sanitize_permissions(std::path::Path::new("file.txt"), 0o664, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sanitize_permissions_edge_case_zero() {
        let config = SecurityConfig::default();
        let result = sanitize_permissions(std::path::Path::new("file.txt"), 0o000, &config);
        assert_eq!(result.unwrap(), 0o000);
    }

    // H-TEST-1: Sticky bit handling test
    #[test]
    fn test_sticky_bit_preservation() {
        let config = SecurityConfig::default();

        // Sticky bit (0o1000) should be preserved for directories
        // This is commonly used for /tmp-like directories
        let mode_with_sticky = 0o1755; // rwxr-xr-x with sticky bit
        let result = sanitize_permissions(std::path::Path::new("dir/"), mode_with_sticky, &config);
        assert!(result.is_ok(), "sticky bit should be allowed");

        let sanitized = result.unwrap();
        assert_eq!(
            sanitized & 0o1000,
            0o1000,
            "sticky bit should be preserved"
        );
        assert_eq!(sanitized, 0o1755, "full mode should be preserved");
    }

    #[test]
    fn test_sticky_bit_with_setuid_stripped() {
        let config = SecurityConfig::default();

        // Sticky bit preserved, but setuid/setgid stripped
        let mode = 0o7755; // All special bits
        let result = sanitize_permissions(std::path::Path::new("dir/"), mode, &config);
        assert!(result.is_ok());

        let sanitized = result.unwrap();
        assert_eq!(sanitized & 0o1000, 0o1000, "sticky bit should remain");
        assert_eq!(sanitized & 0o4000, 0, "setuid should be stripped");
        assert_eq!(sanitized & 0o2000, 0, "setgid should be stripped");
        assert_eq!(sanitized, 0o1755, "result should be sticky + rwxr-xr-x");
    }

    // M-CODE-1: Test world-writable with config flag
    #[test]
    fn test_world_writable_allowed_with_config() {
        let mut config = SecurityConfig::default();
        config.allowed.world_writable = true;

        // World-writable should be allowed when config permits
        let result = sanitize_permissions(std::path::Path::new("file.txt"), 0o777, &config);
        assert!(result.is_ok(), "world-writable should be allowed with config");

        let sanitized = result.unwrap();
        assert_eq!(
            sanitized & 0o002,
            0o002,
            "world-writable bit should be preserved"
        );
        // setuid/setgid should still be stripped
        assert_eq!(sanitized & 0o4000, 0, "setuid should be stripped");
        assert_eq!(sanitized & 0o2000, 0, "setgid should be stripped");
        assert_eq!(sanitized, 0o777, "result should be rwxrwxrwx");
    }

    #[test]
    fn test_world_writable_rejected_by_default() {
        let config = SecurityConfig::default();

        // World-writable should be rejected by default
        let result = sanitize_permissions(std::path::Path::new("file.txt"), 0o777, &config);
        assert!(
            matches!(result, Err(ExtractionError::InvalidPermissions { .. })),
            "world-writable should be rejected by default"
        );
    }
}
