//! File permission validation and sanitization.

use crate::SecurityConfig;
use crate::config::Validated;

/// A Unix permission mode that has already passed through
/// [`sanitize_permissions`].
///
/// This newtype closes the gap between "a raw mode read from an archive
/// header" and "a mode safe to apply to an extracted file": both are
/// otherwise a plain `u32`, so a caller could pass an unsanitized mode to
/// permission-setting code by mistake, with the invariant living only in a
/// doc comment. `SanitizedMode` can only be constructed by
/// [`sanitize_permissions`] — its single field is private, so external
/// callers (and other modules in this crate) cannot fabricate one that
/// skipped the setuid/setgid/world-writable stripping.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "testing")]
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use exarch_core::SecurityConfig;
/// use exarch_core::security::sanitize_permissions;
///
/// let config = SecurityConfig::default().validate()?;
///
/// // Setuid bit is stripped
/// let sanitized = sanitize_permissions(0o4755, &config);
/// assert_eq!(sanitized.as_u32(), 0o755);
/// # Ok(())
/// # }
/// # #[cfg(not(feature = "testing"))]
/// # fn main() {}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SanitizedMode(u32);

impl SanitizedMode {
    /// Returns the sanitized mode as a raw Unix permission bitmask.
    #[inline]
    #[must_use]
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

/// Sanitizes file permissions by stripping dangerous bits.
///
/// This function removes security-sensitive permission bits that could
/// lead to privilege escalation:
/// - Setuid bit (04000): Allows execution with file owner's privileges
/// - Setgid bit (02000): Allows execution with file group's privileges
/// - World-writable bit (0002): Stripped by default unless
///   `allow_world_writable` is set
///
/// The [`SanitizedMode`] return type is the only way to obtain a sanitized
/// mode in this crate, so a caller cannot accidentally pass a raw,
/// unsanitized mode to internal permission-setting code such as
/// `create_file_with_mode`.
///
/// # Performance
///
/// This is a pure computation with no I/O. Typical execution time: <10 ns.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "testing")]
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use exarch_core::SecurityConfig;
/// use exarch_core::security::sanitize_permissions;
///
/// let config = SecurityConfig::default().validate()?;
///
/// // Setuid bit is stripped
/// let sanitized = sanitize_permissions(0o4755, &config);
/// assert_eq!(sanitized.as_u32(), 0o755);
///
/// // Setgid bit is stripped
/// let sanitized = sanitize_permissions(0o2755, &config);
/// assert_eq!(sanitized.as_u32(), 0o755);
///
/// // Both setuid and setgid bits stripped
/// let sanitized = sanitize_permissions(0o6755, &config);
/// assert_eq!(sanitized.as_u32(), 0o755);
///
/// // World-writable bit is stripped by default
/// let sanitized = sanitize_permissions(0o777, &config);
/// assert_eq!(sanitized.as_u32(), 0o775);
/// # Ok(())
/// # }
/// # #[cfg(not(feature = "testing"))]
/// # fn main() {}
/// ```
#[must_use]
pub fn sanitize_permissions(mode: u32, config: &SecurityConfig<Validated>) -> SanitizedMode {
    let mut sanitized = mode;

    // Strip setuid bit (04000)
    sanitized &= !0o4000;

    // Strip setgid bit (02000)
    sanitized &= !0o2000;

    // M-CODE-1: Strip world-writable bit (0002) unless explicitly allowed
    if !config.allowed.world_writable {
        sanitized &= !0o002;
    }

    SanitizedMode(sanitized)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_permissions_normal() {
        let config = SecurityConfig::default().validate().expect("valid config");
        assert_eq!(sanitize_permissions(0o644, &config).as_u32(), 0o644);
    }

    #[test]
    fn test_sanitize_permissions_executable() {
        let config = SecurityConfig::default().validate().expect("valid config");
        assert_eq!(sanitize_permissions(0o755, &config).as_u32(), 0o755);
    }

    #[test]
    fn test_sanitize_permissions_strip_setuid() {
        let config = SecurityConfig::default().validate().expect("valid config");
        assert_eq!(sanitize_permissions(0o4755, &config).as_u32(), 0o755);
    }

    #[test]
    fn test_sanitize_permissions_strip_setgid() {
        let config = SecurityConfig::default().validate().expect("valid config");
        assert_eq!(sanitize_permissions(0o2755, &config).as_u32(), 0o755);
    }

    #[test]
    fn test_sanitize_permissions_strip_both() {
        let config = SecurityConfig::default().validate().expect("valid config");
        assert_eq!(sanitize_permissions(0o6755, &config).as_u32(), 0o755);
    }

    #[test]
    fn test_sanitize_permissions_strip_world_writable() {
        let config = SecurityConfig::default().validate().expect("valid config");
        assert_eq!(sanitize_permissions(0o777, &config).as_u32(), 0o775);
    }

    #[test]
    fn test_sanitize_permissions_world_readable_ok() {
        let config = SecurityConfig::default().validate().expect("valid config");
        assert_eq!(sanitize_permissions(0o644, &config).as_u32(), 0o644);
    }

    #[test]
    fn test_sanitize_permissions_owner_writable_ok() {
        let config = SecurityConfig::default().validate().expect("valid config");
        assert_eq!(sanitize_permissions(0o600, &config).as_u32(), 0o600);
    }

    #[test]
    fn test_sanitize_permissions_group_writable_ok() {
        let config = SecurityConfig::default().validate().expect("valid config");
        assert_eq!(sanitize_permissions(0o664, &config).as_u32(), 0o664);
    }

    #[test]
    fn test_sanitize_permissions_edge_case_zero() {
        let config = SecurityConfig::default().validate().expect("valid config");
        assert_eq!(sanitize_permissions(0o000, &config).as_u32(), 0o000);
    }

    #[test]
    fn test_sticky_bit_preservation() {
        let config = SecurityConfig::default().validate().expect("valid config");
        let sanitized = sanitize_permissions(0o1755, &config).as_u32();
        assert_eq!(sanitized & 0o1000, 0o1000, "sticky bit should be preserved");
        assert_eq!(sanitized, 0o1755, "full mode should be preserved");
    }

    #[test]
    fn test_sticky_bit_with_setuid_stripped() {
        let config = SecurityConfig::default().validate().expect("valid config");
        let sanitized = sanitize_permissions(0o7755, &config).as_u32();
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
        let config = config.validate().expect("valid config");
        let sanitized = sanitize_permissions(0o777, &config).as_u32();
        assert_eq!(
            sanitized & 0o002,
            0o002,
            "world-writable bit should be preserved"
        );
        assert_eq!(sanitized & 0o4000, 0, "setuid should be stripped");
        assert_eq!(sanitized & 0o2000, 0, "setgid should be stripped");
        assert_eq!(sanitized, 0o777, "result should be rwxrwxrwx");
    }

    #[test]
    fn test_world_writable_stripped_by_default() {
        let config = SecurityConfig::default().validate().expect("valid config");
        assert_eq!(
            sanitize_permissions(0o777, &config).as_u32(),
            0o775,
            "world-writable bit should be stripped by default"
        );
    }

    #[test]
    fn test_world_writable_bit_only_stripped() {
        let config = SecurityConfig::default().validate().expect("valid config");
        // 0o666 = rw-rw-rw-, only other-write (0o002) should be stripped -> 0o664
        assert_eq!(
            sanitize_permissions(0o666, &config).as_u32(),
            0o664,
            "only world-writable bit should be stripped, not group-write"
        );
    }
}
