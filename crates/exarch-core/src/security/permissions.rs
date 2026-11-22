//! File permission validation and sanitization.

use crate::SecurityConfig;

/// A Unix permission mode exactly as an archive header records it.
///
/// The only consumer is `sanitize_permissions`, so a raw mode cannot be
/// passed where a [`SanitizedMode`] is expected, and the reverse.
///
/// # Examples
///
/// ```
/// use exarch_core::RawMode;
///
/// assert_eq!(RawMode::new(0o4755).get(), 0o4755);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawMode(u32);

impl RawMode {
    /// Wraps the mode bits read from an archive header.
    #[must_use]
    pub const fn new(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the unsanitized bits.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A Unix permission mode that has already passed through
/// `sanitize_permissions`.
///
/// This newtype closes the gap between "a raw mode read from an archive
/// header" and "a mode safe to apply to an extracted file": both are
/// otherwise a plain `u32`, so a caller could pass an unsanitized mode to
/// permission-setting code by mistake, with the invariant living only in a
/// doc comment. `SanitizedMode` can only be constructed by
/// `sanitize_permissions` — its single field is private, so external
/// callers (and other modules in this crate) cannot fabricate one that
/// skipped the setuid/setgid/sticky/world-writable stripping.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "testing")]
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use exarch_core::RawMode;
/// use exarch_core::SecurityConfig;
/// use exarch_core::sanitize_permissions;
///
/// let config = SecurityConfig::default();
///
/// // Setuid bit is stripped
/// let sanitized = sanitize_permissions(RawMode::new(0o4755), &config);
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
/// - Sticky bit (01000): Cleared on regular files, so every format yields the
///   same mode for the same stored bits; it has no effect on a regular file on
///   Linux and a historical one on some BSDs. Directory modes are not restored
///   by any format, so directories are unaffected
/// - World-writable bit (0002): Stripped by default unless
///   `allow_world_writable` is set
///
/// The [`SanitizedMode`] return type is the only way to obtain a sanitized
/// mode in this crate, so a caller cannot accidentally pass a raw,
/// unsanitized mode to internal permission-setting code such as
/// `VettedDir::create_new_deferred`.
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
/// use exarch_core::RawMode;
/// use exarch_core::SecurityConfig;
/// use exarch_core::sanitize_permissions;
///
/// let config = SecurityConfig::default();
///
/// // Setuid bit is stripped
/// let sanitized = sanitize_permissions(RawMode::new(0o4755), &config);
/// assert_eq!(sanitized.as_u32(), 0o755);
///
/// // Setgid bit is stripped
/// let sanitized = sanitize_permissions(RawMode::new(0o2755), &config);
/// assert_eq!(sanitized.as_u32(), 0o755);
///
/// // Both setuid and setgid bits stripped
/// let sanitized = sanitize_permissions(RawMode::new(0o6755), &config);
/// assert_eq!(sanitized.as_u32(), 0o755);
///
/// // Sticky bit is stripped
/// let sanitized = sanitize_permissions(RawMode::new(0o1755), &config);
/// assert_eq!(sanitized.as_u32(), 0o755);
///
/// // World-writable bit is stripped by default
/// let sanitized = sanitize_permissions(RawMode::new(0o777), &config);
/// assert_eq!(sanitized.as_u32(), 0o775);
/// # Ok(())
/// # }
/// # #[cfg(not(feature = "testing"))]
/// # fn main() {}
/// ```
#[must_use]
#[cfg_attr(
    not(feature = "testing"),
    allow(
        unreachable_pub,
        reason = "reachable outside the crate only with the testing feature"
    )
)]
pub fn sanitize_permissions(mode: RawMode, config: &SecurityConfig) -> SanitizedMode {
    let mut sanitized = mode.get();

    // Strip setuid bit (04000)
    sanitized &= !0o4000;

    // Strip setgid bit (02000)
    sanitized &= !0o2000;

    // Strip sticky bit (01000)
    sanitized &= !0o1000;

    // M-CODE-1: Strip world-writable bit (0002) unless explicitly allowed
    if !config.allowed.world_writable.is_allowed() {
        sanitized &= !0o002;
    }

    SanitizedMode(sanitized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_permissions_normal() {
        let config = SecurityConfig::default();
        assert_eq!(
            sanitize_permissions(RawMode::new(0o644), &config).as_u32(),
            0o644
        );
    }

    #[test]
    fn test_sanitize_permissions_executable() {
        let config = SecurityConfig::default();
        assert_eq!(
            sanitize_permissions(RawMode::new(0o755), &config).as_u32(),
            0o755
        );
    }

    #[test]
    fn test_sanitize_permissions_strip_setuid() {
        let config = SecurityConfig::default();
        assert_eq!(
            sanitize_permissions(RawMode::new(0o4755), &config).as_u32(),
            0o755
        );
    }

    #[test]
    fn test_sanitize_permissions_strip_setgid() {
        let config = SecurityConfig::default();
        assert_eq!(
            sanitize_permissions(RawMode::new(0o2755), &config).as_u32(),
            0o755
        );
    }

    #[test]
    fn test_sanitize_permissions_strip_both() {
        let config = SecurityConfig::default();
        assert_eq!(
            sanitize_permissions(RawMode::new(0o6755), &config).as_u32(),
            0o755
        );
    }

    #[test]
    fn test_sanitize_permissions_strip_world_writable() {
        let config = SecurityConfig::default();
        assert_eq!(
            sanitize_permissions(RawMode::new(0o777), &config).as_u32(),
            0o775
        );
    }

    #[test]
    fn test_sanitize_permissions_world_readable_ok() {
        let config = SecurityConfig::default();
        assert_eq!(
            sanitize_permissions(RawMode::new(0o644), &config).as_u32(),
            0o644
        );
    }

    #[test]
    fn test_sanitize_permissions_owner_writable_ok() {
        let config = SecurityConfig::default();
        assert_eq!(
            sanitize_permissions(RawMode::new(0o600), &config).as_u32(),
            0o600
        );
    }

    #[test]
    fn test_sanitize_permissions_group_writable_ok() {
        let config = SecurityConfig::default();
        assert_eq!(
            sanitize_permissions(RawMode::new(0o664), &config).as_u32(),
            0o664
        );
    }

    #[test]
    fn test_sanitize_permissions_edge_case_zero() {
        let config = SecurityConfig::default();
        assert_eq!(
            sanitize_permissions(RawMode::new(0o000), &config).as_u32(),
            0o000
        );
    }

    #[test]
    fn test_sticky_bit_stripped() {
        let config = SecurityConfig::default();
        let sanitized = sanitize_permissions(RawMode::new(0o1755), &config).as_u32();
        assert_eq!(sanitized & 0o1000, 0, "sticky bit should be stripped");
        assert_eq!(sanitized, 0o755, "only the sticky bit should be removed");
    }

    #[test]
    fn test_sticky_bit_stripped_with_setuid_and_setgid() {
        let config = SecurityConfig::default();
        let sanitized = sanitize_permissions(RawMode::new(0o7755), &config).as_u32();
        assert_eq!(sanitized & 0o1000, 0, "sticky should be stripped");
        assert_eq!(sanitized & 0o4000, 0, "setuid should be stripped");
        assert_eq!(sanitized & 0o2000, 0, "setgid should be stripped");
        assert_eq!(sanitized, 0o755, "result should be rwxr-xr-x");
    }

    // M-CODE-1: Test world-writable with config flag
    #[test]
    fn test_world_writable_allowed_with_config() {
        let mut config = SecurityConfig::default();
        config.allowed.world_writable = crate::Admit::Allow;
        let sanitized = sanitize_permissions(RawMode::new(0o777), &config).as_u32();
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
        let config = SecurityConfig::default();
        assert_eq!(
            sanitize_permissions(RawMode::new(0o777), &config).as_u32(),
            0o775,
            "world-writable bit should be stripped by default"
        );
    }

    #[test]
    fn test_world_writable_bit_only_stripped() {
        let config = SecurityConfig::default();
        // 0o666 = rw-rw-rw-, only other-write (0o002) should be stripped ->
        // 0o664
        assert_eq!(
            sanitize_permissions(RawMode::new(0o666), &config).as_u32(),
            0o664,
            "only world-writable bit should be stripped, not group-write"
        );
    }
}
