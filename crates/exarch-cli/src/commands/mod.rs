//! Command implementations.

pub mod completion;
pub mod create;
pub mod extract;
pub mod list;
pub mod verify;

use exarch_core::SecurityConfig;

/// Applies CLI-provided size-limit overrides to a [`SecurityConfig`],
/// leaving `SecurityConfig::default()`'s own limits in place when an
/// override is not supplied.
pub fn apply_size_limits(
    config: SecurityConfig,
    max_total: Option<u64>,
    max_file: Option<u64>,
) -> SecurityConfig {
    let config = match max_total {
        Some(v) => config.with_max_total_size(v),
        None => config,
    };
    match max_file {
        Some(v) => config.with_max_file_size(v),
        None => config,
    }
}

#[cfg(test)]
mod tests {
    use super::apply_size_limits;
    use exarch_core::SecurityConfig;

    #[test]
    fn both_none_keeps_defaults() {
        let defaults = SecurityConfig::default();
        let (default_total, default_file) = (defaults.max_total_size, defaults.max_file_size);

        let config = apply_size_limits(SecurityConfig::default(), None, None);

        assert_eq!(config.max_total_size, default_total);
        assert_eq!(config.max_file_size, default_file);
    }

    #[test]
    fn both_some_overrides_both() {
        let config = apply_size_limits(
            SecurityConfig::default(),
            Some(10 * 1024 * 1024 * 1024),
            Some(1024 * 1024 * 1024),
        );

        assert_eq!(config.max_total_size, 10 * 1024 * 1024 * 1024);
        assert_eq!(config.max_file_size, 1024 * 1024 * 1024);
    }

    #[test]
    fn total_some_file_none_overrides_only_total() {
        let default_file = SecurityConfig::default().max_file_size;

        let config = apply_size_limits(SecurityConfig::default(), Some(1024), None);

        assert_eq!(config.max_total_size, 1024);
        assert_eq!(config.max_file_size, default_file);
    }

    #[test]
    fn total_none_file_some_overrides_only_file() {
        let default_total = SecurityConfig::default().max_total_size;

        let config = apply_size_limits(SecurityConfig::default(), None, Some(2048));

        assert_eq!(config.max_total_size, default_total);
        assert_eq!(config.max_file_size, 2048);
    }
}
