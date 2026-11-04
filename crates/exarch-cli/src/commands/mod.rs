//! Command implementations.

mod atomic_swap;
pub mod completion;
pub mod create;
pub mod extract;
pub mod list;
pub mod verify;

use exarch_core::ArchiveError;
use exarch_core::ConfigSetting;
use exarch_core::Limit;
use exarch_core::SecurityConfig;

/// Builds the default [`SecurityConfig`] with the CLI-provided count and
/// size-limit overrides, leaving the default size limits in place when an
/// override is not supplied.
///
/// # Errors
///
/// Returns `InvalidConfiguration` naming the setting when a limit is zero.
pub fn apply_size_limits(
    max_files: usize,
    max_total: Option<u64>,
    max_file: Option<u64>,
) -> Result<SecurityConfig, ArchiveError> {
    let config = SecurityConfig::default().with_max_file_count(
        Limit::<std::num::NonZeroUsize>::parse(ConfigSetting::MaxFileCount, max_files)?,
    );
    let config = match max_total {
        Some(v) => config.with_max_total_size(Limit::<std::num::NonZeroU64>::parse(
            ConfigSetting::MaxTotalSize,
            v,
        )?),
        None => config,
    };
    Ok(match max_file {
        Some(v) => config.with_max_file_size(Limit::<std::num::NonZeroU64>::parse(
            ConfigSetting::MaxFileSize,
            v,
        )?),
        None => config,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::apply_size_limits;
    use exarch_core::SecurityConfig;

    const FILES: usize = 10_000;

    #[test]
    fn both_none_keeps_defaults() {
        let defaults = SecurityConfig::default();
        let config = apply_size_limits(FILES, None, None).unwrap();

        assert_eq!(config.max_total_size, defaults.max_total_size);
        assert_eq!(config.max_file_size, defaults.max_file_size);
        assert_eq!(config.max_file_count.ceiling(), FILES);
    }

    #[test]
    fn both_some_overrides_both() {
        let config = apply_size_limits(
            FILES,
            Some(10 * 1024 * 1024 * 1024),
            Some(1024 * 1024 * 1024),
        )
        .unwrap();

        assert_eq!(config.max_total_size.ceiling(), 10 * 1024 * 1024 * 1024);
        assert_eq!(config.max_file_size.ceiling(), 1024 * 1024 * 1024);
    }

    #[test]
    fn total_some_file_none_overrides_only_total() {
        let default_file = SecurityConfig::default().max_file_size;

        let config = apply_size_limits(FILES, Some(1024), None).unwrap();

        assert_eq!(config.max_total_size.ceiling(), 1024);
        assert_eq!(config.max_file_size, default_file);
    }

    #[test]
    fn total_none_file_some_overrides_only_file() {
        let default_total = SecurityConfig::default().max_total_size;

        let config = apply_size_limits(FILES, None, Some(2048)).unwrap();

        assert_eq!(config.max_total_size, default_total);
        assert_eq!(config.max_file_size.ceiling(), 2048);
    }

    #[test]
    fn a_zero_limit_names_its_setting() {
        for (files, total, file, setting) in [
            (0, None, None, "max_file_count"),
            (FILES, Some(0), None, "max_total_size"),
            (FILES, None, Some(0), "max_file_size"),
        ] {
            let err = apply_size_limits(files, total, file).unwrap_err();
            assert_eq!(err.ffi_kind().setting().unwrap().as_str(), setting);
        }
    }
}
