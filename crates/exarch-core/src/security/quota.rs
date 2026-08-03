//! Extraction quota tracking and validation.

use std::marker::PhantomData;

use crate::ArchiveError;
use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;

/// Proof that a file's size was successfully reserved against a
/// [`QuotaTracker`].
///
/// This is a capability token, not a data type: it carries no payload and
/// exists only so that code holding one can prove a tracker actually
/// authorized the charge. Its only producer is [`QuotaTracker::reserve`] —
/// the private field means no other code, in or out of this crate, can
/// assemble one directly. `EntryValidator` exposes three ways to obtain one,
/// all funneling through that same `reserve` call:
/// [`EntryValidator::validate_entry`] embeds it in
/// [`ValidatedEntryType::File`] for the common case where path validation and
/// quota reservation happen together; its crate-private `reserve_hardlink`
/// and `reserve_file` methods return it standalone for callers that must
/// decouple the two — hardlinks (target size only known in a second pass)
/// and 7z's duplicate-skip check (quota must not be reserved for an entry
/// that turns out to be a skipped duplicate), respectively.
///
/// Deliberately not `Clone`/`Copy`/`Default`: a permit represents a single
/// reservation and must not be duplicated or spent more than once. Zero-sized
/// (`PhantomData`-based), so wrapping it in `Result` costs nothing over
/// `Result<()>`.
///
/// [`ValidatedEntryType::File`]: crate::security::validator::ValidatedEntryType::File
/// [`EntryValidator::validate_entry`]: crate::security::validator::EntryValidator::validate_entry
///
/// # Examples
///
/// The common case: a `QuotaPermit` arrives already embedded in a validated
/// file entry, via [`EntryValidator::validate_entry`]:
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::security::EntryValidator;
/// use exarch_core::security::ValidatedEntryType;
/// use exarch_core::types::DestDir;
/// use exarch_core::types::EntryType;
/// use std::path::Path;
/// use std::path::PathBuf;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dest = DestDir::new(PathBuf::from("/tmp"))?;
/// let config = SecurityConfig::default().validate()?;
/// let mut validator = EntryValidator::new(&config, &dest);
///
/// let entry = validator.validate_entry(
///     Path::new("file.txt"),
///     &EntryType::File,
///     1024, // uncompressed size
///     None, // compressed size
///     None, // mode
///     None, // dir_cache
/// )?;
///
/// if let ValidatedEntryType::File(permit) = entry.entry_type() {
///     println!("{permit:?}");
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
#[must_use]
pub struct QuotaPermit(PhantomData<()>);

/// Tracks resource usage during extraction.
#[derive(Debug, Default)]
pub struct QuotaTracker {
    files_extracted: usize,
    bytes_written: u64,
}

impl QuotaTracker {
    /// Creates a new quota tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserves quota capacity for a file extraction, returning a capability
    /// token that proves the reservation succeeded.
    ///
    /// # Errors
    ///
    /// Returns an error if quotas are exceeded or integer overflow is detected.
    ///
    /// # Performance
    ///
    /// OPT-C003: Fast path for unlimited quotas reduces overhead by 3-5%.
    /// When all quotas are set to maximum values (unlimited), the function
    /// skips quota checks and only tracks counters with overflow detection.
    #[inline]
    pub fn reserve(
        &mut self,
        size: u64,
        config: &SecurityConfig<Validated>,
    ) -> Result<QuotaPermit> {
        // OPT-C003: Fast path when all quotas unlimited - skip checks, only detect
        // overflow
        if config.max_file_size == u64::MAX
            && config.max_file_count == usize::MAX
            && config.max_total_size == u64::MAX
        {
            self.files_extracted = self.files_extracted.checked_add(1).ok_or_else(|| {
                core::hint::cold_path();
                ArchiveError::QuotaExceeded {
                    resource: crate::QuotaResource::IntegerOverflow,
                }
            })?;

            self.bytes_written = self.bytes_written.checked_add(size).ok_or_else(|| {
                core::hint::cold_path();
                ArchiveError::QuotaExceeded {
                    resource: crate::QuotaResource::IntegerOverflow,
                }
            })?;

            return Ok(QuotaPermit(PhantomData));
        }

        self.record_file_checked(size, config)?;
        Ok(QuotaPermit(PhantomData))
    }

    /// Internal implementation with full quota validation.
    ///
    /// This is the slow path called when quotas are actually enforced.
    /// Separated from the fast path to keep the hot path small and inlinable.
    #[inline(never)]
    fn record_file_checked(&mut self, size: u64, config: &SecurityConfig<Validated>) -> Result<()> {
        if size > config.max_file_size {
            core::hint::cold_path();
            return Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileSize {
                    size,
                    max: config.max_file_size,
                },
            });
        }

        self.files_extracted = self.files_extracted.checked_add(1).ok_or_else(|| {
            core::hint::cold_path();
            ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::IntegerOverflow,
            }
        })?;

        self.bytes_written = self.bytes_written.checked_add(size).ok_or_else(|| {
            core::hint::cold_path();
            ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::IntegerOverflow,
            }
        })?;

        if self.files_extracted > config.max_file_count {
            core::hint::cold_path();
            return Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileCount {
                    current: self.files_extracted,
                    max: config.max_file_count,
                },
            });
        }

        if self.bytes_written > config.max_total_size {
            core::hint::cold_path();
            return Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::TotalSize {
                    current: self.bytes_written,
                    max: config.max_total_size,
                },
            });
        }

        Ok(())
    }

    /// Returns the number of files extracted.
    #[must_use]
    pub fn files_extracted(&self) -> usize {
        self.files_extracted
    }

    /// Returns the total bytes written.
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default, clippy::expect_used)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn test_quota_tracker_new() {
        let tracker = QuotaTracker::new();
        assert_eq!(tracker.files_extracted(), 0);
        assert_eq!(tracker.bytes_written(), 0);
    }

    #[test]
    fn test_quota_tracker_reserve() {
        let mut tracker = QuotaTracker::new();
        let config = SecurityConfig::default().validate().expect("valid config");

        assert!(tracker.reserve(1000, &config).is_ok());
        assert_eq!(tracker.files_extracted(), 1);
        assert_eq!(tracker.bytes_written(), 1000);
    }

    #[test]
    fn test_quota_tracker_exceed_file_count() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_count = 2;
        let config = config.validate().expect("valid config");

        assert!(tracker.reserve(100, &config).is_ok());
        assert!(tracker.reserve(100, &config).is_ok());
        let result = tracker.reserve(100, &config);
        assert_matches!(result, Err(ArchiveError::QuotaExceeded { .. }));
    }

    #[test]
    fn test_quota_tracker_exceed_total_size() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_total_size = 1000;
        let config = config.validate().expect("valid config");

        assert!(tracker.reserve(600, &config).is_ok());
        let result = tracker.reserve(500, &config);
        assert_matches!(result, Err(ArchiveError::QuotaExceeded { .. }));
    }

    #[test]
    fn test_quota_tracker_exceed_file_size() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_size = 1000;
        let config = config.validate().expect("valid config");

        let result = tracker.reserve(2000, &config);
        assert_matches!(result, Err(ArchiveError::QuotaExceeded { .. }));
    }

    // H-TEST-4: Quota boundary conditions test
    #[test]
    fn test_quota_exactly_at_file_count_limit() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_count = 3;
        config.max_total_size = u64::MAX;
        config.max_file_size = u64::MAX;
        let config = config.validate().expect("valid config");

        // Exactly at file count limit should succeed
        assert!(
            tracker.reserve(100, &config).is_ok(),
            "file 1 should succeed"
        );
        assert!(
            tracker.reserve(100, &config).is_ok(),
            "file 2 should succeed"
        );
        assert!(
            tracker.reserve(100, &config).is_ok(),
            "file 3 should succeed"
        );
        assert_eq!(tracker.files_extracted(), 3, "should have 3 files");

        // One more should fail (exceeds limit)
        let result = tracker.reserve(100, &config);
        assert_matches!(
            result,
            Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileCount { current: 4, max: 3 }
            }),
            "file 4 should exceed quota"
        );
    }

    #[test]
    fn test_quota_exactly_at_total_size_limit() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_count = 100;
        config.max_total_size = 1000;
        config.max_file_size = u64::MAX;
        let config = config.validate().expect("valid config");

        // Add files up to exactly the limit
        assert!(tracker.reserve(600, &config).is_ok());
        assert_eq!(tracker.bytes_written(), 600);

        assert!(tracker.reserve(400, &config).is_ok());
        assert_eq!(tracker.bytes_written(), 1000, "should be exactly at limit");

        // One more byte should fail
        let result = tracker.reserve(1, &config);
        assert_matches!(
            result,
            Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::TotalSize {
                    current: 1001,
                    max: 1000
                }
            }),
            "exceeding total size should fail"
        );
    }

    #[test]
    fn test_quota_exactly_at_file_size_limit() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_count = 100;
        config.max_total_size = u64::MAX;
        config.max_file_size = 5000;
        let config = config.validate().expect("valid config");

        // File exactly at limit should succeed
        assert!(
            tracker.reserve(5000, &config).is_ok(),
            "file exactly at limit should succeed"
        );

        // File one byte over should fail
        let result = tracker.reserve(5001, &config);
        assert_matches!(
            result,
            Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileSize {
                    size: 5001,
                    max: 5000
                }
            }),
            "file exceeding limit should fail"
        );
    }

    #[test]
    fn test_quota_off_by_one_file_count() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_count = 1;
        config.max_total_size = u64::MAX;
        config.max_file_size = u64::MAX;
        let config = config.validate().expect("valid config");

        // First file should succeed
        assert!(tracker.reserve(100, &config).is_ok());

        // Second file should fail (max is 1)
        let result = tracker.reserve(100, &config);
        assert_matches!(result, Err(ArchiveError::QuotaExceeded { .. }));
    }

    // OPT-C003: Test fast path for unlimited quotas
    #[test]
    fn test_quota_fast_path_unlimited() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        // Set all quotas to unlimited (MAX values)
        config.max_file_size = u64::MAX;
        config.max_file_count = usize::MAX;
        config.max_total_size = u64::MAX;
        let config = config.validate().expect("valid config");

        for i in 1..=1000 {
            assert!(
                tracker.reserve(1000, &config).is_ok(),
                "file {i} should succeed with unlimited quotas"
            );
        }

        assert_eq!(tracker.files_extracted(), 1000);
        assert_eq!(tracker.bytes_written(), 1_000_000);
    }

    // OPT-C003: Verify fast path still catches overflow
    #[test]
    fn test_quota_fast_path_overflow_detection() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_size = u64::MAX;
        config.max_file_count = usize::MAX;
        config.max_total_size = u64::MAX;
        let config = config.validate().expect("valid config");

        // Manually set bytes_written to near overflow
        tracker.bytes_written = u64::MAX - 100;

        // Adding 200 bytes should trigger overflow detection
        let result = tracker.reserve(200, &config);
        assert_matches!(
            result,
            Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::IntegerOverflow
            }),
            "fast path should still detect overflow"
        );
    }
}
