//! Extraction quota tracking and validation.

use std::marker::PhantomData;
use std::num::NonZeroU64;

use crate::ArchiveError;
use crate::Limit;
use crate::Result;
use crate::SecurityConfig;
use crate::security::zipbomb::Uncompressed;

/// Proof that a file's size was successfully reserved against a
/// [`QuotaTracker`].
///
/// This is a capability token that records the byte count it reserved, so the
/// write cap is read from the permit and cannot be re-supplied by a caller
/// that reserved one quantity and enforces another (GHSA-5j8q). Its only
/// producers are [`QuotaTracker::reserve`] and the crate-private
/// `QuotaTracker::charge` — the private field means no other code, in or out of
/// this crate, can assemble one directly. `EntryValidator` exposes three ways
/// to obtain one: [`EntryValidator::validate_entry`] embeds it in
/// [`ValidatedEntryType::File`] for the common case where path validation and
/// quota reservation happen together; its crate-private `charge_hardlink`
/// and `reserve_file` methods return it standalone for callers that must
/// decouple the two — hardlinks (target size only known in a second pass,
/// after [`EntryCount`] counted them in the first) and 7z's duplicate-skip
/// check (quota must not be reserved for an entry that turns out to be a
/// skipped duplicate), respectively.
///
/// Deliberately not `Clone`/`Copy`/`Default`: a permit represents a single
/// reservation and must not be duplicated or spent more than once.
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
/// use exarch_core::security::EntrySize;
/// use exarch_core::security::EntryValidator;
/// use exarch_core::security::Uncompressed;
/// use exarch_core::security::ValidatedEntryType;
/// use exarch_core::types::DestDir;
/// use exarch_core::types::EntryType;
/// use std::path::Path;
/// use std::path::PathBuf;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dest = DestDir::new(PathBuf::from("/tmp"))?;
/// let config = SecurityConfig::default();
/// let mut validator = EntryValidator::new(&config, &dest);
///
/// let entry = validator.validate_entry(
///     Path::new("file.txt"),
///     &EntryType::File,
///     EntrySize::new(Uncompressed(1024), None),
///     None,
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
pub struct QuotaPermit {
    bytes: Uncompressed,
}

impl QuotaPermit {
    const fn new(bytes: u64) -> Self {
        Self {
            bytes: Uncompressed(bytes),
        }
    }

    /// Spends the permit, yielding the byte count it reserved, which is also
    /// the write ceiling.
    pub(crate) const fn into_bytes(self) -> u64 {
        self.bytes.0
    }

    /// Spends the permit, yielding a copyable view of the bytes it reserved
    /// for a sink to read.
    pub(crate) const fn into_admitted(self) -> AdmittedSize {
        AdmittedSize(self.bytes.0)
    }
}

/// The size of a file the pipeline admitted: the bytes a [`QuotaPermit`]
/// reserved for it.
///
/// A read-only, copyable view handed to an [`EntrySink`](crate::EntrySink) so
/// it can tell a size the quota tracker already charged from any other number.
/// Only the pipeline can build one: the field is private and the sole
/// constructor spends a permit.
///
/// # Examples
///
/// ```
/// use exarch_core::AdmittedSize;
///
/// fn capacity_hint(size: AdmittedSize) -> usize {
///     usize::try_from(size.get().min(1 << 16)).unwrap_or(0)
/// }
/// # let _ = capacity_hint;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdmittedSize(u64);

impl AdmittedSize {
    /// The admitted size in bytes.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Proof that one entry was counted against `max_file_count` while its bytes
/// are not yet charged.
///
/// A hardlink's size is only known in the second extraction pass, but the
/// number of entries must be bounded in the first, before anything is
/// buffered or copied. The first pass takes an `EntryCount`; the second spends
/// it in `QuotaTracker::charge`, which adds the bytes without counting the
/// entry again. Holding one therefore makes counting an entry twice, or never,
/// unrepresentable.
///
/// Deliberately not `Clone`/`Copy`/`Default`, and only producible by
/// `QuotaTracker::reserve_count`. Zero-sized.
///
/// # Examples
///
/// A validated hardlink carries its `EntryCount`:
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::security::EntrySize;
/// use exarch_core::security::EntryValidator;
/// use exarch_core::security::Uncompressed;
/// use exarch_core::security::ValidatedEntryType;
/// use exarch_core::types::DestDir;
/// use exarch_core::types::EntryType;
/// use std::path::Path;
/// use std::path::PathBuf;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dest = DestDir::new(PathBuf::from("/tmp"))?;
/// let config = SecurityConfig::default().with_allow_hardlinks(true);
/// let mut validator = EntryValidator::new(&config, &dest);
///
/// let entry = validator.validate_entry(
///     Path::new("link"),
///     &EntryType::Hardlink {
///         target: PathBuf::from("target.txt"),
///     },
///     EntrySize::new(Uncompressed(0), None),
///     None,
/// )?;
///
/// if let ValidatedEntryType::Hardlink { counted, .. } = entry.entry_type() {
///     println!("{counted:?}");
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
#[must_use]
pub struct EntryCount(PhantomData<()>);

/// Tracks resource usage during extraction.
#[derive(Debug, Default)]
pub struct QuotaTracker {
    files_extracted: usize,
    bytes_written: u64,
}

fn check_file_size(size: u64, max: Limit<NonZeroU64>) -> Result<()> {
    if !max.admits(size) {
        core::hint::cold_path();
        return Err(ArchiveError::QuotaExceeded {
            resource: crate::QuotaResource::FileSize {
                size,
                max: max.ceiling(),
            },
        });
    }
    Ok(())
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
    pub fn reserve(&mut self, size: u64, config: &SecurityConfig) -> Result<QuotaPermit> {
        self.reserve_within(size, config.max_file_size, config)
    }

    /// Counts one entry against `max_file_count` without charging any bytes,
    /// returning the token [`charge`](Self::charge) later spends.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::QuotaExceeded`] if the file count limit is
    /// exceeded or the counter overflows.
    pub(crate) fn reserve_count(&mut self, config: &SecurityConfig) -> Result<EntryCount> {
        self.bump_files()?;
        self.check_file_count(config)?;

        Ok(EntryCount(PhantomData))
    }

    /// Charges `size` bytes for an entry already counted by
    /// [`reserve_count`](Self::reserve_count), without counting it again.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::QuotaExceeded`] if `size` exceeds
    /// `max_file_size`, the running total exceeds `max_total_size`, or the
    /// byte counter overflows.
    pub(crate) fn charge(
        &mut self,
        count: EntryCount,
        size: u64,
        config: &SecurityConfig,
    ) -> Result<QuotaPermit> {
        drop(count);

        check_file_size(size, config.max_file_size)?;
        self.add_bytes(size)?;
        self.check_total_size(config)?;

        Ok(QuotaPermit::new(size))
    }

    /// Reserves quota capacity without enforcing the per-file size limit.
    ///
    /// For `verify`'s listing pre-flight only, which must see oversized
    /// entries so `verify_entry` can report them. The file count and total
    /// size limits still apply; extraction must use [`reserve`](Self::reserve).
    ///
    /// # Errors
    ///
    /// Returns an error if the file count or total size quota is exceeded or
    /// integer overflow is detected.
    pub(crate) fn reserve_without_file_limit(
        &mut self,
        size: u64,
        config: &SecurityConfig,
    ) -> Result<QuotaPermit> {
        self.reserve_within(size, Limit::Unbounded, config)
    }

    #[inline]
    fn reserve_within(
        &mut self,
        size: u64,
        max_file_size: Limit<NonZeroU64>,
        config: &SecurityConfig,
    ) -> Result<QuotaPermit> {
        // OPT-C003: Fast path when all quotas unlimited - skip checks, only
        // detect overflow
        if max_file_size == Limit::Unbounded
            && config.max_file_count == Limit::Unbounded
            && config.max_total_size == Limit::Unbounded
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

            return Ok(QuotaPermit::new(size));
        }

        self.record_file_checked(size, max_file_size, config)?;
        Ok(QuotaPermit::new(size))
    }

    /// Internal implementation with full quota validation.
    ///
    /// This is the slow path called when quotas are actually enforced.
    /// Separated from the fast path to keep the hot path small and inlinable.
    #[inline(never)]
    fn record_file_checked(
        &mut self,
        size: u64,
        max_file_size: Limit<NonZeroU64>,
        config: &SecurityConfig,
    ) -> Result<()> {
        check_file_size(size, max_file_size)?;
        self.bump_files()?;
        self.add_bytes(size)?;
        self.check_file_count(config)?;
        self.check_total_size(config)
    }

    fn bump_files(&mut self) -> Result<()> {
        self.files_extracted = self.files_extracted.checked_add(1).ok_or_else(|| {
            core::hint::cold_path();
            ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::IntegerOverflow,
            }
        })?;
        Ok(())
    }

    fn add_bytes(&mut self, size: u64) -> Result<()> {
        self.bytes_written = self.bytes_written.checked_add(size).ok_or_else(|| {
            core::hint::cold_path();
            ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::IntegerOverflow,
            }
        })?;
        Ok(())
    }

    fn check_file_count(&self, config: &SecurityConfig) -> Result<()> {
        if !config.max_file_count.admits(self.files_extracted) {
            core::hint::cold_path();
            return Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileCount {
                    current: self.files_extracted,
                    max: config.max_file_count.ceiling(),
                },
            });
        }
        Ok(())
    }

    fn check_total_size(&self, config: &SecurityConfig) -> Result<()> {
        if !config.max_total_size.admits(self.bytes_written) {
            core::hint::cold_path();
            return Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::TotalSize {
                    current: self.bytes_written,
                    max: config.max_total_size.ceiling(),
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
    fn permit_carries_the_reserved_size() {
        let mut tracker = QuotaTracker::new();
        let config = SecurityConfig::default();

        let permit = tracker.reserve(1234, &config).expect("within quota");

        assert_eq!(permit.into_bytes(), 1234);
    }

    #[test]
    fn test_quota_tracker_reserve() {
        let mut tracker = QuotaTracker::new();
        let config = SecurityConfig::default();

        assert!(tracker.reserve(1000, &config).is_ok());
        assert_eq!(tracker.files_extracted(), 1);
        assert_eq!(tracker.bytes_written(), 1000);
    }

    #[test]
    fn test_quota_tracker_exceed_file_count() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_count = crate::Limit::Bounded(crate::non_zero!(2));

        assert!(tracker.reserve(100, &config).is_ok());
        assert!(tracker.reserve(100, &config).is_ok());
        let result = tracker.reserve(100, &config);
        assert_matches!(result, Err(ArchiveError::QuotaExceeded { .. }));
    }

    #[test]
    fn test_quota_tracker_exceed_total_size() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_total_size = crate::Limit::Bounded(crate::non_zero!(1000));

        assert!(tracker.reserve(600, &config).is_ok());
        let result = tracker.reserve(500, &config);
        assert_matches!(result, Err(ArchiveError::QuotaExceeded { .. }));
    }

    #[test]
    fn test_quota_tracker_exceed_file_size() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_size = crate::Limit::Bounded(crate::non_zero!(1000));

        let result = tracker.reserve(2000, &config);
        assert_matches!(result, Err(ArchiveError::QuotaExceeded { .. }));
    }

    // H-TEST-4: Quota boundary conditions test
    #[test]
    fn test_quota_exactly_at_file_count_limit() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_count = crate::Limit::Bounded(crate::non_zero!(3));
        config.max_total_size = crate::Limit::Unbounded;
        config.max_file_size = crate::Limit::Unbounded;

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
        config.max_file_count = crate::Limit::Bounded(crate::non_zero!(100));
        config.max_total_size = crate::Limit::Bounded(crate::non_zero!(1000));
        config.max_file_size = crate::Limit::Unbounded;

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
        config.max_file_count = crate::Limit::Bounded(crate::non_zero!(100));
        config.max_total_size = crate::Limit::Unbounded;
        config.max_file_size = crate::Limit::Bounded(crate::non_zero!(5000));

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
        config.max_file_count = crate::Limit::Bounded(crate::non_zero!(1));
        config.max_total_size = crate::Limit::Unbounded;
        config.max_file_size = crate::Limit::Unbounded;

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
        config.max_file_size = crate::Limit::Unbounded;
        config.max_file_count = crate::Limit::Unbounded;
        config.max_total_size = crate::Limit::Unbounded;

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
        config.max_file_size = crate::Limit::Unbounded;
        config.max_file_count = crate::Limit::Unbounded;
        config.max_total_size = crate::Limit::Unbounded;

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

    #[test]
    fn test_reserve_without_file_limit_skips_only_file_size() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_size = crate::Limit::Bounded(crate::non_zero!(10));
        config.max_file_count = crate::Limit::Bounded(crate::non_zero!(2));
        config.max_total_size = crate::Limit::Bounded(crate::non_zero!(1000));

        assert_matches!(
            tracker.reserve(500, &config),
            Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileSize { size: 500, max: 10 }
            })
        );
        assert!(tracker.reserve_without_file_limit(500, &config).is_ok());
        assert_matches!(
            tracker.reserve_without_file_limit(501, &config),
            Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::TotalSize {
                    current: 1001,
                    max: 1000
                }
            })
        );
    }

    #[test]
    fn test_reserve_without_file_limit_enforces_file_count() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_size = crate::Limit::Bounded(crate::non_zero!(10));
        config.max_file_count = crate::Limit::Bounded(crate::non_zero!(1));

        assert!(tracker.reserve_without_file_limit(500, &config).is_ok());
        assert_matches!(
            tracker.reserve_without_file_limit(500, &config),
            Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileCount { current: 2, max: 1 }
            })
        );
    }

    #[test]
    fn test_reserve_without_file_limit_fast_path_accepts_oversized_file() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_size = crate::Limit::Bounded(crate::non_zero!(10));
        config.max_file_count = crate::Limit::Unbounded;
        config.max_total_size = crate::Limit::Unbounded;

        assert!(tracker.reserve(500, &config).is_err());
        assert!(tracker.reserve_without_file_limit(500, &config).is_ok());
        assert_eq!(tracker.files_extracted(), 1);
        assert_eq!(tracker.bytes_written(), 500);
    }

    #[test]
    fn test_reserve_without_file_limit_fast_path_detects_overflow() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_size = crate::Limit::Bounded(crate::non_zero!(10));
        config.max_file_count = crate::Limit::Unbounded;
        config.max_total_size = crate::Limit::Unbounded;

        tracker.bytes_written = u64::MAX - 100;
        assert_matches!(
            tracker.reserve_without_file_limit(200, &config),
            Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::IntegerOverflow
            })
        );
    }

    #[test]
    fn test_charge_adds_bytes_without_counting_again() {
        let mut tracker = QuotaTracker::new();
        let config = SecurityConfig::default();

        let count = tracker.reserve_count(&config).expect("count");
        assert_eq!(tracker.files_extracted(), 1);
        assert_eq!(tracker.bytes_written(), 0);

        drop(tracker.charge(count, 40, &config).expect("charge"));
        assert_eq!(tracker.files_extracted(), 1);
        assert_eq!(tracker.bytes_written(), 40);
    }

    #[test]
    fn test_reserve_count_exceeds_file_count() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_count = crate::Limit::Bounded(crate::non_zero!(1));

        let _first = tracker.reserve_count(&config).expect("first");
        assert_matches!(
            tracker.reserve_count(&config),
            Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileCount { current: 2, max: 1 }
            })
        );
    }

    #[test]
    fn test_charge_enforces_file_and_total_size() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_size = crate::Limit::Bounded(crate::non_zero!(100));
        config.max_total_size = crate::Limit::Bounded(crate::non_zero!(150));

        let a = tracker.reserve_count(&config).expect("a");
        let b = tracker.reserve_count(&config).expect("b");
        let c = tracker.reserve_count(&config).expect("c");

        assert_matches!(
            tracker.charge(a, 101, &config),
            Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileSize { .. }
            })
        );
        drop(tracker.charge(b, 100, &config).expect("within budget"));
        assert_matches!(
            tracker.charge(c, 100, &config),
            Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::TotalSize { .. }
            })
        );
    }
}
