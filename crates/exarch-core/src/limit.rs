//! Typed configuration limits.
//!
//! A limit is either a positive bound or no bound at all. [`Limit`] and
//! [`RatioLimit`] make a zero limit or a non-positive ratio unrepresentable, so
//! no later check has to reject one and no sentinel value (`u64::MAX`) has to
//! stand for "unbounded".

use std::num::NonZeroU64;
use std::num::NonZeroUsize;

use crate::ArchiveError;
use crate::ConfigProblem;
use crate::ConfigSetting;
use crate::Result;

/// Builds a [`NonZero`](std::num::NonZero) value from a constant, failing the
/// build when the constant is zero.
///
/// # Examples
///
/// ```
/// use std::num::NonZeroU64;
///
/// let limit: NonZeroU64 = exarch_core::non_zero!(1024);
/// assert_eq!(limit.get(), 1024);
/// ```
///
/// A zero constant does not compile:
///
/// ```compile_fail
/// let _: std::num::NonZeroU64 = exarch_core::non_zero!(0);
/// ```
#[macro_export]
macro_rules! non_zero {
    ($value:expr) => {
        const {
            match ::std::num::NonZero::new($value) {
                ::std::option::Option::Some(value) => value,
                ::std::option::Option::None => panic!("non_zero! needs a non-zero value"),
            }
        }
    };
}

/// Builds a [`RatioLimit`] from a constant, failing the build when it is not
/// finite and positive.
///
/// # Examples
///
/// ```
/// let ratio = exarch_core::ratio_limit!(50.0);
/// assert_eq!(ratio.get(), 50.0);
/// ```
///
/// A non-positive constant does not compile:
///
/// ```compile_fail
/// let _ = exarch_core::ratio_limit!(0.0);
/// ```
#[macro_export]
macro_rules! ratio_limit {
    ($value:expr) => {
        const {
            match $crate::RatioLimit::new($value) {
                ::std::option::Option::Some(ratio) => ratio,
                ::std::option::Option::None => {
                    panic!("ratio_limit! needs a finite, positive value")
                }
            }
        }
    };
}

/// A positive bound, or no bound.
///
/// # Examples
///
/// ```
/// use exarch_core::Limit;
/// use exarch_core::non_zero;
/// use std::num::NonZeroU64;
///
/// let bounded: Limit<NonZeroU64> = non_zero!(10).into();
/// assert!(bounded.admits(10));
/// assert!(!bounded.admits(11));
/// assert!(Limit::<NonZeroU64>::Unbounded.admits(u64::MAX));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Limit<T> {
    /// At most this many.
    Bounded(T),
    /// No bound.
    Unbounded,
}

const _: () = assert!(size_of::<Limit<NonZeroU64>>() == size_of::<u64>());

impl<T> From<T> for Limit<T> {
    fn from(bound: T) -> Self {
        Self::Bounded(bound)
    }
}

impl Limit<NonZeroU64> {
    /// Whether `value` is within the limit.
    #[must_use]
    pub const fn admits(self, value: u64) -> bool {
        match self {
            Self::Bounded(bound) => value <= bound.get(),
            Self::Unbounded => true,
        }
    }

    /// The bound as a number, `u64::MAX` when unbounded, for reporting.
    #[must_use]
    pub const fn ceiling(self) -> u64 {
        match self {
            Self::Bounded(bound) => bound.get(),
            Self::Unbounded => u64::MAX,
        }
    }

    /// Parses a runtime value, refusing zero.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidConfiguration`] naming `setting` when
    /// `value` is zero.
    pub fn parse(setting: ConfigSetting, value: u64) -> Result<Self> {
        non_zero_u64(setting, value).map(Self::Bounded)
    }
}

impl Limit<NonZeroUsize> {
    /// Whether `value` is within the limit.
    #[must_use]
    pub const fn admits(self, value: usize) -> bool {
        match self {
            Self::Bounded(bound) => value <= bound.get(),
            Self::Unbounded => true,
        }
    }

    /// The bound as a number, `usize::MAX` when unbounded, for reporting.
    #[must_use]
    pub const fn ceiling(self) -> usize {
        match self {
            Self::Bounded(bound) => bound.get(),
            Self::Unbounded => usize::MAX,
        }
    }

    /// Parses a runtime value, refusing zero.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidConfiguration`] naming `setting` when
    /// `value` is zero.
    pub fn parse(setting: ConfigSetting, value: usize) -> Result<Self> {
        non_zero_usize(setting, value).map(Self::Bounded)
    }
}

/// Parses a runtime byte count, refusing zero.
///
/// # Errors
///
/// Returns [`ArchiveError::InvalidConfiguration`] naming `setting` when `value`
/// is zero.
pub fn non_zero_u64(setting: ConfigSetting, value: u64) -> Result<NonZeroU64> {
    NonZeroU64::new(value).ok_or(ArchiveError::InvalidConfiguration {
        setting,
        problem: ConfigProblem::Zero,
    })
}

/// Parses a signed integer from a binding, refusing zero, negative values and
/// values above `u64::MAX`.
///
/// # Errors
///
/// Returns [`ArchiveError::InvalidConfiguration`] naming `setting` with
/// [`ConfigProblem::Negative`], [`ConfigProblem::Zero`] or
/// [`ConfigProblem::TooLarge`].
///
/// # Examples
///
/// ```
/// use exarch_core::ConfigSetting;
/// use exarch_core::positive_from_i128;
///
/// assert_eq!(positive_from_i128(ConfigSetting::MaxBytes, 7)?.get(), 7);
/// assert!(positive_from_i128(ConfigSetting::MaxBytes, -1).is_err());
/// assert!(positive_from_i128(ConfigSetting::MaxBytes, 0).is_err());
/// assert!(positive_from_i128(ConfigSetting::MaxBytes, i128::from(u64::MAX) + 1).is_err());
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
pub fn positive_from_i128(setting: ConfigSetting, value: i128) -> Result<NonZeroU64> {
    let refuse = |problem| ArchiveError::InvalidConfiguration { setting, problem };
    if value < 0 {
        return Err(refuse(ConfigProblem::Negative));
    }
    let value =
        u64::try_from(value).map_err(|_| refuse(ConfigProblem::TooLarge { max: u64::MAX }))?;
    non_zero_u64(setting, value)
}

/// The largest whole number an `f64` holds exactly (2^53 - 1), which is also
/// `Number.MAX_SAFE_INTEGER`.
const MAX_EXACT_F64: u64 = (1 << 53) - 1;

/// Parses a floating-point number from a binding (a JavaScript number) into a
/// positive whole count of at most 2^53 - 1.
///
/// # Errors
///
/// Returns [`ArchiveError::InvalidConfiguration`] naming `setting` with
/// [`ConfigProblem::NotFinite`], [`ConfigProblem::Negative`],
/// [`ConfigProblem::Zero`], [`ConfigProblem::NotWholeNumber`] or
/// [`ConfigProblem::TooLarge`].
///
/// # Examples
///
/// ```
/// use exarch_core::ConfigSetting;
/// use exarch_core::positive_from_f64;
///
/// assert_eq!(positive_from_f64(ConfigSetting::MaxBytes, 12.0)?.get(), 12);
/// for bad in [
///     f64::NAN,
///     f64::INFINITY,
///     -1.0,
///     0.0,
///     1.5,
///     9_007_199_254_740_992.0,
/// ] {
///     assert!(positive_from_f64(ConfigSetting::MaxBytes, bad).is_err());
/// }
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "value is a whole number in 1..=2^53-1 after the checks"
)]
pub fn positive_from_f64(setting: ConfigSetting, value: f64) -> Result<NonZeroU64> {
    let refuse = |problem| ArchiveError::InvalidConfiguration { setting, problem };
    if !value.is_finite() {
        return Err(refuse(ConfigProblem::NotFinite));
    }
    if value < 0.0 {
        return Err(refuse(ConfigProblem::Negative));
    }
    if value == 0.0 {
        return Err(refuse(ConfigProblem::Zero));
    }
    if value.fract() != 0.0 {
        return Err(refuse(ConfigProblem::NotWholeNumber));
    }
    if value > MAX_EXACT_F64 as f64 {
        return Err(refuse(ConfigProblem::TooLarge { max: MAX_EXACT_F64 }));
    }
    non_zero_u64(setting, value as u64)
}

/// Parses a runtime count, refusing zero.
///
/// # Errors
///
/// Returns [`ArchiveError::InvalidConfiguration`] naming `setting` when `value`
/// is zero.
pub fn non_zero_usize(setting: ConfigSetting, value: usize) -> Result<NonZeroUsize> {
    NonZeroUsize::new(value).ok_or(ArchiveError::InvalidConfiguration {
        setting,
        problem: ConfigProblem::Zero,
    })
}

/// A compression ratio limit: finite and greater than zero.
///
/// # Examples
///
/// ```
/// use exarch_core::ConfigSetting;
/// use exarch_core::RatioLimit;
///
/// let ratio = RatioLimit::parse(ConfigSetting::MaxCompressionRatio, 50.0)?;
/// assert_eq!(ratio.get(), 50.0);
/// assert!(RatioLimit::parse(ConfigSetting::MaxCompressionRatio, 0.0).is_err());
/// assert!(RatioLimit::parse(ConfigSetting::MaxCompressionRatio, f64::NAN).is_err());
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RatioLimit(f64);

impl RatioLimit {
    /// Parses a runtime ratio.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidConfiguration`] naming `setting` when
    /// `ratio` is not finite ([`ConfigProblem::NotFinite`]), is negative
    /// ([`ConfigProblem::Negative`]) or is zero ([`ConfigProblem::Zero`]).
    pub fn parse(setting: ConfigSetting, ratio: f64) -> Result<Self> {
        let problem = if !ratio.is_finite() {
            ConfigProblem::NotFinite
        } else if ratio < 0.0 {
            ConfigProblem::Negative
        } else {
            ConfigProblem::Zero
        };
        Self::new(ratio).ok_or(ArchiveError::InvalidConfiguration { setting, problem })
    }

    /// The ratio.
    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }

    /// A ratio from a constant: `None` unless `ratio` is finite and positive.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::RatioLimit;
    ///
    /// assert_eq!(RatioLimit::new(100.0).map(RatioLimit::get), Some(100.0));
    /// assert!(RatioLimit::new(f64::NAN).is_none());
    /// ```
    #[must_use]
    pub const fn new(ratio: f64) -> Option<Self> {
        if ratio.is_finite() && ratio > 0.0 {
            Some(Self(ratio))
        } else {
            None
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_refused_with_its_setting() {
        let err = Limit::<NonZeroU64>::parse(ConfigSetting::MaxFileSize, 0).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid configuration: max_file_size must not be zero"
        );
        assert!(Limit::<NonZeroUsize>::parse(ConfigSetting::MaxFileCount, 0).is_err());
    }

    #[test]
    fn limits_admit_up_to_the_bound() {
        let limit = Limit::<NonZeroU64>::parse(ConfigSetting::MaxFileSize, 7).unwrap();
        assert!(limit.admits(7));
        assert!(!limit.admits(8));
    }

    #[test]
    fn ratios_must_be_finite_and_positive() {
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert!(RatioLimit::parse(ConfigSetting::MaxCompressionRatio, bad).is_err());
        }
    }
}
