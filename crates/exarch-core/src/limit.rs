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
    /// `ratio` is not finite or not greater than zero.
    pub fn parse(setting: ConfigSetting, ratio: f64) -> Result<Self> {
        if ratio.is_finite() && ratio > 0.0 {
            Ok(Self(ratio))
        } else {
            Err(ArchiveError::InvalidConfiguration {
                setting,
                problem: ConfigProblem::NotPositive,
            })
        }
    }

    /// The ratio.
    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }

    /// A ratio from a constant, failing the build when it is not finite and
    /// positive.
    ///
    /// # Panics
    ///
    /// Panics when `ratio` is not finite and positive; in a `const` that is a
    /// compile error.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::RatioLimit;
    ///
    /// const LIMIT: RatioLimit = RatioLimit::constant(100.0);
    /// assert_eq!(LIMIT.get(), 100.0);
    /// ```
    #[must_use]
    pub const fn constant(ratio: f64) -> Self {
        assert!(
            ratio.is_finite() && ratio > 0.0,
            "a ratio limit must be finite and positive"
        );
        Self(ratio)
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
