//! Declarative table for enums whose variants have a stable string form.

use crate::ArchiveError;
use crate::ConfigProblem;
use crate::ConfigSetting;
use crate::Result;

pub(crate) mod private {
    pub trait Sealed {}
}

/// An enum with a fixed set of variants and a stable string form for each.
///
/// Implemented only inside this crate, by the table macro behind every closed
/// enum, so a front end can parse the string of any of them through one typed
/// entry point instead of matching strings itself.
///
/// # Examples
///
/// ```
/// use exarch_core::ClosedEnum;
/// use exarch_core::ConfigSetting;
/// use exarch_core::ZipConsistencyPolicy;
///
/// let policy = ZipConsistencyPolicy::parse_for(ConfigSetting::ZipConsistency, "ignore")?;
/// assert_eq!(policy, ZipConsistencyPolicy::Ignore);
/// assert!(ZipConsistencyPolicy::parse_for(ConfigSetting::ZipConsistency, "x").is_err());
/// assert_eq!(ZipConsistencyPolicy::NAMES, &["enforce", "ignore"]);
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
pub trait ClosedEnum: Copy + 'static + private::Sealed {
    /// Every variant, in declaration order.
    const ALL: &'static [Self];

    /// The string form of every variant, in declaration order.
    const NAMES: &'static [&'static str];

    /// The stable string form of this variant.
    fn as_str(self) -> &'static str;

    /// Parses the string form of a variant.
    ///
    /// # Errors
    ///
    /// [`ArchiveError::InvalidConfiguration`] naming `setting` with
    /// [`ConfigProblem::NotOneOf`] listing [`NAMES`](Self::NAMES) for any other
    /// string.
    fn parse_for(setting: ConfigSetting, value: &str) -> Result<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|variant| variant.as_str() == value)
            .ok_or(ArchiveError::InvalidConfiguration {
                setting,
                problem: ConfigProblem::NotOneOf {
                    allowed: Self::NAMES,
                },
            })
    }
}

/// Defines an enum together with `ALL`, `NAMES`, `as_str` and `Display` from
/// one table.
///
/// The variant set, the `ALL` slice and the string spellings all come from the
/// same `Variant => "text"` table, so they cannot drift apart. Variants are
/// emitted in table order, which matters for derived `PartialOrd`/`Ord`.
macro_rules! closed_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident => $text:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis enum $name {
            $( $(#[$vmeta])* $variant ),+
        }

        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: &'static [Self] = &[ $( Self::$variant ),+ ];

            /// The string form of every variant, in declaration order.
            pub const NAMES: &'static [&'static str] = &[ $( $text ),+ ];

            /// Returns the stable string form shared by `Display` and all
            /// language bindings.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $text ),+
                }
            }
        }

        impl $crate::closed_enum::ClosedEnum for $name {
            const ALL: &'static [Self] = Self::ALL;
            const NAMES: &'static [&'static str] = Self::NAMES;

            fn as_str(self) -> &'static str {
                Self::as_str(self)
            }
        }

        impl $crate::closed_enum::private::Sealed for $name {}

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

pub(crate) use closed_enum;
