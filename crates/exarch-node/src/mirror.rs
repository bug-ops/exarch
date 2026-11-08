//! The rule for core enums this binding does not know, and the test-build guard
//! that keeps its mirrors complete.
//!
//! Core enums are `#[non_exhaustive]`. Output data (report fields, warnings,
//! dispositions, link targets, entries) emits core's `as_str()` token
//! unchanged, typed in TypeScript as the known union widened with
//! `(string & {})`; a structured payload of an unknown variant degrades to an
//! object holding only its token. A successful core call therefore never fails
//! because a report field is newer than the binding. Inputs keep the closed
//! `string_enum` mirrors, which refuse a spelling they do not list.

/// Implements `TryFrom<$core> for $mirror` with one arm per listed variant, in
/// test builds only.
///
/// The mirrors give the TypeScript unions their members; the `every_*` tests
/// in `error.rs` use these conversions to fail the test suite when core gains a
/// variant that no mirror lists.
macro_rules! mirror_from_core {
    ($mirror:ty, $core:ty, $what:literal, [$($variant:ident),+ $(,)?]) => {
        #[cfg(test)]
        impl TryFrom<$core> for $mirror {
            type Error = napi::Error;

            fn try_from(core: $core) -> napi::Result<Self> {
                match core {
                    $(<$core>::$variant => Ok(Self::$variant),)+
                    other => Err(crate::report::unknown_variant($what, &format!("{other:?}"))),
                }
            }
        }
    };
}

pub(crate) use mirror_from_core;

/// Implements `From<$mirror> for $core` with one arm per listed variant.
///
/// The match is exhaustive over the mirror, so a mirror variant without a core
/// counterpart does not compile.
macro_rules! mirror_into_core {
    ($mirror:ty => $core:ty, [$($variant:ident),+ $(,)?]) => {
        impl From<$mirror> for $core {
            fn from(mirror: $mirror) -> Self {
                match mirror {
                    $(<$mirror>::$variant => Self::$variant,)+
                }
            }
        }
    };
}

/// Implements `From<$core> for $mirror` for a core enum that is not
/// `#[non_exhaustive]`.
///
/// The match is exhaustive over `$core`, so a core variant that the list omits
/// does not compile.
macro_rules! mirror_from_closed_core {
    ($core:ty => $mirror:ty, [$($variant:ident),+ $(,)?]) => {
        impl From<$core> for $mirror {
            fn from(core: $core) -> Self {
                match core {
                    $(<$core>::$variant => Self::$variant,)+
                }
            }
        }
    };
}

pub(crate) use mirror_from_closed_core;
pub(crate) use mirror_into_core;
