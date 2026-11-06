//! Conversions from core's closed enums to the `string_enum` types that are
//! the runtime value of report fields.

/// Implements `TryFrom<$core> for $mirror` with one arm per listed variant.
///
/// The core enums are `#[non_exhaustive]`, so a variant added to core after
/// this list was written is refused with an "older than exarch-core" error
/// instead of reaching JavaScript as a token outside the generated union; the
/// `every_*` tests in `error.rs` reject that at build time.
macro_rules! mirror_from_core {
    ($mirror:ty, $core:ty, $what:literal, [$($variant:ident),+ $(,)?]) => {
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
