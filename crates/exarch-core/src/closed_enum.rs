//! Declarative table for enums whose variants have a stable string form.

/// Defines an enum together with `ALL`, `as_str` and `Display` from one table.
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

            /// Returns the stable string form shared by `Display` and all
            /// language bindings.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $text ),+
                }
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

pub(crate) use closed_enum;
