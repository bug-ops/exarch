//! Escaping wrappers for untrusted text written to a terminal.
//!
//! Archive entry names, link targets and messages derived from them are
//! attacker-controlled. Printed raw, an ESC or CSI byte in a name can recolor
//! output, rewrite earlier lines, or set the window title. Every human-readable
//! string that can carry archive data goes through one of these types, which
//! render control characters as visible escapes. `--json` output never uses
//! them and keeps the exact path.
//!
//! Invisible characters are escaped too: format characters (Cf), the line and
//! paragraph separators (Zl, Zp) and every `Default_Ignorable_Code_Point`
//! (Unicode 16.0), such as U+034F, U+3164 and the variation selectors. They
//! make a name read differently from the bytes it holds, for example bidi
//! controls such as U+202E, or `report1.pdf` against `report1\u{fe0f}.pdf`.
//! Characters up to U+00FF render as `\xHH`, others as `\u{hhhh}`. A backslash
//! is left as is, so an escape is not distinguishable from a name that
//! contains the same literal text.
//!
//! A variation selector stays raw only directly after a character it can
//! modify, so legitimate emoji, ideographic and Mongolian names print intact:
//! U+FE0E/U+FE0F after an emoji-variation base (`#`, `*` and the digits only
//! when the selector is followed by U+20E3, the keycap), U+E0100..U+E01EF after
//! a CJK ideograph, and the Mongolian free variation selectors after a
//! Mongolian letter.

use std::cmp::Ordering;
use std::fmt;
use std::fmt::Write as _;
use std::path::Path;

type Ranges = &'static [(char, char)];

/// Inclusive ranges of Cf, Zl, Zp and `Default_Ignorable_Code_Point` (Unicode
/// 16.0, from `UnicodeData.txt` and `DerivedCoreProperties.txt`).
const INVISIBLE_RANGES: Ranges = &[
    ('\u{00AD}', '\u{00AD}'),
    ('\u{034F}', '\u{034F}'),
    ('\u{0600}', '\u{0605}'),
    ('\u{061C}', '\u{061C}'),
    ('\u{06DD}', '\u{06DD}'),
    ('\u{070F}', '\u{070F}'),
    ('\u{0890}', '\u{0891}'),
    ('\u{08E2}', '\u{08E2}'),
    ('\u{115F}', '\u{1160}'),
    ('\u{17B4}', '\u{17B5}'),
    ('\u{180B}', '\u{180F}'),
    ('\u{200B}', '\u{200F}'),
    ('\u{2028}', '\u{202E}'),
    ('\u{2060}', '\u{206F}'),
    ('\u{3164}', '\u{3164}'),
    ('\u{FE00}', '\u{FE0F}'),
    ('\u{FEFF}', '\u{FEFF}'),
    ('\u{FFA0}', '\u{FFA0}'),
    ('\u{FFF0}', '\u{FFFB}'),
    ('\u{110BD}', '\u{110BD}'),
    ('\u{110CD}', '\u{110CD}'),
    ('\u{13430}', '\u{1343F}'),
    ('\u{1BCA0}', '\u{1BCA3}'),
    ('\u{1D173}', '\u{1D17A}'),
    ('\u{E0000}', '\u{E0FFF}'),
];

/// Inclusive ranges of the bases of an emoji variation sequence in Unicode 16.0
/// `emoji-variation-sequences.txt`, without `#`, `*` and `0-9`, which only form
/// a sequence with the keycap (see [`is_keycap_base`]).
const EMOJI_VARIATION_BASES: Ranges = &[
    ('\u{00A9}', '\u{00A9}'),
    ('\u{00AE}', '\u{00AE}'),
    ('\u{203C}', '\u{203C}'),
    ('\u{2049}', '\u{2049}'),
    ('\u{2122}', '\u{2122}'),
    ('\u{2139}', '\u{2139}'),
    ('\u{2194}', '\u{2199}'),
    ('\u{21A9}', '\u{21AA}'),
    ('\u{231A}', '\u{231B}'),
    ('\u{2328}', '\u{2328}'),
    ('\u{23CF}', '\u{23CF}'),
    ('\u{23E9}', '\u{23F3}'),
    ('\u{23F8}', '\u{23FA}'),
    ('\u{24C2}', '\u{24C2}'),
    ('\u{25AA}', '\u{25AB}'),
    ('\u{25B6}', '\u{25B6}'),
    ('\u{25C0}', '\u{25C0}'),
    ('\u{25FB}', '\u{25FE}'),
    ('\u{2600}', '\u{2604}'),
    ('\u{260E}', '\u{260E}'),
    ('\u{2611}', '\u{2611}'),
    ('\u{2614}', '\u{2615}'),
    ('\u{2618}', '\u{2618}'),
    ('\u{261D}', '\u{261D}'),
    ('\u{2620}', '\u{2620}'),
    ('\u{2622}', '\u{2623}'),
    ('\u{2626}', '\u{2626}'),
    ('\u{262A}', '\u{262A}'),
    ('\u{262E}', '\u{262F}'),
    ('\u{2638}', '\u{263A}'),
    ('\u{2640}', '\u{2640}'),
    ('\u{2642}', '\u{2642}'),
    ('\u{2648}', '\u{2653}'),
    ('\u{265F}', '\u{2660}'),
    ('\u{2663}', '\u{2663}'),
    ('\u{2665}', '\u{2666}'),
    ('\u{2668}', '\u{2668}'),
    ('\u{267B}', '\u{267B}'),
    ('\u{267E}', '\u{267F}'),
    ('\u{2692}', '\u{2697}'),
    ('\u{2699}', '\u{2699}'),
    ('\u{269B}', '\u{269C}'),
    ('\u{26A0}', '\u{26A1}'),
    ('\u{26A7}', '\u{26A7}'),
    ('\u{26AA}', '\u{26AB}'),
    ('\u{26B0}', '\u{26B1}'),
    ('\u{26BD}', '\u{26BE}'),
    ('\u{26C4}', '\u{26C5}'),
    ('\u{26C8}', '\u{26C8}'),
    ('\u{26CE}', '\u{26CF}'),
    ('\u{26D1}', '\u{26D1}'),
    ('\u{26D3}', '\u{26D4}'),
    ('\u{26E9}', '\u{26EA}'),
    ('\u{26F0}', '\u{26F5}'),
    ('\u{26F7}', '\u{26FA}'),
    ('\u{26FD}', '\u{26FD}'),
    ('\u{2702}', '\u{2702}'),
    ('\u{2705}', '\u{2705}'),
    ('\u{2708}', '\u{270D}'),
    ('\u{270F}', '\u{270F}'),
    ('\u{2712}', '\u{2712}'),
    ('\u{2714}', '\u{2714}'),
    ('\u{2716}', '\u{2716}'),
    ('\u{271D}', '\u{271D}'),
    ('\u{2721}', '\u{2721}'),
    ('\u{2728}', '\u{2728}'),
    ('\u{2733}', '\u{2734}'),
    ('\u{2744}', '\u{2744}'),
    ('\u{2747}', '\u{2747}'),
    ('\u{274C}', '\u{274C}'),
    ('\u{274E}', '\u{274E}'),
    ('\u{2753}', '\u{2755}'),
    ('\u{2757}', '\u{2757}'),
    ('\u{2763}', '\u{2764}'),
    ('\u{2795}', '\u{2797}'),
    ('\u{27A1}', '\u{27A1}'),
    ('\u{27B0}', '\u{27B0}'),
    ('\u{27BF}', '\u{27BF}'),
    ('\u{2934}', '\u{2935}'),
    ('\u{2B05}', '\u{2B07}'),
    ('\u{2B1B}', '\u{2B1C}'),
    ('\u{2B50}', '\u{2B50}'),
    ('\u{2B55}', '\u{2B55}'),
    ('\u{3030}', '\u{3030}'),
    ('\u{303D}', '\u{303D}'),
    ('\u{3297}', '\u{3297}'),
    ('\u{3299}', '\u{3299}'),
    ('\u{1F004}', '\u{1F004}'),
    ('\u{1F170}', '\u{1F171}'),
    ('\u{1F17E}', '\u{1F17F}'),
    ('\u{1F202}', '\u{1F202}'),
    ('\u{1F21A}', '\u{1F21A}'),
    ('\u{1F22F}', '\u{1F22F}'),
    ('\u{1F237}', '\u{1F237}'),
    ('\u{1F30D}', '\u{1F30F}'),
    ('\u{1F315}', '\u{1F315}'),
    ('\u{1F31C}', '\u{1F31C}'),
    ('\u{1F321}', '\u{1F321}'),
    ('\u{1F324}', '\u{1F32C}'),
    ('\u{1F336}', '\u{1F336}'),
    ('\u{1F378}', '\u{1F378}'),
    ('\u{1F37D}', '\u{1F37D}'),
    ('\u{1F393}', '\u{1F393}'),
    ('\u{1F396}', '\u{1F397}'),
    ('\u{1F399}', '\u{1F39B}'),
    ('\u{1F39E}', '\u{1F39F}'),
    ('\u{1F3A7}', '\u{1F3A7}'),
    ('\u{1F3AC}', '\u{1F3AE}'),
    ('\u{1F3C2}', '\u{1F3C2}'),
    ('\u{1F3C4}', '\u{1F3C4}'),
    ('\u{1F3C6}', '\u{1F3C6}'),
    ('\u{1F3CA}', '\u{1F3CE}'),
    ('\u{1F3D4}', '\u{1F3E0}'),
    ('\u{1F3ED}', '\u{1F3ED}'),
    ('\u{1F3F3}', '\u{1F3F3}'),
    ('\u{1F3F5}', '\u{1F3F5}'),
    ('\u{1F3F7}', '\u{1F3F7}'),
    ('\u{1F408}', '\u{1F408}'),
    ('\u{1F415}', '\u{1F415}'),
    ('\u{1F41F}', '\u{1F41F}'),
    ('\u{1F426}', '\u{1F426}'),
    ('\u{1F43F}', '\u{1F43F}'),
    ('\u{1F441}', '\u{1F442}'),
    ('\u{1F446}', '\u{1F449}'),
    ('\u{1F44D}', '\u{1F44E}'),
    ('\u{1F453}', '\u{1F453}'),
    ('\u{1F46A}', '\u{1F46A}'),
    ('\u{1F47D}', '\u{1F47D}'),
    ('\u{1F4A3}', '\u{1F4A3}'),
    ('\u{1F4B0}', '\u{1F4B0}'),
    ('\u{1F4B3}', '\u{1F4B3}'),
    ('\u{1F4BB}', '\u{1F4BB}'),
    ('\u{1F4BF}', '\u{1F4BF}'),
    ('\u{1F4CB}', '\u{1F4CB}'),
    ('\u{1F4DA}', '\u{1F4DA}'),
    ('\u{1F4DF}', '\u{1F4DF}'),
    ('\u{1F4E4}', '\u{1F4E6}'),
    ('\u{1F4EA}', '\u{1F4ED}'),
    ('\u{1F4F7}', '\u{1F4F7}'),
    ('\u{1F4F9}', '\u{1F4FB}'),
    ('\u{1F4FD}', '\u{1F4FD}'),
    ('\u{1F508}', '\u{1F508}'),
    ('\u{1F50D}', '\u{1F50D}'),
    ('\u{1F512}', '\u{1F513}'),
    ('\u{1F549}', '\u{1F54A}'),
    ('\u{1F550}', '\u{1F567}'),
    ('\u{1F56F}', '\u{1F570}'),
    ('\u{1F573}', '\u{1F579}'),
    ('\u{1F587}', '\u{1F587}'),
    ('\u{1F58A}', '\u{1F58D}'),
    ('\u{1F590}', '\u{1F590}'),
    ('\u{1F5A5}', '\u{1F5A5}'),
    ('\u{1F5A8}', '\u{1F5A8}'),
    ('\u{1F5B1}', '\u{1F5B2}'),
    ('\u{1F5BC}', '\u{1F5BC}'),
    ('\u{1F5C2}', '\u{1F5C4}'),
    ('\u{1F5D1}', '\u{1F5D3}'),
    ('\u{1F5DC}', '\u{1F5DE}'),
    ('\u{1F5E1}', '\u{1F5E1}'),
    ('\u{1F5E3}', '\u{1F5E3}'),
    ('\u{1F5E8}', '\u{1F5E8}'),
    ('\u{1F5EF}', '\u{1F5EF}'),
    ('\u{1F5F3}', '\u{1F5F3}'),
    ('\u{1F5FA}', '\u{1F5FA}'),
    ('\u{1F610}', '\u{1F610}'),
    ('\u{1F687}', '\u{1F687}'),
    ('\u{1F68D}', '\u{1F68D}'),
    ('\u{1F691}', '\u{1F691}'),
    ('\u{1F694}', '\u{1F694}'),
    ('\u{1F698}', '\u{1F698}'),
    ('\u{1F6AD}', '\u{1F6AD}'),
    ('\u{1F6B2}', '\u{1F6B2}'),
    ('\u{1F6B9}', '\u{1F6BA}'),
    ('\u{1F6BC}', '\u{1F6BC}'),
    ('\u{1F6CB}', '\u{1F6CB}'),
    ('\u{1F6CD}', '\u{1F6CF}'),
    ('\u{1F6E0}', '\u{1F6E5}'),
    ('\u{1F6E9}', '\u{1F6E9}'),
    ('\u{1F6F0}', '\u{1F6F0}'),
    ('\u{1F6F3}', '\u{1F6F3}'),
];

/// `Unified_Ideograph` (Unicode 16.0 `PropList.txt`). Every base in the IVD
/// (2026-08-03) lies in it; the exact IVD base list is about 5700 ranges, so
/// this superset is kept instead.
const IDEOGRAPH_BASES: Ranges = &[
    ('\u{3400}', '\u{4DBF}'),
    ('\u{4E00}', '\u{9FFF}'),
    ('\u{FA0E}', '\u{FA0F}'),
    ('\u{FA11}', '\u{FA11}'),
    ('\u{FA13}', '\u{FA14}'),
    ('\u{FA1F}', '\u{FA1F}'),
    ('\u{FA21}', '\u{FA21}'),
    ('\u{FA23}', '\u{FA24}'),
    ('\u{FA27}', '\u{FA29}'),
    ('\u{20000}', '\u{2A6DF}'),
    ('\u{2A700}', '\u{2B739}'),
    ('\u{2B740}', '\u{2B81D}'),
    ('\u{2B820}', '\u{2CEA1}'),
    ('\u{2CEB0}', '\u{2EBE0}'),
    ('\u{2EBF0}', '\u{2EE5D}'),
    ('\u{30000}', '\u{3134A}'),
    ('\u{31350}', '\u{323AF}'),
];

/// Bases of a Mongolian free variation sequence in Unicode 16.0
/// `StandardizedVariants.txt`.
const MONGOLIAN_BASES: Ranges = &[
    ('\u{1820}', '\u{1826}'),
    ('\u{1828}', '\u{1828}'),
    ('\u{182A}', '\u{182A}'),
    ('\u{182C}', '\u{182D}'),
    ('\u{1830}', '\u{1830}'),
    ('\u{1832}', '\u{1833}'),
    ('\u{1835}', '\u{1836}'),
    ('\u{1838}', '\u{1838}'),
    ('\u{1844}', '\u{1849}'),
    ('\u{184D}', '\u{184E}'),
    ('\u{185D}', '\u{185E}'),
    ('\u{1860}', '\u{1860}'),
    ('\u{1863}', '\u{1863}'),
    ('\u{1868}', '\u{1869}'),
    ('\u{186F}', '\u{186F}'),
    ('\u{1873}', '\u{1874}'),
    ('\u{1876}', '\u{1876}'),
    ('\u{1880}', '\u{1881}'),
    ('\u{1887}', '\u{1888}'),
    ('\u{188A}', '\u{188A}'),
];

const KEYCAP: char = '\u{20E3}';

fn contains(table: &[(char, char)], c: char) -> bool {
    table
        .binary_search_by(|&(lo, hi)| {
            if c < lo {
                Ordering::Greater
            } else if c > hi {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        })
        .is_ok()
}

const fn is_keycap_base(c: char) -> bool {
    matches!(c, '#' | '*' | '0'..='9')
}

/// Whether the invisible `c` is a variation selector attached to `prev`, the
/// character printed raw right before it. `rest` is the text after `c`.
fn is_attached_selector(c: char, prev: Option<char>, rest: &str) -> bool {
    let Some(base) = prev else {
        return false;
    };
    match c {
        '\u{FE0F}' if is_keycap_base(base) => rest.starts_with(KEYCAP),
        '\u{FE0E}' | '\u{FE0F}' => contains(EMOJI_VARIATION_BASES, base),
        '\u{E0100}'..='\u{E01EF}' => contains(IDEOGRAPH_BASES, base),
        '\u{180B}'..='\u{180D}' | '\u{180F}' => contains(MONGOLIAN_BASES, base),
        _ => false,
    }
}

fn needs_escape(c: char, prev: Option<char>, rest: &str) -> bool {
    c.is_control() || (contains(INVISIBLE_RANGES, c) && !is_attached_selector(c, prev, rest))
}

fn write_escape(f: &mut fmt::Formatter<'_>, c: char) -> fmt::Result {
    let code = u32::from(c);
    if code <= 0xFF {
        write!(f, "\\x{code:02x}")
    } else {
        write!(f, "\\u{{{code:04x}}}")
    }
}

fn write_escaped(f: &mut fmt::Formatter<'_>, text: &str) -> fmt::Result {
    let mut prev = None;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if needs_escape(c, prev, chars.as_str()) {
            write_escape(f, c)?;
            prev = None;
        } else {
            f.write_char(c)?;
            prev = Some(c);
        }
    }
    Ok(())
}

/// Single-line text with every control and invisible character escaped.
///
/// Escapes C0 (including `\n`, `\r` and `\t`), DEL, C1, Unicode format (Cf),
/// line or paragraph separator and other default-ignorable characters, so the
/// value can never start a new line, an escape sequence or reorder or disguise
/// the surrounding text. A variation selector right after a character it
/// modifies is kept, so emoji and ideographs print as written. Code points up
/// to U+00FF become `\xHH`, higher ones `\u{hhhh}`. Clean text is written
/// without allocating.
#[derive(Debug, Clone, Copy)]
pub struct TerminalText<'a>(&'a str);

impl<'a> TerminalText<'a> {
    /// Wraps `text` for display.
    #[must_use]
    pub const fn new(text: &'a str) -> Self {
        Self(text)
    }
}

impl fmt::Display for TerminalText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_escaped(f, self.0)
    }
}

/// A path rendered like [`Path::display`] with control and invisible
/// characters escaped.
#[derive(Debug, Clone, Copy)]
pub struct TerminalPath<'a>(&'a Path);

impl<'a> TerminalPath<'a> {
    /// Wraps `path` for display.
    #[must_use]
    pub const fn new(path: &'a Path) -> Self {
        Self(path)
    }
}

impl fmt::Display for TerminalPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_escaped(f, &self.0.to_string_lossy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_TABLES: [(&str, Ranges); 4] = [
        ("invisible", INVISIBLE_RANGES),
        ("emoji bases", EMOJI_VARIATION_BASES),
        ("ideograph bases", IDEOGRAPH_BASES),
        ("mongolian bases", MONGOLIAN_BASES),
    ];

    fn shown(text: &str) -> String {
        TerminalText::new(text).to_string()
    }

    #[test]
    fn text_escapes_c0_del_and_c1() {
        let hostile = "a\x1b[31m\x07\n\r\t\x7f\u{9b}\u{85}z";
        assert_eq!(
            shown(hostile),
            "a\\x1b[31m\\x07\\x0a\\x0d\\x09\\x7f\\x9b\\x85z"
        );
    }

    #[test]
    fn text_leaves_clean_unicode_untouched() {
        assert_eq!(shown("файл ✓ .txt"), "файл ✓ .txt");
        assert_eq!(shown("❤\u{fe0f} 日本"), "❤\u{fe0f} 日本");
        assert_eq!(shown(""), "");
    }

    #[test]
    fn text_escapes_bidi_and_format_controls() {
        assert_eq!(
            shown("a\u{202e}b\u{2066}c\u{2069}d\u{200d}e\u{feff}"),
            "a\\u{202e}b\\u{2066}c\\u{2069}d\\u{200d}e\\u{feff}"
        );
    }

    #[test]
    fn text_escapes_line_and_paragraph_separators() {
        assert_eq!(shown("a\u{2028}b\u{2029}c"), "a\\u{2028}b\\u{2029}c");
    }

    #[test]
    fn text_escapes_soft_hyphen_as_hex_byte() {
        assert_eq!(shown("a\u{ad}b"), "a\\xadb");
    }

    #[test]
    fn text_escapes_supplementary_plane_tag_characters() {
        assert_eq!(shown("a\u{e0001}\u{e007f}b"), "a\\u{e0001}\\u{e007f}b");
    }

    #[test]
    fn text_escapes_default_ignorable_outside_cf() {
        assert_eq!(
            shown("a\u{34f}b\u{3164}c\u{ffa0}d\u{115f}e\u{17b4}f"),
            "a\\u{034f}b\\u{3164}c\\u{ffa0}d\\u{115f}e\\u{17b4}f"
        );
    }

    #[test]
    fn text_escapes_unassigned_default_ignorable() {
        assert_eq!(
            shown("a\u{2065}b\u{fff0}c\u{e0000}d\u{e0fff}"),
            "a\\u{2065}b\\u{fff0}c\\u{e0000}d\\u{e0fff}"
        );
    }

    #[test]
    fn text_keeps_backslash_and_neighbours_of_ranges() {
        let text = "a\\b\u{2027}\u{202f}\u{205f}\u{2070}\u{34e}\u{350}\u{fdff}\u{fe10}\u{e1000}";
        assert_eq!(shown(text), text);
    }

    #[test]
    fn variation_selector_without_base_is_escaped() {
        assert_eq!(shown("\u{fe0f}a"), "\\u{fe0f}a");
        assert_eq!(shown("a\u{fe0f}"), "a\\u{fe0f}");
        assert_eq!(shown("a\u{fe0e}"), "a\\u{fe0e}");
    }

    #[test]
    fn variation_selector_after_emoji_base_is_kept() {
        assert_eq!(shown("\u{2764}\u{fe0f}"), "\u{2764}\u{fe0f}");
        assert_eq!(shown("\u{2764}\u{fe0e}"), "\u{2764}\u{fe0e}");
        assert_eq!(shown("\u{1f6f3}\u{fe0f}x"), "\u{1f6f3}\u{fe0f}x");
    }

    #[test]
    fn second_variation_selector_in_a_row_is_escaped() {
        assert_eq!(
            shown("\u{2764}\u{fe0f}\u{fe0f}"),
            "\u{2764}\u{fe0f}\\u{fe0f}"
        );
    }

    #[test]
    fn variation_selector_after_escaped_char_is_escaped() {
        assert_eq!(shown("\x1b\u{fe0f}"), "\\x1b\\u{fe0f}");
        assert_eq!(shown("\u{200d}\u{fe0f}"), "\\u{200d}\\u{fe0f}");
    }

    #[test]
    fn ascii_variation_selector_is_distinct_from_plain_name() {
        let spoofed = shown("report1\u{fe0f}.pdf");
        assert_eq!(spoofed, "report1\\u{fe0f}.pdf");
        assert_ne!(spoofed, shown("report1.pdf"));
        assert_eq!(shown("a#\u{fe0f}b*\u{fe0e}"), "a#\\u{fe0f}b*\\u{fe0e}");
    }

    #[test]
    fn keycap_sequences_are_kept() {
        assert_eq!(
            shown("#\u{fe0f}\u{20e3}*\u{fe0f}\u{20e3}0\u{fe0f}\u{20e3}9\u{fe0f}\u{20e3}"),
            "#\u{fe0f}\u{20e3}*\u{fe0f}\u{20e3}0\u{fe0f}\u{20e3}9\u{fe0f}\u{20e3}"
        );
    }

    #[test]
    fn keycap_text_style_selector_is_escaped() {
        assert_eq!(shown("1\u{fe0e}\u{20e3}"), "1\\u{fe0e}\u{20e3}");
    }

    #[test]
    fn keycap_selector_must_be_followed_by_keycap_directly() {
        assert_eq!(
            shown("1\u{fe0f}\u{200d}\u{20e3}"),
            "1\\u{fe0f}\\u{200d}\u{20e3}"
        );
    }

    #[test]
    fn ideographic_variation_selector_after_ideograph_is_kept() {
        assert_eq!(shown("\u{845b}\u{e0100}"), "\u{845b}\u{e0100}");
        assert_eq!(shown("\u{20000}\u{e01ef}"), "\u{20000}\u{e01ef}");
        assert_eq!(shown("a\u{e0100}"), "a\\u{e0100}");
        assert_eq!(shown("\u{845b}\u{e01f0}"), "\u{845b}\\u{e01f0}");
    }

    #[test]
    fn mongolian_variation_selector_after_letter_is_kept() {
        assert_eq!(
            shown("\u{1820}\u{180b}\u{1820}\u{180f}"),
            "\u{1820}\u{180b}\u{1820}\u{180f}"
        );
        assert_eq!(shown("a\u{180b}"), "a\\u{180b}");
        assert_eq!(shown("\u{1820}\u{180e}"), "\u{1820}\\u{180e}");
    }

    #[test]
    fn mongolian_selector_follows_every_standardized_base_only() {
        for base in ['\u{1880}', '\u{1881}', '\u{1887}', '\u{1888}', '\u{188a}'] {
            let text = format!("{base}\u{180b}");
            assert_eq!(shown(&text), text);
        }
        for base in ['\u{1827}', '\u{1877}', '\u{1878}', '\u{1882}', '\u{188b}'] {
            assert_eq!(
                shown(&format!("{base}\u{180b}")),
                format!("{base}\\u{{180b}}")
            );
        }
    }

    #[test]
    fn ideographic_selector_is_escaped_after_non_unified_ideograph() {
        for base in [
            '\u{f900}',
            '\u{fa10}',
            '\u{faff}',
            '\u{2a6e0}',
            '\u{2f800}',
            '\u{323b0}',
        ] {
            assert_eq!(
                shown(&format!("{base}\u{e0100}")),
                format!("{base}\\u{{e0100}}")
            );
        }
        for base in ['\u{fa0e}', '\u{fa29}', '\u{3400}', '\u{2b739}', '\u{323af}'] {
            let text = format!("{base}\u{e0100}");
            assert_eq!(shown(&text), text);
        }
    }

    #[test]
    fn range_tables_are_sorted_and_disjoint() {
        for (name, table) in ALL_TABLES {
            for &(lo, hi) in table {
                assert!(lo <= hi, "{name}: {lo:?}..{hi:?}");
            }
            for [first, second] in table.array_windows::<2>() {
                assert!(first.1 < second.0, "{name}: {first:?} {second:?}");
            }
        }
    }

    #[test]
    fn range_tables_cover_every_range_boundary() {
        for (name, table) in ALL_TABLES {
            for &(lo, hi) in table {
                assert!(contains(table, lo) && contains(table, hi), "{name}");
            }
        }
    }

    #[test]
    fn emoji_bases_exclude_keycap_bases() {
        for c in ['#', '*', '0', '5', '9'] {
            assert!(is_keycap_base(c));
            assert!(!contains(EMOJI_VARIATION_BASES, c));
        }
    }

    #[test]
    fn path_escapes_control_characters() {
        assert_eq!(
            TerminalPath::new(Path::new("d/\x1b]0;t\x07/f\n")).to_string(),
            "d/\\x1b]0;t\\x07/f\\x0a"
        );
    }

    #[test]
    fn path_escapes_bidi_override() {
        assert_eq!(
            TerminalPath::new(Path::new("evil\u{202e}gpj.exe")).to_string(),
            "evil\\u{202e}gpj.exe"
        );
    }

    #[test]
    fn path_escapes_default_ignorable() {
        assert_eq!(
            TerminalPath::new(Path::new("a\u{34f}b")).to_string(),
            "a\\u{034f}b"
        );
    }

    #[cfg(unix)]
    #[test]
    fn path_renders_non_utf8_lossily() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let path = Path::new(OsStr::from_bytes(b"a\xffb"));
        assert_eq!(TerminalPath::new(path).to_string(), "a\u{fffd}b");
    }
}
