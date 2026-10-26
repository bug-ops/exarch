//! Escaping wrappers for untrusted text written to a terminal.
//!
//! Archive entry names, link targets and messages derived from them are
//! attacker-controlled. Printed raw, an ESC or CSI byte in a name can recolor
//! output, rewrite earlier lines, or set the window title. Every human-readable
//! string that can carry archive data goes through one of these types, which
//! render control characters as visible escapes. `--json` output never uses
//! them and keeps the exact path.
//!
//! Format characters (Cf) and the line and paragraph separators (Zl, Zp) are
//! escaped too: bidirectional controls such as U+202E make a name read
//! differently from the bytes it holds. Characters up to U+00FF render as
//! `\xHH`, others as `\u{hhhh}`. A backslash is left as is, so an escape is
//! not distinguishable from a name that contains the same literal text.
//!
//! Invisible default-ignorable characters outside Cf (U+034F, U+3164,
//! variation selectors, ...) still pass through unchanged; see #753.

use std::cmp::Ordering;
use std::fmt;
use std::path::Path;

/// Inclusive ranges of the Unicode general categories Cf, Zl and Zp (Unicode
/// 16.0).
const INVISIBLE_RANGES: &[(char, char)] = &[
    ('\u{00AD}', '\u{00AD}'),
    ('\u{0600}', '\u{0605}'),
    ('\u{061C}', '\u{061C}'),
    ('\u{06DD}', '\u{06DD}'),
    ('\u{070F}', '\u{070F}'),
    ('\u{0890}', '\u{0891}'),
    ('\u{08E2}', '\u{08E2}'),
    ('\u{180E}', '\u{180E}'),
    ('\u{200B}', '\u{200F}'),
    ('\u{2028}', '\u{202E}'),
    ('\u{2060}', '\u{2064}'),
    ('\u{2066}', '\u{206F}'),
    ('\u{FEFF}', '\u{FEFF}'),
    ('\u{FFF9}', '\u{FFFB}'),
    ('\u{110BD}', '\u{110BD}'),
    ('\u{110CD}', '\u{110CD}'),
    ('\u{13430}', '\u{1343F}'),
    ('\u{1BCA0}', '\u{1BCA3}'),
    ('\u{1D173}', '\u{1D17A}'),
    ('\u{E0001}', '\u{E0001}'),
    ('\u{E0020}', '\u{E007F}'),
];

fn is_invisible(c: char) -> bool {
    INVISIBLE_RANGES
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

fn write_escape(f: &mut fmt::Formatter<'_>, c: char) -> fmt::Result {
    let code = u32::from(c);
    if code <= 0xFF {
        write!(f, "\\x{code:02x}")
    } else {
        write!(f, "\\u{{{code:04x}}}")
    }
}

fn write_escaped(f: &mut fmt::Formatter<'_>, text: &str, keep_newline: bool) -> fmt::Result {
    let needs_escape =
        |c: char| (c.is_control() || is_invisible(c)) && !(keep_newline && c == '\n');

    let mut rest = text;
    while let Some(pos) = rest.find(needs_escape) {
        let (clean, tail) = rest.split_at(pos);
        f.write_str(clean)?;
        let mut chars = tail.chars();
        if let Some(c) = chars.next() {
            write_escape(f, c)?;
        }
        rest = chars.as_str();
    }
    f.write_str(rest)
}

/// Single-line text with every control and invisible format character escaped.
///
/// Escapes C0 (including `\n`, `\r` and `\t`), DEL, C1, Unicode format (Cf)
/// and line or paragraph separator characters, so the value can never start a
/// new line, an escape sequence or reorder the surrounding text. Code points up
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
        write_escaped(f, self.0, false)
    }
}

/// Multi-line text authored by the CLI with every other control character
/// escaped.
///
/// Like [`TerminalText`] but keeps `\n`, for CLI-written messages that span
/// lines (hints, partial-extraction summaries). Only text whose line
/// structure the CLI itself controls may use it; archive-derived values inside
/// it must already be escaped with [`TerminalText`] or [`TerminalPath`].
#[derive(Debug, Clone, Copy)]
pub struct TerminalBlock<'a>(&'a str);

impl<'a> TerminalBlock<'a> {
    /// Wraps `text` for display.
    #[must_use]
    pub const fn new(text: &'a str) -> Self {
        Self(text)
    }
}

impl fmt::Display for TerminalBlock<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_escaped(f, self.0, true)
    }
}

/// A path rendered like [`Path::display`] with control and invisible format
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
        write_escaped(f, &self.0.to_string_lossy(), false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_escapes_c0_del_and_c1() {
        let hostile = "a\x1b[31m\x07\n\r\t\x7f\u{9b}\u{85}z";
        assert_eq!(
            TerminalText::new(hostile).to_string(),
            "a\\x1b[31m\\x07\\x0a\\x0d\\x09\\x7f\\x9b\\x85z"
        );
    }

    #[test]
    fn text_leaves_clean_unicode_untouched() {
        assert_eq!(TerminalText::new("файл ✓ .txt").to_string(), "файл ✓ .txt");
        assert_eq!(
            TerminalText::new("❤\u{fe0f} 日本").to_string(),
            "❤\u{fe0f} 日本"
        );
        assert_eq!(TerminalText::new("").to_string(), "");
    }

    #[test]
    fn text_escapes_bidi_and_format_controls() {
        assert_eq!(
            TerminalText::new("a\u{202e}b\u{2066}c\u{2069}d\u{200d}e\u{feff}").to_string(),
            "a\\u{202e}b\\u{2066}c\\u{2069}d\\u{200d}e\\u{feff}"
        );
    }

    #[test]
    fn text_escapes_line_and_paragraph_separators() {
        assert_eq!(
            TerminalText::new("a\u{2028}b\u{2029}c").to_string(),
            "a\\u{2028}b\\u{2029}c"
        );
    }

    #[test]
    fn text_escapes_soft_hyphen_as_hex_byte() {
        assert_eq!(TerminalText::new("a\u{ad}b").to_string(), "a\\xadb");
    }

    #[test]
    fn text_escapes_supplementary_plane_tag_characters() {
        assert_eq!(
            TerminalText::new("a\u{e0001}\u{e007f}b").to_string(),
            "a\\u{e0001}\\u{e007f}b"
        );
    }

    #[test]
    fn text_keeps_backslash_and_neighbours_of_ranges() {
        let text = "a\\b\u{2027}\u{202f}\u{205f}\u{2065}\u{2070}";
        assert_eq!(
            TerminalText::new(text).to_string(),
            "a\\b\u{2027}\u{202f}\u{205f}\u{2065}\u{2070}"
        );
    }

    #[test]
    fn invisible_ranges_are_sorted_and_disjoint() {
        for window in INVISIBLE_RANGES.windows(2) {
            assert!(window[0].1 < window[1].0, "{window:?}");
        }
        for &(lo, hi) in INVISIBLE_RANGES {
            assert!(lo <= hi, "{lo:?}..{hi:?}");
        }
    }

    #[test]
    fn invisible_ranges_cover_every_range_boundary() {
        for &(lo, hi) in INVISIBLE_RANGES {
            assert!(is_invisible(lo) && is_invisible(hi));
        }
    }

    #[test]
    fn block_keeps_only_newline() {
        assert_eq!(
            TerminalBlock::new("a\nb\x1b\tc\u{202e}").to_string(),
            "a\nb\\x1b\\x09c\\u{202e}"
        );
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

    #[cfg(unix)]
    #[test]
    fn path_renders_non_utf8_lossily() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let path = Path::new(OsStr::from_bytes(b"a\xffb"));
        assert_eq!(TerminalPath::new(path).to_string(), "a\u{fffd}b");
    }
}
