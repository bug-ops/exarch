//! Escaping wrappers for untrusted text written to a terminal.
//!
//! Archive entry names, link targets and messages derived from them are
//! attacker-controlled. Printed raw, an ESC or CSI byte in a name can recolor
//! output, rewrite earlier lines, or set the window title. Every human-readable
//! string that can carry archive data goes through one of these types, which
//! render control characters as visible `\xHH` escapes. `--json` output never
//! uses them and keeps the exact path.
//!
//! `TODO(#749)`: Unicode format and bidirectional controls (U+202A..U+202E,
//! U+2066..U+2069) are not control characters and pass through unchanged.

use std::fmt;
use std::path::Path;

fn write_escaped(f: &mut fmt::Formatter<'_>, text: &str, keep_newline: bool) -> fmt::Result {
    let needs_escape = |c: char| c.is_control() && !(keep_newline && c == '\n');

    let mut rest = text;
    while let Some(pos) = rest.find(needs_escape) {
        let (clean, tail) = rest.split_at(pos);
        f.write_str(clean)?;
        let mut chars = tail.chars();
        if let Some(c) = chars.next() {
            write!(f, "\\x{:02x}", u32::from(c))?;
        }
        rest = chars.as_str();
    }
    f.write_str(rest)
}

/// Single-line text with every control character escaped.
///
/// Escapes C0 (including `\n`, `\r` and `\t`), DEL and C1 characters as
/// `\xHH`, so the value can never start a new line or an escape sequence.
/// Clean text is written without allocating.
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

/// A path rendered like [`Path::display`] with control characters escaped.
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
        assert_eq!(TerminalText::new("").to_string(), "");
    }

    #[test]
    fn block_keeps_only_newline() {
        assert_eq!(
            TerminalBlock::new("a\nb\x1b\tc").to_string(),
            "a\nb\\x1b\\x09c"
        );
    }

    #[test]
    fn path_escapes_control_characters() {
        assert_eq!(
            TerminalPath::new(Path::new("d/\x1b]0;t\x07/f\n")).to_string(),
            "d/\\x1b]0;t\\x07/f\\x0a"
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
