//! Injective text for paths.

use std::fmt::Write as _;
use std::path::Path;

use crate::Malformation;

/// The text of an archive entry path, or the refusal a front end must raise.
///
/// A lossy rendering could merge two distinct entries into one name, so a path
/// that is not valid UTF-8 is an error rather than a `\u{FFFD}` rendering. Use
/// [`path_text`] where the path is only shown.
///
/// # Errors
///
/// Returns [`Malformation::EntryPathNotUtf8`] when `path` is not valid UTF-8.
///
/// # Examples
///
/// ```
/// use std::path::Path;
///
/// use exarch_core::utf8_entry_path;
///
/// assert_eq!(utf8_entry_path(Path::new("a/b.txt"))?, "a/b.txt");
/// # Ok::<(), exarch_core::Malformation>(())
/// ```
pub fn utf8_entry_path(path: &Path) -> Result<&str, Malformation> {
    path.to_str().ok_or_else(|| Malformation::EntryPathNotUtf8 {
        path: path.to_path_buf(),
    })
}

/// Renders a path as text so that two distinct paths never render alike.
///
/// Valid text is kept as it is, except that a backslash is written `\x5C` on
/// Unix, where it is an ordinary character of a name. On Windows a backslash
/// is a separator, so the components of the path are joined with `/` and the
/// same entry name reads alike on every host (`x\y` renders as `x/y`).
/// Each byte of a Unix path that is not part of valid UTF-8 is written
/// `\xNN` (upper-case hex), and each unpaired UTF-16 unit of a Windows path is
/// written `\uNNNN`. Because the escape character is itself escaped, the
/// rendering is injective: a literal `a\xFFb` renders as `a\x5CxFFb`, never as
/// the path `a<0xFF>b`.
///
/// Use this wherever a path is shown or serialized as text and refusing it
/// would hide the finding that reports it (listings, verification issues,
/// progress callbacks). A front end that can hold raw paths keeps them
/// lossless instead, as Python does with `os.fsdecode`.
///
/// # Examples
///
/// ```
/// use std::path::Path;
///
/// use exarch_core::path_text;
///
/// assert_eq!(
///     path_text(Path::new("dir/caf\u{e9}.txt")),
///     "dir/caf\u{e9}.txt"
/// );
/// # #[cfg(unix)]
/// # {
/// assert_eq!(path_text(Path::new("a\\b")), "a\\x5Cb");
/// use std::ffi::OsStr;
/// use std::os::unix::ffi::OsStrExt;
///
/// let raw = Path::new(OsStr::from_bytes(b"a\xffb"));
/// assert_eq!(path_text(raw), "a\\xFFb");
/// assert_ne!(path_text(raw), path_text(Path::new("a\\xFFb")));
/// # }
/// ```
#[must_use]
pub fn path_text(path: &Path) -> String {
    let mut out = String::new();
    push_path(&mut out, path);
    out
}

fn push_text(out: &mut String, text: &str) {
    for ch in text.chars() {
        if ch == '\\' {
            out.push_str("\\x5C");
        } else {
            out.push(ch);
        }
    }
}

/// Renders raw bytes of an archive name as text, by the rules of
/// [`path_text`].
///
/// Valid UTF-8 is kept as it is except for backslashes (`\x5C`), and each
/// invalid byte is written `\xNN`. Use it for names that are held as bytes, as
/// they are stored in the archive, so two names that differ only in invalid
/// bytes never render alike.
///
/// # Examples
///
/// ```
/// use exarch_core::bytes_text;
///
/// assert_eq!(bytes_text(b"caf\xc3\xa9"), "caf\u{e9}");
/// assert_eq!(bytes_text(b"caf\xe9"), "caf\\xE9");
/// assert_ne!(bytes_text(b"caf\xe9"), bytes_text(b"caf\xe8"));
/// ```
#[must_use]
pub fn bytes_text(bytes: &[u8]) -> String {
    let mut out = String::new();
    push_bytes(&mut out, bytes);
    out
}

fn push_bytes(out: &mut String, bytes: &[u8]) {
    for chunk in bytes.utf8_chunks() {
        push_text(out, chunk.valid());
        for byte in chunk.invalid() {
            // Writing to a String cannot fail.
            let _ = write!(out, "\\x{byte:02X}");
        }
    }
}

#[cfg(unix)]
fn push_path(out: &mut String, path: &Path) {
    use std::os::unix::ffi::OsStrExt;

    push_bytes(out, path.as_os_str().as_bytes());
}

/// On Windows the components of the path are joined with `/`, whatever
/// separator the path was spelled with, so a name reads the same on every
/// host. A component of a normalized name never holds a `\`, which on Windows
/// is a separator, so no two paths share a rendering.
#[cfg(windows)]
fn push_path(out: &mut String, path: &Path) {
    use std::path::Component;

    for component in path.components() {
        match component {
            Component::RootDir => out.push('/'),
            other => {
                if !out.is_empty() && !out.ends_with('/') {
                    out.push('/');
                }
                push_wide(out, other.as_os_str());
            }
        }
    }
}

#[cfg(windows)]
fn push_wide(out: &mut String, text: &std::ffi::OsStr) {
    use std::os::windows::ffi::OsStrExt;

    for unit in char::decode_utf16(text.encode_wide()) {
        match unit {
            Ok(ch) => push_text(out, ch.encode_utf8(&mut [0; 4])),
            Err(unpaired) => {
                // Writing to a String cannot fail.
                let _ = write!(out, "\\u{:04X}", unpaired.unpaired_surrogate());
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn push_path(out: &mut String, path: &Path) {
    push_text(out, &path.to_string_lossy());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_text_is_unchanged_but_for_backslashes() {
        assert_eq!(path_text(Path::new("a/b é.txt")), "a/b é.txt");
        #[cfg(unix)]
        assert_eq!(path_text(Path::new("x\\y")), "x\\x5Cy");
        #[cfg(windows)]
        assert_eq!(path_text(Path::new("x\\y")), "x/y");
    }

    #[test]
    fn bytes_are_escaped_the_same_on_every_platform() {
        assert_eq!(bytes_text(b"x\\y"), "x\\x5Cy");
        assert_eq!(bytes_text(b"a/b"), "a/b");
        assert_eq!(bytes_text(b"caf\xe9"), "caf\\xE9");
        assert_ne!(bytes_text(b"caf\xe9"), bytes_text(b"caf\xe8"));
        assert_ne!(bytes_text(b"\xff"), bytes_text(b"\\xFF"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_components_are_joined_with_a_forward_slash() {
        assert_eq!(path_text(Path::new(r"x\y\z")), "x/y/z");
        assert_eq!(path_text(Path::new(r"x/y\z")), "x/y/z");
        assert_eq!(path_text(Path::new(r"a\.\b")), "a/b");
        assert_eq!(
            path_text(Path::new("x/y/z")),
            path_text(Path::new(r"x\y\z"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn distinct_invalid_bytes_render_distinctly() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let render = |bytes: &[u8]| path_text(Path::new(OsStr::from_bytes(bytes)));
        assert_eq!(render(b"a\xffb"), "a\\xFFb");
        assert_eq!(render(b"a\xfeb"), "a\\xFEb");
        assert_ne!(render(b"a\xffb"), render(b"a\\xFFb"));
    }
}
