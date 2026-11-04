//! Validated `SecurityConfig` list entries.
//!
//! An allowlisted extension and a banned path component each have a rule for
//! what a usable value is. These types parse a raw string once, so every front
//! end (core, CLI, Python, Node) shares one constructor and a value that could
//! never match is refused instead of silently turning extraction into a no-op.

use std::fmt;

use crate::ArchiveError;
use crate::Result;
use crate::security::boundary::MAX_CONFIG_ENTRY_LENGTH;

fn invalid(field: &str, problem: &str) -> ArchiveError {
    ArchiveError::InvalidConfiguration {
        reason: format!("{field} {problem}"),
    }
}

fn check_length_and_nul(value: &str, field: &str) -> Result<()> {
    if value.len() > MAX_CONFIG_ENTRY_LENGTH {
        return Err(invalid(
            field,
            &format!(
                "exceeds maximum length of {MAX_CONFIG_ENTRY_LENGTH} bytes (got {} bytes)",
                value.len()
            ),
        ));
    }
    if value.contains('\0') {
        return Err(invalid(
            field,
            "contains null bytes - potential security issue",
        ));
    }
    Ok(())
}

fn has_separator(value: &str) -> bool {
    value.contains(['/', '\\'])
}

/// A file extension without its leading dot, ASCII-lowercased.
///
/// Built only through [`TryFrom<&str>`]: one leading `.` is stripped and the
/// rest is lowercased. The value is never empty and holds no ASCII whitespace
/// or control character, path separator or inner `.` (`Path::extension` never
/// yields one, so such an entry could never match), and is at most
/// [`MAX_CONFIG_ENTRY_LENGTH`] bytes.
///
/// # Examples
///
/// ```
/// use exarch_core::Extension;
///
/// assert_eq!(Extension::try_from(".TXT")?.as_str(), "txt");
/// assert!(Extension::try_from("tar.gz").is_err());
/// assert!(Extension::try_from(" gz").is_err());
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Extension(Box<str>);

impl Extension {
    const FIELD: &'static str = "allowed extension";

    /// The normalized extension, without a leading dot.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `extension`, as `Path::extension` yields it, is this extension
    /// ignoring ASCII case.
    #[must_use]
    pub fn matches(&self, extension: &str) -> bool {
        self.0.eq_ignore_ascii_case(extension)
    }
}

impl TryFrom<&str> for Extension {
    type Error = ArchiveError;

    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidConfiguration`] for an empty value (after
    /// the leading dot), a null byte, ASCII whitespace or control character,
    /// path separator, inner `.`, or a value over [`MAX_CONFIG_ENTRY_LENGTH`]
    /// bytes.
    fn try_from(value: &str) -> Result<Self> {
        check_length_and_nul(value, Self::FIELD)?;
        let name = value.strip_prefix('.').unwrap_or(value);
        if name.is_empty() {
            return Err(invalid(Self::FIELD, "must not be empty"));
        }
        if name
            .chars()
            .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
        {
            return Err(invalid(
                Self::FIELD,
                "must not contain whitespace or control characters",
            ));
        }
        if has_separator(name) {
            return Err(invalid(Self::FIELD, "must not contain a path separator"));
        }
        if name.contains('.') {
            return Err(invalid(
                Self::FIELD,
                "must be a single extension without an inner dot (use `gz`, not `tar.gz`)",
            ));
        }
        Ok(Self(name.to_ascii_lowercase().into_boxed_str()))
    }
}

impl fmt::Display for Extension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One normal path component that archive entries may not contain.
///
/// Built only through [`TryFrom<&str>`]. The value is never empty, holds no
/// null byte or path separator, is not `.` or `..`, neither starts nor ends
/// with an ASCII whitespace or control character, and is at most
/// [`MAX_CONFIG_ENTRY_LENGTH`] bytes, so it can equal a single component.
/// Matching ignores ASCII case.
///
/// # Examples
///
/// ```
/// use exarch_core::PathComponentName;
///
/// let banned = PathComponentName::try_from(".git")?;
/// assert!(banned.matches(".GIT"));
/// assert!(PathComponentName::try_from("a/b").is_err());
/// assert!(PathComponentName::try_from("..").is_err());
/// assert!(PathComponentName::try_from(" .git").is_err());
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathComponentName(Box<str>);

impl PathComponentName {
    const FIELD: &'static str = "banned path component";

    /// The component name as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `component` equals this name ignoring ASCII case, so a ban
    /// holds on case-insensitive filesystems.
    #[must_use]
    pub fn matches(&self, component: &str) -> bool {
        self.0.eq_ignore_ascii_case(component)
    }
}

impl TryFrom<&str> for PathComponentName {
    type Error = ArchiveError;

    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidConfiguration`] for an empty value, one
    /// with leading or trailing ASCII whitespace or control characters, a null
    /// byte, a path separator, `.`, `..`, or a value over
    /// [`MAX_CONFIG_ENTRY_LENGTH`] bytes.
    fn try_from(value: &str) -> Result<Self> {
        check_length_and_nul(value, Self::FIELD)?;
        if value.is_empty() {
            return Err(invalid(Self::FIELD, "must not be empty"));
        }
        let is_blank = |c: char| c.is_ascii_whitespace() || c.is_ascii_control();
        if value.starts_with(is_blank) || value.ends_with(is_blank) {
            return Err(invalid(
                Self::FIELD,
                "must not start or end with whitespace or control characters",
            ));
        }
        if has_separator(value) {
            return Err(invalid(Self::FIELD, "must not contain a path separator"));
        }
        if value == "." || value == ".." {
            return Err(invalid(Self::FIELD, "must not be `.` or `..`"));
        }
        Ok(Self(value.into()))
    }
}

impl fmt::Display for PathComponentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn extension_strips_one_leading_dot_and_lowercases() {
        for (raw, normalized) in [
            ("txt", "txt"),
            (".txt", "txt"),
            (".TXT", "txt"),
            ("Gz", "gz"),
        ] {
            assert_eq!(Extension::try_from(raw).unwrap().as_str(), normalized);
        }
    }

    #[test]
    fn extension_matches_ignoring_ascii_case_on_the_path_side() {
        let txt = Extension::try_from("txt").unwrap();
        assert!(txt.matches("TXT"));
        assert!(txt.matches("txt"));
        assert!(!txt.matches("tx"));
    }

    #[test]
    fn extension_refuses_unusable_values() {
        let long = "x".repeat(MAX_CONFIG_ENTRY_LENGTH + 1);
        for raw in [
            "",
            ".",
            "..txt",
            "tar.gz",
            "a/b",
            "a\\b",
            " gz",
            "gz ",
            "g z",
            "g\tz",
            "bad\0ext",
            "g\u{7f}z",
            long.as_str(),
        ] {
            assert!(Extension::try_from(raw).is_err(), "{raw:?} must be refused");
        }
    }

    #[test]
    fn extension_accepts_the_maximum_length() {
        assert!(Extension::try_from("x".repeat(MAX_CONFIG_ENTRY_LENGTH).as_str()).is_ok());
    }

    #[test]
    fn extension_length_is_measured_in_bytes() {
        let multibyte = "日".repeat(100);
        let err = Extension::try_from(multibyte.as_str()).unwrap_err();
        assert!(err.to_string().contains("bytes"), "{err}");
    }

    #[test]
    fn component_keeps_its_case_and_matches_ignoring_it() {
        let git = PathComponentName::try_from(".Git").unwrap();
        assert_eq!(git.as_str(), ".Git");
        assert!(git.matches(".git"));
        assert!(!git.matches(".gitx"));
    }

    #[test]
    fn component_accepts_inner_spaces() {
        assert!(PathComponentName::try_from("my dir").is_ok());
    }

    #[test]
    fn component_refuses_unusable_values() {
        let long = "x".repeat(MAX_CONFIG_ENTRY_LENGTH + 1);
        for raw in [
            "",
            " ",
            "\t",
            " .git",
            ".git ",
            "\n.git",
            ".git\u{7f}",
            ".",
            "..",
            "a/b",
            "a\\b",
            "/",
            "bad\0",
            long.as_str(),
        ] {
            assert!(
                PathComponentName::try_from(raw).is_err(),
                "{raw:?} must be refused"
            );
        }
    }
}
