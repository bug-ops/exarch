//! Typed configuration refusals.
//!
//! [`ArchiveError::InvalidConfiguration`] names the setting that was refused
//! ([`ConfigSetting`]) and why ([`ConfigProblem`]), so a front end can point at
//! the offending flag or property without parsing a message.
//!
//! [`ArchiveError::InvalidConfiguration`]: super::ArchiveError::InvalidConfiguration

use std::fmt;
use std::path::PathBuf;

use crate::closed_enum::closed_enum;
use crate::formats::detect::ExtractOnlyFormat;

closed_enum! {
    /// A configuration value or required input that was refused.
    ///
    /// `as_str` is the stable `snake_case` identifier shared by the Python, Node
    /// and CLI front ends; [`label`](Self::label) is the noun used in messages.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ConfigSetting;
    ///
    /// assert_eq!(ConfigSetting::MaxFileSize.as_str(), "max_file_size");
    /// assert_eq!(ConfigSetting::AllowedExtension.label(), "allowed extension");
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum ConfigSetting {
        /// `SecurityConfig::max_file_size`.
        MaxFileSize => "max_file_size",
        /// `SecurityConfig::max_total_size`.
        MaxTotalSize => "max_total_size",
        /// `SecurityConfig::max_file_count`.
        MaxFileCount => "max_file_count",
        /// `SecurityConfig::max_path_depth`.
        MaxPathDepth => "max_path_depth",
        /// `SecurityConfig::max_compression_ratio`.
        MaxCompressionRatio => "max_compression_ratio",
        /// `SecurityConfig::max_solid_compression_ratio`.
        MaxSolidCompressionRatio => "max_solid_compression_ratio",
        /// `SecurityConfig::max_solid_block_memory`.
        MaxSolidBlockMemory => "max_solid_block_memory",
        /// `SecurityConfig::max_tar_metadata_bytes`.
        MaxTarMetadataBytes => "max_tar_metadata_bytes",
        /// `SecurityConfig::max_decoder_memory`.
        MaxDecoderMemory => "max_decoder_memory",
        /// The decompression budget of an integrity check.
        DecompressionBudget => "decompression_budget",
        /// An entry of the extension allowlist.
        AllowedExtension => "allowed_extension",
        /// An entry of the banned path component list.
        BannedPathComponent => "banned_path_component",
        /// The path of the archive to create or the destination of an
        /// extraction.
        OutputPath => "output_path",
        /// The paths to add to an archive.
        SourcePaths => "source_paths",
        /// The prefix stripped from entry names.
        StripPrefix => "strip_prefix",
        /// The archive format to create.
        CreationFormat => "creation_format",
        /// Atomic extraction.
        AtomicExtraction => "atomic_extraction",
        /// The writer a ZIP archive is created into.
        ZipOutputWriter => "zip_output_writer",
        /// The byte cap of an in-memory extraction.
        MaxBytes => "max_bytes",
        /// `SecurityConfig::parallel_decode`, the lookahead memory of parallel
        /// 7z decoding.
        ParallelDecodeMemory => "parallel_decode_memory",
        /// An entry of the creation exclude patterns.
        ExcludePattern => "exclude_pattern",
        /// The ZIP structure policy.
        ZipConsistency => "zip_consistency",
        /// The path model of a sink extraction.
        PathModel => "path_model",
        /// The archive format of an extraction or listing.
        ArchiveFormat => "archive_format",
        /// The decode reuse mode of an extraction.
        DecodeReuse => "decode_reuse",
        /// The byte limit of a decode reuse mode.
        DecodeReuseLimit => "decode_reuse_limit",
        /// The kind of an entry skip.
        SkipKind => "skip_kind",
        /// The durability of a created archive file.
        Durability => "durability",
        /// The occupied-destination policy of an extraction.
        ExistingFiles => "existing_files",
        /// The staging mode of an extraction.
        Staging => "staging",
        /// The entry selection of an extraction.
        EntrySelection => "entry_selection",
        /// An entry include pattern of an extraction.
        EntryInclude => "entry_include",
        /// An entry exclude pattern of an extraction.
        EntryExclude => "entry_exclude",
        /// The number of leading path components stripped from entries.
        StripComponents => "strip_components",
    }
}

impl ConfigSetting {
    /// The message of a refused configuration: `"{label} {problem}"`, or
    /// `"no {label} provided"` for a list that came up empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ConfigProblem;
    /// use exarch_core::ConfigSetting;
    ///
    /// let text = ConfigSetting::MaxFileSize.describe(&ConfigProblem::Zero);
    /// assert_eq!(text, "max_file_size must not be zero");
    /// ```
    #[must_use]
    pub fn describe(self, problem: &ConfigProblem) -> String {
        match problem {
            ConfigProblem::NoneProvided => format!("no {} provided", self.label()),
            ConfigProblem::NotCreatable { .. } => problem.to_string(),
            other => format!("{} {other}", self.label()),
        }
    }

    /// The noun used for this setting in messages.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DecompressionBudget => "decompression budget",
            Self::AllowedExtension => "allowed extension",
            Self::BannedPathComponent => "banned path component",
            Self::OutputPath => "output path",
            Self::SourcePaths => "source paths",
            Self::CreationFormat => "creation format",
            Self::AtomicExtraction => "atomic extraction",
            Self::ZipOutputWriter => "ZIP output writer",
            Self::ParallelDecodeMemory => "parallel decode memory",
            Self::ExcludePattern => "exclude pattern",
            Self::ZipConsistency => "zip consistency",
            Self::PathModel => "path model",
            Self::ArchiveFormat => "archive format",
            Self::DecodeReuse => "decode reuse",
            Self::DecodeReuseLimit => "decode reuse limit",
            Self::SkipKind => "skip kind",
            Self::ExistingFiles => "existing files policy",
            Self::Staging => "staging",
            Self::EntrySelection => "entry selection",
            Self::EntryInclude => "entry include pattern",
            Self::EntryExclude => "entry exclude pattern",
            Self::StripComponents => "strip components",
            Self::MaxFileSize
            | Self::MaxTotalSize
            | Self::MaxFileCount
            | Self::MaxPathDepth
            | Self::MaxCompressionRatio
            | Self::MaxSolidCompressionRatio
            | Self::MaxSolidBlockMemory
            | Self::MaxTarMetadataBytes
            | Self::MaxDecoderMemory
            | Self::StripPrefix
            | Self::Durability
            | Self::MaxBytes => self.as_str(),
        }
    }
}

/// Why a configuration value or input was refused.
///
/// # Examples
///
/// ```
/// use exarch_core::ConfigProblem;
///
/// assert_eq!(ConfigProblem::Zero.to_string(), "must not be zero");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigProblem {
    /// A limit is zero.
    Zero,
    /// A byte count is negative.
    Negative,
    /// A number is NaN or infinite.
    NotFinite,
    /// A number has a fractional part.
    NotWholeNumber,
    /// A number is above the largest accepted value.
    TooLarge {
        /// The largest accepted value.
        max: u64,
    },
    /// A required input is missing.
    NotSet,
    /// No input of this kind was given.
    NoneProvided,
    /// The path has no parent directory.
    NoParent,
    /// The operation is not supported for this input.
    NotSupported,
    /// Atomic extraction cannot target a sink.
    CannotTargetSink,
    /// The prefix would remove the whole name of this path.
    RemovesWholeName {
        /// The path that would be left without a name.
        path: PathBuf,
    },
    /// The writer is not at offset zero.
    NotAtStart,
    /// The entry is empty.
    Empty,
    /// The entry has whitespace or control characters.
    BlankOrControl,
    /// The entry starts or ends with whitespace or control characters.
    PaddedWithBlank,
    /// The entry contains a path separator.
    ContainsSeparator,
    /// The extension has an inner dot.
    InnerDot,
    /// The entry is `.` or `..`.
    DotEntry,
    /// The value is not one of the allowed values.
    NotOneOf {
        /// The accepted string forms.
        allowed: &'static [&'static str],
    },
    /// The format can be read but not created.
    NotCreatable {
        /// The extract-only format that was asked for.
        format: ExtractOnlyFormat,
    },
    /// The entry is longer than the maximum.
    TooLong {
        /// The longest accepted length in bytes.
        max: usize,
        /// The length of the entry in bytes.
        got: usize,
    },
    /// The entry contains a NUL byte.
    ContainsNul,
    /// A creation exclude pattern the matcher does not support.
    ExcludePatternRefused {
        /// The refused pattern text, cut to the maximum entry length.
        pattern: String,
        /// Why the pattern is refused.
        reason: ExcludeRefusal,
    },
    /// The path exists and is not a directory.
    NotADirectory,
    /// The path is a symbolic link.
    IsSymlink,
    /// Two sources map to the same entry name.
    EntryNameCollision {
        /// The entry name both sources map to.
        name: String,
        /// The first source that maps to it.
        first: PathBuf,
        /// The second source that maps to it.
        second: PathBuf,
    },
    /// Replacing this path as a whole would destroy something that must stay.
    ReplacesProtectedPath {
        /// What the destination is.
        path: ProtectedPath,
    },
}

closed_enum! {
    /// What makes a destination too important to replace as a whole.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ProtectedPath;
    ///
    /// assert_eq!(ProtectedPath::FilesystemRoot.as_str(), "filesystem_root");
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum ProtectedPath {
        /// The destination is a filesystem root.
        FilesystemRoot => "filesystem_root",
        /// The destination is, or contains, the archive being extracted.
        ArchiveAncestor => "archive_ancestor",
        /// The destination is, or contains, the process working directory.
        WorkingDirectory => "working_directory",
    }
}

impl ProtectedPath {
    /// A short explanation for a message.
    #[must_use]
    pub const fn explanation(self) -> &'static str {
        match self {
            Self::FilesystemRoot => "a filesystem root",
            Self::ArchiveAncestor => "the archive or a directory that contains it",
            Self::WorkingDirectory => "the working directory or a directory that contains it",
        }
    }
}

closed_enum! {
    /// Why a creation exclude pattern is refused.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ExcludeRefusal;
    ///
    /// assert_eq!(ExcludeRefusal::BraceAlternation.as_str(), "brace_alternation");
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum ExcludeRefusal {
        /// The pattern is empty
        Empty => "empty",
        /// The pattern is longer than the maximum entry length
        TooLong => "too_long",
        /// The pattern contains a NUL byte
        ContainsNul => "contains_nul",
        /// A path component is `.` or `..`
        DotEntry => "dot_entry",
        /// The pattern is an absolute path
        Absolute => "absolute",
        /// `**` is glued to other characters instead of being a whole component
        UnsupportedWildcard => "unsupported_wildcard",
        /// The pattern starts with `!`; patterns cannot negate
        LeadingNegation => "leading_negation",
        /// The pattern holds `{` or `}`; alternation is not supported
        BraceAlternation => "brace_alternation",
        /// A class is negated, POSIX or holds a non-ASCII character
        UnsupportedClass => "unsupported_class",
        /// A `[` has no closing `]` in the same path component
        UnterminatedClass => "unterminated_class",
        /// A class range is reversed or not within `0-9`, `a-z` or `A-Z`
        InvalidClassRange => "invalid_class_range",
        /// The glob engine rejected the pattern for another reason
        UnsupportedSyntax => "unsupported_syntax",
        /// The pattern starts or ends with whitespace or a control character
        PaddedWithBlank => "padded_with_blank",
        /// The pattern holds a comma, which reads as a list separator
        ContainsComma => "contains_comma",
    }
}

impl ExcludeRefusal {
    /// A short explanation for a message.
    #[must_use]
    pub const fn explanation(self) -> &'static str {
        match self {
            Self::Empty => "is empty",
            Self::TooLong => "is longer than the maximum entry length",
            Self::ContainsNul => "contains a null byte",
            Self::DotEntry => "has a `.` or `..` component",
            Self::Absolute => {
                "is an absolute path; patterns match archive paths, which are relative"
            }
            Self::UnsupportedWildcard => {
                "glues `**` to other characters; `**` must be a whole path component"
            }
            Self::LeadingNegation => "starts with `!`; patterns cannot be negated",
            Self::BraceAlternation => {
                "contains `{` or `}`; alternation is not supported, give one pattern per option"
            }
            Self::UnsupportedClass => {
                "has a negated, POSIX or non-ASCII character class; only positive ASCII classes such as `[abc]` are supported"
            }
            Self::UnterminatedClass => "has a `[` without a closing `]` in the same path component",
            Self::InvalidClassRange => {
                "has a class range that is reversed or not within `0-9`, `a-z` or `A-Z`"
            }
            Self::UnsupportedSyntax => "uses glob syntax that is not supported",
            Self::PaddedWithBlank => "starts or ends with whitespace",
            Self::ContainsComma => "contains a comma; give one pattern per option",
        }
    }
}

impl fmt::Display for ConfigProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => f.write_str("must not be zero"),
            Self::Negative => f.write_str("must not be negative"),
            Self::NotOneOf { allowed } => {
                write!(
                    f,
                    "is not one of the allowed values: {}",
                    allowed.join(", ")
                )
            }
            Self::NotCreatable { format } => {
                write!(
                    f,
                    "{} archive creation is not supported",
                    format.extension()
                )
            }
            Self::NotFinite => f.write_str("must be a finite number"),
            Self::NotWholeNumber => f.write_str("must be a whole number"),
            Self::TooLarge { max } => write!(f, "must not exceed {max}"),
            Self::NotSet => f.write_str("not set"),
            Self::NoneProvided => f.write_str("none provided"),
            Self::NoParent => f.write_str("has no parent"),
            Self::NotSupported => f.write_str("is not supported"),
            Self::CannotTargetSink => f.write_str("renames a directory and cannot target a sink"),
            Self::RemovesWholeName { path } => {
                write!(f, "removes the whole name of {}", path.display())
            }
            Self::NotAtStart => f.write_str("must be positioned at offset 0"),
            Self::Empty => f.write_str("must not be empty"),
            Self::BlankOrControl => {
                f.write_str("must not contain whitespace or control characters")
            }
            Self::PaddedWithBlank => {
                f.write_str("must not start or end with whitespace or control characters")
            }
            Self::ContainsSeparator => f.write_str("must not contain a path separator"),
            Self::InnerDot => f.write_str(
                "must be a single extension without an inner dot (use `gz`, not `tar.gz`)",
            ),
            Self::DotEntry => f.write_str("must not be `.` or `..`"),
            Self::TooLong { max, got } => {
                write!(f, "exceeds maximum length of {max} bytes (got {got} bytes)")
            }
            Self::ContainsNul => f.write_str("contains null bytes - potential security issue"),
            Self::ExcludePatternRefused { pattern, reason } => {
                write!(f, "{pattern:?} {}", reason.explanation())
            }
            Self::NotADirectory => f.write_str("is not a directory"),
            Self::IsSymlink => f.write_str("is a symbolic link"),
            Self::EntryNameCollision {
                name,
                first,
                second,
            } => write!(
                f,
                "entry name {name:?} is produced by both {} and {}",
                first.display(),
                second.display()
            ),
            Self::ReplacesProtectedPath { path } => {
                write!(f, "would replace {}", path.explanation())
            }
        }
    }
}

pub(crate) fn message(setting: ConfigSetting, problem: &ConfigProblem) -> String {
    setting.describe(problem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ffi_kind_names_the_setting() {
        let err = crate::ArchiveError::InvalidConfiguration {
            setting: ConfigSetting::MaxFileCount,
            problem: ConfigProblem::Zero,
        };
        assert_eq!(err.ffi_kind().setting(), Some(ConfigSetting::MaxFileCount));
        assert_eq!(
            crate::ArchiveError::from(crate::Malformation::PackSizesOverflow)
                .ffi_kind()
                .setting(),
            None
        );
    }

    #[test]
    fn a_host_path_keeps_its_native_spelling() {
        let problem = ConfigProblem::RemovesWholeName {
            path: PathBuf::from("C:\\src\\a"),
        };
        let text = problem.to_string();
        assert!(text.ends_with("C:\\src\\a"), "{text}");
    }

    #[test]
    fn messages_keep_their_established_text() {
        let cases = [
            (
                ConfigSetting::MaxFileSize,
                ConfigProblem::Zero,
                "max_file_size must not be zero",
            ),
            (
                ConfigSetting::MaxCompressionRatio,
                ConfigProblem::NotFinite,
                "max_compression_ratio must be a finite number",
            ),
            (
                ConfigSetting::DecompressionBudget,
                ConfigProblem::Zero,
                "decompression budget must not be zero",
            ),
            (
                ConfigSetting::SourcePaths,
                ConfigProblem::NoneProvided,
                "no source paths provided",
            ),
            (
                ConfigSetting::OutputPath,
                ConfigProblem::NoParent,
                "output path has no parent",
            ),
            (
                ConfigSetting::CreationFormat,
                ConfigProblem::NotCreatable {
                    format: ExtractOnlyFormat::SevenZ,
                },
                "7z archive creation is not supported",
            ),
            (
                ConfigSetting::AtomicExtraction,
                ConfigProblem::CannotTargetSink,
                "atomic extraction renames a directory and cannot target a sink",
            ),
            (
                ConfigSetting::DecodeReuse,
                ConfigProblem::NotOneOf {
                    allowed: crate::DecodeReuseKind::NAMES,
                },
                "decode reuse is not one of the allowed values: off, memory, temp_file",
            ),
            (
                ConfigSetting::StripPrefix,
                ConfigProblem::RemovesWholeName { path: "a".into() },
                "strip_prefix removes the whole name of a",
            ),
            (
                ConfigSetting::ZipOutputWriter,
                ConfigProblem::NotAtStart,
                "ZIP output writer must be positioned at offset 0",
            ),
            (
                ConfigSetting::AllowedExtension,
                ConfigProblem::TooLong { max: 4, got: 5 },
                "allowed extension exceeds maximum length of 4 bytes (got 5 bytes)",
            ),
        ];
        for (setting, problem, text) in cases {
            assert_eq!(message(setting, &problem), text);
        }
    }
}
