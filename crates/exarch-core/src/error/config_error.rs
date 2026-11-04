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
        /// The path of the archive to create.
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
            Self::CreationFormat => "7z archive creation",
            Self::AtomicExtraction => "atomic extraction",
            Self::ZipOutputWriter => "ZIP output writer",
            Self::ParallelDecodeMemory => "parallel decode memory",
            Self::ExcludePattern => "exclude pattern",
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
    /// The entry is longer than the maximum.
    TooLong {
        /// The longest accepted length in bytes.
        max: usize,
        /// The length of the entry in bytes.
        got: usize,
    },
    /// The entry contains a NUL byte.
    ContainsNul,
}

impl fmt::Display for ConfigProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => f.write_str("must not be zero"),
            Self::Negative => f.write_str("must not be negative"),
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
                ConfigProblem::NotSupported,
                "7z archive creation is not supported",
            ),
            (
                ConfigSetting::AtomicExtraction,
                ConfigProblem::CannotTargetSink,
                "atomic extraction renames a directory and cannot target a sink",
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
