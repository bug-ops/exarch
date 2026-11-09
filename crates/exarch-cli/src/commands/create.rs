//! Create command implementation.

use crate::cli::CreateArgs;
use crate::commands::CommandResult;
use crate::commands::Outcome;
use crate::interrupt;
use crate::operation::Operation;
use crate::output::OutputFormatter;
use crate::output::OutputMode;
use crate::progress::BarLength;
use crate::progress::progress_for;
use exarch_core::CompressionLevel;
use exarch_core::ConfigSetting;
use exarch_core::CreateRequest;
use exarch_core::CreationConfig;
use exarch_core::EntryPattern;
use exarch_core::Limit;
use exarch_core::OutputFile;
use std::num::NonZeroU64;

/// Runs `create`: builds the archive inside the armed interrupt window and
/// prints the report once the window is closed.
///
/// # Errors
///
/// The core failure of the run, or the CLI's own refusal of a flag value.
pub fn execute(
    args: &CreateArgs,
    formatter: &mut dyn OutputFormatter,
    mode: OutputMode,
) -> CommandResult {
    let guard = interrupt::install(&args.output, interrupt::Run::Create, mode);

    let max_file_size = match args.max_file_size {
        Some(size) => Limit::<NonZeroU64>::parse(ConfigSetting::MaxFileSize, size)?,
        None => Limit::Unbounded,
    };

    // Build config
    let mut config = CreationConfig::default()
        .with_follow_symlinks(args.follow_symlinks)
        .with_include_hidden(args.include_hidden)
        .with_strip_prefix(args.strip_prefix.clone())
        .with_max_file_size(max_file_size)
        .with_preserve_permissions(args.preserve_permissions);
    if let Some(requested) = args.compression_level {
        config = config.with_compression_level(CompressionLevel::try_from(requested)?);
    }

    // Add user exclude patterns to defaults
    for pattern in &args.exclude {
        let pattern = EntryPattern::try_from(pattern.as_str())?;
        config.exclude_patterns.push(pattern);
    }

    let mut progress = progress_for(mode, BarLength::Discover, Operation::Create, &guard);
    let output = if args.force {
        OutputFile::replace(&args.output)
    } else {
        OutputFile::create_new(&args.output)
    };
    let result = CreateRequest::new(&config)
        .with_progress(progress.as_mut())
        .create(&output, &args.sources);
    drop(progress);
    drop(guard);
    let report = result?;

    formatter.format_creation_result(&args.output, &report)?;

    Ok(Outcome::Ok)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::output::ManifestView;
    use crate::output::OutputFormatter;
    use crate::output::Verbosity;
    use anyhow::Result;
    use exarch_core::ArchiveManifest;
    use exarch_core::CreationReport;
    use exarch_core::ExtractionReport;
    use exarch_core::VerificationReport;
    use std::cell::Cell;
    use std::path::Path;
    use std::path::PathBuf;

    struct SpyFormatter {
        called: Cell<bool>,
        quiet: bool,
    }

    impl SpyFormatter {
        fn new(quiet: bool) -> Self {
            Self {
                called: Cell::new(false),
                quiet,
            }
        }

        fn was_called(&self) -> bool {
            self.called.get()
        }
    }

    impl OutputFormatter for SpyFormatter {
        fn format_extraction_result(&mut self, _: &ExtractionReport) -> Result<()> {
            Ok(())
        }

        fn format_creation_result(&mut self, _: &Path, _: &CreationReport) -> Result<()> {
            if !self.quiet {
                self.called.set(true);
            }
            Ok(())
        }

        fn format_manifest(
            &mut self,
            _: &ArchiveManifest,
            _: ManifestView,
            _: &crate::output::Dispositions,
        ) -> Result<()> {
            Ok(())
        }

        fn format_verification_report(&mut self, _: &VerificationReport) -> Result<()> {
            Ok(())
        }

        fn format_error(&mut self, _: Operation, _: &anyhow::Error) {}

        fn format_verification_failed(&mut self) {}
    }

    /// `JsonFormatter` always calls `format_creation_result` regardless of
    /// quiet.
    struct AlwaysCallSpyFormatter {
        called: Cell<bool>,
    }

    impl AlwaysCallSpyFormatter {
        fn new() -> Self {
            Self {
                called: Cell::new(false),
            }
        }

        fn was_called(&self) -> bool {
            self.called.get()
        }
    }

    impl OutputFormatter for AlwaysCallSpyFormatter {
        fn format_extraction_result(&mut self, _: &ExtractionReport) -> Result<()> {
            Ok(())
        }

        fn format_creation_result(&mut self, _: &Path, _: &CreationReport) -> Result<()> {
            self.called.set(true);
            Ok(())
        }

        fn format_manifest(
            &mut self,
            _: &ArchiveManifest,
            _: ManifestView,
            _: &crate::output::Dispositions,
        ) -> Result<()> {
            Ok(())
        }

        fn format_verification_report(&mut self, _: &VerificationReport) -> Result<()> {
            Ok(())
        }

        fn format_error(&mut self, _: Operation, _: &anyhow::Error) {}

        fn format_verification_failed(&mut self) {}
    }

    fn make_args(output: PathBuf, source: PathBuf) -> CreateArgs {
        CreateArgs {
            output,
            sources: vec![source],
            compression_level: None,
            follow_symlinks: false,
            include_hidden: false,
            exclude: vec![],
            strip_prefix: None,
            max_file_size: None,
            preserve_permissions: true,
            force: false,
        }
    }

    #[test]
    fn zero_max_file_size_is_refused_as_invalid_configuration() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("hello.txt");
        std::fs::write(&src, b"hello").unwrap();
        let out = tmp.path().join("out.tar.gz");

        let mut args = make_args(out.clone(), src);
        args.max_file_size = Some(0);
        let mut formatter = SpyFormatter::new(false);

        let err = execute(&args, &mut formatter, OutputMode::Human(Verbosity::Quiet))
            .unwrap_err()
            .contextualize(Operation::Create, &out);

        assert!(
            format!("{err:#}").contains("max_file_size must not be zero"),
            "unexpected error: {err:#}"
        );
        assert!(!out.exists(), "no archive may be created");
        assert!(!formatter.was_called());
    }

    // Regression test for issue #357: JSON formatter must emit output even when
    // quiet=true.
    #[test]
    fn json_formatter_emits_when_quiet() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("hello.txt");
        std::fs::write(&src, b"hello").unwrap();
        let out = tmp.path().join("out.tar.gz");

        let args = make_args(out, src);
        let mut formatter = AlwaysCallSpyFormatter::new();

        execute(&args, &mut formatter, OutputMode::Human(Verbosity::Quiet)).unwrap();

        assert!(
            formatter.was_called(),
            "format_creation_result must be called even when quiet=true (JSON mode)"
        );
    }

    #[test]
    fn json_formatter_emits_when_not_quiet() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("hello.txt");
        std::fs::write(&src, b"hello").unwrap();
        let out = tmp.path().join("out.tar.gz");

        let args = make_args(out, src);
        let mut formatter = AlwaysCallSpyFormatter::new();

        execute(&args, &mut formatter, OutputMode::Human(Verbosity::Normal)).unwrap();

        assert!(formatter.was_called());
    }

    // Human formatter with quiet=true must suppress output — SpyFormatter
    // mirrors HumanFormatter behavior.
    #[test]
    fn human_formatter_suppresses_when_quiet() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("hello.txt");
        std::fs::write(&src, b"hello").unwrap();
        let out = tmp.path().join("out.tar.gz");

        let args = make_args(out, src);
        let mut formatter = SpyFormatter::new(true);

        execute(&args, &mut formatter, OutputMode::Human(Verbosity::Quiet)).unwrap();

        assert!(
            !formatter.was_called(),
            "human formatter must not produce output when quiet=true"
        );
    }
}
