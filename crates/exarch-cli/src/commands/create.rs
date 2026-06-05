//! Create command implementation.

use crate::cli::CreateArgs;
use crate::output::OutputFormatter;
use crate::progress::CliProgress;
use anyhow::Context;
use anyhow::Result;
use exarch_core::CreationConfig;
use exarch_core::NoopProgress;
use exarch_core::create_archive_with_progress;

pub fn execute(args: &CreateArgs, formatter: &dyn OutputFormatter, quiet: bool) -> Result<()> {
    // Check if output exists
    if args.output.exists() && !args.force {
        anyhow::bail!(
            "Output file already exists: {}. Use --force to overwrite",
            args.output.display()
        );
    }

    // Remove existing file if --force
    if args.output.exists() && args.force {
        std::fs::remove_file(&args.output).with_context(|| {
            format!("Failed to remove existing file: {}", args.output.display())
        })?;
    }

    // Build config
    let mut config = CreationConfig {
        follow_symlinks: args.follow_symlinks,
        include_hidden: args.include_hidden,
        compression_level: args.compression_level,
        strip_prefix: args.strip_prefix.clone(),
        max_file_size: args.max_file_size,
        preserve_permissions: args.preserve_permissions,
        ..Default::default()
    };

    // Add user exclude patterns to defaults
    config.exclude_patterns.extend(args.exclude.iter().cloned());

    // Create archive with progress if TTY is detected
    let report = if !quiet && CliProgress::should_show() {
        let mut progress = CliProgress::new(100, "Creating");
        create_archive_with_progress(&args.output, &args.sources, &config, &mut progress)
            .with_context(|| format!("Failed to create archive: {}", args.output.display()))?
    } else {
        let mut noop = NoopProgress;
        create_archive_with_progress(&args.output, &args.sources, &config, &mut noop)
            .with_context(|| format!("Failed to create archive: {}", args.output.display()))?
    };

    formatter.format_creation_result(&args.output, &report)?;

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::output::OutputFormatter;
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
        fn format_extraction_result(&self, _: &ExtractionReport) -> Result<()> {
            Ok(())
        }

        fn format_creation_result(&self, _: &Path, _: &CreationReport) -> Result<()> {
            if !self.quiet {
                self.called.set(true);
            }
            Ok(())
        }

        fn format_manifest_short(&self, _: &ArchiveManifest) -> Result<()> {
            Ok(())
        }

        fn format_manifest_long(&self, _: &ArchiveManifest, _: bool) -> Result<()> {
            Ok(())
        }

        fn format_verification_report(&self, _: &VerificationReport) -> Result<()> {
            Ok(())
        }

        fn format_error(&self, _: &str, _: &anyhow::Error) {}
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
        fn format_extraction_result(&self, _: &ExtractionReport) -> Result<()> {
            Ok(())
        }

        fn format_creation_result(&self, _: &Path, _: &CreationReport) -> Result<()> {
            self.called.set(true);
            Ok(())
        }

        fn format_manifest_short(&self, _: &ArchiveManifest) -> Result<()> {
            Ok(())
        }

        fn format_manifest_long(&self, _: &ArchiveManifest, _: bool) -> Result<()> {
            Ok(())
        }

        fn format_verification_report(&self, _: &VerificationReport) -> Result<()> {
            Ok(())
        }

        fn format_error(&self, _: &str, _: &anyhow::Error) {}
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

    // Regression test for issue #357: JSON formatter must emit output even when
    // quiet=true.
    #[test]
    fn json_formatter_emits_when_quiet() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("hello.txt");
        std::fs::write(&src, b"hello").unwrap();
        let out = tmp.path().join("out.tar.gz");

        let args = make_args(out, src);
        let formatter = AlwaysCallSpyFormatter::new();

        execute(&args, &formatter, true).unwrap();

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
        let formatter = AlwaysCallSpyFormatter::new();

        execute(&args, &formatter, false).unwrap();

        assert!(formatter.was_called());
    }

    // Human formatter with quiet=true must suppress output — SpyFormatter mirrors
    // HumanFormatter behavior.
    #[test]
    fn human_formatter_suppresses_when_quiet() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("hello.txt");
        std::fs::write(&src, b"hello").unwrap();
        let out = tmp.path().join("out.tar.gz");

        let args = make_args(out, src);
        let formatter = SpyFormatter::new(true);

        execute(&args, &formatter, true).unwrap();

        assert!(
            !formatter.was_called(),
            "human formatter must not produce output when quiet=true"
        );
    }
}
