//! Human-readable output formatter with colors and styling.

use super::formatter::OutputFormatter;
use super::humanize_bytes;
use anyhow::Result;
use console::Term;
use console::style;
use exarch_core::ArchiveManifest;
use exarch_core::CreationReport;
use exarch_core::ExtractionReport;
use exarch_core::IssueSeverity;
use exarch_core::VerificationReport;
use std::io::Write;
use std::path::Path;

/// Human-readable formatter writing non-error output to `O` and error output
/// to `E`. Defaults to the process stdout/stderr terminals; tests can inject
/// in-memory writers via [`HumanFormatter::with_writers`] to capture output.
pub struct HumanFormatter<O: Write = Term, E: Write = Term> {
    verbose: bool,
    quiet: bool,
    use_colors: bool,
    out: O,
    err: E,
}

impl HumanFormatter<Term, Term> {
    /// Creates a formatter writing to the process stdout/stderr terminals,
    /// with colors auto-detected from the environment.
    pub fn new(verbose: bool, quiet: bool) -> Self {
        Self {
            verbose,
            quiet,
            use_colors: console::colors_enabled(),
            out: Term::stdout(),
            err: Term::stderr(),
        }
    }
}

impl<O: Write, E: Write> HumanFormatter<O, E> {
    /// Creates a formatter writing to the given writers, with `use_colors`
    /// set explicitly rather than auto-detected — lets tests assert on
    /// deterministic output regardless of TTY state.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_writers(out: O, err: E, verbose: bool, quiet: bool, use_colors: bool) -> Self {
        Self {
            verbose,
            quiet,
            use_colors,
            out,
            err,
        }
    }

    /// Returns a reference to the non-error output writer.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn out(&self) -> &O {
        &self.out
    }

    /// Returns a reference to the error output writer.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn err(&self) -> &E {
        &self.err
    }

    fn format_number(n: usize) -> String {
        let s = n.to_string();
        let mut result = String::new();
        let mut count = 0;

        for c in s.chars().rev() {
            if count == 3 {
                result.push(',');
                count = 0;
            }
            result.push(c);
            count += 1;
        }

        result.chars().rev().collect()
    }
}

/// Renders `args` to a line and issues a single [`Write::write_all`] call.
///
/// `write!`/`writeln!` on a multi-argument format string invoke the
/// underlying writer once per formatted fragment; for [`Term`], each of
/// those calls flushes independently (`console::Term`'s `Write` impl has no
/// internal buffering), turning one logical line into several syscalls.
/// Formatting into a `String` first and writing it in one call restores the
/// single-write-per-line behavior of the old `Term::write_line`.
fn emit_line<W: Write>(writer: &mut W, args: std::fmt::Arguments<'_>) {
    use std::fmt::Write as _;
    let mut line = String::new();
    let _ = line.write_fmt(args);
    line.push('\n');
    let _ = writer.write_all(line.as_bytes());
}

/// Writes a single blank line in one call. See [`emit_line`].
fn emit_blank<W: Write>(writer: &mut W) {
    let _ = writer.write_all(b"\n");
}

impl<O: Write, E: Write> OutputFormatter for HumanFormatter<O, E> {
    fn format_extraction_result(&mut self, report: &ExtractionReport) -> Result<()> {
        if self.quiet {
            return Ok(());
        }

        if self.use_colors {
            emit_line(
                &mut self.out,
                format_args!("{} Extraction complete", style("✓").green().bold()),
            );
        } else {
            emit_line(&mut self.out, format_args!("Extraction complete"));
        }

        emit_line(
            &mut self.out,
            format_args!("  Files extracted: {}", report.files_extracted),
        );
        emit_line(
            &mut self.out,
            format_args!("  Directories: {}", report.directories_created),
        );
        emit_line(
            &mut self.out,
            format_args!("  Total size: {}", humanize_bytes(report.bytes_written)),
        );

        if self.verbose {
            emit_line(
                &mut self.out,
                format_args!("  Symlinks: {}", report.symlinks_created),
            );
            emit_line(
                &mut self.out,
                format_args!("  Duration: {:?}", report.duration),
            );
        }

        Ok(())
    }

    fn format_creation_result(
        &mut self,
        output_path: &Path,
        report: &CreationReport,
    ) -> Result<()> {
        if self.quiet {
            return Ok(());
        }

        if self.use_colors {
            emit_line(
                &mut self.out,
                format_args!(
                    "{} Archive created: {}",
                    style("✓").green().bold(),
                    output_path.display()
                ),
            );
        } else {
            emit_line(
                &mut self.out,
                format_args!("Archive created: {}", output_path.display()),
            );
        }

        emit_blank(&mut self.out);
        emit_line(
            &mut self.out,
            format_args!(
                "  Files added:      {}",
                Self::format_number(report.files_added)
            ),
        );
        emit_line(
            &mut self.out,
            format_args!(
                "  Directories:      {}",
                Self::format_number(report.directories_added)
            ),
        );
        emit_line(
            &mut self.out,
            format_args!(
                "  Total size:       {}",
                humanize_bytes(report.bytes_written)
            ),
        );

        if report.bytes_compressed > 0 {
            emit_line(
                &mut self.out,
                format_args!(
                    "  Compressed size:  {}",
                    humanize_bytes(report.bytes_compressed)
                ),
            );
            emit_line(
                &mut self.out,
                format_args!(
                    "  Compression:      {:.1}%",
                    report.compression_percentage()
                ),
            );
        }

        if report.files_skipped > 0 {
            emit_line(
                &mut self.out,
                format_args!("  Files skipped:    {}", report.files_skipped),
            );
        }

        if report.has_warnings() {
            emit_blank(&mut self.out);
            if self.use_colors {
                emit_line(
                    &mut self.out,
                    format_args!("{}", style("Warnings:").yellow().bold()),
                );
            } else {
                emit_line(&mut self.out, format_args!("Warnings:"));
            }
            for warning in &report.warnings {
                emit_line(&mut self.out, format_args!("  - {warning}"));
            }
        }

        Ok(())
    }

    fn format_error(&mut self, _operation: &str, error: &anyhow::Error) {
        // Always show errors on stderr, even in quiet mode
        if self.use_colors {
            emit_line(
                &mut self.err,
                format_args!("{} {error:#}", style("Error:").red().bold()),
            );
        } else {
            emit_line(&mut self.err, format_args!("Error: {error:#}"));
        }
    }

    fn format_manifest_short(&mut self, manifest: &ArchiveManifest) -> Result<()> {
        if self.quiet {
            return Ok(());
        }

        for entry in &manifest.entries {
            emit_line(&mut self.out, format_args!("{}", entry.path.display()));
        }

        Ok(())
    }

    fn format_manifest_long(
        &mut self,
        manifest: &ArchiveManifest,
        human_readable: bool,
    ) -> Result<()> {
        if self.quiet {
            return Ok(());
        }

        for entry in &manifest.entries {
            let size_str = if human_readable {
                humanize_bytes(entry.size)
            } else {
                entry.size.to_string()
            };

            let mode_str = entry
                .mode
                .map_or_else(|| "-".to_string(), |m| format!("{m:o}"));

            let type_char = match entry.entry_type {
                exarch_core::ManifestEntryType::File => "-",
                exarch_core::ManifestEntryType::Directory => "d",
                exarch_core::ManifestEntryType::Symlink => "l",
                exarch_core::ManifestEntryType::Hardlink => "h",
            };

            let link_target = match entry.entry_type {
                exarch_core::ManifestEntryType::Symlink => entry.symlink_target.as_ref(),
                exarch_core::ManifestEntryType::Hardlink => entry.hardlink_target.as_ref(),
                _ => None,
            };
            if let Some(target) = link_target {
                emit_line(
                    &mut self.out,
                    format_args!(
                        "{}{:<6} {:>10}  {} -> {}",
                        type_char,
                        mode_str,
                        size_str,
                        entry.path.display(),
                        target.display()
                    ),
                );
            } else {
                emit_line(
                    &mut self.out,
                    format_args!(
                        "{}{:<6} {:>10}  {}",
                        type_char,
                        mode_str,
                        size_str,
                        entry.path.display()
                    ),
                );
            }
        }

        emit_blank(&mut self.out);
        emit_line(
            &mut self.out,
            format_args!(
                "Total: {} files, {}",
                Self::format_number(manifest.total_entries),
                humanize_bytes(manifest.total_size)
            ),
        );

        Ok(())
    }

    fn format_verification_report(&mut self, report: &VerificationReport) -> Result<()> {
        if self.quiet {
            return Ok(());
        }

        // Header
        if self.use_colors {
            let status_str = match report.status {
                exarch_core::VerificationStatus::Pass => style("PASSED").green().bold(),
                exarch_core::VerificationStatus::Warning => style("WARNING").yellow().bold(),
                exarch_core::VerificationStatus::Fail => style("FAILED").red().bold(),
            };
            emit_line(
                &mut self.out,
                format_args!("Archive verification: {status_str}"),
            );
        } else {
            emit_line(
                &mut self.out,
                format_args!("Archive verification: {}", report.status),
            );
        }

        // Summary
        emit_line(
            &mut self.out,
            format_args!("  Integrity: {}", report.integrity_status),
        );
        emit_line(
            &mut self.out,
            format_args!("  Security: {}", report.security_status),
        );
        emit_line(
            &mut self.out,
            format_args!(
                "  Total entries: {}",
                Self::format_number(report.total_entries)
            ),
        );

        if report.suspicious_entries > 0 {
            emit_line(
                &mut self.out,
                format_args!("  Suspicious entries: {}", report.suspicious_entries),
            );
        }

        // Issues
        if !report.issues.is_empty() {
            emit_blank(&mut self.out);
            emit_line(&mut self.out, format_args!("Issues:"));

            for issue in &report.issues {
                let severity_str = if self.use_colors {
                    match issue.severity {
                        IssueSeverity::Critical => style("CRITICAL").red().bold().to_string(),
                        IssueSeverity::High => style("HIGH").red().to_string(),
                        IssueSeverity::Medium => style("MEDIUM").yellow().to_string(),
                        IssueSeverity::Low => style("LOW").blue().to_string(),
                        IssueSeverity::Info => style("INFO").cyan().to_string(),
                    }
                } else {
                    format!("[{}]", issue.severity)
                };

                if let Some(ref path) = issue.entry_path {
                    emit_line(
                        &mut self.out,
                        format_args!("  {} {}: {}", severity_str, path.display(), issue.message),
                    );
                } else {
                    emit_line(
                        &mut self.out,
                        format_args!("  {} {}", severity_str, issue.message),
                    );
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn formatter(verbose: bool, quiet: bool, use_colors: bool) -> HumanFormatter<Vec<u8>, Vec<u8>> {
        HumanFormatter::with_writers(Vec::new(), Vec::new(), verbose, quiet, use_colors)
    }

    fn out_text(f: &HumanFormatter<Vec<u8>, Vec<u8>>) -> String {
        String::from_utf8(f.out().clone()).unwrap()
    }

    fn err_text(f: &HumanFormatter<Vec<u8>, Vec<u8>>) -> String {
        String::from_utf8(f.err().clone()).unwrap()
    }

    type TestFormatter = HumanFormatter<Vec<u8>, Vec<u8>>;

    #[test]
    fn test_format_number_small() {
        assert_eq!(TestFormatter::format_number(0), "0");
        assert_eq!(TestFormatter::format_number(1), "1");
        assert_eq!(TestFormatter::format_number(42), "42");
        assert_eq!(TestFormatter::format_number(999), "999");
    }

    #[test]
    fn test_format_number_thousands() {
        assert_eq!(TestFormatter::format_number(1000), "1,000");
        assert_eq!(TestFormatter::format_number(1234), "1,234");
        assert_eq!(TestFormatter::format_number(9999), "9,999");
    }

    #[test]
    fn test_format_number_millions() {
        assert_eq!(TestFormatter::format_number(1_000_000), "1,000,000");
        assert_eq!(TestFormatter::format_number(1_234_567), "1,234,567");
        assert_eq!(TestFormatter::format_number(42_000_000), "42,000,000");
    }

    #[test]
    fn test_format_number_large() {
        assert_eq!(TestFormatter::format_number(1_000_000_000), "1,000,000,000");
        assert_eq!(
            TestFormatter::format_number(123_456_789_012),
            "123,456,789,012"
        );
        assert_eq!(TestFormatter::format_number(usize::MAX), {
            let s = usize::MAX.to_string();
            let mut result = String::new();
            let mut count = 0;
            for c in s.chars().rev() {
                if count == 3 {
                    result.push(',');
                    count = 0;
                }
                result.push(c);
                count += 1;
            }
            result.chars().rev().collect::<String>()
        });
    }

    fn sample_extraction_report() -> ExtractionReport {
        ExtractionReport {
            files_extracted: 3,
            directories_created: 1,
            symlinks_created: 0,
            bytes_written: 2048,
            duration: std::time::Duration::from_secs(1),
            ..Default::default()
        }
    }

    fn sample_creation_report() -> CreationReport {
        CreationReport {
            files_added: 2,
            directories_added: 1,
            symlinks_added: 0,
            bytes_written: 1024,
            bytes_compressed: 0,
            files_skipped: 0,
            duration: std::time::Duration::from_secs(1),
            warnings: vec![],
        }
    }

    #[test]
    fn format_extraction_result_no_colors() {
        let mut f = formatter(false, false, false);
        f.format_extraction_result(&sample_extraction_report())
            .unwrap();
        let text = out_text(&f);
        assert!(text.contains("Extraction complete"));
        assert!(
            !text.contains('✓'),
            "no-colors branch must not print the check mark"
        );
        assert!(text.contains("Files extracted: 3"));
        assert!(text.contains("Directories: 1"));
        assert!(text.contains("Total size: 2.0 KB"));
        assert!(!text.contains("Symlinks:"));
    }

    #[test]
    fn format_extraction_result_verbose() {
        let mut f = formatter(true, false, false);
        f.format_extraction_result(&sample_extraction_report())
            .unwrap();
        let text = out_text(&f);
        assert!(text.contains("Symlinks: 0"));
        assert!(text.contains("Duration:"));
    }

    #[test]
    fn format_extraction_result_quiet_suppresses_output() {
        let mut f = formatter(false, true, false);
        f.format_extraction_result(&sample_extraction_report())
            .unwrap();
        assert!(out_text(&f).is_empty());
    }

    #[test]
    fn format_extraction_result_with_colors() {
        let mut f = formatter(false, false, true);
        f.format_extraction_result(&sample_extraction_report())
            .unwrap();
        // A reset escape sits between the styled "✓" and the following
        // literal text, so the two are never byte-adjacent when real ANSI
        // codes are rendered (e.g. under `CLICOLOR_FORCE=1`); strip them
        // before asserting so the check holds regardless of whether colors
        // actually rendered in this environment.
        let text = console::strip_ansi_codes(&out_text(&f)).into_owned();
        assert!(
            text.contains("✓ Extraction complete"),
            "colors branch must prefix the success line with the check mark: {text}"
        );
    }

    #[test]
    fn format_creation_result_no_colors() {
        let mut f = formatter(false, false, false);
        let path = Path::new("out.tar.gz");
        f.format_creation_result(path, &sample_creation_report())
            .unwrap();
        let text = out_text(&f);
        assert!(text.contains("Archive created: out.tar.gz"));
        assert!(text.contains("Files added:      2"));
        assert!(text.contains("Directories:      1"));
        assert!(text.contains("Total size:       1.0 KB"));
    }

    #[test]
    fn format_creation_result_with_compression_and_warnings() {
        let mut f = formatter(false, false, false);
        let mut report = sample_creation_report();
        report.bytes_compressed = 512;
        report.files_skipped = 1;
        report.warnings.push("skipped a broken symlink".to_string());
        f.format_creation_result(Path::new("out.tar.gz"), &report)
            .unwrap();
        let text = out_text(&f);
        assert!(text.contains("Compressed size:  512 B"));
        assert!(text.contains("Compression:"));
        assert!(text.contains("Files skipped:    1"));
        assert!(text.contains("Warnings:"));
        assert!(text.contains("skipped a broken symlink"));
    }

    #[test]
    fn format_creation_result_quiet_suppresses_output() {
        let mut f = formatter(false, true, false);
        f.format_creation_result(Path::new("out.tar.gz"), &sample_creation_report())
            .unwrap();
        assert!(out_text(&f).is_empty());
    }

    #[test]
    fn format_error_writes_to_stderr_not_stdout() {
        let mut f = formatter(false, false, false);
        let err = anyhow::anyhow!(exarch_core::ArchiveError::ZipBomb {
            compressed: 1000,
            uncompressed: 1_000_000,
            ratio: 1000.0,
        });
        f.format_error("extract", &err);
        assert!(out_text(&f).is_empty());
        let text = err_text(&f);
        assert!(text.starts_with("Error: "));
        assert!(!text.contains('{'), "human errors are plain text, not JSON");
    }

    // `format_error`'s two branches emit the identical literal "Error: " prefix
    // (unlike the extraction/verification branches, which use different
    // literals) — the only actual difference is the ANSI escape codes that
    // `style(..)` emits, and those are gated on console's *global*
    // `colors_enabled()`, not on `HumanFormatter::use_colors`. Force the
    // global flag for the duration of this test (nextest runs each test in
    // its own process, so this cannot leak into other tests) to make the
    // color branch observably different from the no-colors branch.
    #[test]
    fn format_error_with_colors() {
        let previous = console::colors_enabled();
        console::set_colors_enabled(true);

        let mut f = formatter(false, false, true);
        let err = anyhow::anyhow!("boom");
        f.format_error("extract", &err);

        console::set_colors_enabled(previous);

        let text = err_text(&f);
        assert!(text.contains("boom"));
        assert!(
            text.contains("\x1b["),
            "colors branch must emit ANSI escape codes when colors are enabled: {text:?}"
        );
    }

    #[test]
    fn format_error_ignores_quiet() {
        let mut f = formatter(false, true, false);
        let err = anyhow::anyhow!("boom");
        f.format_error("extract", &err);
        assert!(err_text(&f).contains("boom"));
    }

    fn sample_manifest() -> ArchiveManifest {
        use exarch_core::ArchiveEntry;
        use exarch_core::ManifestEntryType;
        use exarch_core::formats::detect::ArchiveType;

        ArchiveManifest {
            format: ArchiveType::TarGz,
            total_entries: 2,
            total_size: 1536,
            entries: vec![
                ArchiveEntry {
                    path: std::path::PathBuf::from("file.txt"),
                    entry_type: ManifestEntryType::File,
                    size: 1024,
                    compressed_size: None,
                    mode: Some(0o644),
                    modified: None,
                    symlink_target: None,
                    hardlink_target: None,
                },
                ArchiveEntry {
                    path: std::path::PathBuf::from("link.txt"),
                    entry_type: ManifestEntryType::Symlink,
                    size: 512,
                    compressed_size: None,
                    mode: Some(0o777),
                    modified: None,
                    symlink_target: Some(std::path::PathBuf::from("file.txt")),
                    hardlink_target: None,
                },
            ],
        }
    }

    #[test]
    fn format_manifest_short_lists_paths_only() {
        let mut f = formatter(false, false, false);
        f.format_manifest_short(&sample_manifest()).unwrap();
        let text = out_text(&f);
        assert!(text.contains("file.txt"));
        assert!(text.contains("link.txt"));
        assert!(!text.contains("Total:"));
    }

    #[test]
    fn format_manifest_short_quiet_suppresses_output() {
        let mut f = formatter(false, true, false);
        f.format_manifest_short(&sample_manifest()).unwrap();
        assert!(out_text(&f).is_empty());
    }

    #[test]
    fn format_manifest_long_human_readable_size() {
        let mut f = formatter(false, false, false);
        f.format_manifest_long(&sample_manifest(), true).unwrap();
        let text = out_text(&f);
        assert!(text.contains("1.0 KB"));
        assert!(text.contains("512 B"));
        assert!(text.contains("Total: 2 files, 1.5 KB"));
    }

    #[test]
    fn format_manifest_long_raw_size() {
        let mut f = formatter(false, false, false);
        f.format_manifest_long(&sample_manifest(), false).unwrap();
        let text = out_text(&f);
        assert!(text.contains("1024"));
        assert!(text.contains("512"));
    }

    #[test]
    fn format_manifest_long_shows_symlink_target() {
        let mut f = formatter(false, false, false);
        f.format_manifest_long(&sample_manifest(), true).unwrap();
        let text = out_text(&f);
        assert!(text.contains("link.txt -> file.txt"));
    }

    #[test]
    fn format_manifest_long_shows_hardlink_target() {
        use exarch_core::ArchiveEntry;
        use exarch_core::ManifestEntryType;
        use exarch_core::formats::detect::ArchiveType;

        let manifest = ArchiveManifest {
            format: ArchiveType::TarGz,
            total_entries: 1,
            total_size: 256,
            entries: vec![ArchiveEntry {
                path: std::path::PathBuf::from("hard.txt"),
                entry_type: ManifestEntryType::Hardlink,
                size: 256,
                compressed_size: None,
                mode: Some(0o644),
                modified: None,
                symlink_target: None,
                hardlink_target: Some(std::path::PathBuf::from("original.txt")),
            }],
        };

        let mut f = formatter(false, false, false);
        f.format_manifest_long(&manifest, true).unwrap();
        let text = out_text(&f);
        assert!(text.contains("hard.txt -> original.txt"));
    }

    #[test]
    fn format_manifest_long_quiet_suppresses_output() {
        let mut f = formatter(false, true, false);
        f.format_manifest_long(&sample_manifest(), true).unwrap();
        assert!(out_text(&f).is_empty());
    }

    fn sample_verification_report(status: exarch_core::VerificationStatus) -> VerificationReport {
        use exarch_core::CheckStatus;
        use exarch_core::formats::detect::ArchiveType;

        VerificationReport {
            status,
            integrity_status: CheckStatus::Pass,
            security_status: CheckStatus::Pass,
            total_entries: 5,
            suspicious_entries: 0,
            total_size: 4096,
            format: ArchiveType::TarGz,
            issues: vec![],
        }
    }

    #[test]
    fn format_verification_report_pass_no_colors() {
        let mut f = formatter(false, false, false);
        f.format_verification_report(&sample_verification_report(
            exarch_core::VerificationStatus::Pass,
        ))
        .unwrap();
        let text = out_text(&f);
        assert!(text.contains("Archive verification: PASS\n"));
        assert!(
            !text.contains("PASSED"),
            "no-colors branch must use the terse Display form, not the colored literal: {text}"
        );
        assert!(text.contains("Total entries: 5"));
    }

    #[test]
    fn format_verification_report_with_colors() {
        let mut f = formatter(false, false, true);
        f.format_verification_report(&sample_verification_report(
            exarch_core::VerificationStatus::Pass,
        ))
        .unwrap();
        // See the comment in `format_extraction_result_with_colors`: the
        // leading fg/attr escapes sit directly before "PASSED", so strip
        // ANSI codes before asserting adjacency.
        let text = console::strip_ansi_codes(&out_text(&f)).into_owned();
        assert!(
            text.contains("Archive verification: PASSED"),
            "colors branch must use the longer colored literal, not the terse Display form: {text}"
        );
    }

    #[test]
    fn format_verification_report_quiet_suppresses_output() {
        let mut f = formatter(false, true, false);
        f.format_verification_report(&sample_verification_report(
            exarch_core::VerificationStatus::Pass,
        ))
        .unwrap();
        assert!(out_text(&f).is_empty());
    }
}
