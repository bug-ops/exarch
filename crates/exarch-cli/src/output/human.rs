//! Human-readable output formatter with colors and styling.

use super::formatter::OutputFormatter;
use anyhow::Result;
use console::Term;
use console::style;
use exarch_core::ArchiveManifest;
use exarch_core::CreationReport;
use exarch_core::ExtractionReport;
use exarch_core::IssueSeverity;
use exarch_core::VerificationReport;
use std::path::Path;

pub struct HumanFormatter {
    verbose: bool,
    quiet: bool,
    use_colors: bool,
    term: Term,
}

impl HumanFormatter {
    pub fn new(verbose: bool, quiet: bool) -> Self {
        Self {
            verbose,
            quiet,
            use_colors: console::colors_enabled(),
            term: Term::stdout(),
        }
    }

    fn format_size(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        if bytes >= GB {
            format!("{:.1} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.1} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.1} KB", bytes as f64 / KB as f64)
        } else {
            format!("{bytes} B")
        }
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

impl OutputFormatter for HumanFormatter {
    fn format_extraction_result(&self, report: &ExtractionReport) -> Result<()> {
        if self.quiet {
            return Ok(());
        }

        if self.use_colors {
            let _ = self.term.write_line(&format!(
                "{} Extraction complete",
                style("✓").green().bold()
            ));
        } else {
            let _ = self.term.write_line("Extraction complete");
        }

        let _ = self
            .term
            .write_line(&format!("  Files extracted: {}", report.files_extracted));
        let _ = self
            .term
            .write_line(&format!("  Directories: {}", report.directories_created));
        let _ = self.term.write_line(&format!(
            "  Total size: {}",
            Self::format_size(report.bytes_written)
        ));

        if self.verbose {
            let _ = self
                .term
                .write_line(&format!("  Symlinks: {}", report.symlinks_created));
            let _ = self
                .term
                .write_line(&format!("  Duration: {:?}", report.duration));
        }

        Ok(())
    }

    fn format_creation_result(&self, output_path: &Path, report: &CreationReport) -> Result<()> {
        if self.quiet {
            return Ok(());
        }

        if self.use_colors {
            let _ = self.term.write_line(&format!(
                "{} Archive created: {}",
                style("✓").green().bold(),
                output_path.display()
            ));
        } else {
            let _ = self
                .term
                .write_line(&format!("Archive created: {}", output_path.display()));
        }

        let _ = self.term.write_line("");
        let _ = self.term.write_line(&format!(
            "  Files added:      {}",
            Self::format_number(report.files_added)
        ));
        let _ = self.term.write_line(&format!(
            "  Directories:      {}",
            Self::format_number(report.directories_added)
        ));
        let _ = self.term.write_line(&format!(
            "  Total size:       {}",
            Self::format_size(report.bytes_written)
        ));

        if report.bytes_compressed > 0 {
            let _ = self.term.write_line(&format!(
                "  Compressed size:  {}",
                Self::format_size(report.bytes_compressed)
            ));
            let _ = self.term.write_line(&format!(
                "  Compression:      {:.1}%",
                report.compression_percentage()
            ));
        }

        if report.files_skipped > 0 {
            let _ = self
                .term
                .write_line(&format!("  Files skipped:    {}", report.files_skipped));
        }

        if report.has_warnings() {
            let _ = self.term.write_line("");
            if self.use_colors {
                let _ = self
                    .term
                    .write_line(&format!("{}", style("Warnings:").yellow().bold()));
            } else {
                let _ = self.term.write_line("Warnings:");
            }
            for warning in &report.warnings {
                let _ = self.term.write_line(&format!("  - {warning}"));
            }
        }

        Ok(())
    }

    fn format_error(&self, error: &anyhow::Error) {
        // Always show errors, even in quiet mode
        if self.use_colors {
            let _ = self
                .term
                .write_line(&format!("{} {error:?}", style("ERROR:").red().bold()));
        } else {
            let _ = self.term.write_line(&format!("ERROR: {error:?}"));
        }
    }

    fn format_success(&self, message: &str) {
        if self.quiet {
            return;
        }

        if self.use_colors {
            let _ = self
                .term
                .write_line(&format!("{} {message}", style("✓").green().bold()));
        } else {
            let _ = self.term.write_line(message);
        }
    }

    fn format_warning(&self, message: &str) {
        if self.quiet {
            return;
        }

        if self.use_colors {
            let _ = self
                .term
                .write_line(&format!("{} {message}", style("⚠").yellow().bold()));
        } else {
            let _ = self.term.write_line(&format!("WARNING: {message}"));
        }
    }

    fn format_manifest_short(&self, manifest: &ArchiveManifest) -> Result<()> {
        if self.quiet {
            return Ok(());
        }

        for entry in &manifest.entries {
            let _ = self.term.write_line(&format!("{}", entry.path.display()));
        }

        Ok(())
    }

    fn format_manifest_long(&self, manifest: &ArchiveManifest, human_readable: bool) -> Result<()> {
        if self.quiet {
            return Ok(());
        }

        for entry in &manifest.entries {
            let size_str = if human_readable {
                Self::format_size(entry.size)
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

            let _ = self.term.write_line(&format!(
                "{}{:<6} {:>10}  {}",
                type_char,
                mode_str,
                size_str,
                entry.path.display()
            ));
        }

        let _ = self.term.write_line("");
        let _ = self.term.write_line(&format!(
            "Total: {} files, {}",
            Self::format_number(manifest.total_entries),
            Self::format_size(manifest.total_size)
        ));

        Ok(())
    }

    fn format_verification_report(&self, report: &VerificationReport) -> Result<()> {
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
            let _ = self
                .term
                .write_line(&format!("Archive verification: {status_str}"));
        } else {
            let _ = self
                .term
                .write_line(&format!("Archive verification: {}", report.status));
        }

        // Summary
        let _ = self
            .term
            .write_line(&format!("  Integrity: {}", report.integrity_status));
        let _ = self
            .term
            .write_line(&format!("  Security: {}", report.security_status));
        let _ = self.term.write_line(&format!(
            "  Total entries: {}",
            Self::format_number(report.total_entries)
        ));

        if report.suspicious_entries > 0 {
            let _ = self.term.write_line(&format!(
                "  Suspicious entries: {}",
                report.suspicious_entries
            ));
        }

        // Issues
        if !report.issues.is_empty() {
            let _ = self.term.write_line("");
            let _ = self.term.write_line("Issues:");

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
                    let _ = self.term.write_line(&format!(
                        "  {} {}: {}",
                        severity_str,
                        path.display(),
                        issue.message
                    ));
                } else {
                    let _ = self
                        .term
                        .write_line(&format!("  {} {}", severity_str, issue.message));
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

    #[test]
    fn test_format_size_bytes() {
        assert_eq!(HumanFormatter::format_size(0), "0 B");
        assert_eq!(HumanFormatter::format_size(512), "512 B");
        assert_eq!(HumanFormatter::format_size(1023), "1023 B");
    }

    #[test]
    fn test_format_size_kilobytes() {
        assert_eq!(HumanFormatter::format_size(1024), "1.0 KB");
        assert_eq!(HumanFormatter::format_size(2048), "2.0 KB");
        assert_eq!(HumanFormatter::format_size(1536), "1.5 KB");
    }

    #[test]
    fn test_format_size_megabytes() {
        assert_eq!(HumanFormatter::format_size(1024 * 1024), "1.0 MB");
        assert_eq!(HumanFormatter::format_size(2 * 1024 * 1024), "2.0 MB");
        assert_eq!(HumanFormatter::format_size(1536 * 1024), "1.5 MB");
    }

    #[test]
    fn test_format_size_gigabytes() {
        assert_eq!(HumanFormatter::format_size(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(
            HumanFormatter::format_size(2 * 1024 * 1024 * 1024),
            "2.0 GB"
        );
        assert_eq!(HumanFormatter::format_size(1536 * 1024 * 1024), "1.5 GB");
    }

    #[test]
    fn test_format_size_edge_cases() {
        // u64::MAX = 18446744073709551615 bytes ≈ 17179869184 GB
        assert_eq!(HumanFormatter::format_size(u64::MAX), "17179869184.0 GB");
    }

    #[test]
    fn test_format_number_small() {
        assert_eq!(HumanFormatter::format_number(0), "0");
        assert_eq!(HumanFormatter::format_number(1), "1");
        assert_eq!(HumanFormatter::format_number(42), "42");
        assert_eq!(HumanFormatter::format_number(999), "999");
    }

    #[test]
    fn test_format_number_thousands() {
        assert_eq!(HumanFormatter::format_number(1000), "1,000");
        assert_eq!(HumanFormatter::format_number(1234), "1,234");
        assert_eq!(HumanFormatter::format_number(9999), "9,999");
    }

    #[test]
    fn test_format_number_millions() {
        assert_eq!(HumanFormatter::format_number(1_000_000), "1,000,000");
        assert_eq!(HumanFormatter::format_number(1_234_567), "1,234,567");
        assert_eq!(HumanFormatter::format_number(42_000_000), "42,000,000");
    }

    #[test]
    fn test_format_number_large() {
        assert_eq!(
            HumanFormatter::format_number(1_000_000_000),
            "1,000,000,000"
        );
        assert_eq!(
            HumanFormatter::format_number(123_456_789_012),
            "123,456,789,012"
        );
        assert_eq!(HumanFormatter::format_number(usize::MAX), {
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
}
