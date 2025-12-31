//! Human-readable output formatter with colors and styling.

use super::formatter::OutputFormatter;
use anyhow::Result;
use console::Term;
use console::style;
use exarch_core::ExtractionReport;

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
}
