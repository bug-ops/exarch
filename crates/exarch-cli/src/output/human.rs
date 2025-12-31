//! Human-readable output formatter with colors and styling.

use super::formatter::OutputFormatter;
use anyhow::Result;
use console::Term;
use console::style;
use exarch_core::ExtractionReport;

pub struct HumanFormatter {
    verbose: bool,
    use_colors: bool,
    term: Term,
}

impl HumanFormatter {
    pub fn new(verbose: bool) -> Self {
        Self {
            verbose,
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
        if self.use_colors {
            let _ = self
                .term
                .write_line(&format!("{} {error:?}", style("ERROR:").red().bold()));
        } else {
            let _ = self.term.write_line(&format!("ERROR: {error:?}"));
        }
    }

    fn format_success(&self, message: &str) {
        if self.use_colors {
            let _ = self
                .term
                .write_line(&format!("{} {message}", style("✓").green().bold()));
        } else {
            let _ = self.term.write_line(message);
        }
    }

    fn format_warning(&self, message: &str) {
        if self.use_colors {
            let _ = self
                .term
                .write_line(&format!("{} {message}", style("⚠").yellow().bold()));
        } else {
            let _ = self.term.write_line(&format!("WARNING: {message}"));
        }
    }
}
