//! CLI argument parsing using clap.

use clap::Parser;
use clap::Subcommand;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "exarch")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Suppress non-error output
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Output results in JSON format
    #[arg(short, long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Extract archive contents
    Extract(ExtractArgs),
    /// Create a new archive
    Create(CreateArgs),
    /// List archive contents without extraction
    List(ListArgs),
    /// Verify archive integrity
    Verify(VerifyArgs),
}

#[derive(clap::Args)]
pub struct ExtractArgs {
    /// Path to the archive file
    #[arg(value_name = "ARCHIVE")]
    pub archive: PathBuf,

    /// Output directory (default: current directory)
    #[arg(value_name = "OUTPUT_DIR")]
    pub output_dir: Option<PathBuf>,

    /// Maximum number of files to extract
    #[arg(long, default_value = "10000")]
    pub max_files: usize,

    /// Maximum total extracted size in bytes
    #[arg(long, value_parser = parse_byte_size)]
    pub max_total_size: Option<u64>,

    /// Maximum single file size in bytes
    #[arg(long, value_parser = parse_byte_size)]
    pub max_file_size: Option<u64>,

    /// Maximum compression ratio
    #[arg(long, default_value = "100")]
    pub max_compression_ratio: u32,

    /// Allow symlinks (within extraction directory)
    #[arg(long)]
    pub allow_symlinks: bool,

    /// Allow hardlinks (within extraction directory)
    #[arg(long)]
    pub allow_hardlinks: bool,

    /// Preserve file permissions from archive
    #[arg(long)]
    pub preserve_permissions: bool,

    /// Overwrite existing files
    #[arg(long)]
    pub force: bool,
}

#[derive(clap::Args)]
pub struct CreateArgs {
    /// Output archive file path
    #[arg(value_name = "OUTPUT")]
    pub output: PathBuf,

    /// Source files or directories to archive
    #[arg(value_name = "SOURCE", required = true)]
    pub sources: Vec<PathBuf>,
}

#[derive(clap::Args)]
pub struct ListArgs {
    /// Path to the archive file
    #[arg(value_name = "ARCHIVE")]
    pub archive: PathBuf,

    /// Show detailed file information
    #[arg(short, long)]
    pub long: bool,

    /// Show sizes in human-readable format
    #[arg(short = 'H', long)]
    pub human_readable: bool,
}

#[derive(clap::Args)]
pub struct VerifyArgs {
    /// Path to the archive file
    #[arg(value_name = "ARCHIVE")]
    pub archive: PathBuf,

    /// Check archive integrity (checksums, structure)
    #[arg(long)]
    pub check_integrity: bool,

    /// Run security validation
    #[arg(long)]
    pub check_security: bool,
}

/// Parse byte size with optional suffix (K, M, G, T)
#[allow(clippy::option_if_let_else)]
fn parse_byte_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty byte size".to_string());
    }

    let (num_str, multiplier) = if let Some(stripped) = s.strip_suffix('T') {
        (stripped, 1024_u64.pow(4))
    } else if let Some(stripped) = s.strip_suffix('G') {
        (stripped, 1024_u64.pow(3))
    } else if let Some(stripped) = s.strip_suffix('M') {
        (stripped, 1024_u64.pow(2))
    } else if let Some(stripped) = s.strip_suffix('K') {
        (stripped, 1024)
    } else {
        (s, 1)
    };

    num_str
        .parse::<u64>()
        .map(|n| n * multiplier)
        .map_err(|_| format!("invalid byte size: {s}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_byte_size() {
        assert_eq!(parse_byte_size("100").unwrap(), 100);
        assert_eq!(parse_byte_size("1K").unwrap(), 1024);
        assert_eq!(parse_byte_size("2M").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_byte_size("3G").unwrap(), 3 * 1024 * 1024 * 1024);
        assert_eq!(parse_byte_size("1T").unwrap(), 1024_u64.pow(4));
        assert!(parse_byte_size("invalid").is_err());
        assert!(parse_byte_size("").is_err());
    }
}
