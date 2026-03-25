//! List command implementation

use crate::cli::ListArgs;
use crate::output::OutputFormatter;
use anyhow::Result;
use exarch_core::SecurityConfig;
use exarch_core::list_archive;

pub fn execute(args: &ListArgs, formatter: &dyn OutputFormatter) -> Result<()> {
    let config = SecurityConfig {
        max_file_count: args.max_files,
        max_total_size: args
            .max_total_size
            .unwrap_or_else(|| SecurityConfig::default().max_total_size),
        ..Default::default()
    };

    // List archive
    let manifest = list_archive(&args.archive, &config)?;

    // Format output
    if args.long {
        formatter.format_manifest_long(&manifest, args.human_readable)?;
    } else {
        formatter.format_manifest_short(&manifest)?;
    }

    Ok(())
}
