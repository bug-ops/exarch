//! List command implementation

use crate::cli::ListArgs;
use crate::commands::apply_size_limits;
use crate::output::OutputFormatter;
use anyhow::Result;
use exarch_core::SecurityConfig;
use exarch_core::list_archive;

pub fn execute(args: &ListArgs, formatter: &mut dyn OutputFormatter) -> Result<()> {
    let config = apply_size_limits(
        SecurityConfig::default().with_max_file_count(args.max_files),
        args.max_total_size,
        args.max_file_size,
    )
    .with_allow_solid_archives(args.allow_solid_archives);

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
