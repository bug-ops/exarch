//! List command implementation

use crate::cli::ListArgs;
use crate::output::OutputFormatter;
use anyhow::Result;
use exarch_core::SecurityConfig;
use exarch_core::list_archive;

pub fn execute(args: &ListArgs, formatter: &dyn OutputFormatter) -> Result<()> {
    // Build config with default quota limits
    let config = SecurityConfig::default();

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
