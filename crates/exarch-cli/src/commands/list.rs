//! List command implementation

use crate::cli::ListArgs;
use crate::output::OutputFormatter;
use anyhow::Result;
use anyhow::bail;

pub fn execute(_args: &ListArgs, formatter: &dyn OutputFormatter) -> Result<()> {
    formatter.format_warning("Archive listing is not yet implemented (Phase 3)");
    bail!("list command not implemented")
}
