//! Create command implementation (stub for Phase 1).

use crate::cli::CreateArgs;
use crate::output::OutputFormatter;
use anyhow::Result;
use anyhow::bail;

pub fn execute(_args: &CreateArgs, formatter: &dyn OutputFormatter) -> Result<()> {
    formatter.format_warning("Archive creation is not yet implemented (Phase 2)");
    bail!("create command not implemented")
}
