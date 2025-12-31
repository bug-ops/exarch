//! Verify command implementation

use crate::cli::VerifyArgs;
use crate::output::OutputFormatter;
use anyhow::Result;
use anyhow::bail;

pub fn execute(_args: &VerifyArgs, formatter: &dyn OutputFormatter) -> Result<()> {
    formatter.format_warning("Archive verification is not yet implemented (Phase 3)");
    bail!("verify command not implemented")
}
