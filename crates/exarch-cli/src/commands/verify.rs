//! Verify command implementation

use crate::cli::VerifyArgs;
use crate::output::OutputFormatter;
use anyhow::Result;
use anyhow::bail;
use exarch_core::SecurityConfig;
use exarch_core::VerificationStatus;
use exarch_core::verify_archive;

pub fn execute(args: &VerifyArgs, formatter: &dyn OutputFormatter) -> Result<()> {
    // Build config
    let config = SecurityConfig::default();

    // Verify archive
    let report = verify_archive(&args.archive, &config)?;

    // Format output
    formatter.format_verification_report(&report)?;

    // Exit with appropriate code
    match report.status {
        VerificationStatus::Pass => Ok(()),
        VerificationStatus::Warning => {
            // Exit 0 for warnings unless strict mode
            Ok(())
        }
        VerificationStatus::Fail => {
            bail!("Archive verification failed")
        }
    }
}
