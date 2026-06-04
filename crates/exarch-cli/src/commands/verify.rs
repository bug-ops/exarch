//! Verify command implementation

use crate::cli::VerifyArgs;
use crate::error::StrictWarning;
use crate::output::OutputFormatter;
use anyhow::Result;
use anyhow::bail;
use exarch_core::SecurityConfig;
use exarch_core::VerificationStatus;
use exarch_core::verify_archive;

pub fn execute(args: &VerifyArgs, formatter: &dyn OutputFormatter) -> Result<()> {
    let config = SecurityConfig::default()
        .with_max_file_count(args.max_files)
        .with_max_total_size(args.max_total_size.unwrap_or(500 * 1024 * 1024))
        .with_allow_solid_archives(args.allow_solid_archives);

    let report = verify_archive(&args.archive, &config)?;

    formatter.format_verification_report(&report)?;

    match report.status {
        VerificationStatus::Pass => Ok(()),
        VerificationStatus::Warning => {
            if args.strict {
                eprintln!("Archive has warnings; exiting with code 2 (--strict)");
                return Err(anyhow::Error::new(StrictWarning));
            }
            Ok(())
        }
        VerificationStatus::Fail => {
            bail!("Archive verification failed")
        }
    }
}
