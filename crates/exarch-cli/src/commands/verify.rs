//! Verify command implementation

use crate::cli::VerifyArgs;
use crate::commands::apply_size_limits;
use crate::error::StrictWarning;
use crate::error::VerificationFailed;
use crate::output::OutputFormatter;
use anyhow::Result;
use exarch_core::IntegrityCheck;
use exarch_core::SecurityConfig;
use exarch_core::VerificationOptions;
use exarch_core::VerificationStatus;
use exarch_core::verify_archive_with_options;

pub fn execute(args: &VerifyArgs, formatter: &mut dyn OutputFormatter) -> Result<()> {
    let config = args
        .zip
        .apply(args.links.apply(apply_size_limits(
            SecurityConfig::default().with_max_file_count(args.max_files),
            args.max_total_size,
            args.max_file_size,
        )))
        .with_allow_solid_archives(args.allow_solid_archives);

    let options = if args.check_integrity {
        VerificationOptions::default().with_integrity(IntegrityCheck::DecodeToEof(
            args.decompression_budget.unwrap_or_default(),
        ))
    } else {
        VerificationOptions::default()
    };

    let report = verify_archive_with_options(&args.archive, &config, &options)?;

    formatter.format_verification_report(&report)?;

    match report.status() {
        VerificationStatus::Pass => Ok(()),
        VerificationStatus::Warning => {
            if args.strict {
                return Err(anyhow::Error::new(StrictWarning));
            }
            Ok(())
        }
        VerificationStatus::Fail => Err(anyhow::Error::new(VerificationFailed)),
    }
}
