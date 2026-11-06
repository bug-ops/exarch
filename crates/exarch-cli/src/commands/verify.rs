//! Verify command implementation

use crate::cli::VerifyArgs;
use crate::commands::CommandResult;
use crate::commands::Outcome;
use crate::output::OutputFormatter;
use exarch_core::DecompressionBudget;
use exarch_core::IntegrityCheck;
use exarch_core::SecurityConfig;
use exarch_core::VerificationOptions;
use exarch_core::VerificationStatus;
use exarch_core::VerifyRequest;

pub fn execute(args: &VerifyArgs, formatter: &mut dyn OutputFormatter) -> CommandResult {
    let config = args.parallel.apply(
        args.zip.apply(
            args.links
                .apply(args.limits.apply(SecurityConfig::default())?),
        ),
    )?;
    let config = args.selection.apply(config)?;

    let options = if args.check_integrity {
        let budget = match args.decompression_budget {
            Some(bytes) => DecompressionBudget::try_from_bytes(bytes)?,
            None => DecompressionBudget::default(),
        };
        VerificationOptions::default().with_integrity(IntegrityCheck::DecodeToEof(budget))
    } else {
        VerificationOptions::default()
    };

    let report = VerifyRequest::new(&config)
        .with_options(options)
        .verify(&args.archive)?;

    formatter.format_verification_report(&report)?;

    Ok(match report.status() {
        VerificationStatus::Warning if args.strict => Outcome::StrictWarning,
        VerificationStatus::Pass | VerificationStatus::Warning => Outcome::Ok,
        VerificationStatus::Fail => Outcome::VerifyFailed,
    })
}
