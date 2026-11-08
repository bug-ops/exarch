//! Verify command implementation

use crate::cli::VerifyArgs;
use crate::commands::CommandResult;
use crate::commands::Outcome;
use crate::commands::security_config;
use crate::output::OutputFormatter;
use exarch_core::DecompressionBudget;
use exarch_core::IntegrityCheck;
use exarch_core::SecurityConfig;
use exarch_core::VerificationOptions;
use exarch_core::VerificationStatus;
use exarch_core::VerifyRequest;

/// Runs `verify`: checks the archive without extracting it and prints the
/// report; the outcome carries the exit status the report's status calls for.
///
/// # Errors
///
/// The core failure of the verification, or the CLI's own refusal of a flag
/// value.
pub fn execute(args: &VerifyArgs, formatter: &mut dyn OutputFormatter) -> CommandResult {
    let config = security_config(args, SecurityConfig::default())?;

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
