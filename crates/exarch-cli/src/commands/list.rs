//! List command implementation

use crate::cli::ListArgs;
use crate::commands::CommandResult;
use crate::commands::Outcome;
use crate::output::ManifestView;
use crate::output::OutputFormatter;
use crate::output::SizeUnits;
use exarch_core::ListOptions;
use exarch_core::ListRequest;
use exarch_core::SecurityConfig;
use exarch_core::StoredTargets;

/// The listing the flags ask for; `-H` is only accepted together with `-l`.
const fn manifest_view(args: &ListArgs) -> ManifestView {
    match (args.long, args.human_readable) {
        (false, _) => ManifestView::Short,
        (true, false) => ManifestView::Long(SizeUnits::Bytes),
        (true, true) => ManifestView::Long(SizeUnits::Human),
    }
}

pub fn execute(args: &ListArgs, formatter: &mut dyn OutputFormatter) -> CommandResult {
    let config = args
        .zip
        .apply(args.limits.apply(SecurityConfig::default())?);

    let stored_targets = if args.read_link_targets {
        StoredTargets::Read
    } else {
        StoredTargets::Skip
    };
    let options = ListOptions::default().with_stored_targets(stored_targets);

    // List archive
    let manifest = ListRequest::new(&config)
        .with_options(options)
        .list(&args.archive)?;

    // Format output
    formatter.format_manifest(&manifest, manifest_view(args))?;

    Ok(Outcome::Ok)
}
