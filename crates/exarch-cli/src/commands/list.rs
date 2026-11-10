//! List command implementation

use crate::cli::ListArgs;
use crate::commands::CommandError;
use crate::commands::CommandResult;
use crate::commands::Outcome;
use crate::commands::security_config;
use crate::error::convert_error;
use crate::operation::Operation;
use crate::output::Dispositions;
use crate::output::ManifestView;
use crate::output::OutputFormatter;
use crate::output::SizeUnits;
use exarch_core::ListOptions;
use exarch_core::ListRequest;
use exarch_core::SecurityConfig;
use exarch_core::StoredTargets;
use exarch_core::VolumeIdentity;
use std::path::Path;

/// The listing the flags ask for; `-H` is only accepted together with `-l`.
const fn manifest_view(args: &ListArgs) -> ManifestView {
    match (args.long, args.human_readable) {
        (false, _) => ManifestView::Short,
        (true, false) => ManifestView::Long(SizeUnits::Bytes),
        (true, true) => ManifestView::Long(SizeUnits::Human),
    }
}

/// The volume the destination names, or the default when none is given; a
/// failure names the destination, not the archive.
fn destination_volume(destination: Option<&Path>) -> Result<VolumeIdentity, CommandError> {
    destination.map_or_else(
        || Ok(VolumeIdentity::default()),
        |path| {
            VolumeIdentity::of_destination(path)
                .map_err(|error| CommandError::Other(convert_error(Operation::List, error, path)))
        },
    )
}

/// Runs `list`: lists the archive under the selection and prints the manifest.
/// It reports and does not judge: an entry extraction would refuse is marked,
/// and the exit status stays 0.
///
/// # Errors
///
/// The core failure of the listing, or the CLI's own refusal of a flag value.
pub fn execute(args: &ListArgs, formatter: &mut dyn OutputFormatter) -> CommandResult {
    let config = security_config(args, SecurityConfig::default())?;

    let volume = destination_volume(args.destination.as_deref())?;

    let stored_targets = if args.read_link_targets || args.links.allow_symlinks {
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
    let dispositions = Dispositions::of(&manifest, &config, volume);
    formatter.format_manifest(&manifest, manifest_view(args), &dispositions)?;

    Ok(Outcome::Ok)
}
