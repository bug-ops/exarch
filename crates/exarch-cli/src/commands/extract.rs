//! Extract command implementation.

use crate::cli::BannedComponentsArg;
use crate::cli::DecodeReuseArg;
use crate::cli::ExtractArgs;
use crate::cli::ListToken;
use crate::commands::CommandResult;
use crate::commands::Outcome;
use crate::error::ConflictAdvice;
use crate::error::add_archive_context;
use crate::error::convert_error;
use crate::error::convert_error_with_advice;
use crate::operation::Flag;
use crate::operation::Operation;
use crate::output::OutputFormatter;
use crate::output::OutputMode;
use crate::progress::BarLength;
use crate::progress::progress_for;
use anyhow::Context;
use anyhow::Result;
use exarch_core::ArchiveError;
use exarch_core::ArchiveManifest;
use exarch_core::ArchiveType;
use exarch_core::ConfigProblem;
use exarch_core::ConfigSetting;
use exarch_core::DecodeReuse;
use exarch_core::DestinationCheck;
use exarch_core::ExistingFiles;
use exarch_core::Extension;
use exarch_core::ExtensionFilter;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ExtractionReport;
use exarch_core::LandingKind;
use exarch_core::ListOptions;
use exarch_core::ListRequest;
use exarch_core::ListedArchive;
use exarch_core::ListedExtractOptions;
use exarch_core::PathComponentName;
use exarch_core::ProgressCallback;
use exarch_core::SecurityConfig;
use exarch_core::Staging as CoreStaging;
use exarch_core::StoredTargets;
use exarch_core::detect_format;
use exarch_core::non_zero_usize;
use std::env;
use std::io;
use std::path::Path;

/// Parses the `--allowed-extensions` items into [`Extension`]s: blank items
/// are dropped and the rest are parsed by the core constructor.
///
/// # Errors
///
/// Returns the core refusal, naming the offending item, for an entry that
/// can never match (for example `tar.gz` or `a/b`), and an error when values
/// were given but hold no extension at all (an empty list would allow every
/// extension).
fn parse_extensions(tokens: &[ListToken]) -> Result<ExtensionFilter> {
    if tokens.is_empty() {
        return Ok(ExtensionFilter::Any);
    }
    let parsed = items(tokens)
        .map(|ext| {
            Extension::try_from(ext).with_context(|| {
                format!("invalid {} value {ext:?}", Flag::AllowedExtensions.long())
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ExtensionFilter::only(parsed)
        .with_context(|| format!("{} names no extension", Flag::AllowedExtensions.long()))
}

fn items(tokens: &[ListToken]) -> impl Iterator<Item = &str> {
    tokens.iter().filter_map(|token| match token {
        ListToken::Item(item) => Some(item.as_str()),
        ListToken::Empty | ListToken::Blank => None,
    })
}

/// The ban list `--banned-component` asks for: `None` keeps the default list.
///
/// A lone empty value (`--banned-component ""`) is the documented idiom for
/// disabling the default ban list. Any other list must name a component, so a
/// typo such as `,` can never switch the bans off.
///
/// # Errors
///
/// Returns the core refusal, naming the offending value, for a component that
/// can never equal a single path component (for example `a/b` or `..`), and
/// an error for a list that names no component other than a lone `""`.
fn banned_components(tokens: &[ListToken]) -> Result<Option<Vec<PathComponentName>>> {
    match BannedComponentsArg::of(tokens) {
        BannedComponentsArg::Default => Ok(None),
        BannedComponentsArg::Replace(tokens) if tokens == [ListToken::Empty] => {
            Ok(Some(Vec::new()))
        }
        BannedComponentsArg::Replace(tokens) => {
            let components = items(&tokens)
                .map(|component| {
                    PathComponentName::try_from(component).with_context(|| {
                        format!(
                            "invalid {} value {component:?}",
                            Flag::BannedComponent.long()
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            if components.is_empty() {
                return Err(anyhow::Error::new(ArchiveError::InvalidConfiguration {
                    setting: ConfigSetting::BannedPathComponent,
                    problem: ConfigProblem::Empty,
                })
                .context(format!(
                    "{} names no component",
                    Flag::BannedComponent.long()
                )));
            }
            Ok(Some(components))
        }
    }
}

/// Lists the archive before extraction: for conflict detection and the entry
/// count that drives the progress bar. Neither needs link targets, and
/// extraction reads them itself, so the listing leaves 7z targets undecoded.
///
/// Header-known 7z link targets (empty or oversized) are still checked here,
/// as `list` does whatever the link policy, so such a target fails with its own
/// error before extraction can say that symlinks are not allowed.
///
/// Every failure keeps the category message and hint extraction would give the
/// same error, since that is the error the user has to act on.
fn list_for_extract(
    archive: &Path,
    config: &SecurityConfig,
    reuse: DecodeReuse,
) -> Result<ListedArchive> {
    let options = ListOptions::default().with_stored_targets(StoredTargets::Skip);
    ListRequest::new(config)
        .with_options(options)
        .for_extraction(archive, reuse)
        .map_err(|err| convert_error(Operation::Extract, err, archive))
}

/// Whether nothing can exist at `output_dir` yet and its parent is an existing
/// directory.
///
/// Such a destination has no conflicts to look for and no pre-existing content
/// a failed run could damage, so a TAR extraction skips the list pass (a full
/// second decode of a compressed stream) and runs atomically instead: a
/// refusal leaves nothing behind and creates no parent directory. An empty
/// parent (`out/`) means the current directory.
fn is_fresh_destination(output_dir: &Path) -> bool {
    let absent = matches!(
        output_dir.symlink_metadata(),
        Err(ref e) if e.kind() == io::ErrorKind::NotFound
    );
    let parent = match output_dir.parent() {
        Some(p) if !p.is_empty() => p,
        _ => Path::new("."),
    };
    absent && parent.is_dir()
}

/// Whether `archive` is a TAR stream, the only family whose list pass costs a
/// second decode; ZIP and 7z list from their headers, and their list pass also
/// carries header-level diagnostics that extraction reports differently.
fn is_tar_archive(archive: &Path) -> bool {
    detect_format(archive).is_ok_and(ArchiveType::is_tar)
}

/// Number of entries the progress bar counts: every entry extraction lands.
fn listed_entry_count(manifest: &ArchiveManifest, config: &SecurityConfig) -> usize {
    manifest
        .landings(config)
        .filter(|landing| matches!(landing.kind(), LandingKind::Entry(_)))
        .count()
}

/// The configuration the size, count, depth and ratio flags describe; a value
/// core refuses is returned as `InvalidConfiguration` naming the flag's
/// setting.
fn limited_config(args: &ExtractArgs) -> Result<SecurityConfig, ArchiveError> {
    let config = args.parallel.apply(
        args.zip.apply(
            args.links
                .apply(args.limits.apply(SecurityConfig::default())?),
        ),
    )?;
    match args.max_path_depth {
        Some(depth) => {
            Ok(config.with_max_path_depth(non_zero_usize(ConfigSetting::MaxPathDepth, depth)?))
        }
        None => Ok(config),
    }
}

/// How `--force` and `--atomic` combine, resolved once from the arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteMode {
    /// Neither flag: existing files are conflicts and are refused up front.
    Safe,
    /// `--force`: existing files are overwritten in place.
    Force,
    /// `--atomic`: extraction is staged and renamed into place on success.
    Atomic,
    /// Both: staged, and swapped over an existing destination directory.
    AtomicReplace,
}

impl WriteMode {
    const fn of(args: &ExtractArgs) -> Self {
        match (args.force, args.atomic) {
            (false, false) => Self::Safe,
            (true, false) => Self::Force,
            (false, true) => Self::Atomic,
            (true, true) => Self::AtomicReplace,
        }
    }

    const fn stages(self) -> bool {
        matches!(self, Self::Atomic | Self::AtomicReplace)
    }

    /// What core does with a path the destination already holds.
    const fn existing_files(self) -> ExistingFiles {
        match self {
            Self::Safe => ExistingFiles::Refuse,
            Self::Force | Self::AtomicReplace => ExistingFiles::Overwrite,
            Self::Atomic => ExistingFiles::Skip,
        }
    }

    const fn staging(self) -> CoreStaging {
        match self {
            Self::Safe | Self::Force => CoreStaging::InPlace,
            Self::Atomic => CoreStaging::Atomic,
            Self::AtomicReplace => CoreStaging::AtomicReplace,
        }
    }

    /// The up-front destination check of an unstaged mode, with the advice
    /// its refusal gives; staged modes write nothing into the destination
    /// until the end and need none.
    const fn destination_check(self) -> Option<(DestinationCheck, ConflictAdvice)> {
        match self {
            Self::Safe => Some((DestinationCheck::Vacant, ConflictAdvice::UseForce)),
            Self::Force => Some((
                DestinationCheck::Replaceable,
                ConflictAdvice::ForceCannotReplace,
            )),
            Self::Atomic | Self::AtomicReplace => None,
        }
    }
}

/// How an extraction runs, decided once from the write mode and the
/// destination.
enum ExtractPlan {
    /// One streaming pass over the archive; core stages it or refuses
    /// occupied paths as it writes.
    Stream { options: ExtractionOptions },
    /// Extraction from a listing whose destination was checked up front.
    Listed {
        listed: Box<ListedArchive>,
        options: ExtractionOptions,
    },
}

impl ExtractPlan {
    fn manifest(&self) -> Option<&ArchiveManifest> {
        match self {
            Self::Listed { listed, .. } => Some(listed.manifest()),
            Self::Stream { .. } => None,
        }
    }

    fn run(
        self,
        archive: &Path,
        output_dir: &Path,
        config: &SecurityConfig,
        progress: &mut dyn ProgressCallback,
    ) -> Result<ExtractionReport> {
        let result = match self {
            Self::Stream { options } => ExtractRequest::new(config)
                .with_options(options)
                .with_progress(progress)
                .extract(archive, output_dir),
            Self::Listed { listed, options } => {
                let listed_options = ListedExtractOptions::default()
                    .with_staging(options.staging)
                    .with_existing_files(options.existing_files);
                (*listed).extract(output_dir, &listed_options, progress)
            }
        };
        add_archive_context(Operation::Extract, result, archive)
    }
}

fn plan_extraction(
    args: &ExtractArgs,
    mode: WriteMode,
    output_dir: &Path,
    config: &SecurityConfig,
) -> Result<ExtractPlan> {
    let reuse = DecodeReuseArg::resolve(args.decode_reuse);
    let options = |staging: CoreStaging| {
        ExtractionOptions::default()
            .with_staging(staging)
            .with_existing_files(mode.existing_files())
            .with_decode_reuse(reuse)
    };

    // A staged run refuses occupied paths on its own, and a fresh destination
    // has nothing to conflict with, so neither needs the list pass.
    if is_tar_archive(&args.archive) && (mode.stages() || is_fresh_destination(output_dir)) {
        let staging = match mode.staging() {
            CoreStaging::InPlace => CoreStaging::Atomic,
            staged => staged,
        };
        return Ok(ExtractPlan::Stream {
            options: options(staging),
        });
    }

    let listed = list_for_extract(&args.archive, config, reuse)?;
    if let Some((check, advice)) = mode.destination_check() {
        listed.check_destination(output_dir, check).map_err(|err| {
            convert_error_with_advice(Operation::Extract, err, &args.archive, advice)
        })?;
    }
    Ok(ExtractPlan::Listed {
        listed: Box::new(listed),
        options: options(mode.staging()),
    })
}

pub fn execute(
    args: &ExtractArgs,
    formatter: &mut dyn OutputFormatter,
    mode: OutputMode,
) -> CommandResult {
    let output_dir = match &args.output_dir {
        Some(dir) => dir.clone(),
        None => env::current_dir().context("failed to get current directory")?,
    };

    let allowed_extensions = parse_extensions(&args.allowed_extensions)?;

    let config = limited_config(args)?
        .with_allow_absolute_paths(args.allow_absolute_paths)
        .with_allow_world_writable(args.allow_world_writable)
        .with_preserve_permissions(args.preserve_permissions)
        .with_allowed_extensions(allowed_extensions);

    let config = match banned_components(&args.banned_components)? {
        Some(components) => config.with_banned_path_components(components),
        None => config,
    };
    let config = args.selection.apply(config)?;

    let plan = plan_extraction(args, WriteMode::of(args), &output_dir, &config)?;
    let length = plan.manifest().map_or(BarLength::Discover, |manifest| {
        BarLength::Known(listed_entry_count(manifest, &config))
    });
    let mut progress = progress_for(mode, length, Operation::Extract);
    let report = plan.run(&args.archive, &output_dir, &config, progress.as_mut())?;

    formatter.format_extraction_result(&report)?;

    Ok(Outcome::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The items clap would produce for the given raw flag values.
    fn tokens(raw: &[&str]) -> Vec<ListToken> {
        raw.iter()
            .flat_map(|value| value.split(','))
            .map(|item| {
                if item.is_empty() {
                    ListToken::Empty
                } else if item.trim().is_empty() {
                    ListToken::Blank
                } else {
                    ListToken::Item(item.trim().to_owned())
                }
            })
            .collect()
    }

    #[allow(clippy::unwrap_used)]
    fn extension_names(raw: &[&str]) -> Vec<String> {
        parse_extensions(&tokens(raw))
            .unwrap()
            .as_only()
            .map_or_default(|extensions| {
                extensions
                    .as_slice()
                    .iter()
                    .map(|e| e.as_str().to_owned())
                    .collect()
            })
    }

    #[test]
    fn parse_extensions_comma_split() {
        assert_eq!(extension_names(&["zip,tar,gz"]), vec!["zip", "tar", "gz"]);
    }

    #[test]
    fn parse_extensions_strips_leading_dot() {
        assert_eq!(extension_names(&[".zip", ".TAR"]), vec!["zip", "tar"]);
    }

    #[test]
    fn parse_extensions_trims_whitespace() {
        assert_eq!(
            extension_names(&[" zip , tar ", " gz"]),
            vec!["zip", "tar", "gz"]
        );
    }

    #[test]
    fn parse_extensions_lowercases() {
        assert_eq!(extension_names(&["ZIP", "Txt"]), vec!["zip", "txt"]);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn parse_extensions_refuses_an_inner_dot() {
        for raw in ["tar.gz", "A.TXT", "a/b"] {
            let err = parse_extensions(&tokens(&[raw])).unwrap_err();
            assert!(format!("{err:#}").contains(raw), "{err:#}");
        }
    }

    #[test]
    fn parse_extensions_empty_input() {
        assert!(extension_names(&[]).is_empty());
    }

    #[test]
    fn parse_extensions_refuses_values_without_any_extension() {
        for raw in [",", " ", ""] {
            assert!(parse_extensions(&tokens(&[raw])).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn parse_extensions_filters_empty_tokens() {
        assert_eq!(extension_names(&["zip,,tar, ,"]), vec!["zip", "tar"]);
    }

    #[test]
    fn parse_extensions_mixed_repeatable_and_comma() {
        assert_eq!(
            extension_names(&["zip,tar", ".GZ"]),
            vec!["zip", "tar", "gz"]
        );
    }

    #[allow(clippy::unwrap_used)]
    fn banned_names(raw: &[&str]) -> Option<Vec<String>> {
        banned_components(&tokens(raw))
            .unwrap()
            .map(|c| c.iter().map(|n| n.as_str().to_owned()).collect())
    }

    #[test]
    fn banned_components_absent_keeps_the_default_list() {
        assert_eq!(banned_names(&[]), None);
    }

    #[test]
    fn banned_components_lone_empty_value_disables_the_list() {
        assert_eq!(banned_names(&[""]), Some(Vec::new()));
    }

    #[test]
    fn banned_components_keep_non_empty_entries() {
        assert_eq!(
            banned_names(&[".git", "", ".ssh"]),
            Some(vec![".git".to_owned(), ".ssh".to_owned()])
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn banned_components_refuse_a_separator() {
        for raw in ["a/b", ".."] {
            let err = banned_components(&tokens(&[raw])).unwrap_err();
            assert!(format!("{err:#}").contains("--banned-component"), "{err:#}");
        }
    }

    #[test]
    fn banned_components_refuse_a_list_without_any_component() {
        for raw in [",", " ", " , "] {
            assert!(banned_components(&tokens(&[raw])).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn banned_components_split_on_commas_and_trim() {
        assert_eq!(
            banned_names(&[".git, .ssh ,,.env"]),
            Some(vec![
                ".git".to_owned(),
                ".ssh".to_owned(),
                ".env".to_owned()
            ])
        );
    }

    #[test]
    fn write_mode_is_resolved_from_both_flags() {
        let mode = |force, atomic| {
            let mut args = extract_args();
            args.force = force;
            args.atomic = atomic;
            WriteMode::of(&args)
        };
        assert_eq!(mode(false, false), WriteMode::Safe);
        assert_eq!(mode(true, false), WriteMode::Force);
        assert_eq!(mode(false, true), WriteMode::Atomic);
        assert_eq!(mode(true, true), WriteMode::AtomicReplace);
        assert!(!WriteMode::Force.stages() && WriteMode::Atomic.stages());
        assert_eq!(WriteMode::Safe.existing_files(), ExistingFiles::Refuse);
        assert_eq!(WriteMode::Force.existing_files(), ExistingFiles::Overwrite);
        assert_eq!(WriteMode::Safe.staging(), CoreStaging::InPlace);
        assert_eq!(
            WriteMode::AtomicReplace.staging(),
            CoreStaging::AtomicReplace
        );
        assert!(WriteMode::Atomic.destination_check().is_none());
    }

    fn extract_args() -> ExtractArgs {
        use clap::Parser as _;
        let crate::cli::Commands::Extract(args) =
            crate::cli::Cli::parse_from(["exarch", "extract", "a.tar"]).command
        else {
            panic!("expected extract command");
        };
        args
    }
}
