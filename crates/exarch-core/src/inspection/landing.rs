//! Where the entries of a listed archive land under the destination.
//!
//! A front end that wants to know which host paths an extraction would write
//! (for a conflict pre-check, say) must not re-implement the entry-to-path
//! mapping: it differs in the details that matter (Windows drive prefixes,
//! `./` and leading separators, symlinked parents, non-file entries). This
//! module derives the landing from the same validation and projection that
//! `verify` and the sink use.

use std::borrow::Cow;
use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;

use crate::ArchiveError;
use crate::DestinationStep;
use crate::EntrySelection;
use crate::Result;
use crate::SecurityConfig;
use crate::SkipKind;
use crate::closed_enum::closed_enum;
use crate::error::Violation;
use crate::formats::common::is_extension_allowed;
use crate::formats::common::occupied_without_destination;
use crate::formats::common::require_symlink_creation;
use crate::formats::common::symlink_target_too_large;
use crate::formats::file_identity::FileIdentity;
use crate::formats::file_identity::identity_of;
use crate::formats::occupant::is_run_duplicate;
use crate::formats::occupant::refuse_unless_duplicate;
use crate::formats::occupant::tree_occupant_refusal;
use crate::inspection::manifest::ArchiveEntry;
use crate::inspection::manifest::ArchiveManifest;
use crate::inspection::manifest::LinkTarget;
use crate::inspection::manifest::ManifestEntryKind;
use crate::security::context::ValidationContext;
use crate::security::fs_view::CollisionRecording;
use crate::security::fs_view::Conflict;
use crate::security::fs_view::LandingLimits;
use crate::security::fs_view::LinkKind;
use crate::security::fs_view::Node;
use crate::security::fs_view::NodeBudget;
use crate::security::fs_view::Occupant;
use crate::security::fs_view::PathModel;
use crate::security::fs_view::PlaceError;
use crate::security::fs_view::Placement;
use crate::security::fs_view::VirtualRoot;
use crate::security::fs_view::VirtualTree;
use crate::security::hardlink::HardlinkTracker;
use crate::security::hardlink::require_hardlinks_allowed;
use crate::security::hardlink::require_target_present;
use crate::security::validator::Gated;
use crate::security::validator::route_validated;
use crate::selection::EntryShape;
use crate::selection::LandingClaims;
use crate::selection::SelectionRun;
use crate::sink::place_error;
use crate::types::SafePath;
use crate::types::SafeSymlink;
use crate::types::safe_symlink::require_symlinks_allowed;

/// The destination-relative path an entry lands at, derived lexically.
///
/// The path is relative and normalized (no root, drive prefix, `.` or `..`),
/// its name lengths fit the host, and every symlink among the earlier entries
/// it passes through has been resolved. It is a **lexical** answer: it says
/// nothing about what already exists on disk, so it does not claim that
/// writing there stays inside the destination. A caller that acts on the
/// filesystem must still use `symlink_metadata` and the extraction itself for
/// containment.
///
/// # Examples
///
/// ```
/// use exarch_core::ArchiveEntry;
/// use exarch_core::ArchiveManifest;
/// use exarch_core::ArchiveType;
/// use exarch_core::ManifestEntryKind;
/// use exarch_core::SecurityConfig;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut manifest = ArchiveManifest::new(ArchiveType::Tar);
/// manifest.add_entry(ArchiveEntry::new(
///     "./a/b.txt".into(),
///     ManifestEntryKind::Directory,
/// ))?;
/// let config = SecurityConfig::default();
/// let landed: Vec<_> = manifest.landing_paths(&config).collect();
/// assert_eq!(landed[0].1.as_path(), std::path::Path::new("a/b.txt"));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LandingPath(PathBuf);

impl LandingPath {
    /// The relative path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Consumes the value and returns the relative path.
    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

impl AsRef<Path> for LandingPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

/// What extraction does with a listed entry.
///
/// # Examples
///
/// ```
/// use exarch_core::ArchiveEntry;
/// use exarch_core::ArchiveManifest;
/// use exarch_core::ArchiveType;
/// use exarch_core::Disposition;
/// use exarch_core::ManifestEntryKind;
/// use exarch_core::SecurityConfig;
/// use exarch_core::SkipKind;
/// use std::assert_matches;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SecurityConfig::default().try_add_include("a")?;
/// let mut manifest = ArchiveManifest::with_selection(ArchiveType::Tar, config.selection.clone());
/// manifest.add_entry(ArchiveEntry::new(
///     "a/x".into(),
///     ManifestEntryKind::Directory,
/// ))?;
/// manifest.add_entry(ArchiveEntry::new(
///     "b/y".into(),
///     ManifestEntryKind::Directory,
/// ))?;
/// let dispositions: Vec<_> = manifest.dispositions(&config).map(|(_, d)| d).collect();
/// assert_matches!(dispositions[0], Disposition::Extract(_));
/// assert_matches!(dispositions[1], Disposition::Skip(SkipKind::NotSelected));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Disposition {
    /// The entry is extracted and lands here.
    Extract(LandingPath),
    /// The entry is validated but not extracted, for this reason.
    Skip(SkipKind),
    /// The entry is refused by validation or policy, or cannot be placed.
    Refuse,
}

closed_enum! {
    /// Which way a [`Disposition`] went, without its payload.
    ///
    /// The string form is stable and shared by every front end.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::DispositionKind;
    ///
    /// assert_eq!(DispositionKind::Skip.as_str(), "skip");
    /// assert_eq!(DispositionKind::NAMES, &["extract", "skip", "refuse"]);
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[non_exhaustive]
    pub enum DispositionKind {
        /// The entry is extracted
        Extract => "extract",
        /// The entry is validated but left out
        Skip => "skip",
        /// The entry is refused by validation or policy, or cannot be placed
        Refuse => "refuse",
    }
}

impl Disposition {
    /// Which way this disposition went.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::Disposition;
    /// use exarch_core::DispositionKind;
    /// use exarch_core::SkipKind;
    ///
    /// assert_eq!(
    ///     Disposition::Skip(SkipKind::NotSelected).kind(),
    ///     DispositionKind::Skip
    /// );
    /// assert_eq!(Disposition::Refuse.kind(), DispositionKind::Refuse);
    /// ```
    #[must_use]
    pub const fn kind(&self) -> DispositionKind {
        match self {
            Self::Extract(_) => DispositionKind::Extract,
            Self::Skip(_) => DispositionKind::Skip,
            Self::Refuse => DispositionKind::Refuse,
        }
    }
}

/// What put a path in the landing set.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum LandingKind<'a> {
    /// An archive entry lands here.
    Entry(&'a ArchiveEntry),
    /// No entry names this path, but extraction creates it as a parent
    /// directory of one that lands below it.
    ImplicitParent,
}

/// A path extraction creates, with what put it there.
#[derive(Debug, Clone)]
pub struct Landing<'a> {
    path: LandingPath,
    kind: LandingKind<'a>,
}

impl<'a> Landing<'a> {
    /// Where the path lands.
    #[must_use]
    pub const fn path(&self) -> &LandingPath {
        &self.path
    }

    /// Whether an entry or an implied parent directory lands here.
    #[must_use]
    pub const fn kind(&self) -> LandingKind<'a> {
        self.kind
    }
}

/// How the destination volume tells two landings apart, which decides which
/// repeated names extraction skips as duplicates.
///
/// Extraction under [`ExistingFiles::Refuse`](crate::ExistingFiles::Refuse)
/// skips an entry that names a path an earlier file or symlink of the same run
/// created. It recognizes that occupant by file identity where the volume has
/// one, which is exact on a case-insensitive host: `x` then `X` is one
/// landing. On a volume without file identities (Windows volumes without
/// `FileIdInfo`) it falls back to the landing path as the archive spelled it,
/// so a repeat spelled differently (`x` then `X`, `d/x` then `D/x`, or `l/x`
/// then `d/x` through an archive symlink `l` to `d`) is refused instead of
/// skipped. A listing has no destination to ask, so
/// [`ArchiveManifest::dispositions_on`] takes this as input, and
/// [`of_destination`](Self::of_destination) learns it from the destination
/// the caller names. Without a destination a listing keeps the default.
///
/// # Examples
///
/// ```
/// use exarch_core::VolumeIdentity;
///
/// assert_eq!(VolumeIdentity::default(), VolumeIdentity::FileIds);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum VolumeIdentity {
    /// The volume gives every entry a file identity, as every Unix file system,
    /// NTFS and `ReFS` do. A repeated name is a duplicate whatever its
    /// spelling.
    #[default]
    FileIds,
    /// The volume gives no file identity, so a repeat counts as a duplicate
    /// only when the archive spells the path exactly as the earlier entry did;
    /// any other spelling of an occupied landing is refused.
    LandingPaths,
}

impl VolumeIdentity {
    /// The identity basis of the volume that holds `destination`.
    ///
    /// Probes the nearest existing ancestor of `destination`, resolved through
    /// symlinks, junctions and mount points first so the volume asked is the
    /// one extraction writes to, not the one that holds a link to it. A volume
    /// that reports no file id for its directory yields
    /// [`LandingPaths`](Self::LandingPaths); every Unix file system, NTFS and
    /// `ReFS` yield [`FileIds`](Self::FileIds). Nothing is created or written.
    ///
    /// # Errors
    ///
    /// [`ArchiveError::DestinationNotAccessible`] naming `destination` when no
    /// ancestor of it can be resolved or probed.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::VolumeIdentity;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dir = std::env::temp_dir();
    /// let volume = VolumeIdentity::of_destination(&dir.join("not-yet-created"))?;
    /// # let _ = volume;
    /// # Ok(())
    /// # }
    /// ```
    pub fn of_destination(destination: &Path) -> Result<Self> {
        nearest_existing_ancestor(destination)
            .and_then(|existing| identity_of(&existing))
            .map(Self::from_identity)
            .map_err(|error| {
                ArchiveError::destination_not_accessible(
                    destination,
                    DestinationStep::Resolve,
                    error,
                )
            })
    }

    /// The identity basis for an optional destination: the default
    /// [`FileIds`](Self::FileIds) when there is none, otherwise
    /// [`of_destination`](Self::of_destination).
    ///
    /// # Errors
    ///
    /// As [`of_destination`](Self::of_destination).
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::VolumeIdentity;
    ///
    /// assert_eq!(VolumeIdentity::of_optional(None)?, VolumeIdentity::FileIds);
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    pub fn of_optional(destination: Option<&Path>) -> Result<Self> {
        destination.map_or_else(|| Ok(Self::default()), Self::of_destination)
    }

    const fn from_identity(identity: FileIdentity) -> Self {
        match identity {
            FileIdentity::Known(_) => Self::FileIds,
            FileIdentity::Unknown => Self::LandingPaths,
        }
    }
}

/// The canonical form of the closest ancestor of `path` (or `path` itself)
/// that exists; a relative `path` is resolved against the working directory.
///
/// A missing component below an existing file is an error, as on Unix where
/// the lookup itself fails: Windows reports such a path as not found.
fn nearest_existing_ancestor(path: &Path) -> std::io::Result<PathBuf> {
    for (skipped, candidate) in path.ancestors().enumerate() {
        let candidate = if candidate.is_empty() {
            Path::new(".")
        } else {
            candidate
        };
        match std::fs::canonicalize(candidate) {
            Ok(canonical) if skipped > 0 && !canonical.is_dir() => {
                return Err(std::io::ErrorKind::NotADirectory.into());
            }
            Ok(canonical) => return Ok(canonical),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Err(std::io::ErrorKind::NotFound.into())
}

/// What a listing remembers of the run so far to judge the next entry.
struct JudgeRun {
    hardlinks: HardlinkTracker,
    keys: RunKeys,
    claims: LandingClaims,
}

/// The paths the run created, in the spelling extraction records them under
/// when the volume gives no file identities.
enum RunKeys {
    Identity,
    Spelling(HashSet<PathBuf>),
}

impl RunKeys {
    fn new(volume: VolumeIdentity) -> Self {
        match volume {
            VolumeIdentity::FileIds => Self::Identity,
            VolumeIdentity::LandingPaths => Self::Spelling(HashSet::new()),
        }
    }

    /// Records the entry spelled `rel`; extraction keys only what an entry
    /// itself creates, never its parent directories.
    fn note(&mut self, rel: &Path) {
        if let Self::Spelling(spelled) = self {
            spelled.insert(rel.to_path_buf());
        }
    }

    fn made_here(&self, rel: &Path) -> bool {
        match self {
            Self::Identity => true,
            Self::Spelling(spelled) => spelled.contains(rel),
        }
    }
}

/// Skips a repeat of an entry the run made, refuses an occupant it did not.
fn skip_duplicate_or_refuse(
    shape: EntryShape,
    held: Occupant,
    rel: &Path,
    keys: &RunKeys,
) -> Result<Disposition> {
    refuse_unless_duplicate(
        shape,
        Some(held),
        || keys.made_here(rel),
        |found| occupied_without_destination(rel, found),
    )
    .map(|_| Disposition::Skip(SkipKind::Duplicate))
}

impl ArchiveManifest {
    /// The entries extraction would create, each with where it lands.
    ///
    /// Entries are judged in archive order against a model of what earlier
    /// entries created, so a path through an earlier symlink is resolved the
    /// way extraction resolves it. An entry that extraction would not create
    /// is left out: one the validation refuses (traversal, a banned
    /// component, a symlink or hardlink the config disallows, a symlink whose
    /// target escapes), one that cannot be placed (a conflict with an earlier
    /// entry, a landing longer than the host allows) and a regular file the
    /// extension allowlist skips. Every other kind of entry is covered, not
    /// only regular files.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveEntry;
    /// use exarch_core::ArchiveManifest;
    /// use exarch_core::ArchiveType;
    /// use exarch_core::ManifestEntryKind;
    /// use exarch_core::SecurityConfig;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut manifest = ArchiveManifest::new(ArchiveType::Tar);
    /// manifest.add_entry(ArchiveEntry::new(
    ///     "../evil".into(),
    ///     ManifestEntryKind::Directory,
    /// ))?;
    /// let config = SecurityConfig::default();
    /// assert_eq!(manifest.landing_paths(&config).count(), 0);
    /// # Ok(())
    /// # }
    /// ```
    pub fn landing_paths<'a>(
        &'a self,
        config: &SecurityConfig,
    ) -> impl Iterator<Item = (&'a ArchiveEntry, LandingPath)> + use<'a> {
        self.dispositions(config)
            .filter_map(|(entry, disposition)| match disposition {
                Disposition::Extract(landing) => Some((entry, landing)),
                Disposition::Skip(_) | Disposition::Refuse => None,
            })
    }

    /// Every entry, with what extraction does with it: where it lands, why it
    /// is left out, or that it is refused.
    ///
    /// The selection is the one the manifest was listed with
    /// ([`selection`](Self::selection)), never one taken from `config`, so the
    /// answer cannot disagree with the listing; `config` supplies the limits
    /// and policies. An entry the validation or the policy refuses, or that
    /// cannot be placed, is [`Disposition::Refuse`];
    /// [`landing_paths`](Self::landing_paths) is the extracted subset of this.
    ///
    /// An entry is skipped as [`SkipKind::NotSelected`] when the selection
    /// leaves it out, as [`SkipKind::StrippedAway`] when stripping removes its
    /// whole path, and as [`SkipKind::ExtensionNotAllowed`] when it is a
    /// regular file the allowlist excludes, under the first reason that
    /// applies.
    ///
    /// The answer models default extraction
    /// ([`ExistingFiles::Refuse`](crate::ExistingFiles::Refuse)) with the rule
    /// extraction itself applies: an entry that names a path an earlier file or
    /// symlink of the archive took is [`SkipKind::Duplicate`] (a symlink only
    /// where the host creates symlinks), and a file or link over a directory
    /// the archive made is refused. A symlink entry is refused where the host
    /// cannot create symlinks. Under
    /// [`ExistingFiles::Overwrite`](crate::ExistingFiles::Overwrite) extraction
    /// replaces the earlier file instead.
    pub fn dispositions<'a>(
        &'a self,
        config: &SecurityConfig,
    ) -> impl Iterator<Item = (&'a ArchiveEntry, Disposition)> + use<'a> {
        self.dispositions_on(config, VolumeIdentity::default())
    }

    /// [`dispositions`](Self::dispositions) for a destination volume that
    /// identifies landings as `volume` says.
    ///
    /// Only the repeated-name answers differ: under
    /// [`VolumeIdentity::LandingPaths`] a repeat the archive spells differently
    /// from the earlier entry is [`Disposition::Refuse`], as extraction on such
    /// a volume refuses it. [`VolumeIdentity::of_destination`] learns the
    /// volume of a destination path.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveEntry;
    /// use exarch_core::ArchiveManifest;
    /// use exarch_core::ArchiveType;
    /// use exarch_core::Disposition;
    /// use exarch_core::ManifestEntryKind;
    /// use exarch_core::SecurityConfig;
    /// use exarch_core::SkipKind;
    /// use exarch_core::Uncompressed;
    /// use exarch_core::VolumeIdentity;
    /// use std::assert_matches;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut manifest = ArchiveManifest::new(ArchiveType::Tar);
    /// for _ in 0..2 {
    ///     let file = ManifestEntryKind::File {
    ///         size: Uncompressed(1),
    ///     };
    ///     manifest.add_entry(ArchiveEntry::new("x".into(), file))?;
    /// }
    /// let config = SecurityConfig::default();
    /// let judged: Vec<_> = manifest
    ///     .dispositions_on(&config, VolumeIdentity::LandingPaths)
    ///     .map(|(_, d)| d)
    ///     .collect();
    /// assert_matches!(judged[1], Disposition::Skip(SkipKind::Duplicate));
    /// # Ok(())
    /// # }
    /// ```
    pub fn dispositions_on<'a>(
        &'a self,
        config: &SecurityConfig,
        volume: VolumeIdentity,
    ) -> impl Iterator<Item = (&'a ArchiveEntry, Disposition)> + use<'a> {
        self.judgements(config, volume)
            .map(|(entry, judged)| (entry, judged.unwrap_or(Disposition::Refuse)))
    }

    /// [`dispositions_on`](Self::dispositions_on) with the reason an entry is
    /// refused, the error extraction raises for it.
    fn judgements<'a>(
        &'a self,
        config: &SecurityConfig,
        volume: VolumeIdentity,
    ) -> impl Iterator<Item = (&'a ArchiveEntry, Result<Disposition>)> + use<'a> {
        let root = VirtualRoot::new();
        let mut tree = VirtualTree::new(
            &root,
            PathModel::Host,
            NodeBudget::from_config(config),
            CollisionRecording::Discard,
        )
        .keeping_files_under_links();
        let mut state = JudgeRun {
            hardlinks: HardlinkTracker::new(),
            keys: RunKeys::new(volume),
            claims: LandingClaims::default(),
        };
        let is_hardlink =
            |entry: &ArchiveEntry| matches!(entry.kind, ManifestEntryKind::Hardlink { .. });
        let selection = self.selection();
        // Extraction validates every path at the entry's own position but
        // creates hardlinks after every other entry, so a target that appears
        // later in the archive still exists and a leaf an earlier entry
        // occupies is a duplicate, not a path to resolve.
        let mut judged: Vec<Judged> = Vec::with_capacity(self.entries().len());
        for entry in self.entries() {
            let screened = screen(entry, selection, config, &root, &tree);
            judged.push(match screened {
                Ok(Gated::Admit(safe)) if is_hardlink(entry) => {
                    match hardlink_escape_check(
                        entry, &safe, selection, config, &root, &tree, &mut state,
                    ) {
                        Ok(()) => Judged::Deferred(safe),
                        Err(error) => Judged::Done(Err(error)),
                    }
                }
                Ok(Gated::Admit(safe)) => Judged::Done(land(
                    entry, &safe, selection, config, &root, &mut tree, &mut state,
                )),
                Ok(Gated::Skip(kind)) => Judged::Done(Ok(Disposition::Skip(kind))),
                Err(error) => Judged::Done(Err(error)),
            });
        }
        self.entries()
            .iter()
            .zip(judged)
            .map(|(entry, judged)| {
                let judgement = match judged {
                    Judged::Done(judgement) => judgement,
                    Judged::Deferred(safe) => land(
                        entry, &safe, selection, config, &root, &mut tree, &mut state,
                    ),
                };
                (entry, judgement)
            })
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// Everything extraction would create, entries and the directories it
    /// creates for them on its own, in the order they land.
    ///
    /// An archive can hold `a/b.txt` without an `a/` entry; extraction then
    /// creates `a`. Each such parent is reported once, as
    /// [`LandingKind::ImplicitParent`], before the first entry that needs it,
    /// outermost first. A front end that probes the destination for conflicts
    /// probes every landing, so a parent that is a file (or a symlink) in the
    /// destination is found at that parent and not below it.
    ///
    /// The parents are those of the resolved landing, so a path through an
    /// earlier symlink reports the directories it really lands in.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveEntry;
    /// use exarch_core::ArchiveManifest;
    /// use exarch_core::ArchiveType;
    /// use exarch_core::LandingKind;
    /// use exarch_core::ManifestEntryKind;
    /// use exarch_core::SecurityConfig;
    /// use exarch_core::Uncompressed;
    /// use std::assert_matches;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut manifest = ArchiveManifest::new(ArchiveType::Tar);
    /// let file = ManifestEntryKind::File {
    ///     size: Uncompressed(1),
    /// };
    /// manifest.add_entry(ArchiveEntry::new("a/b.txt".into(), file))?;
    /// let config = SecurityConfig::default();
    /// let landings: Vec<_> = manifest.landings(&config).collect();
    /// assert_eq!(landings.len(), 2);
    /// assert_matches!(landings[0].kind(), LandingKind::ImplicitParent);
    /// assert_eq!(landings[0].path().as_path(), std::path::Path::new("a"));
    /// assert_matches!(landings[1].kind(), LandingKind::Entry(_));
    /// # Ok(())
    /// # }
    /// ```
    pub fn landings<'a>(
        &'a self,
        config: &SecurityConfig,
    ) -> impl Iterator<Item = Landing<'a>> + use<'a> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for (entry, landing) in self.landing_paths(config) {
            let ancestors: Vec<_> = landing
                .as_path()
                .ancestors()
                .skip(1)
                .filter(|p| !p.is_empty())
                .map(Path::to_path_buf)
                .collect();
            for parent in ancestors.into_iter().rev() {
                if seen.insert(parent.clone()) {
                    out.push(Landing {
                        path: LandingPath(parent),
                        kind: LandingKind::ImplicitParent,
                    });
                }
            }
            seen.insert(landing.as_path().to_path_buf());
            out.push(Landing {
                path: landing,
                kind: LandingKind::Entry(entry),
            });
        }
        out.into_iter()
    }
}

/// The error for a link entry whose target the listing could not keep; callers
/// pass a recorded target never, so it reads as missing.
fn unusable_target(kind: LinkKind, target: &LinkTarget) -> ArchiveError {
    match target {
        LinkTarget::Recorded(_) | LinkTarget::Missing => Violation::LinkTargetMissing(kind).into(),
        LinkTarget::Unread => Violation::LinkTargetUnread(kind).into(),
        LinkTarget::Unreadable => Violation::LinkTargetUnreadable(kind).into(),
        LinkTarget::Oversized { bytes } => symlink_target_too_large(*bytes as u64),
    }
}

/// A listing judgement: settled, or a hardlink whose path is validated and
/// whose placement waits for every other entry.
enum Judged {
    Done(Result<Disposition>),
    Deferred(SafePath),
}

/// The validation extraction does at an entry's own position: the path against
/// the tree of the entries before it, then the selection.
fn screen(
    entry: &ArchiveEntry,
    selection: &EntrySelection,
    config: &SecurityConfig,
    root: &VirtualRoot,
    tree: &VirtualTree,
) -> Result<Gated<SafePath>> {
    let original = SafePath::validate_in(&entry.path, root, config, tree)?;
    let ctx = ValidationContext::<VirtualTree>::new(config.allowed.symlinks.is_allowed());
    let run = SelectionRun {
        selection,
        hits: None,
    };
    route_validated(run, original, entry.kind.shape(), root, config, &ctx, tree)
}

/// The hardlink target extraction resolves for `entry`, after the policy and
/// the selection's mapping.
fn mapped_hardlink_target<'a>(
    entry: &ArchiveEntry,
    target: &'a LinkTarget,
    selection: &EntrySelection,
    config: &SecurityConfig,
) -> Result<Cow<'a, Path>> {
    require_hardlinks_allowed(config)?;
    let LinkTarget::Recorded(target) = target else {
        return Err(unusable_target(LinkKind::Hardlink, target));
    };
    selection.mapped_link_target(&entry.path, target, config.allowed.absolute_paths)
}

/// Judges whether a hardlink's target resolves inside the destination, against
/// the entries before it: extraction vets the target at the link's own
/// position, so a `..` or a symlink hop through an entry that comes later does
/// not resolve there yet, even though the link itself is created last.
fn hardlink_escape_check(
    entry: &ArchiveEntry,
    safe: &SafePath,
    selection: &EntrySelection,
    config: &SecurityConfig,
    root: &VirtualRoot,
    tree: &VirtualTree,
    state: &mut JudgeRun,
) -> Result<()> {
    let ManifestEntryKind::Hardlink { target } = &entry.kind else {
        return Ok(());
    };
    let mapped = mapped_hardlink_target(entry, target, selection, config)?;
    state
        .hardlinks
        .validate_hardlink_in(safe, &mapped, root, config, tree)
        .map(drop)
}

/// What extraction does with an entry it can act on, or the error it raises
/// when it cannot be placed.
fn land(
    entry: &ArchiveEntry,
    safe: &SafePath,
    selection: &EntrySelection,
    config: &SecurityConfig,
    root: &VirtualRoot,
    tree: &mut VirtualTree,
    state: &mut JudgeRun,
) -> Result<Disposition> {
    let claims = &state.claims;
    let shape = entry.kind.shape();
    let is_file = matches!(entry.kind, ManifestEntryKind::File { .. });
    if is_file && !is_extension_allowed(safe.as_path(), config) {
        return Ok(Disposition::Skip(SkipKind::ExtensionNotAllowed));
    }
    if is_file {
        claims.claim(selection, safe.as_path());
    }
    let node = match &entry.kind {
        ManifestEntryKind::File { .. } => Node::File,
        ManifestEntryKind::Hardlink { target } => {
            let mapped = mapped_hardlink_target(entry, target, selection, config)?;
            claims.require_unambiguous(&entry.path, &mapped)?;
            require_target_present(&mapped, root, tree)?;
            Node::File
        }
        ManifestEntryKind::Directory => Node::Dir,
        ManifestEntryKind::Symlink { target } => {
            require_symlinks_allowed(config)?;
            require_symlink_creation()?;
            match target {
                LinkTarget::Recorded(t) => {
                    SafeSymlink::validate_in(safe, t, root, config, tree)?;
                    Node::Symlink(t.clone())
                }
                LinkTarget::Unread => Node::OpaqueSymlink,
                LinkTarget::Missing | LinkTarget::Unreadable | LinkTarget::Oversized { .. } => {
                    return Err(unusable_target(LinkKind::Symlink, target));
                }
            }
        }
    };
    match tree.project_landing_found(safe, node.clone(), LandingLimits::Enforced) {
        Ok(Placement::Held { occupant, .. }) if shape != EntryShape::Directory => {
            skip_duplicate_or_refuse(shape, occupant, safe.as_path(), &state.keys)
        }
        Ok(placement) => {
            if matches!(placement, Placement::New(_)) {
                state.keys.note(safe.as_path());
            }
            Ok(Disposition::Extract(LandingPath(
                placement.into_landing().into_path_buf(),
            )))
        }
        Err(PlaceError::Conflict(conflict)) => {
            conflicting_placement(shape, &node, safe.as_path(), conflict, &state.keys)
        }
        Err(other) => Err(place_error(other)),
    }
}

/// What extraction does at a path an earlier entry holds that the node cannot
/// share: skip a duplicate, or fail with the error it raises.
///
/// An unread symlink target cannot be validated, so extraction never skips
/// such a link as a duplicate.
fn conflicting_placement(
    shape: EntryShape,
    node: &Node,
    rel: &Path,
    conflict: Conflict,
    keys: &RunKeys,
) -> Result<Disposition> {
    let occupant = conflict.occupant.filter(|_| conflict.blocked.is_none());
    match occupant {
        Some(held) if *node != Node::OpaqueSymlink && is_run_duplicate(shape, held) => {
            skip_duplicate_or_refuse(shape, held, rel, keys)
        }
        Some(held) => tree_occupant_refusal(shape, held, rel)
            .map_or_else(|| Err(place_error(PlaceError::Conflict(conflict))), Err),
        None => Err(place_error(PlaceError::Conflict(conflict))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::OccupiedBy;
    use std::assert_matches;
    use std::collections::BTreeSet;
    use std::io::Cursor;
    use std::io::Write as _;

    use exarch_testkit::raw_zip::RawEntry;
    use exarch_testkit::raw_zip::RawZip;

    use super::*;
    use crate::extract_archive;
    use crate::list_archive;

    fn config() -> SecurityConfig {
        SecurityConfig::default()
            .with_allow_absolute_paths(true)
            .with_allow_symlinks(true)
    }

    fn tar_entry(
        builder: &mut tar::Builder<Vec<u8>>,
        name: &[u8],
        kind: tar::EntryType,
        link: &str,
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_mode(0o644);
        header.set_size(u64::from(kind == tar::EntryType::Regular));
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        if !link.is_empty() {
            header.set_link_name(link).unwrap();
        }
        header.set_cksum();
        let data: &[u8] = if kind == tar::EntryType::Regular {
            b"x"
        } else {
            b""
        };
        builder.append(&header, data).unwrap();
    }

    fn non_directories(root: &Path) -> BTreeSet<PathBuf> {
        let mut found = BTreeSet::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for item in std::fs::read_dir(&dir).unwrap() {
                let path = item.unwrap().path();
                if std::fs::symlink_metadata(&path).unwrap().is_dir() {
                    stack.push(path);
                } else {
                    found.insert(path.strip_prefix(root).unwrap().to_path_buf());
                }
            }
        }
        found
    }

    fn every_path(root: &Path) -> BTreeSet<PathBuf> {
        let mut found = BTreeSet::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for item in std::fs::read_dir(&dir).unwrap() {
                let path = item.unwrap().path();
                if std::fs::symlink_metadata(&path).unwrap().is_dir() {
                    stack.push(path.clone());
                }
                found.insert(path.strip_prefix(root).unwrap().to_path_buf());
            }
        }
        found
    }

    /// The landing set of the non-directory entries must be the set of
    /// non-directories extraction really created.
    fn assert_landing_matches_extraction(file_name: &str, bytes: &[u8]) {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join(file_name);
        std::fs::write(&archive, bytes).unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        let config = config();

        let manifest = list_archive(&archive, &config).unwrap();
        let landed: BTreeSet<PathBuf> = manifest
            .landing_paths(&config)
            .filter(|(entry, _)| !matches!(entry.kind, ManifestEntryKind::Directory))
            .map(|(_, landing)| landing.into_path_buf())
            .collect();
        extract_archive(&archive, &dest, &config).unwrap();

        assert_eq!(landed, non_directories(&dest), "{file_name}");
        let every: BTreeSet<PathBuf> = manifest
            .landings(&config)
            .map(|landing| landing.path().as_path().to_path_buf())
            .collect();
        assert_eq!(every, every_path(&dest), "{file_name}: implicit parents");
        let implicit = manifest
            .landings(&config)
            .filter(|l| matches!(l.kind(), LandingKind::ImplicitParent))
            .count();
        assert!(implicit > 0, "{file_name}: the fixture implies a parent");
        assert!(!landed.is_empty(), "{file_name}");
    }

    #[test]
    fn tar_landing_matches_extraction_for_dot_slash_absolute_and_linked_parents() {
        let mut builder = tar::Builder::new(Vec::new());
        tar_entry(&mut builder, b"./a.txt", tar::EntryType::Regular, "");
        tar_entry(&mut builder, b"/abs.txt", tar::EntryType::Regular, "");
        tar_entry(&mut builder, b"d/", tar::EntryType::Directory, "");
        tar_entry(&mut builder, b"d/sub.txt", tar::EntryType::Regular, "");
        // Windows extraction refuses symlinks, so the linked parent is
        // Unix-only.
        #[cfg(unix)]
        {
            tar_entry(&mut builder, b"link", tar::EntryType::Symlink, "d");
            tar_entry(
                &mut builder,
                b"link/through.txt",
                tar::EntryType::Regular,
                "",
            );
        }
        tar_entry(&mut builder, b"x/y/z.txt", tar::EntryType::Regular, "");
        assert_landing_matches_extraction("a.tar", &builder.into_inner().unwrap());
    }

    #[test]
    #[cfg(unix)]
    fn a_path_through_a_symlink_lands_at_the_resolved_path() {
        let mut builder = tar::Builder::new(Vec::new());
        tar_entry(&mut builder, b"d/", tar::EntryType::Directory, "");
        tar_entry(&mut builder, b"link", tar::EntryType::Symlink, "d");
        tar_entry(&mut builder, b"link/x.txt", tar::EntryType::Regular, "");
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
        let config = config();

        let manifest = list_archive(&archive, &config).unwrap();
        let landed: Vec<_> = manifest
            .landing_paths(&config)
            .map(|(_, l)| l.into_path_buf())
            .collect();
        assert_eq!(
            landed,
            [
                PathBuf::from("d"),
                PathBuf::from("link"),
                PathBuf::from("d/x.txt")
            ]
        );
    }

    #[test]
    fn zip_landing_matches_extraction_for_backslashes_and_drive_prefixes() {
        let entries = [
            "a\\b.txt",
            "C:\\win.txt",
            "/abs.txt",
            "plain.txt",
            "dir/",
            "p/q/r.txt",
        ]
        .iter()
        .map(|name| RawEntry::stored(name, if name.ends_with('/') { b"" } else { b"x" }))
        .collect();
        let bytes = RawZip::new(entries).build().bytes;
        assert_landing_matches_extraction("a.zip", &bytes);
    }

    #[test]
    fn sevenz_landing_matches_extraction() {
        let mut writer = sevenz_rust2::ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
        for name in ["a.txt", "dir/b.txt", "dir/deeper/c.txt"] {
            writer
                .push_archive_entry(
                    sevenz_rust2::ArchiveEntry::new_file(name),
                    Some(Cursor::new(b"x".to_vec())),
                )
                .unwrap();
        }
        let bytes = writer.finish().unwrap().into_inner();
        assert_landing_matches_extraction("a.7z", &bytes);
    }

    #[test]
    fn refused_and_skipped_entries_do_not_land() {
        let mut builder = tar::Builder::new(Vec::new());
        tar_entry(&mut builder, b"ok.txt", tar::EntryType::Regular, "");
        tar_entry(&mut builder, b"skip.bin", tar::EntryType::Regular, "");
        tar_entry(
            &mut builder,
            b"esc",
            tar::EntryType::Symlink,
            "../../outside",
        );
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
        let config = config().try_add_allowed_extension("txt").unwrap();

        let manifest = list_archive(&archive, &config).unwrap();
        let landed: Vec<_> = manifest
            .landing_paths(&config)
            .map(|(_, l)| l.into_path_buf())
            .collect();
        assert_eq!(landed, [PathBuf::from("ok.txt")]);
    }

    #[test]
    fn disallowed_links_do_not_land() {
        let mut builder = tar::Builder::new(Vec::new());
        tar_entry(&mut builder, b"s", tar::EntryType::Symlink, "ok.txt");
        tar_entry(&mut builder, b"h", tar::EntryType::Link, "ok.txt");
        let _ = builder.get_mut().flush();
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
        let config = config();

        let manifest = list_archive(&archive, &config).unwrap();
        let strict = SecurityConfig::default();
        assert_eq!(manifest.landing_paths(&strict).count(), 0);
    }

    #[test]
    fn implicit_parents_are_reported_once_outermost_first() {
        let mut builder = tar::Builder::new(Vec::new());
        tar_entry(&mut builder, b"first.txt", tar::EntryType::Regular, "");
        tar_entry(&mut builder, b"a/b/c.txt", tar::EntryType::Regular, "");
        tar_entry(&mut builder, b"a/d.txt", tar::EntryType::Regular, "");
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
        let config = config();

        let manifest = list_archive(&archive, &config).unwrap();
        let shape: Vec<_> = manifest
            .landings(&config)
            .map(|l| {
                (
                    l.path().as_path().to_path_buf(),
                    matches!(l.kind(), LandingKind::ImplicitParent),
                )
            })
            .collect();
        assert_eq!(
            shape,
            [
                (PathBuf::from("first.txt"), false),
                (PathBuf::from("a"), true),
                (PathBuf::from("a/b"), true),
                (PathBuf::from("a/b/c.txt"), false),
                (PathBuf::from("a/d.txt"), false),
            ]
        );
    }

    /// The listing's verdict for the first hardlink and the extraction result,
    /// both under `config`.
    fn hardlink_outcome(
        entries: &[(&[u8], tar::EntryType, &str)],
        config: &SecurityConfig,
    ) -> (Result<Disposition>, Result<crate::ExtractionReport>) {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, kind, link) in entries {
            tar_entry(&mut builder, name, *kind, link);
        }
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        let manifest = list_archive(&archive, config).unwrap();
        let judged = manifest
            .judgements(config, VolumeIdentity::default())
            .find(|(entry, _)| matches!(entry.kind, ManifestEntryKind::Hardlink { .. }))
            .map(|(_, judged)| judged)
            .unwrap();
        (judged, extract_archive(&archive, &dest, config))
    }

    fn assert_hardlink_agrees(entries: &[(&[u8], tar::EntryType, &str)], accepted: bool) {
        let config = config().with_allow_hardlinks(true);
        assert_hardlink_agrees_under(entries, &config, accepted);
    }

    /// Both sides accept, or both refuse with the same kind of error.
    fn assert_hardlink_agrees_under(
        entries: &[(&[u8], tar::EntryType, &str)],
        config: &SecurityConfig,
        accepted: bool,
    ) {
        let (listed, extracted) = hardlink_outcome(entries, config);
        assert_eq!(extracted.is_ok(), accepted, "{extracted:?}");
        match (listed, extracted) {
            (Ok(disposition), Ok(_)) => assert_matches!(disposition, Disposition::Extract(_)),
            (Err(listed), Err(extracted)) => {
                let cause = match &extracted {
                    ArchiveError::PartialExtraction(partial) => partial.cause(),
                    other => other,
                };
                assert_eq!(
                    std::mem::discriminant(&listed),
                    std::mem::discriminant(cause),
                    "{listed:?} vs {cause:?}"
                );
            }
            (listed, extracted) => panic!("{listed:?} vs {extracted:?}"),
        }
    }

    const FILE: tar::EntryType = tar::EntryType::Regular;
    const HARD: tar::EntryType = tar::EntryType::Link;

    /// A selection already refuses `..`, so this layout only shows through the
    /// unselected API listing, which this drives.
    #[test]
    fn hardlink_through_a_parent_step_into_a_later_directory_is_refused_through_the_api() {
        assert_hardlink_agrees(
            &[
                (b"b", FILE, ""),
                (b"e", HARD, "d/../b"),
                (b"d/h", tar::EntryType::Directory, ""),
            ],
            false,
        );
    }

    #[test]
    fn hardlink_through_a_parent_step_into_an_earlier_directory_is_extracted() {
        assert_hardlink_agrees(
            &[
                (b"b", FILE, ""),
                (b"d/h", tar::EntryType::Directory, ""),
                (b"e", HARD, "d/../b"),
            ],
            true,
        );
    }

    #[cfg(unix)]
    #[test]
    fn hardlink_through_a_symlink_to_a_later_file_is_refused() {
        assert_hardlink_agrees(
            &[
                (b"b", FILE, ""),
                (b"h", tar::EntryType::Symlink, "e"),
                (b"h2", HARD, "h"),
                (b"e", FILE, ""),
            ],
            false,
        );
    }

    #[cfg(unix)]
    #[test]
    fn hardlink_through_a_symlink_to_an_earlier_file_is_extracted() {
        assert_hardlink_agrees(
            &[
                (b"e", FILE, ""),
                (b"h", tar::EntryType::Symlink, "e"),
                (b"h2", HARD, "h"),
            ],
            true,
        );
    }

    #[test]
    fn hardlink_with_a_leading_parent_step_target_is_refused_alike() {
        assert_hardlink_agrees(&[(b"a", FILE, ""), (b"d/hl", HARD, "../../a")], false);
    }

    #[test]
    fn hardlink_with_an_absolute_target_is_refused_alike_at_its_position() {
        assert_hardlink_agrees(
            &[(b"a", FILE, ""), (b"d/hl", HARD, "/a"), (b"b", FILE, "")],
            false,
        );
    }

    #[test]
    fn hardlink_to_a_present_target_is_extracted() {
        assert_hardlink_agrees(&[(b"a", FILE, ""), (b"hl", HARD, "a")], true);
    }

    #[test]
    fn hardlink_to_a_target_missing_from_the_archive_is_refused() {
        assert_hardlink_agrees(&[(b"a", FILE, ""), (b"hl", HARD, "nope")], false);
    }

    #[test]
    fn hardlink_to_a_target_later_in_the_archive_is_extracted() {
        assert_hardlink_agrees(&[(b"hl", HARD, "a"), (b"a", FILE, "")], true);
    }

    #[test]
    fn hardlink_with_an_absolute_target_is_refused() {
        assert_hardlink_agrees(&[(b"a", FILE, ""), (b"hl", HARD, "/a")], false);
    }

    #[test]
    fn hardlink_with_an_escaping_target_is_refused() {
        assert_hardlink_agrees(&[(b"a", FILE, ""), (b"hl", HARD, "../a")], false);
    }

    #[test]
    fn hardlink_to_a_directory_is_refused() {
        assert_hardlink_agrees(
            &[(b"d/", tar::EntryType::Directory, ""), (b"hl", HARD, "d")],
            false,
        );
    }

    #[test]
    fn hardlink_whose_target_is_not_selected_is_refused() {
        let mut builder = tar::Builder::new(Vec::new());
        tar_entry(&mut builder, b"a", FILE, "");
        tar_entry(&mut builder, b"hl", HARD, "a");
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
        let selection = EntrySelection::default().with_include("hl".parse().unwrap());
        let config = config()
            .with_allow_hardlinks(true)
            .with_selection(selection);
        let manifest = list_archive(&archive, &config).unwrap();
        let (_, disposition) = manifest
            .dispositions(&config)
            .find(|(entry, _)| entry.path == Path::new("hl"))
            .unwrap();
        assert_matches!(disposition, Disposition::Refuse);
    }

    fn strip_one() -> SecurityConfig {
        use crate::PathRewrite;
        use crate::StripComponents;
        use crate::non_zero;

        let strip = StripComponents::new(non_zero!(1), non_zero!(32)).unwrap();
        config()
            .with_allow_hardlinks(true)
            .with_selection(EntrySelection::default().with_rewrite(PathRewrite::Strip(strip)))
    }

    #[test]
    fn hardlink_to_an_ambiguous_landing_is_refused() {
        assert_hardlink_agrees_under(
            &[
                (b"p/x", FILE, ""),
                (b"q/x", FILE, ""),
                (b"p/h", HARD, "p/x"),
            ],
            &strip_one(),
            false,
        );
    }

    // Windows extraction refuses symlinks, so the duplicate symlink is
    // Unix-only.
    #[cfg(unix)]
    const SYM: tar::EntryType = tar::EntryType::Symlink;

    #[cfg(unix)]
    #[test]
    fn hardlink_to_a_file_shadowed_by_a_duplicate_symlink_is_extracted() {
        assert_hardlink_agrees(
            &[(b"x", FILE, ""), (b"x", SYM, "y"), (b"hl", HARD, "x")],
            true,
        );
    }

    #[cfg(unix)]
    #[test]
    fn hardlink_to_a_stripped_file_shadowed_by_a_duplicate_symlink_is_extracted() {
        assert_hardlink_agrees_under(
            &[
                (b"p/x", FILE, ""),
                (b"q/x", SYM, "y"),
                (b"p/hl", HARD, "p/x"),
            ],
            &strip_one(),
            true,
        );
    }

    #[test]
    fn hardlink_to_an_unambiguous_stripped_landing_is_extracted() {
        assert_hardlink_agrees_under(
            &[(b"p/x", FILE, ""), (b"p/h", HARD, "p/x")],
            &strip_one(),
            true,
        );
    }

    #[test]
    fn hardlink_to_a_later_stripped_target_is_extracted() {
        assert_hardlink_agrees_under(
            &[(b"p/h", HARD, "p/x"), (b"p/x", FILE, "")],
            &strip_one(),
            true,
        );
    }

    fn duplicate_symlink_disposition(
        file_name: &str,
        bytes: &[u8],
        config: &SecurityConfig,
    ) -> (
        Disposition,
        LinkTarget,
        crate::Result<crate::ExtractionReport>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join(file_name);
        std::fs::write(&archive, bytes).unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        let manifest = list_archive(&archive, config).unwrap();
        let (entry, disposition) = manifest
            .dispositions(config)
            .find(|(entry, _)| matches!(entry.kind, ManifestEntryKind::Symlink { .. }))
            .unwrap();
        let ManifestEntryKind::Symlink { target } = &entry.kind else {
            unreachable!("filtered to symlinks");
        };
        (
            disposition,
            target.clone(),
            extract_archive(&archive, &dest, config),
        )
    }

    fn tar_duplicate_symlink() -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        tar_entry(&mut builder, b"x", tar::EntryType::Regular, "");
        tar_entry(&mut builder, b"x", tar::EntryType::Symlink, "y");
        builder.into_inner().unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn a_duplicate_symlink_is_skipped_as_extraction_skips_it() {
        let (disposition, _, extracted) =
            duplicate_symlink_disposition("a.tar", &tar_duplicate_symlink(), &config());
        assert_matches!(disposition, Disposition::Skip(SkipKind::Duplicate));
        assert_eq!(extracted.unwrap().skipped.count(SkipKind::Duplicate), 1);
    }

    #[cfg(not(unix))]
    #[test]
    fn a_duplicate_symlink_stays_refused_where_symlinks_cannot_be_created() {
        let (disposition, _, extracted) =
            duplicate_symlink_disposition("a.tar", &tar_duplicate_symlink(), &config());
        assert_matches!(disposition, Disposition::Refuse);
        assert!(extracted.is_err());
    }

    #[test]
    fn a_duplicate_symlink_with_an_escaping_target_stays_refused() {
        let escaping = RawEntry {
            external_attributes: 0o120_777 << 16,
            ..RawEntry::stored("x", b"../../etc")
        };
        let bytes = RawZip::new(vec![RawEntry::stored("x", b"x"), escaping])
            .build()
            .bytes;
        let lenient = config().with_zip_consistency(crate::ZipConsistencyPolicy::Ignore);
        let (disposition, _, extracted) = duplicate_symlink_disposition("a.zip", &bytes, &lenient);
        assert_matches!(disposition, Disposition::Refuse);
        assert!(extracted.is_err());
    }

    #[test]
    fn a_duplicate_symlink_with_an_unread_target_stays_refused() {
        let mut writer = sevenz_rust2::ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
        writer
            .push_archive_entry(
                sevenz_rust2::ArchiveEntry::new_file("x"),
                Some(Cursor::new(b"x".to_vec())),
            )
            .unwrap();
        let mut link = sevenz_rust2::ArchiveEntry::new_file("x");
        link.has_windows_attributes = true;
        link.windows_attributes = 0x8000 | (0o120_777 << 16);
        writer
            .push_archive_entry(link, Some(Cursor::new(b"../../etc".to_vec())))
            .unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        let (disposition, target, _) = duplicate_symlink_disposition("a.7z", &bytes, &config());
        assert_eq!(target, LinkTarget::Unread);
        assert_matches!(disposition, Disposition::Refuse);
    }

    /// Every archive here makes extraction under `Refuse` fail at its last
    /// entry: a file or link over a directory, a directory over a file or link,
    /// and a file over a directory only implied by an earlier entry.
    fn refused_shapes() -> Vec<Vec<(&'static [u8], tar::EntryType, &'static str)>> {
        const DIR: tar::EntryType = tar::EntryType::Directory;
        let target = (&b"t"[..], tar::EntryType::Regular, "");
        let non_directories = [
            (&b"x"[..], tar::EntryType::Regular, ""),
            (&b"x"[..], tar::EntryType::Symlink, "t"),
            (&b"x"[..], tar::EntryType::Link, "t"),
        ];
        let directory = (&b"x"[..], DIR, "");
        let mut shapes = Vec::new();
        for other in non_directories {
            shapes.push(vec![target, other, directory]);
            shapes.push(vec![target, directory, other]);
        }
        shapes.push(vec![
            target,
            (&b"x/a"[..], tar::EntryType::Regular, ""),
            (&b"x"[..], tar::EntryType::Regular, ""),
        ]);
        shapes
    }

    fn occupied_by(error: &ArchiveError) -> Option<OccupiedBy> {
        match error {
            ArchiveError::DestinationOccupied { by, .. } => Some(*by),
            ArchiveError::PartialExtraction(partial) => occupied_by(partial.cause()),
            _ => None,
        }
    }

    #[test]
    fn a_refused_entry_fails_extraction_with_the_same_code() {
        let config = config().with_allow_hardlinks(true);
        let options =
            crate::ExtractionOptions::default().with_existing_files(crate::ExistingFiles::Refuse);
        for shape in refused_shapes() {
            let mut builder = tar::Builder::new(Vec::new());
            for (name, kind, link) in &shape {
                tar_entry(&mut builder, name, *kind, link);
            }
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("a.tar");
            std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
            let dest = dir.path().join("out");
            let manifest = list_archive(&archive, &config).unwrap();

            let refused: Vec<_> = manifest
                .judgements(&config, VolumeIdentity::default())
                .filter_map(|(_, judged)| judged.err())
                .collect();
            let extracted = crate::ExtractRequest::new(&config)
                .with_options(options.clone())
                .extract(&archive, &dest)
                .unwrap_err();

            assert_eq!(refused.len(), 1, "{shape:?}");
            // Elsewhere the capability check refuses a symlink first.
            if cfg!(unix) {
                assert_eq!(
                    refused[0].error_code(),
                    extracted.error_code(),
                    "{shape:?}: {} vs {extracted}",
                    refused[0]
                );
                assert_eq!(
                    occupied_by(&refused[0]),
                    occupied_by(&extracted),
                    "{shape:?}: {} vs {extracted}",
                    refused[0]
                );
            }
        }
    }

    #[cfg(not(unix))]
    #[test]
    fn a_symlink_is_refused_where_symlinks_cannot_be_created() {
        let mut builder = tar::Builder::new(Vec::new());
        tar_entry(&mut builder, b"s", tar::EntryType::Symlink, "ok.txt");
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
        let config = config();

        let manifest = list_archive(&archive, &config).unwrap();
        let (_, disposition) = manifest.dispositions(&config).next().unwrap();
        assert_matches!(disposition, Disposition::Refuse);
        assert!(extract_archive(&archive, dir.path().join("out"), &config).is_err());
    }

    type TarEntries<'a> = &'a [(&'a [u8], tar::EntryType, &'a str)];

    struct VolumeOutcome {
        file_ids: Vec<Disposition>,
        landing_paths: Vec<Disposition>,
        identity_extraction: crate::Result<crate::ExtractionReport>,
        path_extraction: crate::Result<crate::ExtractionReport>,
        file_ids_refusal: Option<ArchiveError>,
        landing_paths_refusal: Option<ArchiveError>,
    }

    fn volume_outcome(entries: TarEntries<'_>) -> VolumeOutcome {
        volume_outcome_under(entries, &config())
    }

    fn volume_outcome_under(entries: TarEntries<'_>, config: &SecurityConfig) -> VolumeOutcome {
        use crate::formats::run_record::key_basis::KeyBasis;
        use crate::formats::run_record::key_basis::with;

        let mut builder = tar::Builder::new(Vec::new());
        for (name, kind, link) in entries {
            tar_entry(&mut builder, name, *kind, link);
        }
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
        let manifest = list_archive(&archive, config).unwrap();
        let judged = |volume| -> Vec<Disposition> {
            manifest
                .dispositions_on(config, volume)
                .map(|(_, d)| d)
                .collect()
        };
        let extract = |basis: KeyBasis, name: &str| {
            let dest = dir.path().join(name);
            std::fs::create_dir(&dest).unwrap();
            let options = crate::ExtractionOptions::default()
                .with_existing_files(crate::ExistingFiles::Refuse);
            with(basis, || {
                crate::ExtractRequest::new(config)
                    .with_options(options)
                    .extract(&archive, &dest)
            })
        };
        let refusal = |volume| {
            manifest
                .judgements(config, volume)
                .filter_map(|(_, judged)| judged.err())
                .last()
        };
        VolumeOutcome {
            file_ids_refusal: refusal(VolumeIdentity::FileIds),
            landing_paths_refusal: refusal(VolumeIdentity::LandingPaths),
            file_ids: judged(VolumeIdentity::FileIds),
            landing_paths: judged(VolumeIdentity::LandingPaths),
            identity_extraction: extract(KeyBasis::Identity, "by-id"),
            path_extraction: extract(KeyBasis::Path, "by-path"),
        }
    }

    fn folds_case() -> bool {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), b"").unwrap();
        cfg!(any(windows, target_os = "macos")) && dir.path().join("A").exists()
    }

    /// Whether the test must stop: its case aliases need a host and a volume
    /// that fold case. Says so on stderr instead of passing silently.
    fn skipped_without_case_folding(test: &str) -> bool {
        let skipped = !folds_case();
        if skipped {
            eprintln!("skipping {test}: the test volume does not fold case");
        }
        skipped
    }

    #[test]
    fn the_volume_of_a_missing_destination_is_the_volume_of_its_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("a").join("b");
        assert_eq!(
            VolumeIdentity::of_destination(&missing).unwrap(),
            VolumeIdentity::of_destination(dir.path()).unwrap()
        );
    }

    #[test]
    fn a_volume_that_gives_file_ids_is_the_default_basis() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            VolumeIdentity::of_destination(dir.path()).unwrap(),
            VolumeIdentity::FileIds
        );
    }

    #[test]
    fn an_unknown_identity_selects_the_path_basis() {
        assert_eq!(
            VolumeIdentity::from_identity(FileIdentity::Unknown),
            VolumeIdentity::LandingPaths
        );
        let known = identity_of(Path::new(".")).unwrap();
        assert_eq!(
            VolumeIdentity::from_identity(known),
            VolumeIdentity::FileIds
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_probe_resolves_a_symlinked_destination_to_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let resolved = nearest_existing_ancestor(&link.join("new")).unwrap();
        assert_eq!(resolved, std::fs::canonicalize(&target).unwrap());
    }

    #[test]
    fn a_destination_below_a_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"").unwrap();
        let probed = file.join("sub");
        assert_matches!(
            VolumeIdentity::of_destination(&probed),
            Err(ArchiveError::DestinationNotAccessible { path, .. }) if path == probed
        );
    }

    /// The identity-keyed preview and extraction skip the last entry as a
    /// duplicate; extraction keyed by spelled path refuses it as occupied by a
    /// foreign entry, and the `LandingPaths` preview agrees.
    fn assert_spelling_refused(entries: TarEntries<'_>) {
        assert_spelling_refused_under(entries, &config());
    }

    fn assert_spelling_refused_under(entries: TarEntries<'_>, config: &SecurityConfig) {
        let outcome = volume_outcome_under(entries, config);
        let last = entries.len() - 1;
        assert_matches!(
            outcome.file_ids[last],
            Disposition::Skip(SkipKind::Duplicate)
        );
        assert_eq!(
            outcome
                .identity_extraction
                .unwrap()
                .skipped
                .count(SkipKind::Duplicate),
            1
        );
        assert_matches!(outcome.landing_paths[last], Disposition::Refuse);
        let refused = outcome.path_extraction.unwrap_err();
        assert_eq!(
            occupied_by(&refused),
            Some(OccupiedBy::Existing),
            "{refused}"
        );
        let previewed = outcome.landing_paths_refusal.unwrap();
        assert_eq!(previewed.error_code(), refused.error_code());
        assert_eq!(occupied_by(&previewed), occupied_by(&refused));
    }

    #[test]
    fn a_case_variant_repeat_is_refused_on_a_path_keyed_volume() {
        if skipped_without_case_folding("a_case_variant_repeat_is_refused_on_a_path_keyed_volume") {
            return;
        }
        assert_spelling_refused(&[(b"x", FILE, ""), (b"X", FILE, "")]);
    }

    #[cfg(unix)]
    #[test]
    fn a_case_variant_symlink_over_a_file_is_refused_on_a_path_keyed_volume() {
        if skipped_without_case_folding(
            "a_case_variant_symlink_over_a_file_is_refused_on_a_path_keyed_volume",
        ) {
            return;
        }
        assert_spelling_refused(&[(b"x", FILE, ""), (b"X", SYM, "y")]);
    }

    #[test]
    fn a_case_variant_under_a_made_directory_is_refused_on_a_path_keyed_volume() {
        if skipped_without_case_folding(
            "a_case_variant_under_a_made_directory_is_refused_on_a_path_keyed_volume",
        ) {
            return;
        }
        assert_spelling_refused(&[
            (b"d/", tar::EntryType::Directory, ""),
            (b"d/x", FILE, ""),
            (b"D/x", FILE, ""),
        ]);
    }

    #[cfg(unix)]
    #[test]
    fn a_repeat_through_a_symlink_is_refused_on_a_path_keyed_volume() {
        assert_spelling_refused(&[
            (b"d/", tar::EntryType::Directory, ""),
            (b"l", SYM, "d"),
            (b"d/x", FILE, ""),
            (b"l/x", FILE, ""),
        ]);
    }

    #[cfg(unix)]
    #[test]
    fn a_hardlink_over_a_file_through_a_symlink_alias_is_refused_on_a_path_keyed_volume() {
        let hardlinks = config().with_allow_hardlinks(true);
        assert_spelling_refused_under(
            &[
                (b"d/", tar::EntryType::Directory, ""),
                (b"l", SYM, "d"),
                (b"d/x", FILE, ""),
                (b"l/x", HARD, "d/x"),
            ],
            &hardlinks,
        );
    }

    #[test]
    fn an_exact_repeat_is_a_duplicate_on_every_volume() {
        let outcome = volume_outcome(&[(b"x", FILE, ""), (b"x", FILE, "")]);
        for judged in [&outcome.file_ids, &outcome.landing_paths] {
            assert_matches!(judged[1], Disposition::Skip(SkipKind::Duplicate));
        }
        for extracted in [outcome.identity_extraction, outcome.path_extraction] {
            assert_eq!(extracted.unwrap().skipped.count(SkipKind::Duplicate), 1);
        }
    }

    #[test]
    fn a_file_over_a_made_directory_is_refused_on_every_volume() {
        let outcome = volume_outcome(&[(b"x", tar::EntryType::Directory, ""), (b"x", FILE, "")]);
        for judged in [&outcome.file_ids, &outcome.landing_paths] {
            assert_matches!(judged[1], Disposition::Refuse);
        }
        let previews = [outcome.file_ids_refusal, outcome.landing_paths_refusal];
        let extractions = [outcome.identity_extraction, outcome.path_extraction];
        for (previewed, extracted) in previews.into_iter().zip(extractions) {
            let refused = extracted.unwrap_err();
            assert_eq!(occupied_by(&refused), Some(OccupiedBy::Archive));
            let previewed = previewed.unwrap();
            assert_eq!(previewed.error_code(), refused.error_code());
            assert_eq!(occupied_by(&previewed), Some(OccupiedBy::Archive));
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_list_model_names_the_occupant_kind_and_the_archive_as_maker() {
        let dir = tar::EntryType::Directory;
        let cases: [(TarEntries<'_>, Option<crate::PathOccupant>); 3] = [
            (
                &[(b"x", FILE, ""), (b"x", dir, "")],
                Some(crate::PathOccupant::File),
            ),
            (
                &[(b"x", dir, ""), (b"x", FILE, "")],
                Some(crate::PathOccupant::Directory),
            ),
            (&[(b"t", FILE, ""), (b"l", SYM, "t"), (b"l", dir, "")], None),
        ];
        for (entries, occupant) in cases {
            let outcome = volume_outcome(entries);
            let refused = outcome.file_ids_refusal.unwrap();
            match (&refused, occupant) {
                (
                    ArchiveError::DestinationOccupied {
                        conflicts,
                        destination: None,
                        by: OccupiedBy::Archive,
                    },
                    Some(kind),
                ) => assert_eq!(conflicts[0].occupant, Some(kind)),
                (
                    ArchiveError::SecurityViolation {
                        kind:
                            crate::Violation::ReplacesSymlink {
                                by: OccupiedBy::Archive,
                                ..
                            },
                    },
                    None,
                ) => {}
                _ => panic!("{entries:?}: {refused:?}"),
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_link_over_a_made_directory_is_refused_as_archive_made_on_every_volume() {
        let hardlinks = config().with_allow_hardlinks(true);
        let dir = (&b"d"[..], tar::EntryType::Directory, "");
        for over in [(&b"d"[..], SYM, "t"), (&b"d"[..], HARD, "t")] {
            let outcome = volume_outcome_under(&[(&b"t"[..], FILE, ""), dir, over], &hardlinks);
            for judged in [&outcome.file_ids, &outcome.landing_paths] {
                assert_matches!(judged[2], Disposition::Refuse);
            }
            for (previewed, extracted) in [
                (outcome.file_ids_refusal, outcome.identity_extraction),
                (outcome.landing_paths_refusal, outcome.path_extraction),
            ] {
                let refused = extracted.unwrap_err();
                assert_eq!(occupied_by(&refused), Some(OccupiedBy::Archive));
                assert_eq!(occupied_by(&previewed.unwrap()), Some(OccupiedBy::Archive));
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_repeat_after_a_file_through_its_case_alias_is_refused() {
        if skipped_without_case_folding(
            "a_symlink_repeat_after_a_file_through_its_case_alias_is_refused",
        ) {
            return;
        }
        let dir = tar::EntryType::Directory;
        assert_spelling_refused(&[
            (b"d/", dir, ""),
            (b"L", SYM, "d"),
            (b"l/x", FILE, ""),
            (b"l", SYM, "d"),
        ]);
        assert_spelling_refused(&[
            (b"d/", dir, ""),
            (b"A", SYM, "d"),
            (b"a/x", FILE, ""),
            (b"a", SYM, "d"),
        ]);
    }

    #[test]
    fn a_case_variant_under_an_implied_parent_is_refused_on_a_path_keyed_volume() {
        if skipped_without_case_folding(
            "a_case_variant_under_an_implied_parent_is_refused_on_a_path_keyed_volume",
        ) {
            return;
        }
        assert_spelling_refused(&[(b"d/x", FILE, ""), (b"D/x", FILE, "")]);
    }

    #[test]
    fn a_case_variant_hardlink_over_a_file_is_refused_on_a_path_keyed_volume() {
        if skipped_without_case_folding(
            "a_case_variant_hardlink_over_a_file_is_refused_on_a_path_keyed_volume",
        ) {
            return;
        }
        let hardlinks = config().with_allow_hardlinks(true);
        assert_spelling_refused_under(&[(b"x", FILE, ""), (b"X", HARD, "x")], &hardlinks);
    }
}
