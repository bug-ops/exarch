//! Kernel confinement of the CLI process (`--sandbox`).
//!
//! The sandbox is defence in depth around the validation pipeline: it never
//! relaxes a check, and it never claims more than the kernel enforced
//! ([`SandboxStatus`] is typed, not a flag). A run asks [`preflight_read_only`]
//! or [`preflight_extract`] first, which predicts the status without
//! restricting anything, so `--sandbox require` fails before the archive is
//! touched. `Preflight::confine` then applies the restriction after the
//! password was read and the destination (or its staging reservation) exists,
//! and before the interrupt handler spawns its thread, so every later thread
//! inherits it. A [`Preflight`] is consumed by `confine`, and its type fixes
//! what it may grant: confining without predicting, or granting a destination
//! to a read-only command, cannot be written.
//!
//! A sandboxed `extract` of a TAR into a missing destination (its parent
//! existing) reserves a staging directory beside it through core's
//! `StagingReservation` and confines the process to the reserved stage and its
//! parent, so a failed or interrupted run discards its output exactly as an
//! unsandboxed run does. The rules are built from the reservation's open
//! descriptors, never from paths.
//!
//! The parent of the destination is granted `MAKE_DIR | REMOVE_DIR` (the
//! publish rename and the stage removal need them), and a Landlock rule covers
//! the whole subtree beneath it. A confined process can therefore, beneath the
//! destination's parent and at any depth, create directories, remove empty
//! directories, and rename or exchange directories within the directory they
//! are in (no reparenting: `REFER` is not granted outside the stage). For
//! example `~/.vim/pack/p/opt` can be renamed to `start`. It cannot create,
//! write, truncate or remove files there.
//!
//! Nothing is granted on the temporary directory: `--decode-reuse temp-file`
//! cannot create its spool there, and core then decodes again instead of
//! reusing, so the result is the same and only the optimisation is lost.
//!
//! Only Linux has a backend (Landlock, ABI v2 or newer). Elsewhere
//! the preflight reports [`Unavailable::NotLinux`], which `--sandbox require`
//! turns into a failure. The status is [`SandboxStatus::Enforced`] only when
//! the kernel handles every filesystem right of ABI v3, Linux 6.2 (create,
//! write, remove, rename, link, read-file, execute, truncate); network rights
//! (v4) and newer rights are handled when present and never required; chmod,
//! chown, xattr and utimens are not covered by Landlock at all.

#![cfg_attr(
    not(target_os = "linux"),
    expect(
        dead_code,
        reason = "only the Landlock backend constructs and reads these"
    )
)]

use std::fmt;
use std::marker::PhantomData;
use std::num::NonZeroU8;
use std::path::Path;

use exarch_core::StagingReservation;
use serde::Serialize;

use crate::operation::Flag;
use crate::output::OutputFormatter;

/// What `--sandbox` asks for.
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SandboxMode {
    /// Do not confine the process.
    #[default]
    Off,
    /// Confine when the kernel can, and report what happened.
    BestEffort,
    /// Confine fully, or fail before the archive is opened.
    Require,
}

/// The `--sandbox` flag shared by `extract`, `list` and `verify`.
#[derive(clap::Args, Clone, Copy, Debug, Default)]
pub struct SandboxArgs {
    /// Confine the process with Linux Landlock so a bug cannot write outside
    /// the destination: `off` (default), `best-effort` (report the outcome)
    /// or `require` (fail unless fully enforced). Linux 5.19 or newer; not
    /// combinable with `--atomic`
    #[arg(
        id = "sandbox",
        long = "sandbox",
        value_enum,
        value_name = "MODE",
        default_value_t = SandboxMode::Off
    )]
    pub mode: SandboxMode,
}

/// A Landlock ABI version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Abi(pub NonZeroU8);

/// A kernel access right the ruleset could not handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessRight {
    /// Run a file.
    Execute,
    /// Open a file for writing.
    WriteFile,
    /// Open a file for reading.
    ReadFile,
    /// Open or list a directory.
    ReadDir,
    /// Remove a directory.
    RemoveDir,
    /// Remove or rename away a file.
    RemoveFile,
    /// Create a character device.
    MakeChar,
    /// Create a directory.
    MakeDir,
    /// Create a regular file.
    MakeReg,
    /// Create a socket.
    MakeSock,
    /// Create a named pipe.
    MakeFifo,
    /// Create a block device.
    MakeBlock,
    /// Create a symbolic link.
    MakeSym,
    /// Link or rename a file across directories.
    Refer,
    /// Truncate a file.
    Truncate,
    /// Run `ioctl` commands on a device file.
    IoctlDev,
    /// Connect to a path-based Unix socket.
    ResolveUnix,
}

impl AccessRight {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Execute => "execute",
            Self::WriteFile => "write_file",
            Self::ReadFile => "read_file",
            Self::ReadDir => "read_dir",
            Self::RemoveDir => "remove_dir",
            Self::RemoveFile => "remove_file",
            Self::MakeChar => "make_char",
            Self::MakeDir => "make_dir",
            Self::MakeReg => "make_reg",
            Self::MakeSock => "make_sock",
            Self::MakeFifo => "make_fifo",
            Self::MakeBlock => "make_block",
            Self::MakeSym => "make_sym",
            Self::Refer => "refer",
            Self::Truncate => "truncate",
            Self::IoctlDev => "ioctl_dev",
            Self::ResolveUnix => "resolve_unix",
        }
    }
}

/// The access rights a partial confinement left unhandled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct UnhandledSet(pub Vec<AccessRight>);

/// Why no confinement was applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unavailable {
    /// The platform is not Linux.
    #[cfg_attr(
        all(target_os = "linux", not(test)),
        expect(
            dead_code,
            reason = "only the non-Linux backend and tests construct it"
        )
    )]
    NotLinux,
    /// The kernel has Landlock disabled or not built in.
    Disabled,
    /// The kernel ABI is below the v2 floor (no `REFER`), so nothing was
    /// restricted.
    AbiTooOld,
    /// The run uses atomic staging, whose rename needs rights outside the
    /// destination.
    AtomicStaging,
    /// The kernel refused the ruleset.
    Kernel {
        /// The `errno` of the failed call, when the failure carried one.
        errno: Option<i32>,
    },
    /// A path the ruleset names (the archive or the destination) could not be
    /// opened, so no rule could be built from it.
    RulePath {
        /// The `errno` of the failed open, when the failure carried one.
        errno: Option<i32>,
    },
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotLinux => f.write_str("Landlock exists only on Linux"),
            Self::Disabled => f.write_str("the kernel has Landlock disabled or not built in"),
            Self::AbiTooOld => f.write_str("the kernel Landlock ABI is older than v2"),
            Self::AtomicStaging => f.write_str("--atomic needs rights outside the destination"),
            Self::Kernel { errno } => {
                f.write_str("the kernel refused the ruleset")?;
                write_errno(f, *errno)
            }
            Self::RulePath { errno } => {
                f.write_str("a path the ruleset names could not be opened")?;
                write_errno(f, *errno)
            }
        }
    }
}

fn write_errno(f: &mut fmt::Formatter<'_>, errno: Option<i32>) -> fmt::Result {
    errno.map_or(Ok(()), |errno| write!(f, " (errno {errno})"))
}

/// The typed outcome of [`Preflight::confine`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SandboxStatus {
    /// The kernel enforced every handled right.
    Enforced {
        /// The negotiated ABI.
        abi: Abi,
        /// Whether threads that already existed were restricted too.
        all_threads: bool,
    },
    /// The kernel enforced part of the ruleset.
    Partial {
        /// The negotiated ABI.
        abi: Abi,
        /// Whether threads that already existed were restricted too.
        all_threads: bool,
        /// What the kernel could not handle.
        unhandled: UnhandledSet,
    },
    /// Nothing was restricted.
    Unavailable {
        /// Why.
        reason: Unavailable,
    },
}

impl fmt::Display for SandboxStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enforced { abi, .. } => write!(f, "enforced (Landlock ABI v{})", abi.0),
            Self::Partial { abi, unhandled, .. } => {
                write!(f, "partial (Landlock ABI v{}), not handled:", abi.0)?;
                unhandled
                    .0
                    .iter()
                    .try_for_each(|right| write!(f, " {}", right.as_str()))
            }
            Self::Unavailable { reason } => write!(f, "unavailable: {reason}"),
        }
    }
}

/// `--sandbox require` could not be met.
#[derive(Debug)]
pub struct NotEnforced(pub SandboxStatus);

impl fmt::Display for NotEnforced {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} require could not fully confine the process: {}",
            Flag::Sandbox.long(),
            self.0
        )
    }
}

impl std::error::Error for NotEnforced {}

/// What the preflight predicted the confinement will do.
#[derive(Clone, Copy, Debug)]
enum Plan {
    /// Restrict the process with this kernel ABI.
    #[cfg(target_os = "linux")]
    Restrict(platform::KernelAbi),
    /// Restrict nothing, for this reason.
    Skip(Unavailable),
}

/// The paths a confinement grants besides the archive.
#[derive(Clone, Copy, Debug)]
enum Rules<'a> {
    ReadOnly,
    InPlace(&'a Path),
    Reserved(&'a StagingReservation),
}

/// Marks a [`Preflight`] of a command that only reads the archive.
#[derive(Debug)]
pub struct ReadOnly;

/// Marks a [`Preflight`] of a command that writes a destination.
#[derive(Debug)]
pub struct Destination;

/// A confinement that was predicted and not yet applied; consumed by
/// `confine`. `S` fixes which grants it can make.
#[derive(Debug)]
#[must_use = "a preflight does nothing until it confines the process"]
pub struct Preflight<S> {
    mode: SandboxMode,
    plan: Plan,
    kind: PhantomData<fn() -> S>,
}

/// Where a confined `extract` may write.
#[derive(Clone, Copy, Debug)]
pub enum DestinationScope<'a> {
    /// `extract` straight into an existing destination: its subtree is
    /// writable.
    InPlace(&'a Path),
    /// `extract` through a reserved stage: the stage is writable, and its
    /// parent may create and remove directories (the publish rename).
    Reserved(&'a StagingReservation),
}

/// Who stages an `extract`, which fixes whether a grant can cover it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtractStaging {
    /// The destination subtree, directly or through a reserved stage.
    Destination,
    /// A staging directory that core resolves itself (`--atomic`), which
    /// needs rights outside the destination and so cannot be confined.
    Core,
}

/// The predicted confinement of an `extract`.
#[derive(Debug)]
#[must_use = "a preflight does nothing until it confines the process"]
pub enum ExtractPreflight {
    /// The process can be confined to the destination.
    Destination(Preflight<Destination>),
    /// Core stages the output itself, so nothing is confined.
    CoreStaged(Unconfined),
}

/// A run that cannot be confined, with the reason.
#[derive(Debug)]
#[must_use = "the status must be reported"]
pub struct Unconfined {
    mode: SandboxMode,
    reason: Unavailable,
}

impl Unconfined {
    /// The status of the unconfined run.
    ///
    /// # Errors
    ///
    /// [`NotEnforced`] under [`SandboxMode::Require`].
    pub fn status(self) -> Result<SandboxStatus, NotEnforced> {
        judge(
            self.mode,
            SandboxStatus::Unavailable {
                reason: self.reason,
            },
        )
    }
}

/// Predicts the confinement `mode` asks for of a command that only reads the
/// archive, without restricting anything, or returns `None` for
/// [`SandboxMode::Off`].
///
/// # Errors
///
/// [`NotEnforced`] under [`SandboxMode::Require`] when the predicted status is
/// anything but [`SandboxStatus::Enforced`]: it fails before the archive is
/// opened.
pub fn preflight_read_only(mode: SandboxMode) -> Result<Option<Preflight<ReadOnly>>, NotEnforced> {
    Preflight::predict(mode)
}

/// Predicts the confinement `mode` asks for of an `extract` with the given
/// staging, without restricting anything, or returns `None` for
/// [`SandboxMode::Off`].
///
/// # Errors
///
/// [`NotEnforced`] under [`SandboxMode::Require`] when the predicted status is
/// anything but [`SandboxStatus::Enforced`]: it fails before the archive is
/// opened.
pub fn preflight_extract(
    mode: SandboxMode,
    staging: ExtractStaging,
) -> Result<Option<ExtractPreflight>, NotEnforced> {
    if mode == SandboxMode::Off {
        return Ok(None);
    }
    match staging {
        ExtractStaging::Destination => {
            Preflight::predict(mode).map(|p| p.map(ExtractPreflight::Destination))
        }
        ExtractStaging::Core => {
            let unconfined = Unconfined {
                mode,
                reason: platform::core_staged_reason(),
            };
            judge(
                mode,
                SandboxStatus::Unavailable {
                    reason: unconfined.reason,
                },
            )?;
            Ok(Some(ExtractPreflight::CoreStaged(unconfined)))
        }
    }
}

impl<S> Preflight<S> {
    fn predict(mode: SandboxMode) -> Result<Option<Self>, NotEnforced> {
        if mode == SandboxMode::Off {
            return Ok(None);
        }
        let preflight = Self {
            mode,
            plan: platform::plan(),
            kind: PhantomData,
        };
        judge(mode, preflight.predicted())?;
        Ok(Some(preflight))
    }

    fn predicted(&self) -> SandboxStatus {
        match self.plan {
            Plan::Skip(reason) => SandboxStatus::Unavailable { reason },
            #[cfg(target_os = "linux")]
            Plan::Restrict(abi) => platform::predicted(abi),
        }
    }

    #[cfg_attr(
        not(target_os = "linux"),
        expect(unused_variables, reason = "only the Landlock backend reads the rules")
    )]
    fn apply(self, archive: &Path, rules: Rules<'_>) -> Result<SandboxStatus, NotEnforced> {
        let status = match self.plan {
            Plan::Skip(reason) => SandboxStatus::Unavailable { reason },
            #[cfg(target_os = "linux")]
            Plan::Restrict(abi) => platform::apply(archive, rules, abi),
        };
        judge(self.mode, status)
    }
}

impl Preflight<ReadOnly> {
    /// Applies the confinement that lets the process read `archive` only and
    /// returns what the kernel enforced.
    ///
    /// Call it after every file the run needs besides the archive was opened
    /// (the password source) and before any thread is spawned, so later
    /// threads inherit the restriction.
    ///
    /// # Errors
    ///
    /// [`NotEnforced`] under [`SandboxMode::Require`] when the kernel enforced
    /// anything but the predicted status (a refused ruleset, or a prediction
    /// miss).
    pub fn confine(self, archive: &Path) -> Result<SandboxStatus, NotEnforced> {
        self.apply(archive, Rules::ReadOnly)
    }
}

impl Preflight<Destination> {
    /// Applies the confinement that lets the process read `archive` and write
    /// `scope`, and returns what the kernel enforced.
    ///
    /// Call it under the same conditions as the read-only form.
    ///
    /// # Errors
    ///
    /// As the read-only form.
    pub fn confine(
        self,
        archive: &Path,
        scope: DestinationScope<'_>,
    ) -> Result<SandboxStatus, NotEnforced> {
        let rules = match scope {
            DestinationScope::InPlace(destination) => Rules::InPlace(destination),
            DestinationScope::Reserved(reservation) => Rules::Reserved(reservation),
        };
        self.apply(archive, rules)
    }
}

/// Predicts, then confines, a command that only reads `archive` (`list`,
/// `verify`), and hands the outcome to `formatter`.
///
/// # Errors
///
/// [`NotEnforced`] under [`SandboxMode::Require`], as for
/// [`preflight_read_only`] and `Preflight::confine`.
pub fn confine_read_only(
    mode: SandboxMode,
    archive: &Path,
    formatter: &mut dyn OutputFormatter,
) -> Result<(), NotEnforced> {
    let status = preflight_read_only(mode)?.map(|preflight| preflight.confine(archive));
    report(status, formatter)
}

/// Hands the outcome of a confinement, when there was one, to `formatter`.
///
/// # Errors
///
/// The [`NotEnforced`] the confinement produced.
pub fn report(
    status: Option<Result<SandboxStatus, NotEnforced>>,
    formatter: &mut dyn OutputFormatter,
) -> Result<(), NotEnforced> {
    if let Some(status) = status {
        formatter.format_sandbox(&status?);
        #[cfg(all(target_os = "linux", feature = "test-hooks", debug_assertions))]
        probe::create_outside();
    }
    Ok(())
}

/// Test-only seam: after confinement, tries to create the file
/// `EXARCH_TEST_SANDBOX_PROBE` names (a path outside the destination) and
/// reports the outcome on stderr, so a test can prove the kernel denies it.
#[cfg(all(target_os = "linux", feature = "test-hooks", debug_assertions))]
mod probe {
    use std::fs::OpenOptions;

    const VARIABLE: &str = "EXARCH_TEST_SANDBOX_PROBE";

    pub(super) fn create_outside() {
        let Some(path) = std::env::var_os(VARIABLE) else {
            return;
        };
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(_) => eprintln!("sandbox probe: created {}", path.to_string_lossy()),
            Err(error) => eprintln!("sandbox probe: {error}"),
        }
    }
}

fn judge(mode: SandboxMode, status: SandboxStatus) -> Result<SandboxStatus, NotEnforced> {
    match (mode, &status) {
        (
            SandboxMode::Require,
            SandboxStatus::Partial { .. } | SandboxStatus::Unavailable { .. },
        ) => Err(NotEnforced(status)),
        _ => Ok(status),
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::Plan;
    use super::Unavailable;

    pub(super) const fn plan() -> Plan {
        Plan::Skip(Unavailable::NotLinux)
    }

    pub(super) const fn core_staged_reason() -> Unavailable {
        Unavailable::NotLinux
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::num::NonZeroU8;
    use std::path::Path;

    use landlock::ABI;
    use landlock::Access;
    use landlock::AccessFs;
    use landlock::AccessNet;
    use landlock::CompatLevel;
    use landlock::Compatible;
    use landlock::PathBeneath;
    use landlock::PathFd;
    use landlock::PathFdError;
    use landlock::RestrictSelfAttr;
    use landlock::RestrictionStatus;
    use landlock::Ruleset;
    use landlock::RulesetAttr;
    use landlock::RulesetCreatedAttr;
    use landlock::RulesetError;
    use landlock::RulesetStatus;
    use landlock::Scope as KernelScope;

    use super::Abi;
    use super::AccessRight;
    use super::Plan;
    use super::Rules;
    use super::SandboxStatus;
    use super::Unavailable;
    use super::UnhandledSet;

    /// The Landlock ABI a restriction is built for.
    pub(super) type KernelAbi = ABI;

    /// The oldest ABI that is enforced at all: v1 denies every cross-directory
    /// link and rename.
    const FLOOR: ABI = ABI::V2;
    /// The ABI whose filesystem rights the status vouches for; a kernel below
    /// it reports [`SandboxStatus::Partial`]. Newer rights are handled when the
    /// kernel has them and are never required.
    const ENFORCED_FROM: ABI = ABI::V3;
    const NEWEST_FIRST: [ABI; 9] = [
        ABI::V9,
        ABI::V8,
        ABI::V7,
        ABI::V6,
        ABI::V5,
        ABI::V4,
        ABI::V3,
        ABI::V2,
        ABI::V1,
    ];

    enum Failure {
        Ruleset(RulesetError),
        Path(PathFdError),
    }

    impl From<RulesetError> for Failure {
        fn from(error: RulesetError) -> Self {
            Self::Ruleset(error)
        }
    }

    impl From<PathFdError> for Failure {
        fn from(error: PathFdError) -> Self {
            Self::Path(error)
        }
    }

    impl Failure {
        fn errno(&self) -> Option<i32> {
            let first: &(dyn std::error::Error + 'static) = match self {
                Self::Ruleset(error) => error,
                Self::Path(error) => error,
            };
            std::iter::successors(Some(first), |error| error.source())
                .find_map(|error| error.downcast_ref::<std::io::Error>()?.raw_os_error())
        }

        fn unavailable(&self) -> Unavailable {
            let errno = self.errno();
            match self {
                Self::Ruleset(_) => Unavailable::Kernel { errno },
                Self::Path(_) => Unavailable::RulePath { errno },
            }
        }
    }

    const fn unavailable(reason: Unavailable) -> SandboxStatus {
        SandboxStatus::Unavailable { reason }
    }

    /// The newest ABI the running kernel handles completely, found without
    /// restricting anything: a hard-requirement ruleset refuses a right the
    /// kernel lacks, and building it makes no syscall that has an effect.
    fn kernel_abi() -> Option<ABI> {
        NEWEST_FIRST.into_iter().find(|&abi| {
            Ruleset::default()
                .set_compatibility(CompatLevel::HardRequirement)
                .handle_access(AccessFs::from_all(abi))
                .is_ok()
        })
    }

    /// What the kernel allows, found without restricting anything.
    pub(super) fn plan() -> Plan {
        match kernel_abi() {
            None => Plan::Skip(Unavailable::Disabled),
            Some(abi) if abi < FLOOR => Plan::Skip(Unavailable::AbiTooOld),
            Some(abi) => Plan::Restrict(abi),
        }
    }

    pub(super) const fn core_staged_reason() -> Unavailable {
        Unavailable::AtomicStaging
    }

    /// The status a restriction with `abi` reports when the kernel enforces
    /// it: [`SandboxStatus::Enforced`] from [`ENFORCED_FROM`], else
    /// [`SandboxStatus::Partial`].
    pub(super) fn predicted(abi: ABI) -> SandboxStatus {
        let Some(version) = NonZeroU8::new(abi as u8) else {
            return unavailable(Unavailable::Disabled);
        };
        enforced_or_partial(abi, super::Abi(version), true)
    }

    pub(super) fn apply(archive: &Path, rules: Rules<'_>, abi: ABI) -> SandboxStatus {
        restrict(archive, rules, abi).unwrap_or_else(|failure| unavailable(failure.unavailable()))
    }

    /// Every right of `abi` except those a destination subtree must never
    /// hold: running a file, device `ioctl`s, connecting to a path socket and
    /// creating device nodes, named pipes or sockets (extraction creates none
    /// of them, and under root a stray node would be a write path outside).
    fn destination_rights(abi: ABI) -> landlock::BitFlags<AccessFs> {
        const WITHHELD: landlock::BitFlags<AccessFs> = landlock::make_bitflags!(AccessFs::{
            Execute | IoctlDev | ResolveUnix | MakeChar | MakeBlock | MakeFifo | MakeSock
        });
        AccessFs::from_all(abi) & !WITHHELD
    }

    fn restrict(archive: &Path, rules: Rules<'_>, abi: ABI) -> Result<SandboxStatus, Failure> {
        let mut ruleset = Ruleset::default().handle_access(AccessFs::from_all(abi))?;
        let network = AccessNet::from_all(abi);
        if !network.is_empty() {
            ruleset = ruleset.handle_access(network)?;
        }
        let scopes = KernelScope::from_all(abi);
        if !scopes.is_empty() {
            ruleset = ruleset.scope(scopes)?;
        }
        let mut created = ruleset
            .create()?
            .add_rule(PathBeneath::new(PathFd::new(archive)?, AccessFs::ReadFile))?;
        match rules {
            Rules::InPlace(destination) => {
                created = created.add_rule(PathBeneath::new(
                    PathFd::new(destination)?,
                    destination_rights(abi),
                ))?;
            }
            Rules::Reserved(reservation) => {
                created = created
                    .add_rule(PathBeneath::new(
                        reservation.staging_fd(),
                        destination_rights(abi),
                    ))?
                    .add_rule(PathBeneath::new(
                        reservation.parent_fd(),
                        make_dir_remove_dir(),
                    ))?;
            }
            Rules::ReadOnly => {}
        }
        let restriction = created.all_threads(true)?.restrict_self()?;
        Ok(status_of(abi, &restriction))
    }

    /// What the parent of a reserved stage needs: the publish rename creates
    /// the destination and removes the stage, nothing else.
    fn make_dir_remove_dir() -> landlock::BitFlags<AccessFs> {
        landlock::make_bitflags!(AccessFs::{ MakeDir | RemoveDir })
    }

    fn status_of(abi: ABI, restriction: &RestrictionStatus) -> SandboxStatus {
        let Some(version) = NonZeroU8::new(abi as u8) else {
            return unavailable(Unavailable::Disabled);
        };
        if restriction.ruleset == RulesetStatus::NotEnforced {
            return unavailable(Unavailable::Disabled);
        }
        enforced_or_partial(abi, Abi(version), restriction.all_threads)
    }

    fn enforced_or_partial(abi: ABI, abi_out: Abi, all_threads: bool) -> SandboxStatus {
        let missing_fs = AccessFs::from_all(ENFORCED_FROM) & !AccessFs::from_all(abi);
        if missing_fs.is_empty() {
            return SandboxStatus::Enforced {
                abi: abi_out,
                all_threads,
            };
        }
        let unhandled = missing_fs.iter().filter_map(fs_right).collect();
        SandboxStatus::Partial {
            abi: abi_out,
            all_threads,
            unhandled: UnhandledSet(unhandled),
        }
    }

    /// `None` for a right a newer `landlock` crate added.
    const fn fs_right(right: AccessFs) -> Option<AccessRight> {
        Some(match right {
            AccessFs::Execute => AccessRight::Execute,
            AccessFs::WriteFile => AccessRight::WriteFile,
            AccessFs::ReadFile => AccessRight::ReadFile,
            AccessFs::ReadDir => AccessRight::ReadDir,
            AccessFs::RemoveDir => AccessRight::RemoveDir,
            AccessFs::RemoveFile => AccessRight::RemoveFile,
            AccessFs::MakeChar => AccessRight::MakeChar,
            AccessFs::MakeDir => AccessRight::MakeDir,
            AccessFs::MakeReg => AccessRight::MakeReg,
            AccessFs::MakeSock => AccessRight::MakeSock,
            AccessFs::MakeFifo => AccessRight::MakeFifo,
            AccessFs::MakeBlock => AccessRight::MakeBlock,
            AccessFs::MakeSym => AccessRight::MakeSym,
            AccessFs::Refer => AccessRight::Refer,
            AccessFs::Truncate => AccessRight::Truncate,
            AccessFs::IoctlDev => AccessRight::IoctlDev,
            AccessFs::ResolveUnix => AccessRight::ResolveUnix,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    fn enforced() -> SandboxStatus {
        SandboxStatus::Enforced {
            abi: Abi(NonZeroU8::MIN),
            all_threads: false,
        }
    }

    fn partial() -> SandboxStatus {
        SandboxStatus::Partial {
            abi: Abi(NonZeroU8::MIN),
            all_threads: false,
            unhandled: UnhandledSet(vec![AccessRight::Truncate]),
        }
    }

    fn unavailable() -> SandboxStatus {
        SandboxStatus::Unavailable {
            reason: Unavailable::Disabled,
        }
    }

    #[test]
    fn off_confines_nothing_and_reports_nothing() {
        assert_matches!(preflight_read_only(SandboxMode::Off), Ok(None));
        assert_matches!(
            preflight_extract(SandboxMode::Off, ExtractStaging::Core),
            Ok(None)
        );
    }

    #[test]
    fn require_accepts_only_an_enforced_status() {
        assert!(judge(SandboxMode::Require, enforced()).is_ok());
        assert!(judge(SandboxMode::Require, partial()).is_err());
        assert!(judge(SandboxMode::Require, unavailable()).is_err());
    }

    #[test]
    fn require_fails_in_the_preflight_for_a_run_core_stages() {
        assert!(preflight_extract(SandboxMode::Require, ExtractStaging::Core).is_err());
        assert_matches!(
            preflight_extract(SandboxMode::BestEffort, ExtractStaging::Core),
            Ok(Some(ExtractPreflight::CoreStaged(_)))
        );
    }

    #[test]
    fn the_core_staged_reason_is_the_platforms_own() {
        let Ok(Some(ExtractPreflight::CoreStaged(unconfined))) =
            preflight_extract(SandboxMode::BestEffort, ExtractStaging::Core)
        else {
            panic!("best-effort core staging is always reported");
        };
        let expected = if cfg!(target_os = "linux") {
            Unavailable::AtomicStaging
        } else {
            Unavailable::NotLinux
        };

        assert_eq!(
            unconfined.status().unwrap(),
            SandboxStatus::Unavailable { reason: expected }
        );
    }

    #[test]
    fn a_failed_rule_path_and_a_refused_ruleset_serialize_apart_with_an_optional_errno() {
        let json = |reason| serde_json::to_value(reason).unwrap();

        assert_eq!(
            json(Unavailable::RulePath { errno: Some(2) }),
            serde_json::json!({"rule_path": {"errno": 2}})
        );
        assert_eq!(
            json(Unavailable::Kernel { errno: None }),
            serde_json::json!({"kernel": {"errno": null}})
        );
        assert_eq!(
            Unavailable::RulePath { errno: Some(2) }.to_string(),
            "a path the ruleset names could not be opened (errno 2)"
        );
        assert_eq!(
            Unavailable::Kernel { errno: None }.to_string(),
            "the kernel refused the ruleset"
        );
    }

    #[test]
    fn best_effort_never_fails_and_keeps_the_status() {
        for status in [enforced(), partial(), unavailable()] {
            assert_eq!(
                judge(SandboxMode::BestEffort, status.clone()).unwrap(),
                status
            );
        }
    }

    #[test]
    fn the_status_never_claims_more_than_it_holds() {
        assert_eq!(
            partial().to_string(),
            "partial (Landlock ABI v1), not handled: truncate"
        );
        assert_eq!(enforced().to_string(), "enforced (Landlock ABI v1)");
        assert_eq!(
            unavailable().to_string(),
            "unavailable: the kernel has Landlock disabled or not built in"
        );
    }

    #[test]
    fn the_status_serializes_with_a_tag() {
        let json = serde_json::to_value(partial()).unwrap();
        assert_eq!(json["status"], "partial");
        assert_eq!(json["abi"], 1);
        assert_eq!(json["unhandled"][0], "truncate");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn off_linux_every_mode_reports_not_linux() {
        let best_effort = preflight_read_only(SandboxMode::BestEffort)
            .unwrap()
            .unwrap();
        assert_matches!(
            best_effort.confine(Path::new("a.tar")),
            Ok(SandboxStatus::Unavailable {
                reason: Unavailable::NotLinux
            })
        );
        assert!(preflight_read_only(SandboxMode::Require).is_err());
    }
}
