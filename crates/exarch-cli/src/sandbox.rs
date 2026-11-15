//! Kernel confinement of the CLI process (`--sandbox`).
//!
//! The sandbox is defence in depth around the validation pipeline: it never
//! relaxes a check, and it never claims more than the kernel enforced
//! ([`SandboxStatus`] is typed, not a flag). [`confine`] runs after the
//! password was read and the destination exists, and before the interrupt
//! handler spawns its thread, so every later thread inherits the restriction.
//!
//! Only Linux has a backend (Landlock, ABI v2 or newer). Elsewhere [`confine`]
//! reports [`Unavailable::NotLinux`], which `--sandbox require` turns into a
//! failure. The status is [`SandboxStatus::Enforced`] only when the kernel
//! handles every filesystem right of ABI v3, Linux 6.2 (create, write, remove,
//! rename, link, read-file, execute, truncate); network rights (v4) and newer
//! rights are handled when present and never required; chmod, chown, xattr and
//! utimens are not covered by Landlock at all.

#![cfg_attr(
    not(target_os = "linux"),
    expect(
        dead_code,
        reason = "only the Landlock backend constructs and reads these"
    )
)]

use std::fmt;
use std::num::NonZeroU8;
use std::path::Path;

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
    Execute,
    WriteFile,
    ReadFile,
    ReadDir,
    RemoveDir,
    RemoveFile,
    MakeChar,
    MakeDir,
    MakeReg,
    MakeSock,
    MakeFifo,
    MakeBlock,
    MakeSym,
    Refer,
    Truncate,
    IoctlDev,
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
        /// The `errno` of the failed call.
        errno: i32,
    },
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotLinux => f.write_str("Landlock exists only on Linux"),
            Self::Disabled => f.write_str("the kernel has Landlock disabled or not built in"),
            Self::AbiTooOld => f.write_str("the kernel Landlock ABI is older than v2"),
            Self::AtomicStaging => f.write_str("--atomic needs rights outside the destination"),
            Self::Kernel { errno } => write!(f, "the kernel refused the ruleset (errno {errno})"),
        }
    }
}

/// The typed outcome of [`confine`].
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

/// What the confined process may touch.
#[derive(Clone, Copy, Debug)]
pub struct Grant<'a> {
    /// The archive, readable as a file.
    pub archive: &'a Path,
    /// The command the grant is for.
    pub scope: Scope<'a>,
}

/// The command a [`Grant`] is for.
#[derive(Clone, Copy, Debug)]
pub enum Scope<'a> {
    /// `extract`: the destination subtree is writable.
    Extract {
        /// The destination directory.
        destination: &'a Path,
        /// Whether the run stages atomically.
        atomic: bool,
    },
    /// `list` and `verify`: only the archive is read.
    ReadOnly,
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

/// Confines the process as `mode` asks, or returns `None` for
/// [`SandboxMode::Off`].
///
/// Call it after every file the run needs besides the grant was opened (the
/// password source) and before any thread is spawned, so later threads inherit
/// the restriction.
///
/// # Errors
///
/// [`NotEnforced`] under [`SandboxMode::Require`] when the status is anything
/// but [`SandboxStatus::Enforced`].
pub fn confine(mode: SandboxMode, grant: &Grant<'_>) -> Result<Option<SandboxStatus>, NotEnforced> {
    match mode {
        SandboxMode::Off => Ok(None),
        SandboxMode::BestEffort | SandboxMode::Require => {
            judge(mode, platform::apply(grant)).map(Some)
        }
    }
}

/// Runs [`confine`] and hands the outcome to `formatter`.
///
/// # Errors
///
/// [`NotEnforced`] under [`SandboxMode::Require`], as for [`confine`].
pub fn confine_and_report(
    mode: SandboxMode,
    grant: &Grant<'_>,
    formatter: &mut dyn OutputFormatter,
) -> Result<(), NotEnforced> {
    if let Some(status) = confine(mode, grant)? {
        formatter.format_sandbox(&status);
    }
    Ok(())
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
    use super::Grant;
    use super::SandboxStatus;
    use super::Unavailable;

    pub(super) const fn apply(_grant: &Grant<'_>) -> SandboxStatus {
        SandboxStatus::Unavailable {
            reason: Unavailable::NotLinux,
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::num::NonZeroU8;

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
    use super::Grant;
    use super::SandboxStatus;
    use super::Scope;
    use super::Unavailable;
    use super::UnhandledSet;

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
        fn errno(&self) -> i32 {
            let first: &(dyn std::error::Error + 'static) = match self {
                Self::Ruleset(error) => error,
                Self::Path(error) => error,
            };
            std::iter::successors(Some(first), |error| error.source())
                .find_map(|error| error.downcast_ref::<std::io::Error>()?.raw_os_error())
                .unwrap_or(libc::EINVAL)
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

    pub(super) fn apply(grant: &Grant<'_>) -> SandboxStatus {
        if matches!(grant.scope, Scope::Extract { atomic: true, .. }) {
            return unavailable(Unavailable::AtomicStaging);
        }
        match kernel_abi() {
            None => unavailable(Unavailable::Disabled),
            Some(abi) if abi < FLOOR => unavailable(Unavailable::AbiTooOld),
            Some(abi) => restrict(grant, abi).unwrap_or_else(|failure| {
                unavailable(Unavailable::Kernel {
                    errno: failure.errno(),
                })
            }),
        }
    }

    /// Every right of `abi` except those a destination subtree must never
    /// hold: running a file, device `ioctl`s and connecting to a path socket.
    fn destination_rights(abi: ABI) -> landlock::BitFlags<AccessFs> {
        AccessFs::from_all(abi) & !(AccessFs::Execute | AccessFs::IoctlDev | AccessFs::ResolveUnix)
    }

    fn restrict(grant: &Grant<'_>, abi: ABI) -> Result<SandboxStatus, Failure> {
        let mut ruleset = Ruleset::default().handle_access(AccessFs::from_all(abi))?;
        let network = AccessNet::from_all(abi);
        if !network.is_empty() {
            ruleset = ruleset.handle_access(network)?;
        }
        let scopes = KernelScope::from_all(abi);
        if !scopes.is_empty() {
            ruleset = ruleset.scope(scopes)?;
        }
        let mut created = ruleset.create()?.add_rule(PathBeneath::new(
            PathFd::new(grant.archive)?,
            AccessFs::ReadFile,
        ))?;
        if let Scope::Extract { destination, .. } = grant.scope {
            created = created.add_rule(PathBeneath::new(
                PathFd::new(destination)?,
                destination_rights(abi),
            ))?;
        }
        let restriction = created.all_threads(true)?.restrict_self()?;
        Ok(status_of(abi, &restriction))
    }

    fn status_of(abi: ABI, restriction: &RestrictionStatus) -> SandboxStatus {
        let Some(version) = NonZeroU8::new(abi as u8) else {
            return unavailable(Unavailable::Disabled);
        };
        if restriction.ruleset == RulesetStatus::NotEnforced {
            return unavailable(Unavailable::Disabled);
        }
        let abi_out = Abi(version);
        let all_threads = restriction.all_threads;
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
        let grant = Grant {
            archive: Path::new("a.tar"),
            scope: Scope::ReadOnly,
        };
        assert!(matches!(confine(SandboxMode::Off, &grant), Ok(None)));
    }

    #[test]
    fn require_accepts_only_an_enforced_status() {
        assert!(judge(SandboxMode::Require, enforced()).is_ok());
        assert!(judge(SandboxMode::Require, partial()).is_err());
        assert!(judge(SandboxMode::Require, unavailable()).is_err());
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
        let grant = Grant {
            archive: Path::new("a.tar"),
            scope: Scope::ReadOnly,
        };
        assert!(matches!(
            confine(SandboxMode::BestEffort, &grant),
            Ok(Some(SandboxStatus::Unavailable {
                reason: Unavailable::NotLinux
            }))
        ));
        assert!(confine(SandboxMode::Require, &grant).is_err());
    }
}
