//! Kernel confinement of the CLI process (`--sandbox`).
//!
//! The sandbox is defence in depth around the validation pipeline: it never
//! relaxes a check, and it never claims more than the kernel enforced
//! ([`SandboxStatus`] is typed, not a flag). [`confine`] runs after the
//! password was read and the destination exists, and before the interrupt
//! handler spawns its thread, so every later thread inherits the restriction.
//!
//! This module is the seam of the sandbox feature: the Landlock backend
//! replaces the body of [`confine`] without changing its signature.

#![expect(
    dead_code,
    reason = "the status shapes are constructed by the Landlock backend"
)]

use std::fmt;
use std::num::NonZeroU8;
use std::path::Path;

use serde::Serialize;

use crate::operation::Flag;

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
    BindTcp,
    ConnectTcp,
    ScopeAbstractUnixSocket,
    ScopeSignal,
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
            "{} require could not fully confine the process: {:?}",
            Flag::Sandbox.long(),
            self.0
        )
    }
}

impl std::error::Error for NotEnforced {}

/// Confines the process as `mode` asks, or returns `None` for
/// [`SandboxMode::Off`].
///
/// # Errors
///
/// [`NotEnforced`] under [`SandboxMode::Require`] when the status is anything
/// but [`SandboxStatus::Enforced`].
pub fn confine(
    mode: SandboxMode,
    _grant: &Grant<'_>,
) -> Result<Option<SandboxStatus>, NotEnforced> {
    let status = SandboxStatus::Unavailable {
        reason: Unavailable::NotLinux,
    };
    match mode {
        SandboxMode::Off => Ok(None),
        SandboxMode::BestEffort => Ok(Some(status)),
        SandboxMode::Require => Err(NotEnforced(status)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> Grant<'static> {
        Grant {
            archive: Path::new("a.tar"),
            scope: Scope::ReadOnly,
        }
    }

    #[test]
    fn off_confines_nothing_and_reports_nothing() {
        assert!(matches!(confine(SandboxMode::Off, &grant()), Ok(None)));
    }

    #[test]
    fn require_fails_when_nothing_was_enforced() {
        assert!(confine(SandboxMode::Require, &grant()).is_err());
        assert!(matches!(
            confine(SandboxMode::BestEffort, &grant()),
            Ok(Some(SandboxStatus::Unavailable { .. }))
        ));
    }
}
