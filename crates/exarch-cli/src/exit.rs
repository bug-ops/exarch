//! The process exit status, one value per documented meaning.

use crate::interrupt::Stop;
use std::process::ExitCode;

/// The process exit status, one value per documented meaning.
///
/// Code 2 is clap's usage-error status and is deliberately not used here, so a
/// script can tell "your flags are wrong" from "the archive has warnings". The
/// two signal statuses are the shell's `128 + signal` convention, and every
/// exit caused by a stop request, graceful or forced, maps through them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitStatus {
    /// The command succeeded.
    Success = 0,
    /// The command failed, or verification reported `Fail`.
    Failure = 1,
    /// `verify --strict` found a warning.
    StrictWarning = 3,
    /// Stopped by SIGINT (Ctrl-C): 128 + 2.
    Interrupted = 130,
    /// Stopped by SIGTERM: 128 + 15.
    Terminated = 143,
}

impl From<Stop> for ExitStatus {
    fn from(stop: Stop) -> Self {
        match stop {
            Stop::Interrupt => Self::Interrupted,
            Stop::Terminate => Self::Terminated,
        }
    }
}

impl From<ExitStatus> for ExitCode {
    fn from(status: ExitStatus) -> Self {
        Self::from(status as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [ExitStatus; 5] = [
        ExitStatus::Success,
        ExitStatus::Failure,
        ExitStatus::StrictWarning,
        ExitStatus::Interrupted,
        ExitStatus::Terminated,
    ];

    #[test]
    fn no_status_shares_clap_usage_error_code() {
        const CLAP_USAGE_ERROR: u8 = 2;
        for status in ALL {
            assert_ne!(status as u8, CLAP_USAGE_ERROR, "{status:?}");
        }
        assert_eq!(ExitStatus::StrictWarning as u8, 3);
    }

    #[test]
    fn statuses_are_distinct() {
        for (i, a) in ALL.iter().enumerate() {
            for b in &ALL[i + 1..] {
                assert_ne!(*a as u8, *b as u8, "{a:?} and {b:?}");
            }
        }
    }

    #[test]
    fn a_stop_exits_with_128_plus_its_signal() {
        assert_eq!(ExitStatus::from(Stop::Interrupt) as u8, 128 + 2);
        assert_eq!(ExitStatus::from(Stop::Terminate) as u8, 128 + 15);
    }
}
