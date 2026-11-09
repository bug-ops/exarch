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

impl ExitStatus {
    /// The numeric status the process exits with.
    pub const fn code(self) -> i32 {
        self as i32
    }

    /// Whether a stop request caused this status.
    pub const fn is_stop(self) -> bool {
        matches!(self, Self::Interrupted | Self::Terminated)
    }
}

/// The status the process ends with: a run that completed after a stop was
/// requested still reports the stop, over a success or a strict warning, so a
/// stop that landed after core's last poll is not lost. A failure keeps its
/// own status, and the stop status of a cancelled run is already `result`.
pub fn final_status(result: ExitStatus, requested: Option<Stop>) -> ExitStatus {
    match (result, requested) {
        (ExitStatus::Success | ExitStatus::StrictWarning, Some(stop)) => ExitStatus::from(stop),
        _ => result,
    }
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
    fn a_stop_after_the_last_poll_still_reports_the_stop() {
        for (completed, stop, expected) in [
            (
                ExitStatus::Success,
                Stop::Interrupt,
                ExitStatus::Interrupted,
            ),
            (ExitStatus::Success, Stop::Terminate, ExitStatus::Terminated),
            (
                ExitStatus::StrictWarning,
                Stop::Interrupt,
                ExitStatus::Interrupted,
            ),
        ] {
            assert_eq!(final_status(completed, Some(stop)), expected);
        }
    }

    #[test]
    fn without_a_stop_or_after_a_failure_the_status_is_unchanged() {
        for status in ALL {
            assert_eq!(final_status(status, None), status);
        }
        assert_eq!(
            final_status(ExitStatus::Failure, Some(Stop::Interrupt)),
            ExitStatus::Failure
        );
        assert_eq!(
            final_status(ExitStatus::Terminated, Some(Stop::Interrupt)),
            ExitStatus::Terminated
        );
    }

    #[test]
    fn the_code_and_the_stop_flag_follow_the_status() {
        assert_eq!(ExitStatus::Interrupted.code(), 130);
        assert_eq!(ExitStatus::Terminated.code(), 143);
        for status in ALL {
            assert_eq!(
                status.is_stop(),
                matches!(status, ExitStatus::Interrupted | ExitStatus::Terminated)
            );
        }
    }

    #[test]
    fn a_stop_exits_with_128_plus_its_signal() {
        assert_eq!(ExitStatus::from(Stop::Interrupt) as u8, 128 + 2);
        assert_eq!(ExitStatus::from(Stop::Terminate) as u8, 128 + 15);
    }
}
