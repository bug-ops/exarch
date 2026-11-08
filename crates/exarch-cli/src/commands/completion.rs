//! Shell completion generation command.

use crate::cli::Cli;
use crate::output::emit_bytes;
use clap::CommandFactory;
use clap_complete::Shell;
use std::io;
use std::io::Write;

/// Generates shell completions for the specified shell and writes them to
/// `out`.
///
/// The script is rendered in memory first and written once through the CLI's
/// stdout policy, so a closed pipe ends quietly and any other write failure is
/// returned instead of panicking inside `clap_complete`.
///
/// Invoke as `exarch completion <shell>` and redirect to the appropriate
/// completions directory for your shell.
///
/// # Errors
///
/// Any write failure except a closed reader (see [`emit_bytes`]).
///
/// # Examples
///
/// Install completions for zsh:
///
/// ```text
/// exarch completion zsh > ~/.zsh/completions/_exarch
/// exarch completion bash > ~/.bash_completion.d/exarch
/// exarch completion fish > ~/.config/fish/completions/exarch.fish
/// exarch completion powershell | Out-File $PROFILE.CurrentUserAllHosts
/// ```
pub fn execute(shell: Shell, out: &mut impl Write) -> io::Result<()> {
    let mut script = Vec::new();
    clap_complete::generate(shell, &mut Cli::command(), "exarch", &mut script);
    emit_bytes(out, &script)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::test_support::FailingWriter;

    const SHELLS: [Shell; 5] = [
        Shell::Bash,
        Shell::Zsh,
        Shell::Fish,
        Shell::PowerShell,
        Shell::Elvish,
    ];

    #[test]
    fn every_shell_gets_a_script_that_names_the_command() {
        for shell in SHELLS {
            let mut script = Vec::new();
            execute(shell, &mut script).unwrap_or_else(|e| panic!("{shell:?}: {e}"));
            let text = String::from_utf8_lossy(&script);
            assert!(text.contains("exarch"), "{shell:?}");
        }
    }

    #[test]
    fn a_closed_stdout_is_not_a_failure() {
        for shell in SHELLS {
            let mut closed = FailingWriter(io::ErrorKind::BrokenPipe);
            assert!(execute(shell, &mut closed).is_ok(), "{shell:?}");
        }
    }

    #[test]
    fn any_other_write_failure_is_returned() {
        let mut full = FailingWriter(io::ErrorKind::StorageFull);
        let err = execute(Shell::Bash, &mut full).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::StorageFull);
    }
}
