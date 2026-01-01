//! Shell completion generation command.

use crate::cli::Cli;
use clap::CommandFactory;
use clap_complete::Shell;
use std::io;

/// Generates shell completions for the specified shell.
///
/// # Arguments
///
/// * `shell` - Target shell (bash, zsh, fish, powershell, elvish)
///
/// # Examples
///
/// ```no_run
/// use clap_complete::Shell;
/// use exarch_cli::commands::completion;
///
/// completion::execute(Shell::Bash);
/// ```
pub fn execute(shell: Shell) {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "exarch", &mut io::stdout());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_completion_generation() {
        // Test that completion generation doesn't panic
        // We can't easily test the output without capturing stdout
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Elvish,
        ] {
            let result = std::panic::catch_unwind(|| {
                let mut cmd = Cli::command();
                let mut output = Vec::new();
                clap_complete::generate(shell, &mut cmd, "exarch", &mut output);
                output
            });
            assert!(result.is_ok(), "Completion generation failed for {shell:?}");
        }
    }
}
