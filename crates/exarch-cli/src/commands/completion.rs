//! Shell completion generation command.

use crate::cli::Cli;
use clap::CommandFactory;
use clap_complete::Shell;
use std::io;

/// Generates shell completions for the specified shell and writes them to
/// stdout.
///
/// Invoke as `exarch completion <shell>` and redirect to the appropriate
/// completions directory for your shell.
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
