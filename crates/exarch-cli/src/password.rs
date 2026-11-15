//! Password input for encrypted archives.
//!
//! The password reaches the process only through a file, a file descriptor or
//! an interactive prompt, never through argv or the environment. [`read`] runs
//! before the sandbox confines the process, because every source opens
//! something outside the destination (a file, a descriptor, `/dev/tty`).
//!
//! The bytes go straight into a core [`Password`], which wipes its buffer on
//! drop. Messages built here never contain them.

use std::fs::File;
use std::io::IsTerminal;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use exarch_core::Password;
use zeroize::Zeroizing;

/// The most bytes a password source may hold: the length cap of a core
/// [`Password`].
const MAX_SOURCE_BYTES: usize = Password::MAX_LEN;

/// Where the password is read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordSource {
    /// The first line of a regular file.
    File(PathBuf),
    /// The first line read from an inherited file descriptor.
    #[cfg(unix)]
    Fd(std::os::fd::RawFd),
    /// A no-echo prompt on the terminal.
    Prompt,
}

/// Reads the password from `source`, or returns `None` when no source was
/// given.
///
/// # Errors
///
/// A source that cannot be read (a missing, unreadable or non-regular file, a
/// file readable by group or others on Unix, a source over 1 KiB, a prompt
/// without a terminal), or whose first line is empty or too long to be a
/// password.
pub fn read(source: Option<&PasswordSource>) -> Result<Option<Arc<Password>>> {
    source.map(read_source).transpose()
}

fn read_source(source: &PasswordSource) -> Result<Arc<Password>> {
    let mut bytes = match source {
        PasswordSource::File(path) => read_file(path)?,
        #[cfg(unix)]
        PasswordSource::Fd(fd) => read_fd(*fd)?,
        PasswordSource::Prompt => prompt()?,
    };
    first_line(&mut bytes);
    let password = Password::new(bytes).context("the password is not usable")?;
    Ok(Arc::new(password))
}

/// Keeps the first line: the bytes before the first newline, without a
/// trailing carriage return.
fn first_line(bytes: &mut Vec<u8>) {
    if let Some(end) = bytes.iter().position(|&byte| byte == b'\n') {
        bytes.truncate(end);
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
}

/// Reads at most [`MAX_SOURCE_BYTES`] from `reader`, refusing more.
fn read_capped(reader: impl Read, origin: &str) -> Result<Vec<u8>> {
    // Fixed capacity so the buffer never reallocates and leaves a copy of the
    // secret behind.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_SOURCE_BYTES + 1));
    reader
        .take(MAX_SOURCE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read the password from {origin}"))?;
    if bytes.len() > MAX_SOURCE_BYTES {
        bail!("the password source {origin} holds more than {MAX_SOURCE_BYTES} bytes");
    }
    Ok(std::mem::take(&mut *bytes))
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    let origin = path.display().to_string();
    // Windows refuses to open a directory with an unrelated error; this
    // pre-check only gives every platform the same message, and the check on
    // the opened descriptor below stays authoritative.
    if std::fs::metadata(path).is_ok_and(|metadata| !metadata.is_file()) {
        bail!("the password file {origin} is not a regular file");
    }
    let file =
        File::open(path).with_context(|| format!("failed to open the password file {origin}"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect the password file {origin}"))?;
    if !metadata.is_file() {
        bail!("the password file {origin} is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "the password file {origin} is accessible to group or others (mode {:o}); run chmod 600",
                metadata.permissions().mode() & 0o777
            );
        }
    }
    read_capped(file, &origin)
}

/// Reads from an inherited descriptor through its `/dev/fd` entry, so no
/// `unsafe` is needed to adopt it. The descriptor itself stays open until the
/// process exits.
#[cfg(unix)]
fn read_fd(fd: std::os::fd::RawFd) -> Result<Vec<u8>> {
    let origin = format!("file descriptor {fd}");
    let file = File::open(format!("/dev/fd/{fd}"))
        .with_context(|| format!("failed to open {origin}; is it inherited and open?"))?;
    read_capped(file, &origin)
}

fn prompt() -> Result<Vec<u8>> {
    if !std::io::stdin().is_terminal() {
        bail!(
            "--password-prompt needs an interactive terminal; use --password-file or \
             --password-fd instead"
        );
    }
    let mut typed = Zeroizing::new(
        rpassword::prompt_password("Password: ")
            .context("failed to read the password from the terminal")?,
    );
    Ok(std::mem::take(&mut *typed).into_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::assert_matches;
    use std::io::Write as _;

    use super::*;

    fn password_file(content: &[u8], mode: u32) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        file
    }

    fn read_from(source: &PasswordSource) -> Result<Arc<Password>> {
        Ok(read(Some(source))?.unwrap())
    }

    #[test]
    fn no_source_means_no_password() {
        assert_matches!(read(None), Ok(None));
    }

    #[test]
    fn first_line_drops_the_newline_and_the_rest() {
        for (input, expected) in [
            (&b"secret\n"[..], &b"secret"[..]),
            (b"secret\r\n", b"secret"),
            (b"secret", b"secret"),
            (b"secret\nsecond line\n", b"secret"),
            (b"two words\n", b"two words"),
        ] {
            let mut bytes = input.to_vec();
            first_line(&mut bytes);
            assert_eq!(bytes, expected);
        }
    }

    #[test]
    fn a_file_with_a_trailing_newline_gives_the_password() {
        let file = password_file(b"correct-horse\n", 0o600);

        let password = read_from(&PasswordSource::File(file.path().to_path_buf())).unwrap();

        assert_eq!(password.byte_len(), "correct-horse".len());
    }

    #[test]
    fn an_empty_first_line_is_refused() {
        let file = password_file(b"\nsecret\n", 0o600);

        let error = read_from(&PasswordSource::File(file.path().to_path_buf())).unwrap_err();

        assert!(format!("{error:#}").contains("must not be empty"));
    }

    #[test]
    fn a_file_over_one_kib_is_refused_without_quoting_it() {
        let file = password_file(&vec![b'x'; MAX_SOURCE_BYTES + 1], 0o600);

        let error = read_from(&PasswordSource::File(file.path().to_path_buf())).unwrap_err();

        let text = format!("{error:#}");
        assert!(text.contains("more than 1024 bytes"));
        assert!(!text.contains("xxxx"));
    }

    #[test]
    fn a_missing_file_and_a_directory_are_refused() {
        let dir = tempfile::tempdir().unwrap();

        assert!(read_from(&PasswordSource::File(dir.path().join("absent"))).is_err());
        let error = read_from(&PasswordSource::File(dir.path().to_path_buf())).unwrap_err();
        assert!(format!("{error:#}").contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn a_group_or_world_readable_file_is_refused() {
        for mode in [0o640, 0o604, 0o644] {
            let file = password_file(b"secret\n", mode);

            let error = read_from(&PasswordSource::File(file.path().to_path_buf())).unwrap_err();

            assert!(format!("{error:#}").contains("chmod 600"), "{mode:o}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_descriptor_gives_the_password() {
        use std::os::fd::AsRawFd as _;

        let file = password_file(b"from-a-descriptor\n", 0o600);
        let open = File::open(file.path()).unwrap();

        let password = read_from(&PasswordSource::Fd(open.as_raw_fd())).unwrap();

        assert_eq!(password.byte_len(), "from-a-descriptor".len());
    }

    #[cfg(unix)]
    #[test]
    fn a_descriptor_that_is_not_open_is_refused() {
        let error = read_from(&PasswordSource::Fd(9999)).unwrap_err();

        assert!(format!("{error:#}").contains("file descriptor 9999"));
    }
}
