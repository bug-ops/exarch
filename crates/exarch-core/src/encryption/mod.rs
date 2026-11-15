//! Password-based decryption of `WinZip` AES ZIP entries and 7z AES archives.
//!
//! The secret lives in a [`Password`], handed to a request per operation and
//! never stored in [`SecurityConfig`](crate::SecurityConfig), which is `Clone`
//! and `Debug`.

use std::fmt;

use thiserror::Error;
use zeroize::Zeroizing;

/// A secret that decrypts archive content.
///
/// The bytes sit in a buffer that is overwritten on drop. `Debug` prints
/// `Password(..)`, there is no `Display` and no `Clone`; share one with
/// [`Arc`](std::sync::Arc).
///
/// ZIP uses the bytes as given. 7z uses the UTF-16LE form of the text, so a 7z
/// password must be valid UTF-8.
///
/// # Examples
///
/// ```
/// use exarch_core::Password;
///
/// let password = Password::new(b"correct-horse".to_vec())?;
/// assert_eq!(format!("{password:?}"), "Password(..)");
/// assert!(Password::new(Vec::new()).is_err());
/// # Ok::<(), exarch_core::PasswordError>(())
/// ```
#[cfg_attr(docsrs, doc(cfg(feature = "encryption")))]
pub struct Password(Zeroizing<Vec<u8>>);

impl Password {
    /// The most bytes a password may hold.
    pub const MAX_LEN: usize = 1024;

    /// Wraps `bytes` as a password.
    ///
    /// # Errors
    ///
    /// [`PasswordError::Empty`] for no bytes and [`PasswordError::TooLong`] for
    /// more than [`MAX_LEN`](Self::MAX_LEN).
    pub fn new(bytes: Vec<u8>) -> Result<Self, PasswordError> {
        let secret = Zeroizing::new(bytes);
        match secret.len() {
            0 => Err(PasswordError::Empty),
            len if len > Self::MAX_LEN => Err(PasswordError::TooLong { len }),
            _ => Ok(Self(secret)),
        }
    }

    /// The number of bytes in the password.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(..)")
    }
}

/// Why a [`Password`] could not be built.
///
/// # Examples
///
/// ```
/// use exarch_core::Password;
/// use exarch_core::PasswordError;
///
/// let error = Password::new(vec![b'a'; Password::MAX_LEN + 1]).unwrap_err();
/// assert_eq!(
///     error,
///     PasswordError::TooLong {
///         len: Password::MAX_LEN + 1
///     }
/// );
/// ```
#[cfg_attr(docsrs, doc(cfg(feature = "encryption")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PasswordError {
    /// The password has no bytes.
    #[error("a password must not be empty")]
    Empty,
    /// The password is longer than [`Password::MAX_LEN`].
    #[error("a password must not exceed {} bytes (got {len})", Password::MAX_LEN)]
    TooLong {
        /// The length that was refused.
        len: usize,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn length_bounds_are_one_to_max() {
        assert_eq!(Password::new(Vec::new()).unwrap_err(), PasswordError::Empty);
        assert!(Password::new(vec![0; 1]).is_ok());
        assert!(Password::new(vec![0; Password::MAX_LEN]).is_ok());
        assert_eq!(
            Password::new(vec![0; Password::MAX_LEN + 1]).unwrap_err(),
            PasswordError::TooLong {
                len: Password::MAX_LEN + 1
            }
        );
    }

    #[test]
    fn debug_hides_the_secret() {
        let password = Password::new(b"hunter2".to_vec()).unwrap();
        assert_eq!(format!("{password:?}"), "Password(..)");
        assert_eq!(password.byte_len(), 7);
    }
}
