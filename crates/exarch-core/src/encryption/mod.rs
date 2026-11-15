//! Password-based decryption of `WinZip` AES ZIP entries and 7z AES archives.
//!
//! The secret lives in a [`Password`], handed to a request per operation and
//! never stored in [`SecurityConfig`](crate::SecurityConfig), which is `Clone`
//! and `Debug`. Inside the crate the secret travels as [`Credentials`], which
//! exists with and without the `encryption` feature so the handlers need no
//! feature gates of their own: without the feature no password can be
//! supplied and every encrypted entry is refused as password-required.

pub(crate) mod kdf;
#[cfg(feature = "encryption")]
mod password;

use std::fmt;
#[cfg(feature = "encryption")]
use std::sync::Arc;

#[cfg(feature = "encryption")]
pub use password::Password;
#[cfg(feature = "encryption")]
pub use password::PasswordError;

/// The password of one operation as the format handlers see it.
///
/// Cheap to clone (it shares the [`Password`]) and never printed.
#[derive(Clone, Default)]
pub(crate) struct Credentials {
    #[cfg(feature = "encryption")]
    password: Option<Arc<Password>>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials(..)")
    }
}

impl Credentials {
    /// No password.
    pub(crate) const NONE: Self = Self {
        #[cfg(feature = "encryption")]
        password: None,
    };

    /// Credentials holding `password`, or none.
    #[cfg(feature = "encryption")]
    pub(crate) const fn new(password: Option<Arc<Password>>) -> Self {
        Self { password }
    }

    /// Whether a password was supplied.
    pub(crate) const fn is_supplied(&self) -> bool {
        #[cfg(feature = "encryption")]
        {
            self.password.is_some()
        }
        #[cfg(not(feature = "encryption"))]
        {
            false
        }
    }

    /// The password bytes as ZIP uses them: as given.
    pub(crate) fn zip_secret(&self) -> Option<&[u8]> {
        #[cfg(feature = "encryption")]
        {
            self.password.as_deref().map(Password::expose)
        }
        #[cfg(not(feature = "encryption"))]
        {
            None
        }
    }

    /// The password as 7z uses it: the UTF-16LE form of its text, or `None`
    /// when no password was supplied.
    ///
    /// # Errors
    ///
    /// [`UnusablePassword`] when the bytes are not valid UTF-8, so no 7z
    /// archive can have been encrypted with them.
    pub(crate) fn sevenz_secret(&self) -> Result<Option<sevenz_rust2::Password>, UnusablePassword> {
        #[cfg(feature = "encryption")]
        {
            let Some(password) = self.password.as_deref() else {
                return Ok(None);
            };
            let text = std::str::from_utf8(password.expose()).map_err(|_| UnusablePassword)?;
            Ok(Some(sevenz_rust2::Password::new(text)))
        }
        #[cfg(not(feature = "encryption"))]
        {
            Ok(None)
        }
    }
}

/// A password that cannot match any 7z archive because it is not UTF-8 text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UnusablePassword;
