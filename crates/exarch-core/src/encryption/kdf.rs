//! Key-derivation cost of 7z AES blocks, charged before any block is decoded.
//!
//! sevenz-rust2 derives a block key with `2^power` SHA-256 rounds and keeps
//! only the last derived key, so a derivation costs only when the pair
//! (power, salt) differs from the previous block's. [`KdfRuns`] mirrors that:
//! it walks the AES blocks in archive order and charges `2^power` for each
//! change of pair.

use std::num::NonZeroU64;

use super::Credentials;
use super::UnusablePassword;
use crate::ArchiveError;
use crate::EncryptionRefusal;
use crate::Malformation;

/// The largest `NumCyclesPower` sevenz-rust2 derives a key for.
pub(crate) const MAX_POWER: u8 = 24;

/// The `NumCyclesPower` that selects raw-key mode: no derivation at all.
const RAW_KEY_POWER: u8 = 0x3F;

/// Work reserved for the key of an encrypted header, which is derived inside
/// `Archive::read` before any coder is visible.
pub(crate) const HEADER_RESERVE: u64 = 1 << MAX_POWER;

/// How a 7z AES coder derives its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyMode {
    /// The key is derived from the password by hashing rounds.
    Derived,
    /// The key is the password itself, with no derivation.
    RawKey,
}

impl KeyMode {
    const fn of_power(power: u8) -> Self {
        if power == RAW_KEY_POWER {
            Self::RawKey
        } else {
            Self::Derived
        }
    }
}

/// The key mode the AES coder `properties` declare, or `None` when they do not
/// parse.
pub(crate) fn key_mode(properties: &[u8]) -> Option<KeyMode> {
    AesParams::parse(properties).map(|params| KeyMode::of_power(params.power))
}

/// What the AES coder properties of a 7z block declare.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AesParams {
    power: u8,
    params_tail: Vec<u8>,
}

impl AesParams {
    /// Parses the coder properties the way sevenz-rust2 does: a lone byte is
    /// padded with a zero size byte, the salt follows the two size bytes.
    fn parse(properties: &[u8]) -> Option<Self> {
        let padded;
        let properties = match properties {
            [] => return None,
            [b0] => {
                padded = [*b0, 0];
                &padded[..]
            }
            full => full,
        };
        let (&b0, &b1) = (properties.first()?, properties.get(1)?);
        let iv_size = usize::from((b0 >> 6) & 1).saturating_add(usize::from(b1 & 15));
        let tail_len = usize::from((b0 >> 7) & 1).saturating_add(usize::from(b1 >> 4));
        let tail_end = 2usize.checked_add(tail_len)?;
        let tail = properties.get(2..tail_end)?;
        if properties.len() < tail_end.checked_add(iv_size)? {
            return None;
        }
        Some(Self {
            power: b0 & 0x3F,
            params_tail: tail.to_vec(),
        })
    }
}

/// The key a 7z AES admission is for.
#[derive(Debug, Clone, Copy)]
pub(crate) enum KeySource<'a> {
    /// The encrypted header, whose own properties are not visible: the mode
    /// the probe read, and the derivation reserved at its worst case.
    Header(KeyMode),
    /// A block's AES coder, with its properties.
    Block(&'a [u8]),
}

/// Why a 7z AES key cannot be admitted, in the order it is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyRefusal {
    /// No password was supplied.
    PasswordRequired,
    /// The password is not UTF-8 text.
    Unusable(UnusablePassword),
    /// The coder properties cannot be parsed.
    Malformed,
    /// Raw-key mode, or a derivation over the budget.
    Refused(EncryptionRefusal),
}

impl From<KeyRefusal> for ArchiveError {
    fn from(refusal: KeyRefusal) -> Self {
        match refusal {
            KeyRefusal::PasswordRequired => crate::formats::common::encrypted_archive_error(),
            KeyRefusal::Unusable(unusable) => unusable.into(),
            KeyRefusal::Malformed => Malformation::SevenZUnsupportedCoder.into(),
            KeyRefusal::Refused(reason) => {
                crate::Violation::Encrypted { reason, name: None }.into()
            }
        }
    }
}

/// The derivation runs of one operation against its `max_kdf_work` budget.
#[derive(Debug)]
pub(crate) struct KdfRuns {
    budget: u64,
    spent: u64,
    last: Option<AesParams>,
}

impl KdfRuns {
    /// A fresh account under `budget`, with the header's reservation charged
    /// when the header is encrypted.
    pub(crate) const fn new(budget: NonZeroU64, header_encrypted: bool) -> Self {
        Self {
            budget: budget.get(),
            spent: if header_encrypted { HEADER_RESERVE } else { 0 },
            last: None,
        }
    }

    /// Admits one 7z AES key, the single place the refusal order lives: no
    /// password, a password that is not UTF-8, raw-key mode, then the budget.
    ///
    /// Returns the password as 7z uses it.
    ///
    /// # Errors
    ///
    /// The first [`KeyRefusal`] in that order.
    pub(crate) fn admit_key(
        &mut self,
        credentials: &Credentials,
        source: KeySource<'_>,
    ) -> Result<sevenz_rust2::Password, KeyRefusal> {
        let password = credentials
            .sevenz_secret()
            .map_err(KeyRefusal::Unusable)?
            .ok_or(KeyRefusal::PasswordRequired)?;
        let admitted = match source {
            KeySource::Block(properties) => self.admit(properties),
            KeySource::Header(KeyMode::RawKey) => Err(KeyRefusal::Refused(
                EncryptionRefusal::WeakEncryptionRefused,
            )),
            KeySource::Header(KeyMode::Derived) => self.within_budget(),
        };
        admitted.map(|()| password)
    }

    fn within_budget(&self) -> Result<(), KeyRefusal> {
        if self.spent > self.budget {
            return Err(KeyRefusal::Refused(EncryptionRefusal::KdfCostExceeded));
        }
        Ok(())
    }

    /// Charges the block whose AES coder has `properties`.
    ///
    /// A power above [`MAX_POWER`] is refused before `2^power` is computed, and
    /// the sum saturates.
    ///
    /// # Errors
    ///
    /// [`KeyRefusal::Malformed`] for properties that do not parse,
    /// `WeakEncryptionRefused` for raw-key mode and `KdfCostExceeded` for a
    /// power above the cap or a total above the budget.
    pub(crate) fn admit(&mut self, properties: &[u8]) -> Result<(), KeyRefusal> {
        let params = AesParams::parse(properties).ok_or(KeyRefusal::Malformed)?;
        if KeyMode::of_power(params.power) == KeyMode::RawKey {
            return Err(KeyRefusal::Refused(
                EncryptionRefusal::WeakEncryptionRefused,
            ));
        }
        if params.power > MAX_POWER {
            return Err(KeyRefusal::Refused(EncryptionRefusal::KdfCostExceeded));
        }
        if self.last.as_ref() != Some(&params) {
            self.spent = self.spent.saturating_add(1u64 << params.power);
            self.last = Some(params);
        }
        self.within_budget()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn props(power: u8, tail: &[u8]) -> Vec<u8> {
        let tail_len = u8::try_from(tail.len()).unwrap();
        let mut bytes = vec![power | if tail.is_empty() { 0 } else { 0x80 }, 0];
        bytes[1] = (tail_len.saturating_sub(1)) << 4;
        bytes.extend_from_slice(tail);
        bytes
    }

    fn round_after(last: u8) -> u8 {
        last.checked_add(1).unwrap()
    }

    fn budget(rounds: u64) -> NonZeroU64 {
        NonZeroU64::new(rounds).unwrap()
    }

    #[test]
    fn a_repeated_pair_is_charged_once() {
        let mut runs = KdfRuns::new(budget(1 << 19), false);
        let block = [19, 0];
        for _ in 0..1000 {
            assert_eq!(runs.admit(&block), Ok(()));
        }
    }

    #[test]
    fn a_changing_tail_is_charged_per_change() {
        let mut runs = KdfRuns::new(budget(3 << 19), false);
        for round in 1u8..=3 {
            assert_eq!(runs.admit(&props(19, &[round])), Ok(()));
        }
        assert_eq!(
            runs.admit(&props(19, &[round_after(3)])),
            Err(KeyRefusal::Refused(EncryptionRefusal::KdfCostExceeded))
        );
    }

    #[test]
    fn the_header_reservation_counts_against_the_budget() {
        let mut runs = KdfRuns::new(budget(HEADER_RESERVE), true);
        assert_eq!(
            runs.admit(&[19, 0]),
            Err(KeyRefusal::Refused(EncryptionRefusal::KdfCostExceeded))
        );
    }

    #[test]
    fn raw_key_mode_is_weak_and_high_powers_exceed_the_cost() {
        let mut runs = KdfRuns::new(budget(u64::MAX), false);
        assert_eq!(
            runs.admit(&[0x3F, 0]),
            Err(KeyRefusal::Refused(
                EncryptionRefusal::WeakEncryptionRefused
            ))
        );
        for power in 25..=0x3E {
            assert_eq!(
                runs.admit(&[power, 0]),
                Err(KeyRefusal::Refused(EncryptionRefusal::KdfCostExceeded))
            );
        }
    }

    #[test]
    fn key_mode_tells_raw_keys_from_derived_ones() {
        assert_eq!(key_mode(&[0x3F, 0]), Some(KeyMode::RawKey));
        assert_eq!(key_mode(&[19, 0]), Some(KeyMode::Derived));
        assert_eq!(key_mode(&[0x80, 0x30]), None);
    }

    #[test]
    fn unparseable_properties_are_malformed() {
        let mut runs = KdfRuns::new(budget(u64::MAX), false);
        assert_eq!(runs.admit(&[]), Err(KeyRefusal::Malformed));
        assert_eq!(runs.admit(&[0x80, 0x30]), Err(KeyRefusal::Malformed));
    }
}
