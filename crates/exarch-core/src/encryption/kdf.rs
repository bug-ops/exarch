//! Key derivation of 7z AES blocks.
//!
//! A 7z AES key is `2^power` SHA-256 rounds over (salt, password, counter).
//! sevenz-rust2 derives it itself and keeps the last result in one
//! process-wide slot, which makes operations of one process evict each other's
//! keys. exarch derives the key of an operation here instead, keeps it only for
//! that operation, and hands it to sevenz-rust2 in its raw-key mode (see
//! `formats::sevenz::raw_key`), so the library's slot is never used.
//!
//! [`KdfRuns`] charges against `max_kdf_work` at admission, before any block
//! is decoded: it walks the AES blocks in archive order and charges `2^power`
//! for each change of pair (power, salt). An operation derives each distinct
//! pair at most once, so what it derives never exceeds that charge.
//!
//! Not covered: other users of sevenz-rust2 in the same process, and the
//! `Read`/`Seek` calls of the archive source.

use std::io;
use std::num::NonZeroU64;

use sha2::Digest;
use sha2::Sha256;

use super::Credentials;
use super::UnusablePassword;
use crate::ArchiveError;
use crate::EncryptionRefusal;
use crate::Malformation;
use crate::formats::io_marker::IoMarker;

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

/// What the AES coder properties of a 7z block declare as its key: the pair
/// (power, salt).
///
/// The salt is at most 16 bytes (one flag bit plus a four-bit size), kept
/// zero-padded so equal parameters compare equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct AesParams {
    power: u8,
    salt_len: u8,
    salt: [u8; 16],
}

/// A parsed 7z AES coder: its key parameters and its initialisation vector.
///
/// The IV is not part of the key, so it is not part of [`AesParams`] equality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AesCoder {
    pub(crate) params: AesParams,
    pub(crate) iv: [u8; 16],
}

impl AesCoder {
    /// Parses the coder properties the way sevenz-rust2 does: a lone byte is
    /// padded with a zero size byte, the salt follows the two size bytes and
    /// the IV follows the salt, zero-padded to 16 bytes.
    pub(crate) fn parse(properties: &[u8]) -> Option<Self> {
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
        let iv_bytes = properties.get(tail_end..tail_end.checked_add(iv_size)?)?;
        let mut salt = [0u8; 16];
        salt.get_mut(..tail.len())?.copy_from_slice(tail);
        let mut iv = [0u8; 16];
        iv.get_mut(..iv_bytes.len())?.copy_from_slice(iv_bytes);
        Some(Self {
            params: AesParams {
                power: b0 & 0x3F,
                salt_len: u8::try_from(tail.len()).ok()?,
                salt,
            },
            iv,
        })
    }
}

impl AesParams {
    /// Parses the key parameters of the coder `properties`; see
    /// [`AesCoder::parse`].
    pub(crate) fn parse(properties: &[u8]) -> Option<Self> {
        AesCoder::parse(properties).map(|coder| coder.params)
    }

    /// The salt bytes.
    fn salt(&self) -> &[u8] {
        self.salt
            .get(..usize::from(self.salt_len))
            .unwrap_or_default()
    }

    /// The number of salt bytes.
    pub(crate) const fn salt_len(&self) -> usize {
        self.salt_len as usize
    }

    /// These parameters as ones a key can be derived for.
    ///
    /// # Errors
    ///
    /// `WeakEncryptionRefused` for raw-key mode and `KdfCostExceeded` for a
    /// power above [`MAX_POWER`]; the power is checked before `2^power` is
    /// ever computed.
    pub(crate) fn derivable(self) -> Result<DerivableParams, KeyRefusal> {
        if KeyMode::of_power(self.power) == KeyMode::RawKey {
            return Err(KeyRefusal::Refused(
                EncryptionRefusal::WeakEncryptionRefused,
            ));
        }
        if self.power > MAX_POWER {
            return Err(KeyRefusal::Refused(EncryptionRefusal::KdfCostExceeded));
        }
        Ok(DerivableParams(self))
    }
}

/// Key parameters whose derivation is allowed: derived mode, power at most
/// [`MAX_POWER`]. Only [`AesParams::derivable`] makes one, so a derivation
/// cannot be requested for an unadmitted power.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DerivableParams(AesParams);

impl DerivableParams {
    /// The parameters.
    pub(crate) const fn params(&self) -> &AesParams {
        &self.0
    }

    /// The work of deriving a key for these parameters, in hash rounds.
    pub(crate) const fn rounds(&self) -> u64 {
        1u64 << self.0.power
    }
}

/// The password of an operation as 7z derives keys from it (UTF-16LE).
///
/// Opaque: there is no accessor and no `Clone`, and `Debug` prints nothing, so
/// the only code that reads the bytes is [`SevenZKey::derive`]. No password
/// built from user input reaches sevenz-rust2.
pub(crate) struct SevenZSecret(sevenz_rust2::Password);

impl SevenZSecret {
    /// Wraps `password`, the UTF-16LE form of the user's text.
    #[cfg(feature = "encryption")]
    pub(super) const fn new(password: sevenz_rust2::Password) -> Self {
        Self(password)
    }
}

impl std::fmt::Debug for SevenZSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SevenZSecret(..)")
    }
}

/// One derived 7z AES key, kept for one operation.
///
/// No `Clone`, and `Debug` prints nothing. These 32 bytes are overwritten on
/// drop when the `encryption` feature is on; the raw `sevenz_rust2::Password`
/// copies made from a key for decoding are not (the library type cannot be
/// zeroized).
pub(crate) struct SevenZKey([u8; 32]);

#[cfg(test)]
thread_local! {
    /// Derivations the current thread has run, for tests.
    pub(crate) static DERIVATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl SevenZKey {
    /// Derives the key of `params` from `secret`: `2^power` SHA-256 rounds over
    /// salt, password and a little-endian round counter, exactly as
    /// sevenz-rust2's own derivation does, and touching no global state.
    pub(crate) fn derive(params: DerivableParams, secret: &SevenZSecret) -> Self {
        #[cfg(test)]
        DERIVATIONS.with(|runs| runs.set(runs.get() + 1));
        let mut sha = Sha256::default();
        let mut counter = [0u8; 8];
        for _ in 0..params.rounds() {
            sha.update(params.params().salt());
            sha.update(secret.0.as_slice());
            sha.update(counter);
            for byte in &mut counter {
                *byte = byte.wrapping_add(1);
                if *byte != 0 {
                    break;
                }
            }
        }
        Self(sha.finalize().into())
    }

    /// The 32 key bytes.
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SevenZKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SevenZKey(..)")
    }
}

#[cfg(feature = "encryption")]
impl Drop for SevenZKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
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
    /// An AES coder of a block whose build order is not known, charged at its
    /// full cost whatever the slot held.
    Uncached(&'a [u8]),
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

/// Marker carried in an [`io::Error`] when repeated key derivation would take
/// an operation over its `max_kdf_work`; recovered by
/// `budget_violation`.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("key derivation would exceed the max_kdf_work budget of this operation")]
pub(crate) struct KdfRepeatExceeded;

impl IoMarker for KdfRepeatExceeded {
    const KIND: io::ErrorKind = io::ErrorKind::Other;
}

impl From<KdfRepeatExceeded> for ArchiveError {
    fn from(_: KdfRepeatExceeded) -> Self {
        crate::Violation::Encrypted {
            reason: EncryptionRefusal::KdfCostExceeded,
            name: None,
        }
        .into()
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
    /// Returns the password as 7z derives keys from it.
    ///
    /// # Errors
    ///
    /// The first [`KeyRefusal`] in that order.
    pub(crate) fn admit_key(
        &mut self,
        credentials: &Credentials,
        source: KeySource<'_>,
    ) -> Result<SevenZSecret, KeyRefusal> {
        let secret = credentials
            .sevenz_secret()
            .map_err(KeyRefusal::Unusable)?
            .ok_or(KeyRefusal::PasswordRequired)?;
        self.admit_source(source).map(|()| secret)
    }

    /// Charges `source` without looking at the password: the part of
    /// [`admit_key`](Self::admit_key) that is accounting.
    ///
    /// # Errors
    ///
    /// The refusals of [`admit`](Self::admit), and `WeakEncryptionRefused` for
    /// a raw-key header.
    pub(crate) fn admit_source(&mut self, source: KeySource<'_>) -> Result<(), KeyRefusal> {
        match source {
            KeySource::Block(properties) => self.admit(properties),
            KeySource::Uncached(properties) => self.admit_uncached(properties),
            KeySource::Header(KeyMode::RawKey) => Err(KeyRefusal::Refused(
                EncryptionRefusal::WeakEncryptionRefused,
            )),
            KeySource::Header(KeyMode::Derived) => self.within_budget(),
        }
    }

    /// Rounds charged so far.
    #[cfg(test)]
    pub(crate) const fn spent(&self) -> u64 {
        self.spent
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
        self.admit_coder(properties, true)
    }

    /// Like [`admit`](Self::admit), but charges the coder in full and forgets
    /// what the previous block left cached.
    ///
    /// For a block whose coders are built in an order exarch cannot see (a
    /// multi-input coder): each coder derives at most once, so the sum over
    /// its AES coders bounds the derivations whatever the order.
    ///
    /// # Errors
    ///
    /// The refusals of [`admit`](Self::admit).
    pub(crate) fn admit_uncached(&mut self, properties: &[u8]) -> Result<(), KeyRefusal> {
        self.admit_coder(properties, false)
    }

    fn admit_coder(&mut self, properties: &[u8], reuse_cached: bool) -> Result<(), KeyRefusal> {
        let params = AesParams::parse(properties).ok_or(KeyRefusal::Malformed)?;
        let derivable = params.derivable()?;
        if !reuse_cached || self.last.as_ref() != Some(&params) {
            self.spent = self.spent.saturating_add(derivable.rounds());
        }
        self.last = reuse_cached.then_some(params);
        self.within_budget()
    }
}

#[cfg(test)]
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
    fn the_coder_properties_split_into_salt_and_zero_padded_iv() {
        let mut bytes = vec![0x80 | 0x40 | 0x13, 0x10 | 0x03];
        bytes.extend_from_slice(&[1, 2]);
        bytes.extend_from_slice(&[9, 8, 7, 6]);
        let coder = AesCoder::parse(&bytes).unwrap();
        assert_eq!(coder.params.power, 19);
        assert_eq!(coder.params.salt(), [1, 2]);
        assert_eq!(coder.params.salt_len(), 2);
        let mut iv = [0u8; 16];
        iv[..4].copy_from_slice(&[9, 8, 7, 6]);
        assert_eq!(coder.iv, iv);
    }

    #[test]
    fn the_iv_is_not_part_of_the_key_parameters() {
        let with_iv = |fill: u8| {
            let mut bytes = vec![0x40 | 0x13, 0x0F];
            bytes.extend_from_slice(&[fill; 16]);
            AesCoder::parse(&bytes).unwrap()
        };
        assert_ne!(with_iv(1).iv, with_iv(2).iv);
        assert_eq!(with_iv(1).params, with_iv(2).params);
    }

    #[test]
    fn only_a_derived_power_within_the_cap_is_derivable() {
        let derivable = |power: u8| AesParams::parse(&[power, 0]).unwrap().derivable();
        assert_eq!(derivable(MAX_POWER).unwrap().rounds(), 1 << MAX_POWER);
        assert_eq!(derivable(0).unwrap().rounds(), 1);
        assert_eq!(
            derivable(RAW_KEY_POWER).unwrap_err(),
            KeyRefusal::Refused(EncryptionRefusal::WeakEncryptionRefused)
        );
        for power in round_after(MAX_POWER)..RAW_KEY_POWER {
            assert_eq!(
                derivable(power).unwrap_err(),
                KeyRefusal::Refused(EncryptionRefusal::KdfCostExceeded)
            );
        }
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn a_key_is_the_sha256_rounds_of_salt_password_and_counter() {
        let secret = SevenZSecret::new(sevenz_rust2::Password::new("pw"));
        let params = AesParams::parse(&props(2, &[5, 6]))
            .unwrap()
            .derivable()
            .unwrap();
        let mut sha = Sha256::default();
        for round in 0u64..4 {
            sha.update([5, 6]);
            sha.update(sevenz_rust2::Password::new("pw").as_slice());
            sha.update(round.to_le_bytes());
        }
        let expected: [u8; 32] = sha.finalize().into();

        let key = SevenZKey::derive(params, &secret);

        assert_eq!(key.as_bytes(), &expected);
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn secrets_and_keys_print_nothing() {
        let secret = SevenZSecret::new(sevenz_rust2::Password::new("hunter2"));
        let params = AesParams::parse(&[1, 0]).unwrap().derivable().unwrap();
        let key = SevenZKey::derive(params, &secret);
        assert_eq!(format!("{secret:?}"), "SevenZSecret(..)");
        assert_eq!(format!("{key:?}"), "SevenZKey(..)");
    }

    #[test]
    fn an_uncached_admission_charges_every_coder_and_forgets_the_pair() {
        let mut runs = KdfRuns::new(budget(3 << 19), false);
        let block = [19, 0];
        for _ in 0..3 {
            assert_eq!(runs.admit_uncached(&block), Ok(()));
        }
        assert_eq!(runs.spent(), 3 << 19);
        assert_eq!(
            runs.admit_uncached(&block),
            Err(KeyRefusal::Refused(EncryptionRefusal::KdfCostExceeded))
        );
        let mut runs = KdfRuns::new(budget(u64::MAX), false);
        assert_eq!(runs.admit_uncached(&block), Ok(()));
        assert_eq!(runs.admit(&block), Ok(()));
        assert_eq!(runs.spent(), 2 << 19);
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
