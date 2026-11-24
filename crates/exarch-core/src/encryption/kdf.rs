//! Key-derivation cost of 7z AES blocks.
//!
//! sevenz-rust2 derives a block key with `2^power` SHA-256 rounds and keeps
//! only the last derived key in one process-wide slot, so a derivation costs
//! only when the pair (power, salt) differs from the previous derivation's.
//!
//! [`KdfRuns`] charges against `max_kdf_work` at admission, before any block
//! is decoded: it walks the AES blocks in archive order and charges `2^power`
//! for each change of pair, which is the work an operation that nobody
//! interrupts performs.
//!
//! Other operations of the process share the slot. Two things keep the charge
//! at or above the derivations performed:
//!
//! - An [`AesTurn`] is held while an AES block sets up its decoder (where the
//!   key is derived) and while an encrypted header is parsed from bytes read
//!   beforehand, never while entry callbacks, progress hooks or sinks run and
//!   never between blocks.
//! - Under the turn the process records a keyed digest of the (power, salt,
//!   password) of the key the slot holds, the same identity the library caches
//!   by; nothing secret is stored. A [`SlotWatch`] charges `2^power` again for
//!   a block whose key admission expected to find cached but the slot does not
//!   hold (another operation, or one nested in a callback, used a different
//!   key, or an encrypted header whose key is not modelled was read), and the
//!   operation is refused with `KdfCostExceeded` once admitted plus repeated
//!   work exceeds the budget. Operations that use the same key cost each other
//!   nothing.
//!
//! Guaranteed: charge >= derivations performed by exarch operations, so the
//! work of one operation stays within `max_kdf_work` plus at most one
//! derivation per concurrent set-up. Consequence: operations with different
//! keys running at the same time can make each other fail mid-operation with
//! `KdfCostExceeded`. Not covered: other users of sevenz-rust2 in the same
//! process, and the `Read`/`Seek` calls of the archive source. An encrypted
//! header is read from the source before the turn is taken, and a block whose
//! AES coder is the first one the decoder builds gives the turn up before the
//! decoder first calls the source. For other block layouts the source's calls
//! run under the turn during the set-up and must not wait on another
//! encrypted 7z operation. The turn is not fair: under
//! sustained load a waiter can be overtaken.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::io;
use std::marker::PhantomData;
use std::num::NonZeroU64;
use std::sync::Condvar;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::thread;
use std::thread::ThreadId;

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

/// What the AES coder properties of a 7z block declare.
///
/// The salt is at most 16 bytes (one flag bit plus a four-bit size), kept
/// zero-padded so equal parameters compare equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AesParams {
    power: u8,
    salt_len: u8,
    salt: [u8; 16],
}

impl AesParams {
    /// Parses the coder properties the way sevenz-rust2 does: a lone byte is
    /// padded with a zero size byte, the salt follows the two size bytes.
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
        if properties.len() < tail_end.checked_add(iv_size)? {
            return None;
        }
        let mut salt = [0u8; 16];
        salt.get_mut(..tail.len())?.copy_from_slice(tail);
        Some(Self {
            power: b0 & 0x3F,
            salt_len: u8::try_from(tail.len()).ok()?,
            salt,
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

/// Locks `mutex`, taking the data of a poisoned one: every guarded value here
/// is a plain record that a panicking holder cannot leave half-written.
pub(crate) fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Who holds the turn and what the key slot holds, behind one lock so that the
/// fingerprint can only be read or changed through an [`AesTurn`].
struct Turn {
    holder: Option<ThreadId>,
    /// Fingerprint of the key the shared slot holds, or `None` when unknown.
    slot: Option<SlotKey>,
}

struct TurnState {
    state: Mutex<Turn>,
    released: Condvar,
}

static TURN: TurnState = TurnState {
    state: Mutex::new(Turn {
        holder: None,
        slot: None,
    }),
    released: Condvar::new(),
};

/// Keys the fingerprints, so one cannot be reversed or compared across
/// processes; the secret itself is never stored.
static FINGERPRINT_KEYS: LazyLock<RandomState> = LazyLock::new(RandomState::new);

/// A keyed digest of the (power, salt, password) a derived key came from,
/// which is what sevenz-rust2's own cache is keyed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SlotKey(u64);

impl SlotKey {
    fn of(params: &AesParams, password: &[u8]) -> Self {
        Self(
            FINGERPRINT_KEYS.hash_one((
                params.power,
                params
                    .salt
                    .get(..usize::from(params.salt_len))
                    .unwrap_or_default(),
                password,
            )),
        )
    }
}

/// Exclusive use of the key slot sevenz-rust2 shares across the process,
/// released on drop.
///
/// Held by one thread at a time. A thread that already holds the turn gets a
/// handle that holds nothing, so a nested use on that thread cannot deadlock.
/// Stays on the thread that took it.
///
/// The fingerprint of the key the slot holds is read and changed only through
/// `&mut AesTurn`, so code that does not hold the turn cannot change it.
#[derive(Debug)]
pub(crate) struct AesTurn {
    owned: bool,
    on_thread: PhantomData<*const ()>,
}

impl AesTurn {
    /// Waits until no other thread holds the turn, then takes it.
    pub(crate) fn acquire() -> Self {
        let me = thread::current().id();
        let mut state = lock_unpoisoned(&TURN.state);
        loop {
            match state.holder {
                None => {
                    state.holder = Some(me);
                    return Self::new(true);
                }
                Some(current) if current == me => return Self::new(false),
                Some(_) => {
                    state = TURN
                        .released
                        .wait(state)
                        .unwrap_or_else(PoisonError::into_inner);
                }
            }
        }
    }

    /// Whether the calling thread holds the turn.
    #[cfg(test)]
    pub(crate) fn held_by_current_thread() -> bool {
        lock_unpoisoned(&TURN.state).holder == Some(thread::current().id())
    }

    /// Marks the key slot unknown, for a block set-up that failed before the
    /// decoder was built.
    pub(crate) fn forget_slot_key(&mut self) {
        self.set_slot(None);
    }

    #[expect(
        clippy::unused_self,
        reason = "the receiver is the proof that the turn is held"
    )]
    fn slot(&self) -> Option<SlotKey> {
        lock_unpoisoned(&TURN.state).slot
    }

    #[expect(
        clippy::unused_self,
        clippy::needless_pass_by_ref_mut,
        reason = "the receiver is the proof that the turn is held"
    )]
    fn set_slot(&mut self, key: Option<SlotKey>) {
        lock_unpoisoned(&TURN.state).slot = key;
    }

    const fn new(owned: bool) -> Self {
        Self {
            owned,
            on_thread: PhantomData,
        }
    }
}

impl Drop for AesTurn {
    fn drop(&mut self) {
        if self.owned {
            lock_unpoisoned(&TURN.state).holder = None;
            TURN.released.notify_one();
        }
    }
}

/// Reads an encrypted 7z header under the turn and records the key the slot
/// holds afterwards: `header_key` (the parameters the probe read from the
/// header's single AES coder) with `password` when the read succeeded, else
/// unknown.
pub(crate) fn with_header_key<T, E>(
    header_key: Option<AesParams>,
    password: &[u8],
    read: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let mut turn = AesTurn::acquire();
    let value = read();
    let known = header_key
        .filter(|params| params.power <= MAX_POWER)
        .filter(|_| value.is_ok())
        .map(|params| SlotKey::of(&params, password));
    turn.set_slot(known);
    value
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

/// What one operation charges beyond admission when the shared key slot does
/// not hold the key admission expected to find there.
#[derive(Debug, Default)]
pub(crate) struct SlotWatch {
    last: Option<AesParams>,
    repeated: u64,
}

impl SlotWatch {
    /// Registers the set-up of a block whose AES coders have `coders`
    /// properties, in the order the decoder builds them, under `turn` before
    /// the decoder is built. Returns the work charged beyond admission for this
    /// block.
    ///
    /// Admission charged nothing for a coder whose pair equals the operation's
    /// previous one. If the slot holds another key (or an unknown one) the
    /// decoder derives it again, so its `2^power` is charged. A slot that holds
    /// the same key, also when another operation put it there, costs nothing.
    pub(crate) fn enter_block<'a>(
        &mut self,
        turn: &mut AesTurn,
        coders: impl IntoIterator<Item = &'a [u8]>,
        password: &[u8],
    ) -> u64 {
        let mut slot = turn.slot();
        let mut charged = 0u64;
        for properties in coders {
            let Some(params) = AesParams::parse(properties) else {
                continue;
            };
            if params.power > MAX_POWER {
                continue;
            }
            let key = SlotKey::of(&params, password);
            let derived = slot != Some(key);
            if derived && self.last.as_ref() == Some(&params) {
                charged = charged.saturating_add(1u64 << params.power);
            }
            slot = Some(key);
            self.last = Some(params);
        }
        turn.set_slot(slot);
        self.repeated = self.repeated.saturating_add(charged);
        charged
    }

    /// Registers the set-up of a block whose coders are built in an order not
    /// visible here. Admission charged every AES coder of it in full, which
    /// bounds the derivations, so nothing is charged now; the slot afterwards
    /// holds a key that is not known, and so does this operation's memory of
    /// its last pair.
    pub(crate) fn enter_unordered_block(&mut self, turn: &mut AesTurn) {
        turn.forget_slot_key();
        self.last = None;
    }

    /// Work charged so far beyond admission.
    pub(crate) const fn repeated(&self) -> u64 {
        self.repeated
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
        self.admit_source(source).map(|()| password)
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
        if KeyMode::of_power(params.power) == KeyMode::RawKey {
            return Err(KeyRefusal::Refused(
                EncryptionRefusal::WeakEncryptionRefused,
            ));
        }
        if params.power > MAX_POWER {
            return Err(KeyRefusal::Refused(EncryptionRefusal::KdfCostExceeded));
        }
        if !reuse_cached || self.last.as_ref() != Some(&params) {
            self.spent = self.spent.saturating_add(1u64 << params.power);
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

    fn input() -> Vec<u8> {
        std::process::id().to_le_bytes().to_vec()
    }

    fn other_input() -> Vec<u8> {
        input().into_iter().map(|byte| !byte).collect()
    }

    fn round_after(last: u8) -> u8 {
        last.checked_add(1).unwrap()
    }

    fn budget(rounds: u64) -> NonZeroU64 {
        NonZeroU64::new(rounds).unwrap()
    }

    #[test]
    fn the_turn_is_exclusive_across_threads() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::atomic::Ordering;

        let inside = AtomicUsize::new(0);
        let overlaps = AtomicUsize::new(0);
        thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..20 {
                        let _turn = AesTurn::acquire();
                        if inside.fetch_add(1, Ordering::SeqCst) != 0 {
                            overlaps.fetch_add(1, Ordering::SeqCst);
                        }
                        thread::yield_now();
                        inside.fetch_sub(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(overlaps.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_nested_turn_on_one_thread_does_not_deadlock_and_keeps_the_outer_one() {
        let outer = AesTurn::acquire();
        let inner = AesTurn::acquire();
        assert!(outer.owned);
        assert!(!inner.owned);
        drop(inner);
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = thread::spawn(move || {
            let _turn = AesTurn::acquire();
            tx.send(()).unwrap();
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(100))
                .is_err()
        );
        drop(outer);
        rx.recv().unwrap();
        waiter.join().unwrap();
    }

    #[test]
    fn a_slot_holding_another_key_charges_a_repeated_pair_again() {
        let mut turn = AesTurn::acquire();
        let same = [19u8, 0];
        let other_pair = [20u8, 0];
        let mut mine = SlotWatch::default();
        let mut other = SlotWatch::default();
        assert_eq!(mine.enter_block(&mut turn, [&same[..]], &input()), 0);
        other.enter_block(&mut turn, [&other_pair[..]], &input());
        assert_eq!(mine.enter_block(&mut turn, [&same[..]], &input()), 1 << 19);
        other.enter_block(&mut turn, [&other_pair[..]], &input());
        assert_eq!(mine.enter_block(&mut turn, [&other_pair[..]], &input()), 0);
        assert_eq!(mine.repeated(), 1 << 19);
    }

    #[test]
    fn a_slot_holding_the_same_key_costs_nothing_and_the_password_is_part_of_the_key() {
        let mut turn = AesTurn::acquire();
        let same = [19u8, 0];
        let mut mine = SlotWatch::default();
        let mut other = SlotWatch::default();
        assert_eq!(mine.enter_block(&mut turn, [&same[..]], &input()), 0);
        other.enter_block(&mut turn, [&same[..]], &input());
        assert_eq!(mine.enter_block(&mut turn, [&same[..]], &input()), 0);
        other.enter_block(&mut turn, [&same[..]], &other_input());
        assert_eq!(mine.enter_block(&mut turn, [&same[..]], &input()), 1 << 19);
    }

    #[test]
    fn a_header_read_leaves_its_own_key_in_the_slot_and_a_failed_one_leaves_none() {
        let mut turn = AesTurn::acquire();
        let props = [19u8, 0];
        let params = AesParams::parse(&props);
        let mut mine = SlotWatch::default();
        assert_eq!(mine.enter_block(&mut turn, [&props[..]], &input()), 0);
        with_header_key(params, &input(), || Ok::<(), ()>(())).unwrap();
        assert_eq!(mine.enter_block(&mut turn, [&props[..]], &input()), 0);
        with_header_key(params, &input(), || Err::<(), ()>(())).unwrap_err();
        assert_eq!(mine.enter_block(&mut turn, [&props[..]], &input()), 1 << 19);
        with_header_key(None, &input(), || Ok::<(), ()>(())).unwrap();
        assert_eq!(mine.enter_block(&mut turn, [&props[..]], &input()), 1 << 19);
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
    fn a_block_with_unordered_coders_leaves_the_slot_unknown() {
        let mut turn = AesTurn::acquire();
        let props = [19u8, 0];
        let mut probe = SlotWatch::default();
        assert_eq!(probe.enter_block(&mut turn, [&props[..]], &input()), 0);
        SlotWatch::default().enter_unordered_block(&mut turn);
        assert_eq!(
            probe.enter_block(&mut turn, [&props[..]], &input()),
            1 << 19
        );
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
