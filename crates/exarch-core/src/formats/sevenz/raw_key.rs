//! Hands exarch-derived keys to sevenz-rust2 in its raw-key mode.
//!
//! sevenz-rust2 derives an AES key from the password and keeps the last one in
//! a process-wide slot, so concurrent operations evict each other's keys. Its
//! raw-key mode (`NumCyclesPower == 0x3F`) takes the key straight from the
//! coder's salt bytes followed by the password and touches no shared state.
//! exarch derives each key itself ([`SevenZKey`]) and rewrites what the library
//! reads:
//!
//! - every AES coder of a data block becomes a raw-key *donor*: a coder whose
//!   properties are `[0x7F, 0x0F, iv]` (raw-key power, no salt, the original
//!   IV), with the full 32-byte key as the block's password;
//! - the encoded-header record of an archive with an encrypted header is
//!   patched in place (power bits, salt bytes, both checksums) so the header
//!   parses under `key[salt_len..]` as password.
//!
//! `sevenz_rust2::Coder` has no public constructor, so a donor is parsed out of
//! a tiny synthesized archive. Each donor is proven to be the same coder as the
//! original (id, stream counts, properties) before the key mode is swapped.

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use super::header::BlockIndex;
use super::header::PerBlock;
use super::header::SevenZHeader;
use super::header::is_aes_coder;
use super::header_probe::EncryptedHeader;
use crate::ArchiveError;
use crate::EncryptionRefusal;
use crate::Malformation;
use crate::encryption::kdf::AesCoder;
use crate::encryption::kdf::AesParams;
use crate::encryption::kdf::DerivableParams;
use crate::encryption::kdf::HEADER_RESERVE;
use crate::encryption::kdf::KdfRepeatExceeded;
use crate::encryption::kdf::KeyRefusal;
use crate::encryption::kdf::SevenZKey;
use crate::encryption::kdf::SevenZSecret;
use crate::formats::io_marker::IoMarker;
use crate::formats::le;
use sevenz_rust2::Archive;
use sevenz_rust2::Block;
use sevenz_rust2::Coder;
use sevenz_rust2::Password;

const AES_ID: [u8; 4] = [0x06, 0xF1, 0x07, 0x01];
const SIGNATURE_HEADER_LEN: usize = 32;
const PACK_LEN: u64 = 16;

const K_END: u8 = 0x00;
const K_HEADER: u8 = 0x01;
const K_MAIN_STREAMS_INFO: u8 = 0x04;
const K_FILES_INFO: u8 = 0x05;
const K_PACK_INFO: u8 = 0x06;
const K_UNPACK_INFO: u8 = 0x07;
const K_SUBSTREAMS_INFO: u8 = 0x08;
const K_SIZE: u8 = 0x09;
const K_FOLDER: u8 = 0x0B;
const K_CODERS_UNPACK_SIZE: u8 = 0x0C;
const K_NAME: u8 = 0x11;

/// Raw-key `NumCyclesPower` (`0x3F`) with the IV-size flag set, and a second
/// size byte that declares no salt and a 15 + 1 byte IV.
const RAW_KEY_PROPERTIES: [u8; 2] = [0x7F, 0x0F];

fn unsupported_coder() -> ArchiveError {
    Malformation::SevenZUnsupportedCoder.into()
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(bytes);
    crc.sum()
}

/// Appends `value` in the 7z variable-length number encoding.
fn put_number(out: &mut Vec<u8>, value: u64) {
    let bytes = value.to_le_bytes();
    let extra = (0..8u32)
        .find(|&extra| {
            value
                .checked_shr(extra.saturating_mul(7).saturating_add(7))
                .is_none_or(|rest| rest == 0)
        })
        .unwrap_or(8);
    let marker = 0xFF00u16.checked_shr(extra).unwrap_or(0).to_le_bytes()[0];
    let extra = usize::try_from(extra).unwrap_or(8);
    out.push(marker | bytes.get(extra).copied().unwrap_or(0));
    out.extend_from_slice(bytes.get(..extra).unwrap_or_default());
}

/// A plain-header 7z archive of one folder, made of the coder bytes in `coder`
/// (the coder count and the coder), with `pack_streams` pack streams.
fn synthesized_archive(coder: &[u8], pack_streams: u64) -> Vec<u8> {
    let mut header = vec![K_HEADER, K_MAIN_STREAMS_INFO, K_PACK_INFO, 0];
    put_number(&mut header, pack_streams);
    header.push(K_SIZE);
    for _ in 0..pack_streams {
        put_number(&mut header, PACK_LEN);
    }
    header.extend([K_END, K_UNPACK_INFO, K_FOLDER, 1, 0]);
    header.extend_from_slice(coder);
    header.push(K_CODERS_UNPACK_SIZE);
    put_number(&mut header, PACK_LEN);
    header.extend([K_END, K_SUBSTREAMS_INFO, K_END, K_END]);
    header.extend([K_FILES_INFO, 1, K_NAME, 5, 0, b'a', 0, 0, 0, K_END, K_END]);

    let packed = pack_streams.saturating_mul(PACK_LEN);
    let mut bytes = vec![0u8; SIGNATURE_HEADER_LEN];
    bytes.splice(..6, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
    bytes.extend(std::iter::repeat_n(
        0u8,
        usize::try_from(packed).unwrap_or_default(),
    ));
    bytes.extend_from_slice(&header);
    let record = [
        packed.to_le_bytes().as_slice(),
        (header.len() as u64).to_le_bytes().as_slice(),
        crc32(&header).to_le_bytes().as_slice(),
    ]
    .concat();
    if let Some(slot) = bytes.get_mut(12..SIGNATURE_HEADER_LEN) {
        slot.copy_from_slice(&record);
    }
    let start_crc = crc32(bytes.get(12..SIGNATURE_HEADER_LEN).unwrap_or_default());
    if let Some(slot) = bytes.get_mut(8..12) {
        slot.copy_from_slice(&start_crc.to_le_bytes());
    }
    bytes
}

/// The first coder of the first block of `archive`.
fn first_coder(archive: &[u8]) -> Result<Coder, ArchiveError> {
    let parsed = Archive::read(&mut Cursor::new(archive), &Password::empty())?;
    parsed
        .blocks
        .into_iter()
        .next()
        .and_then(|block| block.coders.into_iter().next())
        .ok_or_else(unsupported_coder)
}

/// The simple one-in one-out AES coder with `properties`, as sevenz-rust2
/// parses it.
fn donor(properties: &[u8]) -> Result<Coder, ArchiveError> {
    let mut coder = vec![1, 0x20 | 0x04];
    coder.extend_from_slice(&AES_ID);
    put_number(&mut coder, properties.len() as u64);
    coder.extend_from_slice(properties);
    first_coder(&synthesized_archive(&coder, 1))
}

/// The coder that decodes like `original` under the full 32-byte key as
/// password: a raw-key AES coder with the same IV.
///
/// # Errors
///
/// [`Malformation::SevenZUnsupportedCoder`] unless `original` is a simple
/// one-in one-out AES coder whose properties parse. Proven by building a donor
/// from the original properties and requiring it to equal `original`, so a
/// coder with other stream counts or another shape is never normalised into a
/// different graph.
pub(super) fn twin(original: &Coder) -> Result<Coder, ArchiveError> {
    let aes = AesCoder::parse(original.properties()).ok_or_else(unsupported_coder)?;
    if donor(original.properties())? != *original {
        return Err(unsupported_coder());
    }
    let mut properties = RAW_KEY_PROPERTIES.to_vec();
    properties.extend_from_slice(&aes.iv);
    donor(&properties)
}

/// The password that makes a raw-key donor use `key`: all 32 bytes of it.
pub(super) fn raw_key_password(key: &SevenZKey) -> Password {
    Password::from_raw(key.as_bytes())
}

/// The key parameters shared by every AES coder of `block`, or `None` when it
/// has none.
///
/// # Errors
///
/// [`Malformation::SevenZUnsupportedCoder`] when a coder's properties do not
/// parse or two AES coders declare different (power, salt): one raw password
/// per block cannot serve two keys.
pub(super) fn block_pair(block: &Block) -> Result<Option<AesParams>, ArchiveError> {
    let mut pair = None;
    for coder in block.coders.iter().filter(|coder| is_aes_coder(coder)) {
        let params = AesParams::parse(coder.properties()).ok_or_else(unsupported_coder)?;
        match pair {
            Some(known) if known != params => return Err(unsupported_coder()),
            _ => pair = Some(params),
        }
    }
    Ok(pair)
}

/// Why a pair's key could not be derived.
#[derive(Debug, Clone, Copy)]
enum PairFailure {
    OverBudget,
    PasswordRequired,
}

/// One distinct key (power, salt) of the archive, derived on first use.
///
/// No `Debug`: the derived key lives here as a raw `Password`, which the
/// library does not zeroize.
struct PairKey {
    params: DerivableParams,
    key: OnceLock<Result<Password, PairFailure>>,
}

/// Why a block cannot be handed to the decoder; only decoding that block fails.
#[derive(Debug, Clone, Copy)]
enum BlockRefusal {
    /// A coder that cannot be replaced faithfully, or two different keys.
    Unsupported,
    /// A raw-key coder or a power above the cap.
    Key(KeyRefusal),
}

/// How a block gets its password.
#[derive(Clone)]
enum BlockKey {
    /// No AES coder.
    Plain,
    /// The key of this pair, shared by every block with the same parameters.
    Pair(Arc<PairKey>),
    /// Left untouched; decoding it fails.
    Refused(BlockRefusal),
}

/// The parsed archive as block decoding sees it: file checksums off (the
/// callers verify them), every AES coder of an admissible block a raw-key
/// donor, and one raw password per distinct key, derived lazily and at most
/// once per operation.
///
/// Built once per header. Nothing here is derived at build time, so a
/// selective extract pays only for the pairs of the blocks it decodes. A block
/// that cannot be handed over is left as parsed and fails alone when decoded:
/// it never affects the other blocks. The derived raw passwords are
/// `sevenz_rust2::Password` values, which the library does not zeroize, so they
/// live until the header is dropped.
pub(crate) struct DecodeArchive {
    archive: Archive,
    pairs: HashMap<AesParams, Arc<PairKey>>,
    by_block: PerBlock<BlockKey>,
    plain: Password,
    secret: Option<SevenZSecret>,
    reserve: u64,
    budget: u64,
    spent: AtomicU64,
}

impl std::fmt::Debug for DecodeArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodeArchive")
            .field("pairs", &self.pairs.len())
            .finish_non_exhaustive()
    }
}

/// The donor coders of `block` and its key parameters, or why it cannot be
/// handed over.
fn swapped_coders(block: &Block) -> Result<Option<(DerivableParams, Vec<Coder>)>, BlockRefusal> {
    let Some(params) = block_pair(block).map_err(|_| BlockRefusal::Unsupported)? else {
        return Ok(None);
    };
    let params = params.derivable().map_err(BlockRefusal::Key)?;
    let coders = block
        .coders
        .iter()
        .map(|coder| {
            if is_aes_coder(coder) {
                twin(coder).map_err(|_| BlockRefusal::Unsupported)
            } else {
                Ok(coder.clone())
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some((params, coders)))
}

impl DecodeArchive {
    /// Builds the decode view of `header`.
    pub(super) fn build(header: &SevenZHeader) -> Self {
        let mut archive = header.archive().clone();
        archive
            .files
            .iter_mut()
            .for_each(|file| file.has_crc = false);
        let mut pairs: HashMap<AesParams, Arc<PairKey>> = HashMap::new();
        let mut by_block = header.per_block(BlockKey::Plain);
        for (block, index) in archive.blocks.iter_mut().zip(header.block_indices()) {
            match swapped_coders(block) {
                Ok(None) => {}
                Err(refusal) => by_block[index] = BlockKey::Refused(refusal),
                Ok(Some((params, coders))) => {
                    block.coders = coders;
                    let pair = pairs.entry(*params.params()).or_insert_with(|| {
                        Arc::new(PairKey {
                            params,
                            key: OnceLock::new(),
                        })
                    });
                    by_block[index] = BlockKey::Pair(Arc::clone(pair));
                }
            }
        }
        if let Some(seed) = header.header_key()
            && let Some(pair) = pairs.get(&seed.params)
        {
            // The header's key is this pair's key: derived once, not twice.
            let _ = pair.key.set(Ok(raw_key_password(&seed.key)));
        }
        Self {
            archive,
            pairs,
            by_block,
            plain: Password::empty(),
            secret: header.credentials().sevenz_secret().ok().flatten(),
            reserve: if header.header_encrypted() {
                HEADER_RESERVE
            } else {
                0
            },
            budget: header.kdf_budget().get(),
            spent: AtomicU64::new(0),
        }
    }

    /// The archive to hand to `BlockDecoder`.
    pub(super) const fn archive(&self) -> &Archive {
        &self.archive
    }

    /// The password `BlockDecoder` needs for `block`: empty for a block
    /// without AES, else the raw form of its pair's key, derived on first use.
    ///
    /// # Errors
    ///
    /// An I/O error carrying [`KdfRepeatExceeded`] when deriving the pair would
    /// take the operation's derivations (and the header reservation) over
    /// `max_kdf_work`; the refusal is sticky for every later derivation.
    /// `PasswordRequired` when no password was supplied, which admission
    /// refuses first.
    pub(super) fn block_password(
        &self,
        block: BlockIndex,
    ) -> Result<&Password, sevenz_rust2::Error> {
        let pair = match &self.by_block[block] {
            BlockKey::Plain => return Ok(&self.plain),
            BlockKey::Refused(BlockRefusal::Key(KeyRefusal::Refused(
                EncryptionRefusal::KdfCostExceeded,
            ))) => return Err(KdfRepeatExceeded.into_io().into()),
            BlockKey::Refused(_) => {
                return Err(sevenz_rust2::Error::Other(
                    "7z AES block cannot be decoded".into(),
                ));
            }
            BlockKey::Pair(pair) => pair,
        };
        match pair.key.get_or_init(|| self.derive(pair.params)) {
            Ok(password) => Ok(password),
            Err(PairFailure::OverBudget) => Err(KdfRepeatExceeded.into_io().into()),
            Err(PairFailure::PasswordRequired) => Err(sevenz_rust2::Error::PasswordRequired),
        }
    }

    fn derive(&self, params: DerivableParams) -> Result<Password, PairFailure> {
        let before = self
            .spent
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |spent| {
                Some(spent.saturating_add(params.rounds()))
            })
            .unwrap_or(u64::MAX);
        let total = self
            .reserve
            .saturating_add(before)
            .saturating_add(params.rounds());
        if total > self.budget {
            return Err(PairFailure::OverBudget);
        }
        let secret = self.secret.as_ref().ok_or(PairFailure::PasswordRequired)?;
        Ok(raw_key_password(&SevenZKey::derive(params, secret)))
    }
}

/// Where the AES properties of an encrypted header sit in the prefetched
/// bytes.
#[derive(Debug, Clone, Copy)]
pub(super) struct AesSite {
    pub(super) properties_at: u64,
    pub(super) record_at: u64,
    pub(super) record_len: u64,
}

impl EncryptedHeader {
    /// Checks the two checksums sevenz-rust2 would check on these bytes: the
    /// start header's and the next-header record's.
    ///
    /// Run before the header key is derived (a corrupt archive costs no
    /// derivation) and before the bytes are patched (the patch recomputes both
    /// checksums, so it would otherwise turn a failure into acceptance).
    ///
    /// # Errors
    ///
    /// The error the unpatched parse raises for the same mismatch.
    pub(super) fn verify_checksums(&self) -> Result<(), sevenz_rust2::Error> {
        let start = self
            .bytes
            .bytes_at(0, SIGNATURE_HEADER_LEN as u64)
            .ok_or(sevenz_rust2::Error::ChecksumVerificationFailed)?;
        let (stored_start, stored_record) = (le::u32_at(start, 8), le::u32_at(start, 28));
        let covered = start.get(12..SIGNATURE_HEADER_LEN).unwrap_or_default();
        if stored_start != Some(crc32(covered)) {
            return Err(sevenz_rust2::Error::ChecksumVerificationFailed);
        }
        let site = self
            .site
            .ok_or(sevenz_rust2::Error::NextHeaderCrcMismatch)?;
        let record = self
            .bytes
            .bytes_at(site.record_at, site.record_len)
            .ok_or(sevenz_rust2::Error::NextHeaderCrcMismatch)?;
        if stored_record != Some(crc32(record)) {
            return Err(sevenz_rust2::Error::NextHeaderCrcMismatch);
        }
        Ok(())
    }

    /// Rewrites the header's AES coder to raw-key mode for `key` and returns
    /// the bytes with the password that parses them.
    ///
    /// Only the power bits, the salt bytes and the two checksums change; the
    /// salt bytes become `key[..salt_len]` and the password is
    /// `key[salt_len..]`, which is what raw-key mode joins back into `key`.
    /// `None` when the header has no single derived-key AES coder to patch.
    pub(super) fn into_raw_key(
        mut self,
        key: &SevenZKey,
    ) -> Option<(super::prefetched::PrefetchedHeader, Password)> {
        let site = self.site?;
        let salt_len = self.params?.salt_len();
        let (salt, secret) = key.as_bytes().split_at_checked(salt_len)?;
        let first = *self.bytes.bytes_at(site.properties_at, 1)?.first()?;
        self.bytes
            .write_at(site.properties_at, &[(first & 0xC0) | 0x3F])?;
        if !salt.is_empty() {
            self.bytes
                .write_at(site.properties_at.checked_add(2)?, salt)?;
        }
        let record_crc = crc32(self.bytes.bytes_at(site.record_at, site.record_len)?);
        self.bytes.write_at(28, &record_crc.to_le_bytes())?;
        let start_crc = crc32(self.bytes.bytes_at(12, 20)?);
        self.bytes.write_at(8, &start_crc.to_le_bytes())?;
        Some((self.bytes, Password::from_raw(secret)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_round_trip_through_the_reader_encoding() {
        for value in [
            0u64,
            1,
            0x7F,
            0x80,
            0x3FFF,
            0x4000,
            0x1F_FFFF,
            1 << 40,
            u64::MAX,
        ] {
            let mut bytes = Vec::new();
            put_number(&mut bytes, value);
            let first = u64::from(bytes[0]);
            let mut mask = 0x80u64;
            let mut decoded = 0u64;
            let mut at = 1;
            let mut done = false;
            for i in 0..8 {
                if first & mask == 0 {
                    decoded |= (first & (mask - 1)) << (8 * i);
                    done = true;
                    break;
                }
                decoded |= u64::from(bytes[at]) << (8 * i);
                at += 1;
                mask >>= 1;
            }
            assert!(done || at == bytes.len());
            assert_eq!(decoded, value, "{bytes:?}");
            assert_eq!(at, bytes.len(), "{value}");
        }
    }

    fn aes_properties(power: u8, salt: &[u8], iv: [u8; 16]) -> Vec<u8> {
        let salt_flag = if salt.is_empty() { 0 } else { 0x80 };
        let salt_nibble = u8::try_from(salt.len().saturating_sub(1)).unwrap() << 4;
        let mut bytes = vec![power | 0x40 | salt_flag, salt_nibble | 0x0F];
        bytes.extend_from_slice(salt);
        bytes.extend_from_slice(&iv);
        bytes
    }

    #[test]
    fn a_donor_carries_the_properties_it_was_built_from() {
        let properties = aes_properties(19, &[1, 2, 3], [9; 16]);
        let coder = donor(&properties).unwrap();
        assert_eq!(coder.properties(), properties);
        assert_eq!(coder.encoder_method_id(), AES_ID);
    }

    #[test]
    fn the_twin_is_a_raw_key_coder_with_the_original_iv() {
        let iv = [7u8; 16];
        let original = donor(&aes_properties(19, &[4; 16], iv)).unwrap();
        let twin = twin(&original).unwrap();
        let mut expected = RAW_KEY_PROPERTIES.to_vec();
        expected.extend_from_slice(&iv);
        assert_eq!(twin.properties(), expected);
        assert_eq!(twin.encoder_method_id(), AES_ID);
        assert_eq!(AesParams::parse(twin.properties()).unwrap().salt_len(), 0);
    }

    #[test]
    fn a_coder_that_is_not_the_donor_shape_has_no_twin() {
        let properties = aes_properties(19, &[], [1; 16]);
        let mut complex = vec![1, 0x20 | 0x10 | 0x04];
        complex.extend_from_slice(&AES_ID);
        complex.extend([2, 1]);
        put_number(&mut complex, properties.len() as u64);
        complex.extend_from_slice(&properties);
        complex.extend([0, 1]);
        let two_inputs = first_coder(&synthesized_archive(&complex, 2)).unwrap();
        assert_eq!(two_inputs.properties(), properties);
        assert!(matches!(
            twin(&two_inputs),
            Err(ArchiveError::InvalidArchive(
                Malformation::SevenZUnsupportedCoder
            ))
        ));

        let mut other = vec![1, 0x20 | 0x01, 0x00];
        put_number(&mut other, properties.len() as u64);
        other.extend_from_slice(&properties);
        let not_aes = first_coder(&synthesized_archive(&other, 1)).unwrap();
        assert!(twin(&not_aes).is_err());
    }

    #[test]
    fn properties_that_do_not_parse_have_no_twin() {
        let short = first_coder(&synthesized_archive(
            &[1, 0x20 | 0x04, 0x06, 0xF1, 0x07, 0x01, 1, 0x80],
            1,
        ))
        .unwrap();
        assert!(twin(&short).is_err());
    }

    #[cfg(feature = "encryption")]
    mod differential {
        use super::super::super::header::HeaderLimit;
        use super::super::super::header::open_sevenz_header;
        use super::*;
        use crate::encryption::Credentials;
        use std::sync::Arc;

        const CONTENT: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/encryption/content.7z"
        ));
        const HEADER: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/encryption/header.7z"
        ));
        const PASSWORD: &str = "correct-horse";

        fn credentials() -> Credentials {
            Credentials::new(Some(Arc::new(
                crate::Password::new(PASSWORD.as_bytes().to_vec()).unwrap(),
            )))
        }

        fn open(bytes: &[u8]) -> SevenZHeader {
            open_sevenz_header(
                &mut Cursor::new(bytes),
                HeaderLimit::UNLIMITED,
                &credentials(),
            )
            .unwrap()
        }

        /// What every block of `archive` decodes to under `password_of`.
        fn contents(
            bytes: &[u8],
            archive: &Archive,
            password_of: impl Fn(usize) -> Password,
        ) -> Vec<Vec<u8>> {
            let mut out = Vec::new();
            for block in 0..archive.blocks.len() {
                let password = password_of(block);
                let mut source = Cursor::new(bytes);
                sevenz_rust2::BlockDecoder::new(1, block, archive, &password, &mut source)
                    .for_each_entries(&mut |_, reader| {
                        let mut body = Vec::new();
                        reader.read_to_end(&mut body)?;
                        out.push(body);
                        Ok(true)
                    })
                    .unwrap();
            }
            out
        }

        #[test]
        fn blocks_of_a_7zip_archive_decode_the_same_under_the_exarch_key() {
            let header = open(CONTENT);
            let original =
                Archive::read(&mut Cursor::new(CONTENT), &Password::new(PASSWORD)).unwrap();
            let decoded = header.decode_archive();

            let reference = contents(CONTENT, &original, |_| Password::new(PASSWORD));
            let through_donors = contents(CONTENT, decoded.archive(), |block| {
                let index = header.block_indices().nth(block).unwrap();
                decoded.block_password(index).unwrap().clone()
            });

            assert!(!reference.is_empty());
            assert_eq!(through_donors, reference);
        }

        #[test]
        fn a_refused_block_fails_alone_and_leaves_the_other_blocks_decodable() {
            let opened = open(CONTENT);
            let mut archive = opened.archive().clone();
            let mut raw_key_properties = vec![0x7F ^ 0x40, 0x0F];
            raw_key_properties.extend_from_slice(&[7u8; 16]);
            let refused = archive.blocks.get_mut(1).unwrap();
            let coder = refused
                .coders
                .iter_mut()
                .find(|coder| is_aes_coder(coder))
                .unwrap();
            *coder = donor(&raw_key_properties).unwrap();
            let header = SevenZHeader::assume_checked(archive).opened_with(
                credentials(),
                None,
                std::num::NonZeroU64::MAX,
            );
            let blocks: Vec<_> = header.block_indices().collect();
            assert_eq!(blocks.len(), 2);

            let decoded = header.decode_archive();

            assert!(decoded.block_password(blocks[0]).is_ok());
            assert!(decoded.block_password(blocks[1]).is_err());
            assert!(std::ptr::eq(decoded, header.decode_archive()));
        }

        const HEADER_7ZZ: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/encryption/header-7zz.7z"
        ));

        fn derived_by(run: impl FnOnce()) -> usize {
            let before = crate::encryption::kdf::DERIVATIONS.with(std::cell::Cell::get);
            run();
            crate::encryption::kdf::DERIVATIONS.with(std::cell::Cell::get) - before
        }

        #[test]
        fn extracting_a_7zz_encrypted_header_archive_derives_its_key_once() {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("header-7zz.7z");
            std::fs::write(&path, HEADER_7ZZ).unwrap();
            let out = dir.path().join("out");
            std::fs::create_dir(&out).unwrap();
            let config = crate::SecurityConfig::default();
            let password = Some(Arc::new(
                crate::Password::new(PASSWORD.as_bytes().to_vec()).unwrap(),
            ));

            let extracted = derived_by(|| {
                crate::ExtractRequest::new(&config)
                    .with_password(password.clone())
                    .extract(&path, &out)
                    .unwrap();
            });
            let listed = derived_by(|| {
                crate::ListRequest::new(&config)
                    .with_password(password.clone())
                    .list(&path)
                    .unwrap();
            });

            assert_eq!(extracted, 1);
            assert_eq!(listed, 1);
            assert_eq!(
                std::fs::read(out.join("hello.txt")).unwrap(),
                b"hello encrypted\n"
            );
        }

        #[test]
        fn the_encrypted_header_of_a_7zip_archive_opens_like_the_unpatched_one() {
            let header = open(HEADER);
            let original =
                Archive::read(&mut Cursor::new(HEADER), &Password::new(PASSWORD)).unwrap();

            let names = |archive: &Archive| {
                archive
                    .files
                    .iter()
                    .map(|file| file.name().to_owned())
                    .collect::<Vec<_>>()
            };
            assert!(header.header_encrypted());
            assert_eq!(names(header.archive()), names(&original));
            assert_eq!(header.block_count(), original.blocks.len());
        }

        #[test]
        fn a_patched_header_reads_exactly_what_the_patch_changed() {
            let fetched = super::super::super::header_probe::prefetch_encoded_header(
                &mut Cursor::new(HEADER),
                u64::MAX / 4,
                u64::MAX,
            )
            .unwrap();
            assert!(fetched.verify_checksums().is_ok());
            let params = fetched.params.unwrap();
            let site = fetched.site.unwrap();
            let secret = credentials().sevenz_secret().unwrap().unwrap();
            let key = SevenZKey::derive(params.derivable().unwrap(), &secret);
            let before = fetched
                .bytes
                .bytes_at(0, 32)
                .unwrap()
                .iter()
                .chain(
                    fetched
                        .bytes
                        .bytes_at(site.record_at, site.record_len)
                        .unwrap(),
                )
                .copied()
                .collect::<Vec<u8>>();

            let (patched, password) = fetched.into_raw_key(&key).unwrap();

            let after = patched
                .bytes_at(0, 32)
                .unwrap()
                .iter()
                .chain(patched.bytes_at(site.record_at, site.record_len).unwrap())
                .copied()
                .collect::<Vec<u8>>();
            let changed: Vec<usize> = before
                .iter()
                .zip(&after)
                .enumerate()
                .filter_map(|(at, (old, new))| (old != new).then_some(at))
                .collect();
            let properties = usize::try_from(site.properties_at - site.record_at).unwrap() + 32;
            let in_checksums = |at: &usize| (8..12).contains(at) || (28..32).contains(at);
            let in_properties = |at: &usize| {
                *at == properties
                    || (properties + 2..properties + 2 + params.salt_len()).contains(at)
            };
            assert!(!changed.is_empty());
            assert!(
                changed
                    .iter()
                    .all(|at| in_checksums(at) || in_properties(at)),
                "{changed:?}"
            );
            assert_eq!(password.as_slice(), &key.as_bytes()[params.salt_len()..]);
        }
    }
}
