//! Admission of 7z blocks: coder memory, block layout, solid policy and the
//! compression ratio each entry gets, decided before any byte is decoded.

use super::SIGNATURE_HEADER_SIZE;
use super::header::BlockIndex;
use super::header::SevenZHeader;
use crate::ArchiveError;
use crate::EntryCompression;
use crate::Limit;
use crate::Malformation;
use crate::Result;
use crate::SecurityConfig;
use crate::SolidArchives;
use crate::SolidBlock;
use crate::Violation;
use crate::error::QuotaResource;
use crate::formats::common;
use crate::inspection::report::Finding;
use crate::inspection::report::Heuristic;
use crate::inspection::report::IssueSeverity;
use crate::inspection::report::UnverifiedReason;
use crate::inspection::report::VerificationIssue;
use crate::security::Compressed;
use crate::security::Uncompressed;
use crate::security::zipbomb::DeclaredCompressedBudget;
use sevenz_rust2::BlockDecoder;
use sevenz_rust2::Password;
use std::io;

/// Number of packed streams a conforming block consumes: one, plus three more
/// per BCJ2 coder (four inputs, one output). Every other admitted method has a
/// single input.
///
/// The upstream accessors for the stream arity are `pub(crate)`, so the count
/// follows from the public method IDs. A crafted header can declare a coder
/// with the BCJ2 ID that the decode path never reaches; the count then exceeds
/// the real one by up to three streams per such coder, which is never looser
/// than counting every pack stream after the block.
pub(super) fn packed_stream_count(block: &sevenz_rust2::Block) -> usize {
    use sevenz_rust2::EncoderMethod;

    let bcj2 = block
        .coders
        .iter()
        .filter(|coder| coder.encoder_method_id() == EncoderMethod::ID_BCJ2)
        .count();
    1 + 3 * bcj2
}

/// The declared decoded size of one block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BlockTotal {
    /// The checked sum of the declared sizes of the block's files.
    Bytes(u64),
    /// The sum does not fit a `u64`.
    Overflow,
}

impl BlockTotal {
    fn add(self, size: u64) -> Self {
        match self {
            Self::Bytes(total) => total.checked_add(size).map_or(Self::Overflow, Self::Bytes),
            Self::Overflow => Self::Overflow,
        }
    }
}

/// File count and declared decoded size of one block.
struct BlockTally {
    files: usize,
    uncompressed: BlockTotal,
}

/// Tallies the files that have data in each block, 1:1 with the header's
/// blocks.
fn tally_blocks(header: &SevenZHeader) -> Vec<BlockTally> {
    let mut tallies: Vec<BlockTally> = header
        .block_indices()
        .map(|_| BlockTally {
            files: 0,
            uncompressed: BlockTotal::Bytes(0),
        })
        .collect();
    for (index, file) in header.files().iter().enumerate() {
        if let Some(block) = header.file_block(index) {
            let tally = &mut tallies[block.get()];
            tally.files += 1;
            tally.uncompressed = tally.uncompressed.add(file.size);
        }
    }
    tallies
}

/// Derives how each file's data is compressed for ratio checks, after
/// validating the declared pack stream sizes against the archive length.
///
/// The returned vector is 1:1 with `archive.files`:
/// - a file alone in its block gets [`EntryCompression::Entry`] with the
///   checked sum of that block's pack streams;
/// - the first file of a multi-file (solid) block gets
///   [`EntryCompression::SolidBlockStart`] with the block's compressed total
///   and the checked sum of its files' sizes; the other members get
///   [`EntryCompression::SolidBlockMember`];
/// - files without a data stream (empty files, directories) get
///   [`EntryCompression::Unknown`].
///
/// The last block's pack streams are counted from its coders' method IDs (one,
/// plus three more per BCJ2 coder) and capped at the declared pack streams, so
/// pack streams no block references do not inflate its total. `source_len` must
/// be the length of the same source the archive is decoded from.
///
/// # Errors
///
/// Returns [`ArchiveError::InvalidArchive`] when the declared pack sizes
/// exceed the space the archive can hold, or a pack size sum overflows, and
/// [`ArchiveError::QuotaExceeded`] when a block's uncompressed sum overflows.
pub fn sevenz_entry_compression(
    header: &SevenZHeader,
    source_len: u64,
) -> Result<Vec<EntryCompression>> {
    let archive = header.archive();
    let data_region = source_len
        .checked_sub(SIGNATURE_HEADER_SIZE)
        .and_then(|len| len.checked_sub(archive.pack_pos()))
        .ok_or_else(|| ArchiveError::from(Malformation::DeclaredCompressedExceedsArchive))?;
    let mut budget = DeclaredCompressedBudget::new(data_region);
    for &pack_size in archive.pack_sizes() {
        budget.charge(pack_size)?;
    }

    let pack_sizes = archive.pack_sizes();
    let block_compressed = |block: BlockIndex| -> Result<Compressed> {
        let start = header.block_first_pack(block);
        let end = header.next_block_first_pack(block).unwrap_or_else(|| {
            start
                .saturating_add(packed_stream_count(header.block(block)))
                .min(pack_sizes.len())
        });
        pack_sizes[start..end]
            .iter()
            .try_fold(0u64, |acc, &size| acc.checked_add(size))
            .map(Compressed)
            .ok_or_else(|| ArchiveError::from(Malformation::PackSizesOverflow))
    };

    let tallies = tally_blocks(header);
    let mut block_uncompressed = Vec::with_capacity(tallies.len());
    let mut block_files = Vec::with_capacity(tallies.len());
    for tally in &tallies {
        let BlockTotal::Bytes(bytes) = tally.uncompressed else {
            return Err(ArchiveError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow,
            });
        };
        block_uncompressed.push(bytes);
        block_files.push(tally.files);
    }

    header
        .files()
        .iter()
        .enumerate()
        .map(|(index, file)| {
            let Some(block) = header.file_block(index) else {
                return Ok(EntryCompression::Unknown);
            };
            if !file.has_stream {
                return Ok(EntryCompression::Unknown);
            }
            let compressed = block_compressed(block)?;
            if block_files[block.get()] <= 1 {
                return Ok(EntryCompression::Entry(compressed));
            }
            if header.block_first_file(block) == index {
                Ok(EntryCompression::SolidBlockStart(SolidBlock::new(
                    compressed,
                    Uncompressed(block_uncompressed[block.get()]),
                )))
            } else {
                Ok(EntryCompression::SolidBlockMember)
            }
        })
        .collect()
}

/// A refused check: the error `extract` fails with, and why `verify` reports
/// the payload the refusal covers as unverified.
#[derive(Debug)]
pub(super) struct Refused {
    pub(super) reason: UnverifiedReason,
    pub(super) error: ArchiveError,
}

impl Refused {
    const fn new(reason: UnverifiedReason, error: ArchiveError) -> Self {
        Self { reason, error }
    }
}

/// Enforces the solid-archive policy shared by extraction and verification.
///
/// A solid archive needs [`SolidArchives::Allow`], and the declared decoded
/// size of every one of its blocks, single-file blocks included, must fit
/// [`SolidLimits::max_block_memory`]. The limit bounds decoded volume per
/// block, not resident memory: decoding streams, and the memory of parallel
/// decoding is bounded by `parallel_decode`. While `max_total_size` is
/// [`Limit::Unbounded`] the archive-wide sum of the blocks is also held to the
/// same limit, so an unbounded total never removes the cap on a solid archive.
///
/// # Errors
///
/// Refuses with [`UnverifiedReason::SolidPolicy`] and
/// [`ArchiveError::SecurityViolation`] when solid archives are not allowed, and
/// with [`UnverifiedReason::ResourceLimit`] and
/// [`QuotaResource::IntegerOverflow`], [`QuotaResource::SolidBlockMemory`] or
/// [`QuotaResource::TotalSize`] when a size check fails.
pub(super) fn check_solid_policy(
    is_solid: bool,
    blocks: impl IntoIterator<Item = BlockTotal>,
    config: &SecurityConfig,
) -> std::result::Result<(), Refused> {
    if !is_solid {
        return Ok(());
    }
    let SolidArchives::Allow(limits) = config.solid_archives else {
        return Err(Refused::new(
            UnverifiedReason::SolidPolicy,
            Violation::SolidArchive.into(),
        ));
    };
    let max = limits.max_block_memory.get();
    let resource_limit = |resource| {
        Refused::new(
            UnverifiedReason::ResourceLimit,
            ArchiveError::QuotaExceeded { resource },
        )
    };

    let mut archive_total = 0u64;
    for block in blocks {
        let BlockTotal::Bytes(current) = block else {
            return Err(resource_limit(QuotaResource::IntegerOverflow));
        };
        if current > max {
            return Err(resource_limit(QuotaResource::SolidBlockMemory {
                current,
                max,
            }));
        }
        archive_total = archive_total
            .checked_add(current)
            .ok_or_else(|| resource_limit(QuotaResource::IntegerOverflow))?;
    }
    if config.max_total_size == Limit::Unbounded && archive_total > max {
        return Err(resource_limit(QuotaResource::TotalSize {
            current: archive_total,
            max,
        }));
    }
    Ok(())
}

/// Fixed decoder memory charged for a `BZip2` coder, in bytes.
pub(super) const BZIP2_DECODER_MEMORY: u64 = 4 * 1024 * 1024;

/// Dictionary size an LZMA2 coder declares in its one property byte, or `None`
/// for a byte sevenz-rust2 rejects.
pub(super) fn lzma2_dict_size(props: &[u8]) -> Option<u32> {
    let bits = u32::from(*props.first()?);
    match bits {
        0..=39 => Some((2 | (bits & 1)) << (bits / 2 + 11)),
        40 => Some(u32::MAX),
        _ => None,
    }
}

/// Decoder memory a coder needs, estimated from its properties.
///
/// sevenz-rust2 applies no memory limit of its own, so the limit is enforced
/// here from the coder properties. LZMA and LZMA2 grow their window
/// geometrically up to the dictionary size, so the estimate is
/// `min(dict, 2 * unpack)`. `None` means the method is unknown or its
/// properties cannot be parsed, and the caller must fail closed.
pub(super) fn coder_memory(coder: &sevenz_rust2::Coder, unpack_size: u64) -> Option<u64> {
    use sevenz_rust2::EncoderMethod;

    let props = coder.properties();
    let window = |dict: u64| dict.min(unpack_size.saturating_mul(2));
    match coder.encoder_method_id() {
        EncoderMethod::ID_COPY
        | EncoderMethod::ID_DELTA
        | EncoderMethod::ID_BCJ_X86
        | EncoderMethod::ID_BCJ_PPC
        | EncoderMethod::ID_BCJ_IA64
        | EncoderMethod::ID_BCJ_ARM
        | EncoderMethod::ID_BCJ_ARM64
        | EncoderMethod::ID_BCJ_ARM_THUMB
        | EncoderMethod::ID_BCJ_SPARC
        | EncoderMethod::ID_BCJ_RISCV
        | EncoderMethod::ID_BCJ2
        | EncoderMethod::ID_DEFLATE => Some(0),
        EncoderMethod::ID_LZMA => {
            let dict = props.get(1..)?.first_chunk::<4>()?;
            Some(window(u64::from(u32::from_le_bytes(*dict))))
        }
        EncoderMethod::ID_LZMA2 => Some(window(u64::from(lzma2_dict_size(props)?))),
        EncoderMethod::ID_PPMD => {
            let mem = props.get(1..)?.first_chunk::<4>()?;
            Some(u64::from(u32::from_le_bytes(*mem)))
        }
        EncoderMethod::ID_BZIP2 => Some(BZIP2_DECODER_MEMORY),
        _ => None,
    }
}

/// The files the decoder hands out for `block`: the span from its first to its
/// last mapped file, stream-less files in between included.
///
/// `sevenz-rust2` builds the span within the archive's files.
pub(super) fn block_span(header: &SevenZHeader, block: BlockIndex) -> std::ops::Range<usize> {
    let password = Password::empty();
    let mut no_source = io::Cursor::new(&[][..]);
    let count = BlockDecoder::new(1, block.get(), header.archive(), &password, &mut no_source)
        .entry_count();
    let first = header.block_first_file(block);
    first..first.saturating_add(count)
}

/// Sum of the declared sizes of the files mapped to each block, through
/// `stream_map.file_block_index`; `None` for a block whose sum overflows.
pub(super) fn declared_sizes(header: &SevenZHeader) -> Vec<Option<u64>> {
    let mut sizes = vec![Some(0u64); header.block_count()];
    for (index, file) in header.files().iter().enumerate() {
        if let Some(block) = header.file_block(index) {
            let size = &mut sizes[block.get()];
            *size = size.and_then(|sum| sum.checked_add(file.size));
        }
    }
    sizes
}

/// Bytes to charge to a decompression budget for decoding `block`.
///
/// The charge is the largest coder output, so size-preserving filters (BCJ,
/// Delta) are not counted twice.
pub(super) fn block_charge(block: &sevenz_rust2::Block) -> u64 {
    block
        .coders
        .iter()
        .map(|coder| block.get_unpack_size_for_coder(coder))
        .max()
        .unwrap_or_default()
}

/// Admits a 7z block for decoding.
///
/// Decoder memory over `max_decoder_memory` is refused before any byte is
/// decoded. LZMA2 is built without an output bound, so its window can grow to
/// the block's output whatever size its own stream declares; the larger of the
/// block's unpack size and its files' declared sizes is used.
///
/// # Errors
///
/// Refuses with [`UnverifiedReason::ResourceLimit`] and
/// [`ArchiveError::QuotaExceeded`] when the decoder memory exceeds the limit,
/// and with [`UnverifiedReason::NotDecodable`] for AES content encryption
/// ([`ArchiveError::SecurityViolation`]) and for an unknown method,
/// unparseable coder properties, or a block whose files do not add up to its
/// decoded size ([`ArchiveError::InvalidArchive`]).
pub(super) fn admit_sevenz_block(
    block: &sevenz_rust2::Block,
    declared_size: Option<u64>,
    config: &SecurityConfig,
) -> std::result::Result<(), Refused> {
    let not_decodable = |error| Refused::new(UnverifiedReason::NotDecodable, error);
    let output = block_charge(block).max(declared_size.unwrap_or_default());
    let mut memory: u64 = 0;
    for coder in &block.coders {
        if coder.encoder_method_id() == sevenz_rust2::EncoderMethod::ID_AES256_SHA256 {
            return Err(not_decodable(common::encrypted_archive_error()));
        }
        let needed = coder_memory(coder, output).ok_or_else(|| {
            not_decodable(ArchiveError::from(Malformation::SevenZUnsupportedCoder))
        })?;
        memory = memory.saturating_add(needed);
    }
    if memory > config.max_decoder_memory.get() {
        return Err(Refused::new(
            UnverifiedReason::ResourceLimit,
            ArchiveError::QuotaExceeded {
                resource: QuotaResource::DecoderMemory {
                    max: config.max_decoder_memory.get(),
                },
            },
        ));
    }
    // TODO(#769): compare stream files with sub-streams once sevenz-rust2
    // exposes the count; the size sum misses zero-size shifts
    if declared_size != Some(block.get_unpack_size()) {
        return Err(not_decodable(ArchiveError::from(
            Malformation::BlockSizeUnaccounted,
        )));
    }
    Ok(())
}

/// Part of a 7z archive that a policy refuses to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalScope {
    /// The whole archive.
    Archive,
    /// One block.
    Block(BlockIndex),
}

/// A refusal of extraction, shared by `extract` and `verify`.
#[derive(Debug)]
pub struct SevenZRefusal {
    pub(super) scope: RefusalScope,
    unverified: UnverifiedReason,
    pub(super) error: ArchiveError,
}

impl SevenZRefusal {
    fn new(scope: RefusalScope, refused: Refused) -> Self {
        Self {
            scope,
            unverified: refused.reason,
            error: refused.error,
        }
    }

    /// Why the payload the refusal covers stays unverified.
    pub(super) const fn unverified(&self) -> UnverifiedReason {
        self.unverified
    }

    /// The error `extract` fails with.
    pub(crate) fn into_error(self) -> ArchiveError {
        self.error
    }
}

/// Everything `extract` refuses in a parsed 7z archive, in the order it checks.
///
/// This is the single admission point: `extract` fails on the first refusal
/// and `verify` reports each, so the two cannot disagree. It covers the solid
/// policy and, per block, decoder memory, unknown coders, AES content
/// encryption.
///
/// The iterator is lazy: `extract` takes only the first refusal and stops
/// checking blocks there.
pub fn iter_sevenz_refusals<'a>(
    header: &'a SevenZHeader,
    config: &'a SecurityConfig,
) -> impl Iterator<Item = SevenZRefusal> + 'a {
    let solid = check_solid_policy(
        header.is_solid(),
        tally_blocks(header)
            .into_iter()
            .map(|tally| tally.uncompressed),
        config,
    )
    .err()
    .map(|refused| SevenZRefusal::new(RefusalScope::Archive, refused));
    let blocks = header
        .block_indices()
        .zip(declared_sizes(header))
        .filter_map(move |(index, declared)| {
            admit_sevenz_block(header.block(index), declared, config)
                .err()
                .map(|refused| SevenZRefusal::new(RefusalScope::Block(index), refused))
        });
    solid.into_iter().chain(blocks)
}

/// Every refusal of [`iter_sevenz_refusals`], for `verify` to report.
pub fn sevenz_refusals(header: &SevenZHeader, config: &SecurityConfig) -> Vec<SevenZRefusal> {
    iter_sevenz_refusals(header, config).collect()
}

/// Most refusals `verify` lists; the rest are summarized in one issue.
pub(super) const MAX_REFUSAL_ISSUES: usize = 32;

/// Archive-level `verify` issues for the refusals, capped at
/// [`MAX_REFUSAL_ISSUES`].
pub fn refusal_issues(refusals: &[SevenZRefusal]) -> Vec<VerificationIssue> {
    let mut issues: Vec<_> = refusals
        .iter()
        .take(MAX_REFUSAL_ISSUES)
        .map(|r| VerificationIssue::from_error(&r.error, None))
        .collect();
    if let Some(omitted) = refusals.len().checked_sub(MAX_REFUSAL_ISSUES)
        && omitted > 0
    {
        issues.push(VerificationIssue::new(
            IssueSeverity::Info,
            Finding::Heuristic(Heuristic::OmittedRefusals { omitted }),
        ));
    }
    issues
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::SolidLimits;
    use std::assert_matches;

    fn config(max_solid_memory: u64) -> SecurityConfig {
        SecurityConfig::default().with_solid_archives(SolidArchives::Allow(
            SolidLimits::DEFAULT
                .with_max_block_memory(std::num::NonZeroU64::new(max_solid_memory).unwrap()),
        ))
    }

    fn bytes(sizes: &[u64]) -> Vec<BlockTotal> {
        sizes.iter().copied().map(BlockTotal::Bytes).collect()
    }

    #[test]
    fn solid_policy_refusal_carries_its_own_reason() {
        let refused =
            check_solid_policy(true, bytes(&[1]), &SecurityConfig::default()).unwrap_err();
        assert_eq!(refused.reason, UnverifiedReason::SolidPolicy);
        assert_matches!(refused.error, ArchiveError::SecurityViolation { .. });
    }

    #[test]
    fn solid_size_overflow_is_an_integer_overflow() {
        let refused = check_solid_policy(true, [BlockTotal::Overflow], &config(100)).unwrap_err();
        assert_eq!(refused.reason, UnverifiedReason::ResourceLimit);
        assert_matches!(
            refused.error,
            ArchiveError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow
            }
        );
    }

    #[test]
    fn block_totals_that_overflow_together_are_an_integer_overflow() {
        let unbounded = config(u64::MAX).with_max_total_size(Limit::Unbounded);
        let refused = check_solid_policy(true, bytes(&[u64::MAX, 1]), &unbounded).unwrap_err();
        assert_matches!(
            refused.error,
            ArchiveError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow
            }
        );
    }

    #[test]
    fn a_block_over_the_limit_is_a_solid_block_memory_refusal() {
        let refused = check_solid_policy(true, bytes(&[120]), &config(100)).unwrap_err();
        assert_eq!(refused.reason, UnverifiedReason::ResourceLimit);
        assert_matches!(
            refused.error,
            ArchiveError::QuotaExceeded {
                resource: QuotaResource::SolidBlockMemory {
                    current: 120,
                    max: 100
                }
            }
        );
    }

    #[test]
    fn every_block_is_checked_not_only_the_first() {
        let refused = check_solid_policy(true, bytes(&[10, 1, 101]), &config(100)).unwrap_err();
        assert_matches!(
            refused.error,
            ArchiveError::QuotaExceeded {
                resource: QuotaResource::SolidBlockMemory { current: 101, .. }
            }
        );
    }

    #[test]
    fn blocks_each_within_the_limit_pass_while_the_total_is_bounded() {
        let bounded = config(100).with_max_total_size(crate::non_zero!(1000));
        assert!(check_solid_policy(true, bytes(&[60, 60, 60]), &bounded).is_ok());
    }

    #[test]
    fn an_unbounded_total_keeps_the_archive_wide_cap() {
        let unbounded = config(100).with_max_total_size(Limit::Unbounded);
        let refused = check_solid_policy(true, bytes(&[60, 60]), &unbounded).unwrap_err();
        assert_eq!(refused.reason, UnverifiedReason::ResourceLimit);
        assert_matches!(
            refused.error,
            ArchiveError::QuotaExceeded {
                resource: QuotaResource::TotalSize {
                    current: 120,
                    max: 100
                }
            }
        );
    }

    #[test]
    fn non_solid_archive_passes_the_policy() {
        assert!(
            check_solid_policy(false, bytes(&[u64::MAX, 1]), &SecurityConfig::default()).is_ok()
        );
    }
}
