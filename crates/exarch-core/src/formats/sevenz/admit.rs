//! Admission of 7z blocks: coder memory, block layout, solid policy and the
//! compression ratio each entry gets, decided before any byte is decoded.

use super::SIGNATURE_HEADER_SIZE;
use crate::ArchiveError;
use crate::EntryCompression;
use crate::Result;
use crate::SecurityConfig;
use crate::SolidBlock;
use crate::config::Validated;
use crate::error::QuotaResource;
use crate::formats::common;
use crate::inspection::report::IssueCategory;
use crate::inspection::report::IssueSeverity;
use crate::inspection::report::UnverifiedReason;
use crate::inspection::report::VerificationIssue;
use crate::security::zipbomb::DeclaredCompressedBudget;
use sevenz_rust2::Archive;
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
    archive: &Archive,
    source_len: u64,
) -> Result<Vec<EntryCompression>> {
    let data_region = source_len
        .checked_sub(SIGNATURE_HEADER_SIZE)
        .and_then(|len| len.checked_sub(archive.pack_pos()))
        .ok_or_else(|| {
            ArchiveError::InvalidArchive("declared compressed size exceeds archive length".into())
        })?;
    let mut budget = DeclaredCompressedBudget::new(data_region);
    for &pack_size in archive.pack_sizes() {
        budget.charge(pack_size)?;
    }

    let pack_sizes = archive.pack_sizes();
    let first_pack = archive.stream_map.block_first_pack_stream_index();
    let block_compressed = |block: usize| -> Result<u64> {
        let start = first_pack[block];
        let end = first_pack.get(block + 1).copied().unwrap_or_else(|| {
            start
                .saturating_add(packed_stream_count(&archive.blocks[block]))
                .min(pack_sizes.len())
        });
        pack_sizes[start..end]
            .iter()
            .try_fold(0u64, |acc, &size| acc.checked_add(size))
            .ok_or_else(|| ArchiveError::InvalidArchive("7z pack sizes overflow".into()))
    };

    let mut block_uncompressed = vec![0u64; archive.blocks.len()];
    let mut block_files = vec![0usize; archive.blocks.len()];
    for (index, file) in archive.files.iter().enumerate() {
        if let Some(block) = archive.stream_map.file_block_index[index] {
            block_files[block] += 1;
            block_uncompressed[block] = block_uncompressed[block].checked_add(file.size).ok_or(
                ArchiveError::QuotaExceeded {
                    resource: QuotaResource::IntegerOverflow,
                },
            )?;
        }
    }

    archive
        .files
        .iter()
        .enumerate()
        .map(|(index, file)| {
            let Some(block) = archive.stream_map.file_block_index[index] else {
                return Ok(EntryCompression::Unknown);
            };
            if !file.has_stream {
                return Ok(EntryCompression::Unknown);
            }
            let compressed = block_compressed(block)?;
            if block_files[block] <= 1 {
                return Ok(EntryCompression::Entry(compressed));
            }
            if archive.stream_map.block_first_file_index[block] == index {
                Ok(EntryCompression::SolidBlockStart(SolidBlock::new(
                    compressed,
                    block_uncompressed[block],
                )))
            } else {
                Ok(EntryCompression::SolidBlockMember)
            }
        })
        .collect()
}

/// Enforces the solid-archive policy shared by extraction and verification.
///
/// A solid archive needs `allow_solid_archives`, and its total uncompressed
/// size must fit `max_solid_block_memory`. The size check is a heuristic that
/// sums every entry as if the archive were one solid block, with checked
/// arithmetic.
///
/// # Errors
///
/// Returns [`ArchiveError::SecurityViolation`] when solid archives are not
/// allowed and [`ArchiveError::QuotaExceeded`] when the size check fails.
pub fn check_solid_policy(
    is_solid: bool,
    sizes: impl IntoIterator<Item = u64>,
    config: &SecurityConfig<Validated>,
) -> Result<()> {
    if !is_solid {
        return Ok(());
    }
    if !config.allow_solid_archives {
        return Err(ArchiveError::SecurityViolation {
            reason: "solid 7z archives are not allowed (enable allow_solid_archives)".into(),
        });
    }

    let total_uncompressed =
        sizes
            .into_iter()
            .try_fold(0u64, u64::checked_add)
            .ok_or(ArchiveError::QuotaExceeded {
                resource: QuotaResource::TotalSize {
                    current: u64::MAX,
                    max: config.max_solid_block_memory,
                },
            })?;
    if total_uncompressed > config.max_solid_block_memory {
        return Err(ArchiveError::QuotaExceeded {
            resource: QuotaResource::TotalSize {
                current: total_uncompressed,
                max: config.max_solid_block_memory,
            },
        });
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

/// What the file table says about one block, gathered in a single pass.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct BlockShape {
    /// Sum of the declared sizes of the files mapped to the block.
    declared_size: u64,
    /// A stream-less file sits between the block's stream files.
    interleaved_entry: bool,
    /// The block declares streams, but the files it decodes are not exactly the
    /// files mapped to it: an orphan block no file maps to, or a stream count
    /// that disagrees with the mapping.
    span_mismatch: bool,
}

/// The files the decoder hands out for `block`: the span of its first file and
/// its `num_unpack_sub_streams`.
///
/// sevenz-rust2 validated that the span lies within `archive.files`.
pub(super) fn block_span(archive: &Archive, block: usize) -> std::ops::Range<usize> {
    let password = Password::empty();
    let mut no_source = io::Cursor::new(&[][..]);
    let count = BlockDecoder::new(1, block, archive, &password, &mut no_source).entry_count();
    let first = archive.stream_map.block_first_file_index[block];
    first..first.saturating_add(count)
}

/// Maps every block to its [`BlockShape`] through
/// `stream_map.file_block_index`.
///
/// sevenz-rust2 hands a block the contiguous span of `num_unpack_sub_streams`
/// files after its first file, so a stream-less file mapped to a block (the
/// map leaves leading and trailing ones unmapped) pushes the block's last
/// stream file out of the span and the decoder skips it. A trailing block that
/// no file maps to keeps a first-file index of 0, so its span would re-deliver
/// the first files of the archive with its own data.
pub(super) fn block_shapes(archive: &Archive) -> Vec<BlockShape> {
    let mut shapes = vec![BlockShape::default(); archive.blocks.len()];
    let spans: Vec<_> = (0..archive.blocks.len())
        .map(|block| block_span(archive, block))
        .collect();
    let mut mapped = vec![0usize; archive.blocks.len()];
    let mut outside_span = vec![false; archive.blocks.len()];
    for (index, file) in archive.files.iter().enumerate() {
        if let Some(block) = archive.stream_map.file_block_index[index] {
            let shape = &mut shapes[block];
            shape.declared_size = shape.declared_size.saturating_add(file.size);
            shape.interleaved_entry |= !file.has_stream;
            mapped[block] += 1;
            outside_span[block] |= !spans[block].contains(&index);
        }
    }
    for (block, shape) in shapes.iter_mut().enumerate() {
        shape.span_mismatch = !spans[block].is_empty()
            && (outside_span[block] || mapped[block] != spans[block].len());
    }
    shapes
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
/// Returns [`ArchiveError::QuotaExceeded`] when the decoder memory exceeds the
/// limit, [`ArchiveError::SecurityViolation`] for AES content encryption, and
/// [`ArchiveError::InvalidArchive`] for an unknown method, unparseable coder
/// properties, a stream-less file inside the block, or a block whose decoded
/// files are not the files mapped to it.
pub(super) fn admit_sevenz_block(
    block: &sevenz_rust2::Block,
    shape: BlockShape,
    config: &SecurityConfig<Validated>,
) -> Result<()> {
    let output = block_charge(block).max(shape.declared_size);
    let mut memory: u64 = 0;
    for coder in &block.coders {
        if coder.encoder_method_id() == sevenz_rust2::EncoderMethod::ID_AES256_SHA256 {
            return Err(common::encrypted_archive_error());
        }
        let needed = coder_memory(coder, output).ok_or_else(|| {
            ArchiveError::InvalidArchive(
                "7z block uses an unsupported coder or malformed coder properties".into(),
            )
        })?;
        memory = memory.saturating_add(needed);
    }
    if memory > config.max_decoder_memory {
        return Err(ArchiveError::QuotaExceeded {
            resource: QuotaResource::DecoderMemory {
                max: config.max_decoder_memory,
            },
        });
    }
    if shape.interleaved_entry {
        return Err(ArchiveError::InvalidArchive(
            "7z block interleaves a stream-less entry, so a file of the block would be skipped"
                .into(),
        ));
    }
    if shape.span_mismatch {
        return Err(ArchiveError::InvalidArchive(
            "7z block decodes files other than the ones mapped to it".into(),
        ));
    }
    Ok(())
}

/// Part of a 7z archive that a policy refuses to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalScope {
    /// The whole archive.
    Archive,
    /// One block, by index.
    Block(usize),
}

/// A refusal of extraction, shared by `extract` and `verify`.
#[derive(Debug)]
pub struct SevenZRefusal {
    pub(super) scope: RefusalScope,
    pub(super) error: ArchiveError,
}

impl SevenZRefusal {
    /// Why the payload the refusal covers stays unverified.
    pub(super) fn unverified(&self) -> UnverifiedReason {
        match (&self.error, self.scope) {
            (ArchiveError::QuotaExceeded { .. }, _) => UnverifiedReason::ResourceLimit,
            (ArchiveError::SecurityViolation { .. }, RefusalScope::Archive) => {
                UnverifiedReason::SolidPolicy
            }
            _ => UnverifiedReason::NotDecodable,
        }
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
/// encryption and stream-less files interleaved in a block.
///
/// The iterator is lazy: `extract` takes only the first refusal and stops
/// checking blocks there.
pub fn iter_sevenz_refusals<'a>(
    archive: &'a Archive,
    config: &'a SecurityConfig<Validated>,
) -> impl Iterator<Item = SevenZRefusal> + 'a {
    let solid = check_solid_policy(
        archive.is_solid,
        archive.files.iter().map(|f| f.size),
        config,
    )
    .err()
    .map(|error| SevenZRefusal {
        scope: RefusalScope::Archive,
        error,
    });
    let blocks = archive
        .blocks
        .iter()
        .zip(block_shapes(archive))
        .enumerate()
        .filter_map(move |(index, (block, shape))| {
            admit_sevenz_block(block, shape, config)
                .err()
                .map(|error| SevenZRefusal {
                    scope: RefusalScope::Block(index),
                    error,
                })
        });
    solid.into_iter().chain(blocks)
}

/// Every refusal of [`iter_sevenz_refusals`], for `verify` to report.
pub fn sevenz_refusals(
    archive: &Archive,
    config: &SecurityConfig<Validated>,
) -> Vec<SevenZRefusal> {
    iter_sevenz_refusals(archive, config).collect()
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
            IssueCategory::InvalidArchive,
            format!("{omitted} further 7z refusals are not listed"),
        ));
    }
    issues
}
