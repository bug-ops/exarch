//! Integrity pass over the blocks of a 7z archive for `verify` and `list`.

use super::admit::RefusalScope;
use super::admit::block_charge;
use super::admit::sevenz_refusals;
use super::decode::decode_block_entries;
use super::decode::is_sevenz_payload;
use super::header::BlockIndex;
use super::header::PerBlock;
use super::header::SevenZHeader;
use super::links::BlockScan;
use super::links::BlockStop;
use super::links::LinkCapture;
use super::lzma2::DecodeKnobs;
use crate::Result;
use crate::formats::common;
use crate::inspection::integrity::DecodeFailure;
use crate::inspection::integrity::DecodeOutcome;
use crate::inspection::integrity::IntegrityPass;
use crate::inspection::integrity::Slot;
use crate::inspection::list::Progress;
use crate::inspection::report::UnverifiedReason;
use std::collections::BTreeSet;
use std::io::Read;
use std::io::Seek;
use std::path::Path;
use std::path::PathBuf;

/// A payload file of a block: its archive file index and integrity slot.
pub(super) type PayloadFile = (usize, Slot);

/// Groups the payload files of each block through
/// `stream_map.file_block_index`.
///
/// Going through the file-to-block map lets the caller see every payload file
/// that belongs to a block, whether or not the decoder visits it.
pub(super) fn payload_by_block(
    header: &SevenZHeader,
    slots: &[Option<Slot>],
) -> PerBlock<Vec<PayloadFile>> {
    let mut blocks = header.per_block(Vec::new());
    for index in 0..header.files().len() {
        if let (Some(block), Some(Some(slot)), true) = (
            header.file_block(index),
            slots.get(index),
            is_decode_announced(header, index, true),
        ) {
            blocks[block].push((index, *slot));
        }
    }
    blocks
}

/// Whether the integrity decode of the file at `index` (rather than the listing
/// walk) reports it: a payload file that has an integrity slot (`has_slot`) and
/// belongs to a block.
pub(crate) fn is_decode_announced(header: &SevenZHeader, index: usize, has_slot: bool) -> bool {
    has_slot
        && header.file_block(index).is_some()
        && header.files().get(index).is_some_and(is_sevenz_payload)
}

/// Decodes every payload block of a parsed 7z archive for an integrity pass.
///
/// `slots` maps each archive file to its integrity slot (`None` for an anti
/// item), as built by the listing loop. Blocks are the admission unit: a block
/// is decoded only when the solid policy, quota and ratio checks, decoder
/// memory and the budget all allow it, and blocks are tried first-fit.
/// Per-entry CRC mismatches keep the stream aligned, so the scan continues; any
/// other failure abandons the block. A payload file the decoder never visits is
/// counted as not decodable, so no file can escape the check. The block CRC
/// fires only once the whole block has been read, so it is attributed to the
/// block's last entry.
///
/// When `links` is set, the targets of the listed links inside decoded blocks
/// are read in the same decode and handed to it. The links of a block that
/// policy refuses to decode are handed over as unreadable; links the pass
/// leaves undecoded for its quota or budget stay unread.
///
/// # Errors
///
/// Returns the I/O error of a failing disk read, or an error for a link target
/// that is not UTF-8.
pub(crate) fn verify_sevenz_blocks<R: Read + Seek>(
    header: &SevenZHeader,
    source: &mut R,
    pass: &mut IntegrityPass<'_>,
    progress: &mut Progress<'_>,
    slots: &[Option<Slot>],
    mut links: Option<LinkCapture<'_>>,
) -> Result<()> {
    let payload = payload_by_block(header, slots);
    let mut refused = header.per_block(None);
    for refusal in sevenz_refusals(header, pass.config()) {
        match refusal.scope {
            RefusalScope::Archive => {
                let indices = || payload.iter().flatten().map(|&(index, _)| index);
                if let Some(capture) = links.as_mut() {
                    capture.mark_unreadable(header, indices());
                }
                mark_files(pass, header, refusal.unverified(), indices());
                announce_skipped(progress, header, indices())?;
                return Ok(());
            }
            RefusalScope::Block(index) => refused[index] = Some(refusal.unverified()),
        }
    }

    let decode = DecodeContext {
        slots,
        knobs: DecodeKnobs::production(),
    };
    for (block_index, files) in header.block_indices().zip(payload.iter()) {
        if files.is_empty() {
            continue;
        }
        if let Some(reason) = refused[block_index] {
            let indices = || files.iter().map(|&(index, _)| index);
            if let Some(capture) = links.as_mut() {
                capture.mark_unreadable(header, indices());
            }
            mark_files(pass, header, reason, indices());
            announce_skipped(progress, header, indices())?;
        } else {
            let capture = links.as_mut().map(|capture| LinkCapture {
                links: capture.links,
                set: &mut *capture.set,
            });
            let job = BlockJob {
                index: block_index,
                payload: files,
            };
            verify_sevenz_block(header, source, pass, progress, decode, job, capture)?;
        }
    }
    Ok(())
}

/// Path of the archive file at `index`, as listed in the manifest.
pub(super) fn file_path(header: &SevenZHeader, index: usize) -> PathBuf {
    PathBuf::from(common::normalize_entry_name(&file_at(header, index).name))
}

/// The archive file at `index`, an index of the payload lists built from
/// `files().iter().enumerate()` or the decoder's file counter, which
/// `is_decode_announced` checks with `files().get(index)`.
#[expect(
    clippy::indexing_slicing,
    reason = "indices come from `files().iter().enumerate()` payload lists and from the decoder's file counter, which `is_decode_announced` checks with `files().get(index)`"
)]
fn file_at(header: &SevenZHeader, index: usize) -> &sevenz_rust2::ArchiveEntry {
    &header.files()[index]
}

/// Announces and closes the archive files at `indices`, whose payload the
/// decode never reached, so every payload file is reported exactly once.
fn announce_skipped(
    progress: &mut Progress<'_>,
    header: &SevenZHeader,
    indices: impl Iterator<Item = usize>,
) -> Result<()> {
    for index in indices {
        progress.begin(&file_path(header, index))?.complete();
    }
    Ok(())
}

/// Marks the archive files at `indices` as unverified for `reason`.
pub(super) fn mark_files(
    pass: &mut IntegrityPass<'_>,
    header: &SevenZHeader,
    reason: UnverifiedReason,
    indices: impl Iterator<Item = usize>,
) {
    for index in indices {
        pass.mark_unverified(reason, &file_path(header, index));
    }
}

/// Records a block failure against `lead` and marks the `others` further
/// files unverified under the matching reason.
pub(super) fn record_block_failure(
    pass: &mut IntegrityPass<'_>,
    header: &SevenZHeader,
    lead: (&Path, Slot),
    failure: DecodeFailure,
    others: &[usize],
) -> Result<()> {
    let reason = match failure {
        DecodeFailure::ResourceLimit(_) => UnverifiedReason::ResourceLimit,
        _ => UnverifiedReason::NotDecodable,
    };
    pass.record(lead.1, lead.0, DecodeOutcome::Failed(failure))?;
    mark_files(pass, header, reason, others.iter().copied());
    Ok(())
}

/// Lists the entries that only a block CRC could cover but that CRC cannot.
///
/// The block CRC fires once the whole block output was read, which never
/// happens when the entries' sizes do not add up to the block's output. An
/// entry with its own CRC is covered regardless.
pub(super) fn entries_uncovered_by_block_crc(
    block_has_crc: bool,
    entry_sizes: u64,
    block_size: u64,
    entries: impl Iterator<Item = (usize, bool)>,
) -> Vec<usize> {
    if !block_has_crc || entry_sizes == block_size {
        return Vec::new();
    }
    entries
        .filter(|&(_, has_crc)| !has_crc)
        .map(|(index, _)| index)
        .collect()
}

/// What `verify` shares between the blocks of one archive.
#[derive(Clone, Copy)]
pub(super) struct DecodeContext<'a> {
    slots: &'a [Option<Slot>],
    knobs: DecodeKnobs,
}

/// Decodes one file of a block, announcing it when it is a payload file with an
/// integrity slot, which the listing walk left to this decode.
fn visit_announced(
    scan: &mut BlockScan<'_, '_>,
    progress: &mut Progress<'_>,
    header: &SevenZHeader,
    file: &sevenz_rust2::ArchiveEntry,
    reader: &mut dyn Read,
) -> bool {
    let index = scan.next_file;
    if !is_decode_announced(
        header,
        index,
        matches!(scan.slots.get(index), Some(Some(_))),
    ) {
        return scan.visit(file, reader);
    }
    let path = file_path(header, index);
    let in_flight = match progress.begin(&path) {
        Ok(guard) => guard,
        Err(error) => {
            scan.stop = Some(BlockStop::Fatal(error));
            return false;
        }
    };
    let keep_going = scan.visit(file, reader);
    in_flight.complete();
    keep_going
}

/// One block and the payload files it holds.
#[derive(Clone, Copy)]
pub(super) struct BlockJob<'a> {
    index: BlockIndex,
    payload: &'a [PayloadFile],
}

pub(super) fn verify_sevenz_block<R: Read + Seek>(
    header: &SevenZHeader,
    source: &mut R,
    pass: &mut IntegrityPass<'_>,
    progress: &mut Progress<'_>,
    decode: DecodeContext<'_>,
    job: BlockJob<'_>,
    links: Option<LinkCapture<'_>>,
) -> Result<()> {
    let DecodeContext { slots, knobs } = decode;
    let BlockJob {
        index: block_index,
        payload,
    } = job;
    let block = header.block(block_index);
    let all = payload.iter().map(|&(index, _)| index);

    if payload.iter().any(|&(_, slot)| !pass.is_admitted(slot)) {
        mark_files(pass, header, UnverifiedReason::ResourceLimit, all.clone());
        announce_skipped(progress, header, all)?;
        return Ok(());
    }

    if !pass.try_charge(block_charge(block)) {
        mark_files(pass, header, UnverifiedReason::OverBudget, all.clone());
        announce_skipped(progress, header, all)?;
        return Ok(());
    }

    let first = header.block_first_file(block_index);
    let mut scan = BlockScan {
        pass,
        slots,
        links: links.map(|capture| LinkCapture {
            links: capture.links,
            set: &mut *capture.set,
        }),
        next_file: first,
        visited: BTreeSet::new(),
        stop: None,
    };
    let parallel = scan.pass.config().parallel_decode;
    let result = decode_block_entries(
        source,
        header,
        block_index,
        parallel,
        knobs,
        &mut |file, reader| Ok(visit_announced(&mut scan, progress, header, file, reader)),
    );
    let (stop, visited) = (scan.stop.take(), scan.visited);

    let unvisited: Vec<usize> = all.filter(|index| !visited.contains(index)).collect();
    announce_skipped(progress, header, unvisited.iter().copied())?;
    match (stop, result) {
        (Some(BlockStop::Fatal(e)), _) => return Err(e),
        (Some(BlockStop::Abandoned(reason)), _) => {
            mark_files(pass, header, reason, unvisited.into_iter());
        }
        (None, Err(e)) => {
            // A failure outside the per-entry callbacks belongs to the last
            // entry the decoder reached (where a block CRC would
            // fire), else the first.
            let Some(&(index, slot)) = payload
                .iter()
                .rev()
                .find(|(index, _)| visited.contains(index))
                .or_else(|| payload.first())
            else {
                return Err(e.into());
            };
            let path = file_path(header, index);
            let others: Vec<usize> = unvisited.into_iter().filter(|&i| i != index).collect();
            return record_block_failure(
                pass,
                header,
                (path.as_path(), slot),
                DecodeFailure::from_sevenz(e),
                &others,
            );
        }
        (None, Ok(_)) => {
            mark_files(
                pass,
                header,
                UnverifiedReason::NotDecodable,
                unvisited.into_iter(),
            );
            let entry_sizes = payload
                .iter()
                .map(|&(index, _)| file_at(header, index).size)
                .fold(0, u64::saturating_add);
            let own_crcs = payload
                .iter()
                .filter(|(index, _)| visited.contains(index))
                .map(|&(index, _)| (index, file_at(header, index).has_crc));
            let uncovered = entries_uncovered_by_block_crc(
                block.has_crc,
                entry_sizes,
                block.get_unpack_size(),
                own_crcs,
            );
            mark_files(
                pass,
                header,
                UnverifiedReason::UncoveredBlockCrc,
                uncovered.into_iter(),
            );
        }
    }
    Ok(())
}
