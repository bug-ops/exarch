//! Consistency checks for TAR headers and extension headers.
//!
//! The `tar` crate, `bsdtar` and the Python `tarfile` module resolve some
//! header fields and extension records differently: which of two `path`
//! records wins, whether a GNU long name or a PAX `path` has priority, whether
//! a global header applies to later entries, how a sign or a control character
//! inside a numeric field reads, and whether a `prefix` field is honoured. An
//! archive that relies on any of those choices reads as different files in
//! different tools.
//!
//! This module does not frame archives itself. It inspects the header and the
//! extension records the `tar` crate has already attached to a yielded entry
//! and refuses the constructs on which the readers are known to disagree. The
//! raw bytes of a merged `x`, `L` or `K` header are not visible after the
//! `tar` crate consumes them, so the [`window`] child module verifies the
//! bytes the `tar` crate read to reach the entry: the checksum and size of
//! every header and the framing of a local PAX body.

mod window;

use std::collections::HashSet;
use std::io::Read;

use tar::Entry;
use tar::EntryType;
use tar::Header;
use tar::PaxExtensions;

use crate::ArchiveError;
use crate::Malformation;
use crate::Result;
use crate::TarAmbiguity;
use crate::TarExtensionKind;
use crate::TarHeaderField;
use crate::TarPathKey;
use crate::formats::tar_metadata_limit::MetadataWindow;

const PAX_PATH: &[u8] = b"path";
const PAX_LINKPATH: &[u8] = b"linkpath";
const PAX_SIZE: &[u8] = b"size";
const PAX_SPARSE_PREFIX: &[u8] = b"GNU.sparse.";
const PAX_REALSIZE: &[u8] = b"SCHILY.realsize";

/// Longest PAX record `libarchive` accepts, in bytes.
pub const MAX_PAX_RECORD_BYTES: usize = 999_999;

/// Longest key or name echoed in an error message.
const MAX_ECHOED_BYTES: usize = 256;

const SIZE_FIELD: std::ops::Range<usize> = 124..136;
const CHECKSUM_FIELD: std::ops::Range<usize> = 148..156;
const PREFIX_OFFSET: usize = 345;
const BASE256_MARKER: u8 = 0x80;

/// Whether a PAX header describes the next entry or every later entry.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PaxScope {
    Local,
    Global,
}

/// Kind of the entry a header window follows, which decides whether the
/// padding at the start of the window belongs to a global PAX body.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PrecedingEntry {
    /// No entry yet, or an entry whose padding readers never parse.
    #[default]
    Other,
    /// A global PAX header, whose padded block readers parse as records.
    GlobalPax,
}

/// Path overrides a local PAX header carries, owned so the entry can be
/// queried again afterwards.
#[derive(Default)]
struct PathOverrides {
    path: Option<Vec<u8>>,
    linkpath: Option<Vec<u8>>,
}

fn lossy(bytes: &[u8]) -> String {
    let shown = &bytes[..bytes.len().min(MAX_ECHOED_BYTES)];
    let mut text = crate::bytes_text(shown);
    if shown.len() < bytes.len() {
        text.push_str("...");
    }
    text
}

/// Length of the `"<len> <key>=<value>\n"` record, counting the length digits.
fn record_len(key: &[u8], value: &[u8]) -> usize {
    let base = key.len().saturating_add(value.len()).saturating_add(3);
    let mut digits = 1;
    loop {
        let total = base.saturating_add(digits);
        let needed = total.checked_ilog10().map_or(1, |d| d as usize + 1);
        if needed <= digits {
            return total;
        }
        digits = needed;
    }
}

fn scan_records(records: PaxExtensions<'_>, scope: PaxScope) -> Result<PathOverrides> {
    let mut seen: HashSet<&[u8]> = HashSet::new();
    let mut overrides = PathOverrides::default();
    for record in records {
        let record = record.map_err(|_| TarAmbiguity::MalformedRecord)?;
        let key = record.key_bytes();
        let value = record.value_bytes();
        if key.is_empty() {
            return Err(TarAmbiguity::EmptyKey.into());
        }
        if record_len(key, value) > MAX_PAX_RECORD_BYTES {
            return Err(TarAmbiguity::OversizedRecord { key: lossy(key) }.into());
        }
        if !seen.insert(key) {
            return Err(TarAmbiguity::DuplicateRecord { key: lossy(key) }.into());
        }
        if key.starts_with(PAX_SPARSE_PREFIX) || key == PAX_REALSIZE {
            return Err(TarAmbiguity::UnsupportedRecord { key: lossy(key) }.into());
        }
        let overrides_entry = [PAX_PATH, PAX_LINKPATH, PAX_SIZE].contains(&key);
        if scope == PaxScope::Global && overrides_entry {
            return Err(TarAmbiguity::GlobalOverride { key: lossy(key) }.into());
        }
        match key {
            PAX_PATH => overrides.path = Some(value.to_vec()),
            PAX_LINKPATH => overrides.linkpath = Some(value.to_vec()),
            PAX_SIZE if !is_decimal(value) => {
                return Err(TarAmbiguity::InvalidSize.into());
            }
            _ => {}
        }
    }
    Ok(overrides)
}

fn is_decimal(value: &[u8]) -> bool {
    std::str::from_utf8(value)
        .is_ok_and(|text| text.bytes().all(|b| b.is_ascii_digit()) && text.parse::<u64>().is_ok())
}

/// Checks that `body` is a sequence of canonical `"<len> <key>=<value>\n"`
/// records covering every byte: no sign or leading zero in a length, no blank
/// line, no trailing bytes.
fn check_record_framing(body: &[u8]) -> Result<()> {
    let mut rest = body;
    while !rest.is_empty() {
        let space = rest
            .iter()
            .position(|&b| b == b' ')
            .ok_or(TarAmbiguity::MalformedRecord)?;
        let digits = &rest[..space];
        let canonical = !digits.is_empty()
            && digits.iter().all(u8::is_ascii_digit)
            && (digits.len() == 1 || digits[0] != b'0');
        let len = canonical
            .then(|| std::str::from_utf8(digits).ok()?.parse::<usize>().ok())
            .flatten()
            .filter(|len| (1..=MAX_PAX_RECORD_BYTES).contains(len))
            .ok_or(TarAmbiguity::MalformedRecord)?;
        let record = rest.get(..len).ok_or(TarAmbiguity::MalformedRecord)?;
        if record.last() != Some(&b'\n') {
            return Err(TarAmbiguity::MalformedRecord.into());
        }
        rest = &rest[len..];
    }
    Ok(())
}

/// Whether `field` is digits `0`-`7` between optional leading spaces and
/// trailing spaces or NULs, the only form every reader reads the same way.
fn is_plain_octal(field: &[u8]) -> bool {
    let leading_spaces = field.iter().take_while(|&&b| b == b' ').count();
    let trimmed = &field[leading_spaces..];
    let digits = trimmed
        .iter()
        .take_while(|b| (b'0'..=b'7').contains(b))
        .count();
    digits > 0 && trimmed[digits..].iter().all(|&b| b == b' ' || b == 0)
}

/// Whether `field` is a base-256 number that fits 64 bits without a sign.
fn is_plain_base256(field: &[u8]) -> bool {
    field.first() == Some(&BASE256_MARKER) && field[1..4].iter().all(|&b| b == 0)
}

fn check_header_fields(header: &Header) -> Result<()> {
    check_header_block(header.as_bytes(), header.as_ustar().is_some())
}

fn check_header_block(bytes: &[u8; 512], has_ustar_magic: bool) -> Result<()> {
    if !is_plain_octal(&bytes[SIZE_FIELD]) && !is_plain_base256(&bytes[SIZE_FIELD]) {
        return Err(TarAmbiguity::NonCanonicalNumber {
            field: TarHeaderField::Size,
        }
        .into());
    }
    if !is_plain_octal(&bytes[CHECKSUM_FIELD]) {
        return Err(TarAmbiguity::NonCanonicalNumber {
            field: TarHeaderField::Checksum,
        }
        .into());
    }
    if !has_ustar_magic && bytes[PREFIX_OFFSET] != 0 {
        return Err(TarAmbiguity::PrefixWithoutUstar.into());
    }
    Ok(())
}

/// Checks the bytes `tar` read after the last entry when that entry was a
/// global PAX header: its padding must be zero like any extension body's.
///
/// # Errors
///
/// Returns [`ArchiveError::InvalidArchive`] when the padding is not zero.
pub fn check_trailing_headers(
    window: &MetadataWindow<'_>,
    preceding: PrecedingEntry,
) -> Result<()> {
    match preceding {
        PrecedingEntry::GlobalPax => window::check_trailing_global_padding(window),
        PrecedingEntry::Other => Ok(()),
    }
}

/// Refuses an entry whose header or extension headers readers would resolve
/// differently.
///
/// Called for every entry the `tar` crate yields, metadata entries included,
/// before the entry is listed, verified or extracted, by
/// `TarEntryGuard::check`. `window` holds the bytes the `tar` crate read to
/// reach the entry: the checksum and size of every header in it must be plain,
/// a local PAX body must have canonical framing, and the blocks must end
/// exactly at the entry's header.
///
/// The header's size and checksum fields must be plain octal (or a base-256
/// size), a header without a ustar magic must leave the `prefix` area empty,
/// and GNU sparse entries are refused. A local PAX header must have unique,
/// well-formed records, no GNU sparse or `SCHILY.realsize` records and no GNU
/// long name or link record overriding its `path` or `linkpath`, and no `size`
/// record in the same extension chain as a GNU long name or link record. A
/// global PAX header (`git archive` writes one carrying only a `comment`) must
/// be well-formed, must not carry `path`, `linkpath` or `size`, and must not
/// follow a local header or a GNU long record.
///
/// `metadata_limit` bounds how much of a global header is read. `preceding`
/// is the value returned for the previous entry: the padding after a global
/// header and after every extension header body must be zero, and a GNU long
/// name or link body must be one NUL-terminated string.
///
/// Returns the kind of this entry, to pass as `preceding` for the next one.
///
/// # Errors
///
/// Returns [`ArchiveError::InvalidArchive`] naming the ambiguous construct, or
/// when the header body cannot be read.
pub fn check_entry_headers<R: Read>(
    entry: &mut Entry<'_, R>,
    window: &MetadataWindow<'_>,
    metadata_limit: u64,
    preceding: PrecedingEntry,
) -> Result<PrecedingEntry> {
    check_parsed_headers(entry, metadata_limit)?;
    window::check_window(
        window,
        preceding,
        entry.raw_header_position(),
        entry.raw_file_position(),
    )?;
    Ok(if entry.header().entry_type() == EntryType::XGlobalHeader {
        PrecedingEntry::GlobalPax
    } else {
        PrecedingEntry::Other
    })
}

fn check_parsed_headers<R: Read>(entry: &mut Entry<'_, R>, metadata_limit: u64) -> Result<()> {
    check_header_fields(entry.header())?;
    match entry.header().entry_type() {
        EntryType::XHeader => Err(unrecognized(TarExtensionKind::Pax)),
        EntryType::GNULongName => Err(unrecognized(TarExtensionKind::LongName)),
        EntryType::GNULongLink => Err(unrecognized(TarExtensionKind::LongLink)),
        EntryType::GNUSparse => Err(TarAmbiguity::SparseEntry.into()),
        EntryType::XGlobalHeader => check_global_header(entry, metadata_limit),
        _ => check_local_headers(entry),
    }
}

fn unrecognized(kind: TarExtensionKind) -> ArchiveError {
    TarAmbiguity::UnrecognizedHeader { kind }.into()
}

fn pax_header_unreadable(error: &std::io::Error) -> ArchiveError {
    ArchiveError::InvalidArchive(Malformation::TarPaxHeaderUnreadable {
        detail: error.to_string().into(),
    })
}

fn check_local_headers<R: Read>(entry: &mut Entry<'_, R>) -> Result<()> {
    let overrides = match entry
        .pax_extensions()
        .map_err(|e| pax_header_unreadable(&e))?
    {
        Some(records) => scan_records(records, PaxScope::Local)?,
        None => return Ok(()),
    };

    if let Some(pax_path) = overrides.path
        && *entry.path_bytes() != *pax_path
    {
        return Err(TarAmbiguity::StackedLongRecord {
            key: TarPathKey::Path,
        }
        .into());
    }
    if let Some(pax_linkpath) = overrides.linkpath
        && entry.link_name_bytes().as_deref() != Some(pax_linkpath.as_slice())
    {
        return Err(TarAmbiguity::StackedLongRecord {
            key: TarPathKey::LinkPath,
        }
        .into());
    }
    Ok(())
}

fn check_global_header<R: Read>(entry: &mut Entry<'_, R>, metadata_limit: u64) -> Result<()> {
    let size = entry.size();
    if size > metadata_limit {
        return Err(TarAmbiguity::GlobalTooLarge {
            size,
            limit: metadata_limit,
        }
        .into());
    }

    let mut body = Vec::new();
    entry
        .by_ref()
        .take(metadata_limit)
        .read_to_end(&mut body)
        .map_err(|e| pax_header_unreadable(&e))?;

    // The body is already consumed, so only a local header the `tar` crate
    // attached to this entry is still visible here.
    let follows_local = entry
        .pax_extensions()
        .map_err(|e| pax_header_unreadable(&e))?
        .is_some_and(|mut records| records.next().is_some());
    if follows_local {
        return Err(TarAmbiguity::LocalBeforeGlobal.into());
    }

    let header = entry.header();
    if *entry.path_bytes() != *header.path_bytes()
        || entry.link_name_bytes() != header.link_name_bytes()
    {
        return Err(TarAmbiguity::LongRecordBeforeGlobal.into());
    }

    scan_records(PaxExtensions::new(&body), PaxScope::Global)?;
    check_record_framing(&body)
}
