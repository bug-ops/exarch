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

use window::WindowWalk;

use std::collections::HashSet;
use std::io::Read;
use std::time::Duration;
use std::time::SystemTime;

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
use crate::TarNonRegularKind;
use crate::TarPathKey;
use crate::formats::tar_metadata_limit::MetadataWindow;

const PAX_PATH: &[u8] = b"path";
const PAX_LINKPATH: &[u8] = b"linkpath";
const PAX_SIZE: &[u8] = b"size";
const PAX_MTIME: &[u8] = b"mtime";
const PAX_SPARSE_PREFIX: &[u8] = b"GNU.sparse.";
const PAX_REALSIZE: &[u8] = b"SCHILY.realsize";
const PAX_HOLESDATA: &[u8] = b"SUN.holesdata";

/// Longest PAX record `libarchive` accepts, in bytes.
pub(crate) const MAX_PAX_RECORD_BYTES: usize = 999_999;

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
pub(crate) enum PrecedingEntry {
    /// No entry yet, or an entry whose padding readers never parse.
    #[default]
    Other,
    /// A global PAX header, whose padded block readers parse as records.
    GlobalPax,
}

/// What a local PAX header overrides, owned so the entry can be queried again
/// afterwards.
#[derive(Default)]
struct LocalOverrides {
    path: Option<Vec<u8>>,
    linkpath: Option<Vec<u8>>,
    mtime: Option<SystemTime>,
}

/// What [`check_entry_headers`] learned about an entry besides refusing it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CheckedHeaders {
    /// The kind of this entry, to pass as `preceding` for the next one.
    pub(crate) preceding: PrecedingEntry,
    /// The modification time a local PAX `mtime` record declares, when it
    /// parses.
    pub(crate) mtime: Option<SystemTime>,
}

/// Reads a PAX `mtime` value, `-?digits(.digits)?`, as a time. The fraction is
/// cut to nanoseconds; a value that does not fit or does not parse is ignored,
/// so the header mtime stays in effect.
fn parse_pax_mtime(value: &[u8]) -> Option<SystemTime> {
    let (negative, unsigned) = value
        .strip_prefix(b"-")
        .map_or((false, value), |rest| (true, rest));
    let (whole, fraction) = match unsigned.iter().position(|&b| b == b'.') {
        Some(dot) => {
            let (whole, rest) = unsigned.split_at(dot);
            (whole, Some(rest.get(1..)?))
        }
        None => (unsigned, None),
    };
    let digits_only = |part: &[u8]| !part.is_empty() && part.iter().all(u8::is_ascii_digit);
    if !digits_only(whole) || fraction.is_some_and(|f| !digits_only(f)) {
        return None;
    }
    let seconds: u64 = std::str::from_utf8(whole).ok()?.parse().ok()?;
    let nanos: u32 = match fraction {
        Some(f) => {
            let nine: Vec<u8> = f
                .iter()
                .copied()
                .chain(std::iter::repeat(b'0'))
                .take(9)
                .collect();
            std::str::from_utf8(&nine).ok()?.parse().ok()?
        }
        None => 0,
    };
    let offset = Duration::new(seconds, nanos);
    if negative {
        SystemTime::UNIX_EPOCH.checked_sub(offset)
    } else {
        SystemTime::UNIX_EPOCH.checked_add(offset)
    }
}

fn lossy(bytes: &[u8]) -> String {
    let shown = bytes.get(..MAX_ECHOED_BYTES).unwrap_or(bytes);
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

/// One `"<len> <key>=<value>\n"` record, split by its declared length.
#[derive(Clone, Copy)]
struct PaxRecord<'a> {
    key: &'a [u8],
    value: &'a [u8],
}

/// Keys the `tar` crate reads itself while it splits a body at every newline.
const TAR_READ_KEYS: [&[u8]; 5] = [PAX_PATH, PAX_LINKPATH, PAX_SIZE, b"uid", b"gid"];
/// Keys whose lookup in the `tar` crate stops at the first line it cannot
/// parse.
const TAR_STOPPING_KEYS: [&[u8]; 3] = [PAX_SIZE, b"uid", b"gid"];

/// A framed PAX body with its records, parsed once.
struct ParsedPax<'w> {
    body: &'w [u8],
    records: Vec<PaxRecord<'w>>,
    declares_size: bool,
}

impl<'w> ParsedPax<'w> {
    /// Splits `body` into records by their declared length.
    fn parse(body: &'w [u8]) -> Result<Self> {
        let records = parse_records(body)?;
        let declares_size = records.iter().any(|record| record.key == PAX_SIZE);
        Ok(Self {
            body,
            records,
            declares_size,
        })
    }
}

fn parse_records(body: &[u8]) -> Result<Vec<PaxRecord<'_>>> {
    split_records(body)?
        .into_iter()
        .map(|record| {
            let space = record
                .iter()
                .position(|&b| b == b' ')
                .ok_or(TarAmbiguity::MalformedRecord)?;
            let text = record
                .get(space.saturating_add(1)..)
                .and_then(|rest| rest.strip_suffix(b"\n"))
                .ok_or(TarAmbiguity::MalformedRecord)?;
            let equals = text
                .iter()
                .position(|&b| b == b'=')
                .ok_or(TarAmbiguity::MalformedRecord)?;
            let (key, tail) = text.split_at(equals);
            if key.contains(&b'\n') {
                return Err(TarAmbiguity::MalformedRecord.into());
            }
            Ok(PaxRecord {
                key,
                value: tail.get(1..).unwrap_or_default(),
            })
        })
        .collect()
}

/// A record the `tar` crate yields: where its key starts in the body, and
/// whether it passed a line it could not parse first.
struct CrateRecord {
    key_offset: usize,
    after_unparsed: bool,
}

/// Where `part` starts in `body`, or `None` when it is not a slice of it.
fn offset_in(body: &[u8], part: &[u8]) -> Option<usize> {
    body.subslice_range(part).map(|range| range.start)
}

/// Replays how the `tar` crate reads a body: it splits at every newline, skips
/// a line it cannot parse and stops at an empty line.
///
/// A record that is not a slice of `body` is refused, because every offset
/// comparison below relies on the `tar` crate yielding slices of its input.
fn crate_records(body: &[u8]) -> Result<Vec<CrateRecord>> {
    let mut after_unparsed = false;
    let mut yielded = Vec::new();
    for item in PaxExtensions::new(body) {
        match item {
            Ok(record) => yielded.push(CrateRecord {
                key_offset: offset_in(body, record.key_bytes())
                    .ok_or(TarAmbiguity::MalformedRecord)?,
                after_unparsed,
            }),
            Err(_) => after_unparsed = true,
        }
    }
    Ok(yielded)
}

/// Requires that what the `tar` crate reads from a body agrees with the
/// declared records. Every record it yields must be a whole declared record
/// without a newline, at the same offset, so no record can be read out of the
/// middle of a value. A declared record with a key it acts on (`path`,
/// `linkpath`, `size`, `uid`, `gid`) must be one it yields, and for `size`,
/// `uid` and `gid` before any line it cannot parse. Other records may go
/// unseen. A `size` record the crate cannot see is accepted when its canonical
/// decimal value equals `header_size`, the size the crate uses, so every
/// reader reads the same length.
fn check_crate_view(pax: &ParsedPax<'_>, header_size: Option<u64>) -> Result<()> {
    let body = pax.body;
    let yielded = crate_records(body)?;
    let mut seen = yielded.iter().peekable();
    for record in &pax.records {
        let key_offset = offset_in(body, record.key).ok_or(TarAmbiguity::MalformedRecord)?;
        let matched = seen.next_if(|y| y.key_offset == key_offset);
        if TAR_READ_KEYS.contains(&record.key) {
            let stops = TAR_STOPPING_KEYS.contains(&record.key);
            let hidden = matched.is_none_or(|y| stops && y.after_unparsed);
            let equals_header = record.key == PAX_SIZE
                && header_size.is_some_and(|size| canonical_u64(record.value) == Some(size));
            if hidden && !equals_header {
                return Err(TarAmbiguity::MalformedRecord.into());
            }
        }
    }
    // A yielded record that matched no declared key offset lies inside a value
    // and blocks every later match, so it is always left over here. A record
    // yielded at a declared key offset is that record: key and value agree.
    if seen.next().is_some() {
        return Err(TarAmbiguity::MalformedRecord.into());
    }
    Ok(())
}

fn scan_records(
    pax: &ParsedPax<'_>,
    scope: PaxScope,
    header_size: Option<u64>,
) -> Result<LocalOverrides> {
    check_crate_view(pax, header_size)?;
    let mut seen: HashSet<&[u8]> = HashSet::new();
    let mut overrides = LocalOverrides::default();
    for &PaxRecord { key, value } in &pax.records {
        if key.is_empty() {
            return Err(TarAmbiguity::EmptyKey.into());
        }
        if record_len(key, value) > MAX_PAX_RECORD_BYTES {
            return Err(TarAmbiguity::OversizedRecord { key: lossy(key) }.into());
        }
        if !seen.insert(key) {
            return Err(TarAmbiguity::DuplicateRecord { key: lossy(key) }.into());
        }
        if key.starts_with(PAX_SPARSE_PREFIX) || key == PAX_REALSIZE || key == PAX_HOLESDATA {
            return Err(TarAmbiguity::UnsupportedRecord { key: lossy(key) }.into());
        }
        let overrides_entry = [PAX_PATH, PAX_LINKPATH, PAX_SIZE].contains(&key);
        if scope == PaxScope::Global && overrides_entry {
            return Err(TarAmbiguity::GlobalOverride { key: lossy(key) }.into());
        }
        match key {
            PAX_PATH => overrides.path = Some(value.to_vec()),
            PAX_LINKPATH => overrides.linkpath = Some(value.to_vec()),
            PAX_MTIME => overrides.mtime = parse_pax_mtime(value),
            PAX_SIZE if !is_decimal(value) => {
                return Err(TarAmbiguity::InvalidSize.into());
            }
            _ => {}
        }
    }
    Ok(overrides)
}

/// Parses `value` only when it is plain decimal digits without a sign or a
/// leading zero and fits 64 bits.
fn canonical_u64(value: &[u8]) -> Option<u64> {
    let canonical =
        value.iter().all(u8::is_ascii_digit) && (value.len() == 1 || value.first() != Some(&b'0'));
    canonical
        .then(|| std::str::from_utf8(value).ok()?.parse().ok())
        .flatten()
}

/// Accepts leading zeros on purpose: the `tar` crate reads such a `size` the
/// same as every other reader, unlike a record length, which must be canonical.
fn is_decimal(value: &[u8]) -> bool {
    std::str::from_utf8(value)
        .is_ok_and(|text| text.bytes().all(|b| b.is_ascii_digit()) && text.parse::<u64>().is_ok())
}

/// Splits `body` into canonical `"<len> <key>=<value>\n"` records covering
/// every byte: no sign or leading zero in a length, no blank line, no trailing
/// bytes. A record ends at its declared length, so a value may hold newlines.
fn split_records(body: &[u8]) -> Result<Vec<&[u8]>> {
    let mut records = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let space = rest
            .iter()
            .position(|&b| b == b' ')
            .ok_or(TarAmbiguity::MalformedRecord)?;
        let (digits, _) = rest
            .split_at_checked(space)
            .ok_or(TarAmbiguity::MalformedRecord)?;
        let len = canonical_u64(digits)
            .and_then(|len| usize::try_from(len).ok())
            .filter(|len| *len >= 1)
            .ok_or(TarAmbiguity::MalformedRecord)?;
        let (record, tail) = rest
            .split_at_checked(len)
            .ok_or(TarAmbiguity::MalformedRecord)?;
        if record.last() != Some(&b'\n') {
            return Err(TarAmbiguity::MalformedRecord.into());
        }
        records.push(record);
        rest = tail;
    }
    Ok(records)
}

/// Whether `field` is digits `0`-`7` between optional leading spaces and
/// trailing spaces or NULs, the only form every reader reads the same way.
fn is_plain_octal(field: &[u8]) -> bool {
    let leading_spaces = field.iter().take_while(|&&b| b == b' ').count();
    let Some(trimmed) = field.get(leading_spaces..) else {
        return false;
    };
    let digits = trimmed
        .iter()
        .take_while(|b| (b'0'..=b'7').contains(b))
        .count();
    digits > 0
        && trimmed
            .get(digits..)
            .is_some_and(|rest| rest.iter().all(|&b| b == b' ' || b == 0))
}

/// Whether `field` is a base-256 number that fits 64 bits without a sign.
fn is_plain_base256(field: &[u8]) -> bool {
    field.first() == Some(&BASE256_MARKER)
        && field
            .get(1..4)
            .is_some_and(|zeros| zeros.iter().all(|&b| b == 0))
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
pub(crate) fn check_trailing_headers(
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
/// well-formed records, no GNU sparse, `SCHILY.realsize` or `SUN.holesdata`
/// records and no GNU long name or link record overriding its `path` or
/// `linkpath`, and no `size` record in the same extension chain as a GNU long
/// name or link record. A `size` record the `tar` crate cannot read must equal
/// the header size. A global PAX header (`git archive` writes one carrying
/// only a `comment`) must be well-formed, must not carry `path`, `linkpath` or
/// `size`, and must not follow a local header or a GNU long record.
///
/// `metadata_limit` bounds how much of a global header is read. `preceding`
/// is the value returned for the previous entry: the padding after a global
/// header and after every extension header body must be zero, and a GNU long
/// name or link body must be one NUL-terminated string.
///
/// Returns the kind of this entry, to pass as `preceding` for the next one,
/// and the modification time of a local PAX `mtime` record.
///
/// # Errors
///
/// Returns [`ArchiveError::InvalidArchive`] naming the ambiguous construct, or
/// when the header body cannot be read.
pub(crate) fn check_entry_headers<R: Read>(
    entry: &mut Entry<'_, R>,
    window: &MetadataWindow<'_>,
    metadata_limit: u64,
    preceding: PrecedingEntry,
) -> Result<CheckedHeaders> {
    let walk = window::walk_window(
        window,
        preceding,
        entry.raw_header_position(),
        entry.raw_file_position(),
    );
    let mtime = check_parsed_headers(entry, metadata_limit, &walk)?;
    walk.outcome?;
    let preceding = if entry.header().entry_type() == EntryType::XGlobalHeader {
        PrecedingEntry::GlobalPax
    } else {
        PrecedingEntry::Other
    };
    Ok(CheckedHeaders { preceding, mtime })
}

fn check_parsed_headers<R: Read>(
    entry: &mut Entry<'_, R>,
    metadata_limit: u64,
    walk: &WindowWalk<'_>,
) -> Result<Option<SystemTime>> {
    check_header_fields(entry.header())?;
    match entry.header().entry_type() {
        EntryType::XHeader => Err(unrecognized(TarExtensionKind::Pax)),
        EntryType::GNULongName => Err(unrecognized(TarExtensionKind::LongName)),
        EntryType::GNULongLink => Err(unrecognized(TarExtensionKind::LongLink)),
        EntryType::GNUSparse => Err(TarAmbiguity::SparseEntry.into()),
        EntryType::XGlobalHeader => check_global_header(entry, metadata_limit).map(|()| None),
        kind if kind.as_byte() == b'V' => check_volume_label(entry, walk).map(|()| None),
        _ => check_local_headers(entry, walk),
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

/// Accepts a GNU volume label only when every reader skips it the same way.
///
/// The `tar` crate merges a preceding `x`, `L` or `K` header into the label,
/// while `bsdtar` applies it to the next member, so any such header before a
/// label is refused. A label with data is refused too: `bsdtar` reads its
/// payload blocks as headers, other readers skip them.
fn check_volume_label<R: Read>(entry: &Entry<'_, R>, walk: &WindowWalk<'_>) -> Result<()> {
    if let Some(&kind) = walk.extensions.first() {
        return Err(TarAmbiguity::ExtensionBeforeLabel { kind }.into());
    }
    let raw_size = entry
        .header()
        .entry_size()
        .map_err(|_| TarAmbiguity::NonCanonicalNumber {
            field: TarHeaderField::Size,
        })?;
    let size = raw_size.max(entry.size());
    if size == 0 {
        return Ok(());
    }
    Err(TarAmbiguity::NonRegularPayload {
        kind: TarNonRegularKind::VolumeLabel,
        size,
        path: crate::bytes_text(&entry.path_bytes()),
    }
    .into())
}

fn check_local_headers<R: Read>(
    entry: &mut Entry<'_, R>,
    walk: &WindowWalk<'_>,
) -> Result<Option<SystemTime>> {
    let tar_sees_pax = entry
        .pax_extensions()
        .map_err(|e| pax_header_unreadable(&e))?
        .is_some();
    let overrides = match (walk.pax.as_ref(), tar_sees_pax) {
        (Some(pax), true) => scan_records(pax, PaxScope::Local, entry.header().size().ok())?,
        (None, false) => return Ok(None),
        // The window is stricter than the crate, so it can fail before it
        // yields the body; its error is returned by the caller.
        (None, true) if walk.outcome.is_err() => return Ok(None),
        // Defensive: the window and the crate use the same magic test, so no
        // archive reaches this arm; a disagreement is refused, never skipped.
        _ => return Err(TarAmbiguity::WindowMismatch.into()),
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
    Ok(overrides.mtime)
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

    scan_records(&ParsedPax::parse(&body)?, PaxScope::Global, None).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    // `check_crate_view` compares offsets, which holds only while the `tar`
    // crate yields slices of the body it was given.
    #[test]
    fn the_tar_crate_yields_slices_of_the_body() {
        let body = b"12 path=a.t\n14 mtime=1700\n";
        let offsets: Vec<usize> = crate_records(body)
            .unwrap()
            .iter()
            .map(|r| r.key_offset)
            .collect();
        assert_eq!(offsets, [3, 15]);
        for record in PaxExtensions::new(body).flatten() {
            let value_start = offset_in(body, record.value_bytes()).unwrap();
            let value_end = value_start + record.value_bytes().len();
            assert_eq!(body.get(value_start..value_end), Some(record.value_bytes()));
        }
    }

    #[test]
    fn a_slice_outside_the_body_has_no_offset() {
        let body = b"12 path=a.t\n";
        let copy = body.to_vec();
        assert_eq!(offset_in(body, &body[3..7]), Some(3));
        assert_eq!(offset_in(body, &copy[3..7]), None);
    }

    #[test]
    fn a_record_length_with_a_leading_zero_or_sign_is_refused() {
        for body in [&b"012 path=a.t\n"[..], b"+12 path=a.t\n", b"0 path=a.t\n"] {
            assert!(split_records(body).is_err(), "{body:?}");
        }
        assert_eq!(split_records(b"12 path=a.t\n").unwrap().len(), 1);
    }
}
