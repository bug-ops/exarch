//! Consistency checks for TAR extension headers.
//!
//! The `tar` crate, `bsdtar` and the Python `tarfile` module resolve the same
//! PAX and GNU extension records differently: which of two `path` records wins,
//! whether a GNU long name or a PAX `path` has priority, and whether a global
//! header applies to later entries. An archive that relies on any of those
//! choices reads as different files in different tools.
//!
//! This module does not parse headers itself. It inspects what the `tar` crate
//! has already attached to a yielded entry and refuses every construct on which
//! the readers are known to disagree, so the entry list `exarch` reports is the
//! one every other reader sees.

use std::collections::HashSet;
use std::io::Read;

use tar::Entry;
use tar::EntryType;
use tar::PaxExtensions;

use crate::ArchiveError;
use crate::Result;

const PAX_PATH: &[u8] = b"path";
const PAX_LINKPATH: &[u8] = b"linkpath";
const PAX_SIZE: &[u8] = b"size";
const PAX_SPARSE_PREFIX: &[u8] = b"GNU.sparse.";

/// A TAR extension-header construct that readers resolve differently.
#[derive(Debug, thiserror::Error)]
enum ExtensionConflict {
    #[error("malformed PAX record")]
    MalformedRecord,
    #[error("duplicate PAX record {0:?}")]
    DuplicateRecord(String),
    #[error("PAX record {0:?} is not supported")]
    SparseRecord(String),
    #[error("PAX `size` record is not a decimal number")]
    InvalidSize,
    #[error("global PAX record {0:?} would apply to later entries")]
    GlobalOverride(String),
    #[error("global PAX header ({size} bytes) exceeds the metadata limit of {limit} bytes")]
    GlobalTooLarge { size: u64, limit: u64 },
    #[error("global PAX header follows a local PAX header")]
    LocalBeforeGlobal,
    #[error("PAX `{key}` record and a GNU long {what} record both describe the same entry")]
    StackedLongRecord {
        key: &'static str,
        what: &'static str,
    },
    #[error("extension header {0:?} lacks a ustar or GNU magic")]
    UnrecognizedHeader(EntryType),
}

impl From<ExtensionConflict> for ArchiveError {
    fn from(conflict: ExtensionConflict) -> Self {
        Self::InvalidArchive(format!("ambiguous TAR extension headers: {conflict}"))
    }
}

/// Whether a PAX header describes the next entry or every later entry.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PaxScope {
    Local,
    Global,
}

/// Path overrides a local PAX header carries, owned so the entry can be
/// queried again afterwards.
#[derive(Default)]
struct PathOverrides {
    path: Option<Vec<u8>>,
    linkpath: Option<Vec<u8>>,
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn scan_records(records: PaxExtensions<'_>, scope: PaxScope) -> Result<PathOverrides> {
    let mut seen: HashSet<&[u8]> = HashSet::new();
    let mut overrides = PathOverrides::default();
    for record in records {
        let record = record.map_err(|_| ExtensionConflict::MalformedRecord)?;
        let key = record.key_bytes();
        let value = record.value_bytes();
        if !seen.insert(key) {
            return Err(ExtensionConflict::DuplicateRecord(lossy(key)).into());
        }
        if key.starts_with(PAX_SPARSE_PREFIX) {
            return Err(ExtensionConflict::SparseRecord(lossy(key)).into());
        }
        let overrides_entry = [PAX_PATH, PAX_LINKPATH, PAX_SIZE].contains(&key);
        if scope == PaxScope::Global && overrides_entry {
            return Err(ExtensionConflict::GlobalOverride(lossy(key)).into());
        }
        match key {
            PAX_PATH => overrides.path = Some(value.to_vec()),
            PAX_LINKPATH => overrides.linkpath = Some(value.to_vec()),
            PAX_SIZE if !is_decimal(value) => {
                return Err(ExtensionConflict::InvalidSize.into());
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

/// Refuses an entry whose extension headers readers would resolve differently.
///
/// Called for every entry the `tar` crate yields, metadata entries included,
/// before the entry is listed, verified or extracted. A local PAX header must
/// have unique, well-formed records, no GNU sparse records and no GNU long
/// name or link record overriding its `path` or `linkpath`. A global PAX
/// header (`git archive` writes one carrying only a `comment`) must not carry
/// `path`, `linkpath` or `size`, and must not follow a local header.
///
/// `metadata_limit` bounds how much of a global header is read.
///
/// # Errors
///
/// Returns [`ArchiveError::InvalidArchive`] naming the ambiguous construct, or
/// when the header body cannot be read.
pub fn check_entry_headers<R: Read>(entry: &mut Entry<'_, R>, metadata_limit: u64) -> Result<()> {
    match entry.header().entry_type() {
        kind @ (EntryType::XHeader | EntryType::GNULongName | EntryType::GNULongLink) => {
            Err(ExtensionConflict::UnrecognizedHeader(kind).into())
        }
        EntryType::XGlobalHeader => check_global_header(entry, metadata_limit),
        _ => check_local_headers(entry),
    }
}

fn check_local_headers<R: Read>(entry: &mut Entry<'_, R>) -> Result<()> {
    let overrides = match entry
        .pax_extensions()
        .map_err(|e| ArchiveError::InvalidArchive(format!("failed to read PAX header: {e}")))?
    {
        Some(records) => scan_records(records, PaxScope::Local)?,
        None => return Ok(()),
    };

    if let Some(pax_path) = overrides.path
        && *entry.path_bytes() != *pax_path
    {
        return Err(ExtensionConflict::StackedLongRecord {
            key: "path",
            what: "name",
        }
        .into());
    }
    if let Some(pax_linkpath) = overrides.linkpath
        && entry.link_name_bytes().as_deref() != Some(pax_linkpath.as_slice())
    {
        return Err(ExtensionConflict::StackedLongRecord {
            key: "linkpath",
            what: "link",
        }
        .into());
    }
    Ok(())
}

fn check_global_header<R: Read>(entry: &mut Entry<'_, R>, metadata_limit: u64) -> Result<()> {
    let size = entry.size();
    if size > metadata_limit {
        return Err(ExtensionConflict::GlobalTooLarge {
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
        .map_err(|e| ArchiveError::InvalidArchive(format!("failed to read PAX header: {e}")))?;

    // The body is already consumed, so only a local header the `tar` crate
    // attached to this entry is still visible here.
    let follows_local = entry
        .pax_extensions()
        .map_err(|e| ArchiveError::InvalidArchive(format!("failed to read PAX header: {e}")))?
        .is_some_and(|mut records| records.next().is_some());
    if follows_local {
        return Err(ExtensionConflict::LocalBeforeGlobal.into());
    }

    scan_records(PaxExtensions::new(&body), PaxScope::Global).map(|_| ())
}
