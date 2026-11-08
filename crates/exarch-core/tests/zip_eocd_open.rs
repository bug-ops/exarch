//! Open-time EOCD handling of the `zip` crate stays safe (#1028).
//!
//! GHSA-m3j8: many EOCD records pointing at different entries of one central
//! directory made `ZipArchive::new` allocate quadratically in file size.
//! GHSA-w2w4: an EOCD64 locator offset above the record position underflowed
//! a subtraction, and multi-disk fields were not validated.
//!
//! Both are patched upstream; these tests pin the behaviour so a dependency
//! move cannot silently regress it. The test binary is its own because
//! `#[global_allocator]` is process-wide.

#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use std::assert_matches;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::PoisonError;

use exarch_core::ArchiveError;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use tempfile::TempDir;

/// dhat allows one profiler at a time.
static PROFILER: Mutex<()> = Mutex::new(());

const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const CENTRAL_RECORD_LEN: usize = 47;
const ENTRY_SENTINEL: u16 = 0xFFFF;
const FLOOD_ENTRIES: usize = 2000;
const FLOOD_EOCDS: usize = 2900;
const HEAP_BUDGET: u64 = 4 * 1024 * 1024;

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// A central directory record for an empty stored file named `a`.
fn central_record(out: &mut Vec<u8>) {
    push_u32(out, CENTRAL_SIGNATURE);
    push_u16(out, 20);
    push_u16(out, 20);
    out.extend_from_slice(&[0; 20]);
    push_u16(out, 1);
    out.extend_from_slice(&[0; 16]);
    out.push(b'a');
    assert_eq!(out.len() % CENTRAL_RECORD_LEN, 0);
}

fn eocd(out: &mut Vec<u8>, disk: u16, entries: u16, directory_len: usize, offset: usize) {
    push_u32(out, EOCD_SIGNATURE);
    push_u16(out, disk);
    push_u16(out, disk);
    push_u16(out, entries);
    push_u16(out, entries);
    push_u32(out, u32::try_from(directory_len).unwrap());
    push_u32(out, u32::try_from(offset).unwrap());
    push_u16(out, 0);
}

/// A central directory followed by `eocds` end records, record `j` pointing
/// `j` entries into the directory and claiming the sentinel entry count.
fn eocd_flood(entries: usize, eocds: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for _ in 0..entries {
        central_record(&mut bytes);
    }
    let directory_len = bytes.len();
    for j in 0..eocds {
        eocd(
            &mut bytes,
            0,
            ENTRY_SENTINEL,
            directory_len,
            j * CENTRAL_RECORD_LEN,
        );
    }
    bytes
}

/// A ZIP64 locator in front of a sentinel EOCD, with nothing at the offset it
/// names.
fn locator_archive(record_offset: u64, total_disks: u32, eocd_disk: u16) -> Vec<u8> {
    let mut bytes = vec![0u8; 64];
    push_u32(&mut bytes, LOCATOR_SIGNATURE);
    push_u32(&mut bytes, 0);
    push_u64(&mut bytes, record_offset);
    push_u32(&mut bytes, total_disks);
    eocd(&mut bytes, eocd_disk, ENTRY_SENTINEL, 0, 0);
    bytes
}

fn write_fixture(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn assert_rejected_everywhere(path: &Path, reason: &str) {
    let config = SecurityConfig::default();
    let out = TempDir::new().unwrap();
    assert_unreadable(extract_archive(path, out.path(), &config).err(), reason);
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    assert_unreadable(list_archive(path, &config).err(), reason);
    assert_unreadable(verify_archive(path, &config).err(), reason);
}

fn assert_unreadable(error: Option<ArchiveError>, reason: &str) {
    assert_matches!(
        error,
        Some(ArchiveError::InvalidArchive(malformation)) if malformation.to_string().contains(reason)
    );
}

fn peak_open_heap(path: &Path) -> u64 {
    let _profiler = dhat::Profiler::builder().testing().build();
    let _ = list_archive(path, &SecurityConfig::default());
    dhat::HeapStats::get().max_bytes as u64
}

#[test]
fn ghsa_m3j8_eocd_flood_is_rejected_with_bounded_heap() {
    let _only = PROFILER.lock().unwrap_or_else(PoisonError::into_inner);
    let dir = TempDir::new().unwrap();
    let path = write_fixture(&dir, "flood.zip", &eocd_flood(FLOOD_ENTRIES, FLOOD_EOCDS));

    assert_rejected_everywhere(&path, "Invalid Central Directory header");
    let peak = peak_open_heap(&path);
    assert!(peak < HEAP_BUDGET, "open allocated {peak} bytes");
}

#[test]
fn ghsa_m3j8_flood_heap_does_not_grow_with_eocd_count() {
    let _only = PROFILER.lock().unwrap_or_else(PoisonError::into_inner);
    let dir = TempDir::new().unwrap();
    let few = write_fixture(&dir, "few.zip", &eocd_flood(FLOOD_ENTRIES, 100));
    let few_peak = peak_open_heap(&few);
    let many = write_fixture(&dir, "many.zip", &eocd_flood(FLOOD_ENTRIES, FLOOD_EOCDS));
    let many_peak = peak_open_heap(&many);

    assert!(
        many_peak <= few_peak + HEAP_BUDGET / 2,
        "{many_peak} bytes for {FLOOD_EOCDS} records against {few_peak} for 100"
    );
}

#[test]
fn ghsa_w2w4_locator_offset_beyond_record_is_rejected_without_panic() {
    let dir = TempDir::new().unwrap();
    let path = write_fixture(&dir, "far.zip", &locator_archive(u64::MAX / 2, 1, 0));

    assert_rejected_everywhere(&path, "Invalid EOCD64 Locator CD offset");
}

#[test]
fn ghsa_w2w4_locator_offset_just_past_record_is_rejected() {
    let dir = TempDir::new().unwrap();
    let path = write_fixture(&dir, "near.zip", &locator_archive(10_000, 1, 0));

    assert_rejected_everywhere(&path, "Invalid EOCD64 Locator CD offset");
}

#[test]
fn ghsa_w2w4_multi_disk_locator_is_rejected() {
    let dir = TempDir::new().unwrap();
    let path = write_fixture(&dir, "disks.zip", &locator_archive(0, 5, 0));

    assert_rejected_everywhere(&path, "Multi-disk ZIP files are not supported");
}
