//! The encoded 7z header is decoded under `max_decoder_memory` (#674): the
//! header coder's declared dictionary, the plain and decoded header sizes are
//! all held to it, and a refusal is `QuotaExceeded { DecoderMemory }` from
//! `list`, `verify` and `extract` alike. The number of entries the header
//! declares is held to `max_file_count` before the entry table is built, as
//! `QuotaExceeded { HeaderEntryCount }`.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

use std::assert_matches;
use std::path::Path;
use std::path::PathBuf;

use common::RawEntry;
use common::number;
use common::solid_copy_7z;

use exarch_core::ArchiveError;
use exarch_core::QuotaResource;
use exarch_core::SecurityConfig;
use exarch_core::VerifyRequest;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::non_zero;
use tempfile::TempDir;

mod common;

const KIB: u64 = 1024;

fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    std::fs::read(path).unwrap()
}

fn crc(data: &[u8]) -> [u8; 4] {
    let mut crc = flate2::Crc::new();
    crc.update(data);
    crc.sum().to_le_bytes()
}

/// `simple.7z` with its header coder's LZMA dictionary raised to 1 GiB. The
/// next header is the encoded-header record, whose CRC and the start header
/// CRC are refreshed so the archive opens up to the memory check.
fn simple_with_huge_header_dictionary() -> Vec<u8> {
    const LZMA_PROPS: [u8; 6] = [0x05, 0x5D, 0x00, 0x10, 0x00, 0x00];
    let mut bytes = fixture_bytes("simple.7z");
    let next_header =
        usize::try_from(u64::from_le_bytes(bytes[12..20].try_into().unwrap())).unwrap() + 32;
    let at = bytes[next_header..]
        .windows(LZMA_PROPS.len())
        .position(|w| w == LZMA_PROPS)
        .unwrap()
        + next_header;
    bytes[at + 3..at + 6].copy_from_slice(&[0x00, 0x00, 0x40]);
    let header_crc = crc(&bytes[next_header..]);
    bytes[28..32].copy_from_slice(&header_crc);
    let start_crc = crc(&bytes[12..32]);
    bytes[8..12].copy_from_slice(&start_crc);
    bytes
}

fn write(dir: &TempDir, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join("archive.7z");
    std::fs::write(&path, bytes).unwrap();
    path
}

fn assert_decoder_memory(err: &ArchiveError, max: u64) {
    assert_matches!(
        err,
        ArchiveError::QuotaExceeded { resource: QuotaResource::DecoderMemory { max: m } } if *m == max,
        "{err:?}"
    );
}

fn refused_by_every_operation(path: &std::path::Path, config: &SecurityConfig, max: u64) {
    assert_decoder_memory(&list_archive(path, config).unwrap_err(), max);
    assert_decoder_memory(&VerifyRequest::new(config).verify(path).unwrap_err(), max);
    let out = TempDir::new().unwrap();
    assert_decoder_memory(&extract_archive(path, out.path(), config).unwrap_err(), max);
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[test]
fn a_header_dictionary_over_the_limit_is_refused_by_default() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &simple_with_huge_header_dictionary());
    let config = SecurityConfig::default();

    refused_by_every_operation(&path, &config, config.max_decoder_memory.get());
}

#[test]
fn a_small_cap_refuses_an_archive_with_an_encoded_header_at_open() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &fixture_bytes("simple.7z"));
    let config = SecurityConfig::default().with_max_decoder_memory(non_zero!(KIB));

    refused_by_every_operation(&path, &config, KIB);
}

#[test]
fn the_default_cap_opens_an_archive_with_an_encoded_header() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &fixture_bytes("simple.7z"));

    let config = SecurityConfig::default();
    assert!(list_archive(&path, &config).unwrap().total_entries() > 0);
    let out = TempDir::new().unwrap();
    extract_archive(&path, out.path(), &config).unwrap();
}

#[test]
fn a_plain_header_is_held_only_to_its_own_size() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &fixture_bytes("large-file.7z"));
    let config = SecurityConfig::default().with_max_decoder_memory(non_zero!(KIB));

    assert!(list_archive(&path, &config).unwrap().total_entries() > 0);
}

fn config_with_memory(bytes: u64) -> SecurityConfig {
    SecurityConfig::default().with_max_decoder_memory(std::num::NonZeroU64::new(bytes).unwrap())
}

fn opens(path: &Path, config: &SecurityConfig) -> bool {
    match list_archive(path, config) {
        Ok(_) => true,
        Err(ArchiveError::QuotaExceeded {
            resource: QuotaResource::DecoderMemory { .. } | QuotaResource::HeaderSize { .. },
        }) => false,
        Err(other) => panic!("neither opened nor refused on memory: {other:?}"),
    }
}

/// An archive whose header is the encoded-header record over `decoded`, stored
/// in LZMA2 uncompressed chunks so the file is as large as the header.
fn stored_header_archive(decoded: &[u8]) -> Vec<u8> {
    layered_header_archive(decoded, Layout::default())
}

const COPY_ID: &[u8] = &[0x00];
const BCJ_X86_ID: &[u8] = &[0x03, 0x03, 0x01, 0x03];

/// How the record of [`layered_header_archive`] differs from the usual one
/// coder, one pack stream, one folder.
#[derive(Clone, Copy, Default)]
struct Layout {
    /// A second coder, applied after the LZMA2 one.
    filter: Option<&'static [u8]>,
    extra_pack_streams: usize,
    extra_folders: usize,
}

/// [`stored_header_archive`] with the record shaped by `layout`.
fn layered_header_archive(decoded: &[u8], layout: Layout) -> Vec<u8> {
    let mut packed = Vec::new();
    for (i, chunk) in decoded.chunks(1 << 16).enumerate() {
        packed.push(if i == 0 { 0x01 } else { 0x02 });
        packed.extend_from_slice(&u16::try_from(chunk.len() - 1).unwrap().to_be_bytes());
        packed.extend_from_slice(chunk);
    }
    packed.push(0x00);

    let mut record = vec![0x17, 0x06];
    record.extend(number(0));
    record.extend(number(1 + layout.extra_pack_streams));
    record.push(0x09);
    record.extend(number(packed.len()));
    record.extend((0..layout.extra_pack_streams).flat_map(|_| number(0)));
    record.extend([0x00, 0x07, 0x0B]);
    record.extend(number(1 + layout.extra_folders));
    record.push(0x00);
    let coders = 1 + usize::from(layout.filter.is_some());
    record.extend(number(coders));
    if let Some(id) = layout.filter {
        record.push(u8::try_from(id.len()).unwrap());
        record.extend(id);
    }
    record.extend([0x21, 0x21, 0x01, 0x00]);
    if layout.filter.is_some() {
        record.extend([0x00, 0x01]);
    }
    for _ in 0..layout.extra_folders {
        record.extend(number(1));
        record.extend([0x01, 0x00]);
    }
    record.push(0x0C);
    for _ in 0..coders {
        record.extend(number(decoded.len()));
    }
    record.extend((0..layout.extra_folders).flat_map(|_| number(0)));
    record.extend([0x00, 0x00]);

    with_next_header(&packed, &record)
}

/// An archive of `packed` bytes followed by the next header `record`.
fn with_next_header(packed: &[u8], record: &[u8]) -> Vec<u8> {
    let mut start = Vec::new();
    start.extend((packed.len() as u64).to_le_bytes());
    start.extend((record.len() as u64).to_le_bytes());
    start.extend(crc(record));
    let mut out = vec![b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    out.extend(crc(&start));
    out.extend(start);
    out.extend(packed);
    out.extend(record);
    out
}

/// The plain header of an archive written by `solid_copy_7z`.
fn plain_header_of(archive: &[u8]) -> Vec<u8> {
    let field = |at: usize| {
        usize::try_from(u64::from_le_bytes(archive[at..at + 8].try_into().unwrap())).unwrap()
    };
    let start = 32 + field(12);
    archive[start..start + field(20)].to_vec()
}

/// A decoded header that declares `entries` files and nothing else.
fn entry_count_only_header(entries: usize, padded_to: usize) -> Vec<u8> {
    let mut decoded = vec![0x01, 0x05];
    decoded.extend(number(entries));
    decoded.resize(padded_to, 0);
    decoded
}

#[test]
fn the_stored_header_builder_makes_an_archive_that_opens() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &stored_header_archive(&[0x01, 0x00]));

    assert!(opens(&path, &SecurityConfig::default()));
}

#[test]
fn a_header_declaring_more_entries_than_max_file_count_allows_is_refused_unparsed() {
    let dir = TempDir::new().unwrap();
    let decoded = entry_count_only_header(200_000, 200_000);
    let path = write(&dir, &stored_header_archive(&decoded));
    let config = SecurityConfig::default().with_max_file_count(non_zero!(10));
    let memory = config.max_decoder_memory.get();

    for err in [
        list_archive(&path, &config).unwrap_err(),
        VerifyRequest::new(&config).verify(&path).unwrap_err(),
        extract_archive(&path, TempDir::new().unwrap().path(), &config).unwrap_err(),
    ] {
        assert_matches!(
            err,
            ArchiveError::QuotaExceeded { resource: QuotaResource::HeaderSize { max } }
                if max < memory && max >= 64 * KIB,
            "{err:?}"
        );
    }
}

#[test]
fn the_decoded_header_size_is_held_to_the_limit_when_the_raw_header_is_small() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        &stored_header_archive(&entry_count_only_header(0, 200 * 1024)),
    );
    let record_len = u64::from_le_bytes(std::fs::read(&path).unwrap()[20..28].try_into().unwrap());
    assert!(record_len < 100, "the raw header record stays tiny");

    assert!(!opens(&path, &config_with_memory(100 * KIB)));
}

#[test]
fn paths_of_about_a_hundred_characters_at_the_file_cap_open() {
    let names: Vec<String> = (0..1000)
        .map(|i| format!("{i:04}{}", "n".repeat(96)))
        .collect();
    let entries: Vec<RawEntry<'_>> = names.iter().map(|n| RawEntry::Dir(n)).collect();
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &solid_copy_7z(&entries));
    let config = SecurityConfig::default().with_max_file_count(non_zero!(1000));

    assert_eq!(list_archive(&path, &config).unwrap().total_entries(), 1000);
}

#[test]
fn the_dictionary_branch_is_held_at_the_whole_kib_the_header_needs() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &fixture_bytes("simple.7z"));

    assert!(opens(&path, &config_with_memory(26 * KIB)));
    assert!(!opens(&path, &config_with_memory(26 * KIB - 1)));
    assert!(!opens(&path, &config_with_memory(25 * KIB)));
}

/// A plain-header archive whose header is exactly `size` bytes, or `None`.
///
/// Directory names grow the header two bytes per character and each file adds
/// one byte of sub-stream size, so the search reaches both parities.
fn plain_header_archive_of(size: usize) -> Option<Vec<u8>> {
    (1..=4).find_map(|dirs| {
        (0..=1).find_map(|files| {
            (1..=400).find_map(|len| {
                let names: Vec<String> = (0..dirs)
                    .map(|i| format!("{i}{}", "a".repeat(len)))
                    .collect();
                let mut raw: Vec<RawEntry<'_>> = names.iter().map(|n| RawEntry::Dir(n)).collect();
                if files == 1 {
                    raw.push(RawEntry::File("f", b"x"));
                    raw.push(RawEntry::File("g", b"y"));
                }
                let bytes = solid_copy_7z(&raw);
                let header = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
                (header == size as u64).then_some(bytes)
            })
        })
    })
}

#[test]
fn a_plain_header_is_held_at_exactly_the_limit() {
    let at_limit = plain_header_archive_of(1024).unwrap();
    let over = plain_header_archive_of(1026).unwrap();
    let dir = TempDir::new().unwrap();

    let path = write(&dir, &at_limit);
    assert!(opens(&path, &config_with_memory(1024)));
    assert!(!opens(&path, &config_with_memory(1023)));
    let path = write(&dir, &over);
    assert!(!opens(&path, &config_with_memory(1024)));
    assert!(opens(&path, &config_with_memory(2048)));
}

fn long_name_archive(dir: &TempDir) -> PathBuf {
    let names: Vec<String> = (0..1000)
        .map(|i| format!("{i:04}{}", "n".repeat(196)))
        .collect();
    let entries: Vec<RawEntry<'_>> = names.iter().map(|n| RawEntry::Dir(n)).collect();
    write(dir, &solid_copy_7z(&entries))
}

#[test]
fn paths_of_two_hundred_characters_at_the_file_cap_are_over_the_budget() {
    let dir = TempDir::new().unwrap();
    let path = long_name_archive(&dir);
    let config = SecurityConfig::default().with_max_file_count(non_zero!(1000));

    assert!(!opens(&path, &config));
    assert!(opens(
        &path,
        &config.clone().with_max_file_count(non_zero!(2000))
    ));
    assert!(opens(
        &path,
        &config.with_max_file_count(exarch_core::Limit::Unbounded)
    ));
}

#[test]
fn directories_count_toward_the_header_budget() {
    let dir = TempDir::new().unwrap();
    let path = long_name_archive(&dir);
    let few = SecurityConfig::default().with_max_file_count(non_zero!(100));
    let out = TempDir::new().unwrap();

    let err = extract_archive(&path, out.path(), &few).unwrap_err();
    assert_matches!(
        err,
        ArchiveError::QuotaExceeded {
            resource: QuotaResource::HeaderSize { max }
        } if max == 100 * 256 + 64 * KIB
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);

    let enough = SecurityConfig::default().with_max_file_count(non_zero!(2000));
    extract_archive(&path, out.path(), &enough).unwrap();
}

fn assert_header_entry_count(err: &ArchiveError, declared: u64) -> u64 {
    match err {
        ArchiveError::QuotaExceeded {
            resource: QuotaResource::HeaderEntryCount { declared: d, max },
        } if *d == declared && *max < declared => *max,
        other => panic!("expected HeaderEntryCount for {declared} entries: {other:?}"),
    }
}

fn refused_entry_count_by_every_operation(
    path: &Path,
    config: &SecurityConfig,
    declared: u64,
) -> u64 {
    let max = assert_header_entry_count(&list_archive(path, config).unwrap_err(), declared);
    let verify = VerifyRequest::new(config).verify(path).unwrap_err();
    assert_eq!(assert_header_entry_count(&verify, declared), max);
    let out = TempDir::new().unwrap();
    let extract = extract_archive(path, out.path(), config).unwrap_err();
    assert_eq!(assert_header_entry_count(&extract, declared), max);
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    max
}

fn directories_archive(count: usize, encoded: bool) -> Vec<u8> {
    let names: Vec<String> = (0..count).map(|i| format!("d{i}")).collect();
    let entries: Vec<RawEntry<'_>> = names.iter().map(|n| RawEntry::Dir(n)).collect();
    let archive = solid_copy_7z(&entries);
    if encoded {
        stored_header_archive(&plain_header_of(&archive))
    } else {
        archive
    }
}

#[test]
fn header_entry_count_over_limit_is_refused_plain() {
    let dir = TempDir::new().unwrap();
    let header = entry_count_only_header(OVER_LIMIT, 8);
    let path = write(&dir, &with_next_header(&[], &header));
    let config = SecurityConfig::default().with_max_file_count(non_zero!(10));

    refused_entry_count_by_every_operation(&path, &config, OVER_LIMIT as u64);
}

#[test]
fn header_entry_count_over_limit_is_refused_encoded() {
    let dir = TempDir::new().unwrap();
    let header = entry_count_only_header(OVER_LIMIT, 8);
    let path = write(&dir, &stored_header_archive(&header));

    refused_entry_count_by_every_operation(&path, &SecurityConfig::default(), OVER_LIMIT as u64);
}

#[test]
fn the_entry_limit_refuses_the_first_entry_past_its_count_in_plain_and_encoded_headers() {
    for encoded in [false, true] {
        let dir = TempDir::new().unwrap();
        let config = SecurityConfig::default().with_max_file_count(non_zero!(1000));
        let path = write(&dir, &directories_archive(4000, encoded));
        let max =
            usize::try_from(refused_entry_count_by_every_operation(&path, &config, 4000)).unwrap();

        let path = write(&dir, &directories_archive(max, encoded));
        assert_matches!(
            list_archive(&path, &config),
            Err(ArchiveError::QuotaExceeded {
                resource: QuotaResource::FileCount { .. }
            }),
            "encoded={encoded}: the header passes, the file count limit still applies"
        );
        let path = write(&dir, &directories_archive(max + 1, encoded));
        let err = list_archive(&path, &config).unwrap_err();
        assert_eq!(assert_header_entry_count(&err, max as u64 + 1), max as u64);
    }
}

#[test]
fn an_unbounded_file_count_leaves_the_entry_count_to_the_size_limits() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &directories_archive(5000, false));
    let config = SecurityConfig::default().with_max_file_count(exarch_core::Limit::Unbounded);

    assert_eq!(list_archive(&path, &config).unwrap().total_entries(), 5000);
}

fn assert_unsupported_layout(err: &ArchiveError) {
    match err {
        ArchiveError::InvalidArchive(malformation)
            if malformation
                .to_string()
                .contains("unsupported header layout") => {}
        other => panic!("expected an unsupported header layout refusal: {other:?}"),
    }
}

fn refused_as_unsupported_by_every_operation(path: &Path) {
    let config = SecurityConfig::default();
    assert_unsupported_layout(&list_archive(path, &config).unwrap_err());
    assert_unsupported_layout(&VerifyRequest::new(&config).verify(path).unwrap_err());
    let out = TempDir::new().unwrap();
    assert_unsupported_layout(&extract_archive(path, out.path(), &config).unwrap_err());
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[test]
fn header_entry_count_over_limit_is_refused_for_a_long_encoded_record() {
    let dir = TempDir::new().unwrap();
    let header = entry_count_only_header(OVER_LIMIT, 8);
    let layout = Layout {
        extra_pack_streams: 5000,
        extra_folders: 2,
        ..Layout::default()
    };
    let bytes = layered_header_archive(&header, layout);
    let record_len = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
    assert!(record_len > 4096, "{record_len}");
    let path = write(&dir, &bytes);

    refused_entry_count_by_every_operation(&path, &SecurityConfig::default(), OVER_LIMIT as u64);
}

#[test]
fn encoded_headers_with_more_than_one_coder_are_refused_whatever_they_declare() {
    for filter in [COPY_ID, BCJ_X86_ID] {
        let dir = TempDir::new().unwrap();
        let header = entry_count_only_header(OVER_LIMIT, 8);
        let layout = Layout {
            filter: Some(filter),
            ..Layout::default()
        };
        let path = write(&dir, &layered_header_archive(&header, layout));
        refused_as_unsupported_by_every_operation(&path);
    }
}

/// A header entry count above the default limit and the one of
/// `max_file_count(10)`.
const OVER_LIMIT: usize = 20_000;

const AES_ID: &[u8] = &[0x06, 0xF1, 0x07, 0x01];

fn assert_encrypted(err: &ArchiveError) {
    match err {
        ArchiveError::SecurityViolation { .. } if err.to_string().contains("encrypted") => {}
        other => panic!("expected an encrypted archive refusal: {other:?}"),
    }
}

#[test]
fn a_header_with_an_encryption_coder_keeps_the_encrypted_archive_error() {
    let header = entry_count_only_header(OVER_LIMIT, 8);
    let on_chain = layered_header_archive(
        &header,
        Layout {
            filter: Some(AES_ID),
            ..Layout::default()
        },
    );
    let mut off_chain = on_chain.clone();
    let record_start = off_chain.len() - record_len_of(&off_chain);
    let bind = off_chain[record_start..]
        .windows(3)
        .position(|w| w == [0x00, 0x01, 0x0C])
        .unwrap();
    off_chain[record_start + bind + 1] = 0x00;
    let record_crc = crc(&off_chain[record_start..]);
    off_chain[28..32].copy_from_slice(&record_crc);
    let start_crc = crc(&off_chain[12..32]);
    off_chain[8..12].copy_from_slice(&start_crc);

    let config = SecurityConfig::default();
    for bytes in [on_chain, off_chain] {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, &bytes);
        assert_encrypted(&list_archive(&path, &config).unwrap_err());
        assert_encrypted(&VerifyRequest::new(&config).verify(&path).unwrap_err());
        let out = TempDir::new().unwrap();
        assert_encrypted(&extract_archive(&path, out.path(), &config).unwrap_err());
    }
}

fn record_len_of(archive: &[u8]) -> usize {
    usize::try_from(u64::from_le_bytes(archive[20..28].try_into().unwrap())).unwrap()
}

#[test]
fn a_header_coder_over_the_memory_limit_is_refused_for_memory_before_the_count() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &simple_with_huge_header_dictionary());
    let config = SecurityConfig::default().with_max_file_count(non_zero!(10));

    refused_by_every_operation(&path, &config, config.max_decoder_memory.get());
}

#[test]
fn a_header_with_a_missing_start_header_is_refused() {
    let dir = TempDir::new().unwrap();
    let mut bytes = vec![b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    bytes.extend([0u8; 24]);
    bytes.extend(entry_count_only_header(100_000, 100_000));
    let path = write(&dir, &bytes);

    refused_as_unsupported_by_every_operation(&path);
}

#[test]
fn archives_within_the_entry_limit_open_unchanged() {
    let dir = TempDir::new().unwrap();
    for name in ["simple.7z", "large-file.7z", "solid.7z", "nested-dirs.7z"] {
        let path = write(&dir, &fixture_bytes(name));
        let config = SecurityConfig::default();
        assert!(
            list_archive(&path, &config).unwrap().total_entries() > 0,
            "{name}"
        );
    }
}
