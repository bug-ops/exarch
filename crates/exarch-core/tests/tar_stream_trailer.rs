//! The bytes after the TAR end-of-archive marker are read to the end of a
//! compressed stream, so a codec trailer failure (gzip CRC or ISIZE, a corrupt
//! later member) is an error everywhere, and an over-long tail is refused
//! under one cap (#838).

#![allow(clippy::unwrap_used)]

use std::assert_matches;
use std::io::Cursor;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::DecompressionBudget;
use exarch_core::ExtractionOptions;
use exarch_core::IntegrityCheck;
use exarch_core::IntegrityStatus;
use exarch_core::ListOptions;
use exarch_core::MemoryExtractRequest;
use exarch_core::NoopProgress;
use exarch_core::PolicySetting;
use exarch_core::SecurityConfig;
use exarch_core::TarTrailerRefusal;
use exarch_core::TrailerCorruption;
use exarch_core::VerificationOptions;
use exarch_core::extract_archive;
use exarch_core::extract_archive_with_options;
use exarch_core::extract_reader_to_memory;
use exarch_core::formats::TarArchive;
use exarch_core::formats::traits::ArchiveFormat;
use exarch_core::list_archive;
use exarch_core::list_archive_for_extraction;
use exarch_core::verify_archive;
use exarch_core::verify_archive_with_options;
use tempfile::TempDir;

const MIB: usize = 1024 * 1024;
// Big enough for the end-of-archive marker, far below the 1 MiB trailer floor.
const SMALL_LIMIT: u64 = 4096;
// `u64::MAX` is the metadata budget's disarmed marker and breaks any archive.
const HUGE_LIMIT: u64 = u64::MAX - 1;

fn tar_bytes() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(5);
    header.set_mode(0o644);
    builder
        .append_data(&mut header, "a.txt", &b"alpha"[..])
        .unwrap();
    builder.into_inner().unwrap()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn gzip_with_zero_member(zeros: usize) -> Vec<u8> {
    let mut bytes = gzip(&tar_bytes());
    bytes.extend(gzip(&vec![0u8; zeros]));
    bytes
}

fn flip_crc(mut gz: Vec<u8>) -> Vec<u8> {
    let at = gz.len() - 8;
    gz[at] ^= 0xFF;
    gz
}

fn flip_isize(mut gz: Vec<u8>) -> Vec<u8> {
    let at = gz.len() - 1;
    gz[at] ^= 0xFF;
    gz
}

fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn extract(archive: &Path, config: &SecurityConfig) -> Result<(), ArchiveError> {
    let out = TempDir::new().unwrap();
    extract_archive(archive, out.path(), config).map(drop)
}

fn config_with_tail_limit(bytes: u64) -> SecurityConfig {
    SecurityConfig::default().with_max_tar_metadata_bytes(bytes)
}

fn source(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction { source, .. } => source,
        other => other,
    }
}

fn assert_trailer_failure(error: &ArchiveError) {
    assert_matches!(
        source(error),
        ArchiveError::TarTrailer(TarTrailerRefusal::Corrupt { .. } | TarTrailerRefusal::Truncated),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("after the TAR end-of-archive marker"),
        "{error}"
    );
    assert!(!source(error).is_security_violation(), "{error}");
    assert_eq!(source(error).relaxable_by(), None, "{error}");
    assert_eq!(source(error).context(), None, "{error}");
}

fn assert_corrupt(error: &ArchiveError, expected: TrailerCorruption) {
    assert_matches!(
        source(error),
        ArchiveError::TarTrailer(TarTrailerRefusal::Corrupt { cause, .. }) if *cause == expected,
        "{error}"
    );
}

fn assert_over_cap(error: &ArchiveError) {
    assert_matches!(
        source(error),
        ArchiveError::TarTrailer(TarTrailerRefusal::OverCap { .. }),
        "{error}"
    );
    assert!(source(error).is_security_violation(), "{error}");
    assert!(source(error).is_recoverable(), "{error}");
    assert_eq!(
        source(error).relaxable_by(),
        Some(PolicySetting::MaxTarMetadataBytes),
        "{error}"
    );
}

#[test]
fn corrupt_gzip_crc_is_refused_by_extract_and_list() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "a.tar.gz", &flip_crc(gzip(&tar_bytes())));
    let config = SecurityConfig::default();

    assert_trailer_failure(&extract(&archive, &config).unwrap_err());
    assert_trailer_failure(&list_archive(&archive, &config).unwrap_err());
}

#[test]
fn corrupt_gzip_isize_is_refused() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "a.tar.gz", &flip_isize(gzip(&tar_bytes())));

    assert_trailer_failure(&extract(&archive, &SecurityConfig::default()).unwrap_err());
}

#[test]
fn corrupt_later_gzip_member_is_refused() {
    let dir = TempDir::new().unwrap();
    let mut bytes = gzip(&tar_bytes());
    bytes.extend(flip_crc(gzip(&[0u8; 1024])));
    let archive = write(&dir, "a.tar.gz", &bytes);

    assert_trailer_failure(&extract(&archive, &SecurityConfig::default()).unwrap_err());
}

#[test]
fn a_corrupt_checksum_is_a_decoder_corruption() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "a.tar.gz", &flip_crc(gzip(&tar_bytes())));

    let error = extract(&archive, &SecurityConfig::default()).unwrap_err();

    assert_corrupt(&error, TrailerCorruption::Decoder);
}

#[test]
fn bytes_that_are_not_a_member_after_zero_padding_are_trailing_data() {
    let dir = TempDir::new().unwrap();
    let mut bytes = gzip(&tar_bytes());
    bytes.extend_from_slice(b"\0\0\0garbage");
    let archive = write(&dir, "a.tar.gz", &bytes);
    let config = SecurityConfig::default();

    assert_corrupt(
        &extract(&archive, &config).unwrap_err(),
        TrailerCorruption::TrailingData,
    );
    assert_corrupt(
        &list_archive(&archive, &config).unwrap_err(),
        TrailerCorruption::TrailingData,
    );
}

#[test]
fn a_later_member_cut_short_is_truncated() {
    let dir = TempDir::new().unwrap();
    let mut second = gzip(&[7u8; 4096]);
    second.truncate(second.len() / 2);
    let mut bytes = gzip(&tar_bytes());
    bytes.extend(second);
    let archive = write(&dir, "a.tar.gz", &bytes);

    let error = extract(&archive, &SecurityConfig::default()).unwrap_err();

    assert_matches!(
        source(&error),
        ArchiveError::TarTrailer(TarTrailerRefusal::Truncated),
        "{error}"
    );
}

#[test]
fn clean_compressed_archive_still_extracts() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "a.tar.gz", &gzip(&tar_bytes()));
    let out = TempDir::new().unwrap();

    extract_archive(&archive, out.path(), &SecurityConfig::default()).unwrap();

    assert_eq!(std::fs::read(out.path().join("a.txt")).unwrap(), b"alpha");
}

#[test]
fn corrupt_gzip_crc_is_refused_by_the_in_memory_api() {
    let bytes = flip_crc(gzip(&tar_bytes()));
    let reader = ArchiveReader::detect_stream(Cursor::new(bytes)).unwrap();

    let error =
        extract_reader_to_memory(reader, &MemoryExtractRequest::default(), &mut NoopProgress)
            .err()
            .unwrap();

    assert_trailer_failure(&error);
}

#[test]
fn corrupt_gzip_crc_is_refused_by_tar_archive_over_a_decoder() {
    let bytes = flip_crc(gzip(&tar_bytes()));
    let decoder = flate2::read::GzDecoder::new(Cursor::new(bytes));
    let config = SecurityConfig::default().validate().unwrap();
    let out = TempDir::new().unwrap();

    let error = TarArchive::new(decoder)
        .extract(
            out.path(),
            &config,
            &ExtractionOptions::default(),
            &mut NoopProgress,
        )
        .unwrap_err();

    assert_trailer_failure(&error);
}

#[test]
fn tail_over_the_cap_is_a_relaxable_violation_and_just_under_it_passes() {
    let dir = TempDir::new().unwrap();
    let config = SecurityConfig::default();
    let cap = usize::try_from(config.max_tar_metadata_bytes).unwrap();

    let over = write(&dir, "over.tar.gz", &gzip_with_zero_member(cap + 1));
    let error = extract(&over, &config).unwrap_err();
    assert_over_cap(&error);
    assert!(error.to_string().contains(&cap.to_string()), "{error}");
    assert_over_cap(&list_archive(&over, &config).unwrap_err());

    let under = write(&dir, "under.tar.gz", &gzip_with_zero_member(cap - 1024));
    extract(&under, &config).unwrap();
}

#[test]
fn small_metadata_limit_still_allows_one_mebibyte_of_padding() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "a.tar.gz", &gzip_with_zero_member(MIB - 1024));

    extract(&archive, &config_with_tail_limit(SMALL_LIMIT)).unwrap();

    let over = write(&dir, "b.tar.gz", &gzip_with_zero_member(MIB + 1));
    assert_over_cap(&extract(&over, &config_with_tail_limit(SMALL_LIMIT)).unwrap_err());
}

#[test]
fn maximal_metadata_limit_still_checks_the_crc() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "a.tar.gz", &flip_crc(gzip(&tar_bytes())));

    let error = extract(&archive, &config_with_tail_limit(HUGE_LIMIT)).unwrap_err();

    assert_trailer_failure(&error);
}

#[test]
fn plain_tar_with_trailing_junk_still_extracts() {
    let dir = TempDir::new().unwrap();
    let mut bytes = tar_bytes();
    bytes.extend(vec![0x55u8; 2 * MIB]);
    let archive = write(&dir, "a.tar", &bytes);

    extract(&archive, &SecurityConfig::default()).unwrap();
    list_archive(&archive, &SecurityConfig::default()).unwrap();
}

#[test]
fn zero_padded_zstd_stream_is_refused() {
    let dir = TempDir::new().unwrap();
    let mut bytes = zstd::encode_all(tar_bytes().as_slice(), 1).unwrap();
    bytes.extend([0u8; 512]);
    let archive = write(&dir, "a.tar.zst", &bytes);

    let error = extract(&archive, &SecurityConfig::default()).unwrap_err();

    assert_trailer_failure(&error);
}

#[test]
fn concatenated_archives_extract_the_first_and_bound_the_second() {
    let dir = TempDir::new().unwrap();
    let mut small = gzip(&tar_bytes());
    small.extend(gzip(&tar_bytes()));
    let archive = write(&dir, "small.tar.gz", &small);
    extract(&archive, &SecurityConfig::default()).unwrap();

    let mut large = gzip(&tar_bytes());
    large.extend(gzip(&{
        let mut second = tar_bytes();
        second.resize(5 * MIB, 0);
        second
    }));
    let archive = write(&dir, "large.tar.gz", &large);
    assert_over_cap(&extract(&archive, &SecurityConfig::default()).unwrap_err());
}

#[test]
fn plain_verify_does_not_read_the_trailer() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "a.tar.gz", &flip_crc(gzip(&tar_bytes())));

    let report = verify_archive(&archive, &SecurityConfig::default()).unwrap();

    assert_eq!(report.integrity_status(), IntegrityStatus::Skipped);
}

#[test]
fn integrity_check_refuses_an_over_cap_tail_and_fails_a_bad_crc() {
    let dir = TempDir::new().unwrap();
    let options = VerificationOptions::default()
        .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT));
    let config = SecurityConfig::default();
    let cap = usize::try_from(config.max_tar_metadata_bytes).unwrap();

    let over = write(&dir, "over.tar.gz", &gzip_with_zero_member(cap + 1));
    assert_over_cap(&verify_archive_with_options(&over, &config, &options).unwrap_err());

    let bad = write(&dir, "bad.tar.gz", &flip_crc(gzip(&tar_bytes())));
    let report = verify_archive_with_options(&bad, &config, &options).unwrap();
    assert_eq!(report.integrity_status(), IntegrityStatus::Fail);
}

#[test]
fn replay_enforces_the_extract_configs_trailer_limit() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "a.tar.gz", &gzip_with_zero_member(2 * MIB));
    let listed = list_archive_for_extraction(
        &archive,
        &SecurityConfig::default(),
        &ListOptions::default(),
    )
    .unwrap();
    let out = TempDir::new().unwrap();

    let error = listed
        .extract(
            out.path(),
            &config_with_tail_limit(SMALL_LIMIT),
            &ExtractionOptions::default(),
            &mut NoopProgress,
        )
        .unwrap_err();

    assert_over_cap(&error);
}

#[test]
fn extraction_options_variant_reports_the_same_refusal() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "a.tar.gz", &flip_crc(gzip(&tar_bytes())));
    let out = TempDir::new().unwrap();

    let error = extract_archive_with_options(
        &archive,
        out.path(),
        &SecurityConfig::default(),
        &ExtractionOptions::default(),
    )
    .unwrap_err();

    assert_trailer_failure(&error);
}
