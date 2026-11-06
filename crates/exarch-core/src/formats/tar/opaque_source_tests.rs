//! Handlers over a caller-decoded reader: core cannot meter such a source, so
//! these paths differ from the file-based request API and are exercised
//! directly.

use std::assert_matches;
use std::io::Cursor;
use std::io::Write;

use tempfile::TempDir;

use super::TarArchive;
use crate::ArchiveError;
use crate::DecompressionBudget;
use crate::ExtractionOptions;
use crate::IntegrityCheck;
use crate::IntegrityStatus;
use crate::NoopProgress;
use crate::PolicySetting;
use crate::SecurityConfig;
use crate::TarTrailerRefusal;
use crate::VerificationOptions;
use crate::formats::traits::ArchiveFormat;
use crate::non_zero;
use crate::ratio_limit;
use crate::test_utils::create_test_tar;

const MIB: usize = 1024 * 1024;

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn integrity(budget: u64) -> VerificationOptions {
    VerificationOptions::default().with_integrity(IntegrityCheck::DecodeToEof(
        DecompressionBudget::try_from_bytes(budget).unwrap(),
    ))
}

fn source(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    }
}

#[test]
fn corrupt_gzip_crc_is_refused_over_a_caller_decoder() {
    let mut gz = gzip(&create_test_tar(vec![("a.txt", b"alpha")]));
    let at = gz.len() - 8;
    gz[at] ^= 0xFF;
    let decoder = flate2::read::GzDecoder::new(Cursor::new(gz));
    let out = TempDir::new().unwrap();

    let error = TarArchive::new(decoder, &SecurityConfig::default())
        .extract(out.path(), &ExtractionOptions::default(), &mut NoopProgress)
        .unwrap_err();

    assert_matches!(
        source(&error),
        ArchiveError::TarTrailer(TarTrailerRefusal::Corrupt { .. } | TarTrailerRefusal::Truncated),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("after the TAR end-of-archive marker"),
        "{error}"
    );
    assert!(!source(&error).is_security_violation(), "{error}");
    assert_eq!(source(&error).relaxable_by(), None, "{error}");
    assert_eq!(source(&error).context(), None, "{error}");
}

#[test]
fn a_caller_decoded_stream_is_not_bounded_by_ratio() {
    let zeros = vec![0u8; 8 * MIB];
    let tar = create_test_tar(vec![("big.bin", &zeros), ("after.txt", b"hello")]);
    let decoder = flate2::read::GzDecoder::new(Cursor::new(gzip(&tar)));
    let config = SecurityConfig::default()
        .with_max_file_size(non_zero!(2 * MIB as u64))
        .with_max_compression_ratio(ratio_limit!(10.0))
        .try_add_allowed_extension("txt")
        .unwrap();
    let work = TempDir::new().unwrap();

    let report = TarArchive::new(decoder, &config)
        .extract(
            &work.path().join("out"),
            &ExtractionOptions::default(),
            &mut NoopProgress,
        )
        .unwrap();

    assert_eq!(report.files_skipped(), 1);
}

#[test]
fn verify_over_a_plain_reader_reads_the_trailer_within_the_cap() {
    let config = SecurityConfig::default();
    let cap = usize::try_from(config.max_tar_metadata_bytes.get()).unwrap();
    let mut tar = create_test_tar(vec![("a", b"GOOD"), ("b", b"OTHER"), ("c", b"GOOD")]);
    tar.extend(std::iter::repeat_n(0x55u8, 4096));

    let report = TarArchive::new(Cursor::new(tar.clone()), &config)
        .verify(&integrity(1024))
        .unwrap();
    assert_eq!(report.integrity_status(), IntegrityStatus::Pass);

    tar.extend(std::iter::repeat_n(0x55u8, cap));
    let refused = TarArchive::new(Cursor::new(tar), &config)
        .verify(
            &VerificationOptions::default()
                .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT)),
        )
        .unwrap_err();
    assert_eq!(
        refused.relaxable_by(),
        Some(PolicySetting::MaxTarMetadataBytes)
    );
}
