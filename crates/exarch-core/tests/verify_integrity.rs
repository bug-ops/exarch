//! Opt-in payload integrity check of `verify` (#623).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::assert_matches;
use std::io::Cursor;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use common::flip_first;
use exarch_core::ArchiveError;
use exarch_core::DecompressionBudget;
use exarch_core::IntegrityCheck;
use exarch_core::IntegrityStatus;
use exarch_core::IssueCategory;
use exarch_core::QuotaResource;
use exarch_core::SecurityConfig;
use exarch_core::UnverifiedReason;
use exarch_core::VerificationOptions;
use exarch_core::VerificationReport;
use exarch_core::VerificationStatus;
use exarch_core::formats::TarArchive;
use exarch_core::formats::traits::ArchiveFormat;
use exarch_core::verify_archive;
use exarch_core::verify_archive_with_options;
use sevenz_rust2::EncoderConfiguration;
use sevenz_rust2::EncoderMethod;
use tempfile::TempDir;

const GOOD: &[u8] = b"GOODGOODGOODGOODGOODGOODGOODGOOD";
const OTHER: &[u8] = b"OTHEROTHEROTHEROTHEROTHEROTHEROT";

fn integrity(budget: u64) -> VerificationOptions {
    VerificationOptions::default().with_integrity(IntegrityCheck::DecodeToEof(
        DecompressionBudget::try_from_bytes(budget).unwrap(),
    ))
}

fn default_integrity() -> VerificationOptions {
    VerificationOptions::default()
        .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT))
}

fn verify(path: &Path, options: VerificationOptions) -> VerificationReport {
    verify_archive_with_options(path, &SecurityConfig::default(), &options).unwrap()
}

fn verify_err(path: &Path, options: VerificationOptions) -> ArchiveError {
    verify_archive_with_options(path, &SecurityConfig::default(), &options).unwrap_err()
}

fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn count(report: &VerificationReport, category: IssueCategory) -> usize {
    report
        .issues()
        .iter()
        .filter(|i| i.category == category)
        .count()
}

fn corrupt_paths(report: &VerificationReport) -> Vec<String> {
    let mut paths: Vec<_> = report
        .issues()
        .iter()
        .filter(|i| i.category == IssueCategory::CorruptData)
        .filter_map(|i| i.entry_path.as_ref())
        .map(|p| p.display().to_string())
        .collect();
    paths.sort();
    paths
}

mod zip_fixtures {
    use super::*;
    use zip::CompressionMethod;
    use zip::write::SimpleFileOptions;
    use zip::write::ZipWriter;

    pub fn build(entries: &[(&str, &[u8])], method: CompressionMethod) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(method);
        for (name, data) in entries {
            writer.start_file(*name, options).unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    pub fn stored(entries: &[(&str, &[u8])]) -> Vec<u8> {
        build(entries, CompressionMethod::Stored)
    }

    pub fn with_symlink(target: &str) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file("a.txt", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(GOOD).unwrap();
        writer
            .add_symlink("link", target, SimpleFileOptions::default())
            .unwrap();
        writer.finish().unwrap().into_inner()
    }
}

#[test]
fn zip_clean_is_ok_and_default_verify_stays_skipped() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "a.zip",
        &zip_fixtures::stored(&[("a", GOOD), ("b", OTHER)]),
    );

    let report = verify(&path, default_integrity());
    assert_eq!(report.integrity_status(), IntegrityStatus::Pass);
    assert_eq!(report.status(), VerificationStatus::Pass);

    let plain = verify_archive(&path, &SecurityConfig::default()).unwrap();
    assert_eq!(plain.integrity_status(), IntegrityStatus::Skipped);
}

#[test]
fn zip_corrupt_crc_fails_and_names_the_entry() {
    let dir = TempDir::new().unwrap();
    let mut bytes = zip_fixtures::stored(&[("a", GOOD), ("b", OTHER)]);
    flip_first(&mut bytes, GOOD);
    let path = write(&dir, "a.zip", &bytes);

    let report = verify(&path, default_integrity());
    assert_eq!(report.integrity_status(), IntegrityStatus::Fail);
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert_eq!(corrupt_paths(&report), ["a"]);

    let plain = verify_archive(&path, &SecurityConfig::default()).unwrap();
    assert_eq!(plain.integrity_status(), IntegrityStatus::Skipped);
    assert_eq!(plain.status(), VerificationStatus::Pass);
}

#[test]
fn zip_corruption_does_not_stop_the_scan() {
    let dir = TempDir::new().unwrap();
    let mut bytes = zip_fixtures::stored(&[("a", GOOD), ("b", OTHER), ("c", GOOD)]);
    flip_first(&mut bytes, GOOD);
    flip_first(&mut bytes, OTHER);
    let path = write(&dir, "a.zip", &bytes);

    let report = verify(&path, default_integrity());
    assert_eq!(corrupt_paths(&report), ["a", "b"]);
}

#[test]
fn zip_corrupt_deflate_stream_fails() {
    let dir = TempDir::new().unwrap();
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let mut bytes = zip_fixtures::build(
        &[("a", payload.as_slice())],
        zip::CompressionMethod::Deflated,
    );
    let middle = bytes.len() / 3;
    bytes[middle] ^= 0xFF;
    let path = write(&dir, "a.zip", &bytes);

    let report = verify(&path, default_integrity());
    assert_eq!(report.integrity_status(), IntegrityStatus::Fail);
}

#[test]
fn zip_over_budget_entry_is_skipped_but_later_entries_are_still_checked() {
    let dir = TempDir::new().unwrap();
    let big = vec![b'x'; 4096];
    let mut bytes = zip_fixtures::stored(&[("big", big.as_slice()), ("small", GOOD)]);
    flip_first(&mut bytes, GOOD);
    let path = write(&dir, "a.zip", &bytes);

    let report = verify(&path, integrity(GOOD.len() as u64));
    assert_eq!(report.integrity_status(), IntegrityStatus::Fail);
    assert_eq!(corrupt_paths(&report), ["small"]);
    assert_eq!(count(&report, IssueCategory::IntegrityIncomplete), 1);
}

#[test]
fn zip_budget_boundary_total_equal_is_ok_and_one_less_is_incomplete() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "a.zip",
        &zip_fixtures::stored(&[("a", GOOD), ("b", OTHER)]),
    );
    let total = (GOOD.len() + OTHER.len()) as u64;

    let exact = verify(&path, integrity(total));
    assert_eq!(exact.integrity_status(), IntegrityStatus::Pass);

    let short = verify(&path, integrity(total - 1));
    assert_eq!(short.integrity_status(), IntegrityStatus::Incomplete);
    assert_eq!(short.status(), VerificationStatus::Warning);
}

#[test]
fn zip_forged_declared_size_is_a_security_issue_and_incomplete() {
    let dir = TempDir::new().unwrap();
    let payload = vec![b'z'; 64];
    let mut bytes = zip_fixtures::stored(&[("a", payload.as_slice())]);
    let forged = 8u32.to_le_bytes();
    for signature in [[0x50, 0x4B, 0x03, 0x04], [0x50, 0x4B, 0x01, 0x02]] {
        let at = bytes.windows(4).position(|w| w == signature).unwrap();
        let offset = if signature[2] == 3 { 22 } else { 24 };
        bytes[at + offset..at + offset + 4].copy_from_slice(&forged);
    }
    let path = write(&dir, "a.zip", &bytes);

    let report = verify(&path, default_integrity());
    assert_eq!(report.integrity_status(), IntegrityStatus::Incomplete);
    assert_eq!(count(&report, IssueCategory::CorruptData), 0);
    assert!(count(&report, IssueCategory::SecurityPolicy) >= 1);
}

#[test]
fn zip_corrupt_symlink_target_fails_while_default_verify_errors() {
    let dir = TempDir::new().unwrap();
    let mut bytes = zip_fixtures::with_symlink("target-file");
    flip_first(&mut bytes, b"target-file");
    let path = write(&dir, "a.zip", &bytes);
    let config = SecurityConfig::default().with_allow_symlinks(true);

    let report = verify_archive_with_options(&path, &config, &default_integrity()).unwrap();
    assert_eq!(report.integrity_status(), IntegrityStatus::Fail);
    assert_eq!(corrupt_paths(&report), ["link"]);

    assert!(verify_archive(&path, &config).is_err());
}

mod tar_fixtures {
    use super::*;

    pub fn plain(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    pub fn gz(tar: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(tar).unwrap();
        encoder.finish().unwrap()
    }

    pub fn bz2(tar: &[u8]) -> Vec<u8> {
        let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        encoder.write_all(tar).unwrap();
        encoder.finish().unwrap()
    }

    pub fn xz(tar: &[u8]) -> Vec<u8> {
        let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 1);
        encoder.write_all(tar).unwrap();
        encoder.finish().unwrap()
    }

    pub fn zst(tar: &[u8]) -> Vec<u8> {
        zstd::encode_all(tar, 1).unwrap()
    }
}

fn three_entries() -> Vec<u8> {
    tar_fixtures::plain(&[("a", GOOD), ("b", OTHER), ("c", GOOD)])
}

#[test]
fn tar_plain_clean_is_ok() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.tar", &three_entries());

    let report = verify(&path, default_integrity());
    assert_eq!(report.integrity_status(), IntegrityStatus::Pass);
    assert_eq!(report.status(), VerificationStatus::Pass);
}

#[test]
fn tar_plain_truncated_inside_last_entry_is_an_error_with_and_without_integrity() {
    let dir = TempDir::new().unwrap();
    let tar = three_entries();
    let path = write(&dir, "a.tar", &tar[..tar.len() - 1024 - 512 - 10]);

    let without = verify_archive(&path, &SecurityConfig::default());
    assert!(without.is_err());
    assert_matches!(
        verify_err(&path, default_integrity()),
        ArchiveError::InvalidArchive(_)
    );
}

#[test]
fn tar_plain_without_end_marker_is_incomplete() {
    let dir = TempDir::new().unwrap();
    let tar = three_entries();
    let path = write(&dir, "a.tar", &tar[..tar.len() - 1024]);

    let report = verify(&path, default_integrity());
    assert_eq!(report.integrity_status(), IntegrityStatus::Incomplete);
    assert_eq!(report.status(), VerificationStatus::Warning);
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.message.contains("no end-of-archive marker"))
    );
}

#[test]
fn tar_plain_with_trailing_junk_is_ok() {
    let dir = TempDir::new().unwrap();
    let mut tar = three_entries();
    tar.extend(std::iter::repeat_n(0x55u8, 4096));
    let path = write(&dir, "a.tar", &tar);

    let report = verify(&path, integrity(1));
    assert_eq!(report.integrity_status(), IntegrityStatus::Pass);
}

#[test]
fn tar_gz_clean_is_ok() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.tar.gz", &tar_fixtures::gz(&three_entries()));

    let report = verify(&path, default_integrity());
    assert_eq!(report.integrity_status(), IntegrityStatus::Pass);
}

#[test]
fn tar_gz_bad_trailer_crc_is_a_failed_report() {
    let dir = TempDir::new().unwrap();
    let mut gz = tar_fixtures::gz(&three_entries());
    let crc_at = gz.len() - 8;
    gz[crc_at] ^= 0xFF;
    let path = write(&dir, "a.tar.gz", &gz);

    let report = verify(&path, default_integrity());
    assert_eq!(report.integrity_status(), IntegrityStatus::Fail);
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.category == IssueCategory::CorruptData && i.entry_path.is_none())
    );

    let plain = verify_archive(&path, &SecurityConfig::default()).unwrap();
    assert_eq!(plain.integrity_status(), IntegrityStatus::Skipped);
}

#[test]
fn tar_gz_truncated_is_a_hard_error() {
    let dir = TempDir::new().unwrap();
    let gz = tar_fixtures::gz(&three_entries());
    let path = write(&dir, "a.tar.gz", &gz[..gz.len() / 2]);

    assert!(
        verify_archive_with_options(&path, &SecurityConfig::default(), &default_integrity())
            .is_err()
    );
}

/// A gzip stream of two stored deflate blocks split at `split`, with the
/// second block's NLEN field wrong.
fn gz_with_bad_second_block(data: &[u8], split: usize) -> Vec<u8> {
    let mut gz = vec![0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff];
    for (index, block) in [&data[..split], &data[split..]].into_iter().enumerate() {
        let len = u16::try_from(block.len()).unwrap();
        gz.push(u8::from(index == 1));
        gz.extend(len.to_le_bytes());
        let nlen = if index == 1 { len } else { !len };
        gz.extend(nlen.to_le_bytes());
        gz.extend(block);
    }
    let mut crc = flate2::Crc::new();
    crc.update(data);
    gz.extend(crc.sum().to_le_bytes());
    gz.extend(u32::try_from(data.len()).unwrap().to_le_bytes());
    gz
}

#[test]
fn tar_gz_invalid_deflate_block_inside_an_entry_is_a_hard_error() {
    let dir = TempDir::new().unwrap();
    let payload = vec![b'q'; 30_000];
    let tar = tar_fixtures::plain(&[("a", payload.as_slice())]);
    let path = write(&dir, "a.tar.gz", &gz_with_bad_second_block(&tar, 10_000));

    let err = verify_err(&path, default_integrity());
    assert!(
        matches!(&err, ArchiveError::InvalidArchive(m) if m.contains("integrity check failed")),
        "{err:?}"
    );
}

#[test]
fn tar_gz_split_into_two_members_at_a_header_boundary_is_fully_verified() {
    let dir = TempDir::new().unwrap();
    let tar = three_entries();
    let boundary = 2 * (512 + 512);
    let mut gz = tar_fixtures::gz(&tar[..boundary]);
    gz.extend(tar_fixtures::gz(&tar[boundary..]));
    let path = write(&dir, "a.tar.gz", &gz);

    let report = verify(&path, default_integrity());
    assert_eq!(report.integrity_status(), IntegrityStatus::Pass);
}

#[test]
fn tar_zst_trailing_frames_beyond_the_budget_are_incomplete() {
    let dir = TempDir::new().unwrap();
    let mut zst = tar_fixtures::zst(&three_entries());
    zst.extend(zstd::encode_all(vec![0u8; 64 * 1024].as_slice(), 1).unwrap());
    let path = write(&dir, "a.tar.zst", &zst);

    let report = verify(&path, integrity(1024));
    assert_eq!(report.integrity_status(), IntegrityStatus::Incomplete);
    assert_eq!(report.status(), VerificationStatus::Warning);

    let roomy = verify(&path, default_integrity());
    assert_eq!(roomy.integrity_status(), IntegrityStatus::Pass);
}

#[test]
fn tar_bz2_and_xz_clean_are_ok() {
    let dir = TempDir::new().unwrap();
    let tar = three_entries();
    let bz2 = write(&dir, "a.tar.bz2", &tar_fixtures::bz2(&tar));
    let xz = write(&dir, "a.tar.xz", &tar_fixtures::xz(&tar));

    assert_eq!(
        verify(&bz2, default_integrity()).integrity_status(),
        IntegrityStatus::Pass
    );
    assert_eq!(
        verify(&xz, default_integrity()).integrity_status(),
        IntegrityStatus::Pass
    );
}

#[test]
fn tar_bz2_and_xz_trailer_corruption_is_a_failed_report() {
    let dir = TempDir::new().unwrap();
    let tar = three_entries();
    let mut bz2 = tar_fixtures::bz2(&tar);
    let last = bz2.len() - 4;
    bz2[last] ^= 0xFF;
    let mut xz = tar_fixtures::xz(&tar);
    let footer = xz.len() - 3;
    xz[footer] ^= 0xFF;

    for (name, bytes) in [("a.tar.bz2", bz2), ("a.tar.xz", xz)] {
        let path = write(&dir, name, &bytes);
        let report = verify(&path, default_integrity());
        assert_eq!(report.integrity_status(), IntegrityStatus::Fail, "{name}");
    }
}

#[test]
fn tar_xz_over_decoder_memory_is_a_quota_error_not_corruption() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.tar.xz", &tar_fixtures::xz(&three_entries()));
    let config = SecurityConfig::default().with_max_decoder_memory(1024);

    let err = verify_archive_with_options(&path, &config, &default_integrity()).unwrap_err();
    assert_matches!(
        err,
        ArchiveError::QuotaExceeded {
            resource: QuotaResource::DecoderMemory { .. }
        }
    );
}

mod sevenz_fixtures {
    use super::*;
    use sevenz_rust2::ArchiveEntry;
    use sevenz_rust2::ArchiveWriter;
    use sevenz_rust2::EncoderConfiguration;
    use sevenz_rust2::EncoderMethod;
    use sevenz_rust2::SourceReader;

    pub fn solid(entries: &[(&str, &[u8])], methods: Vec<EncoderConfiguration>) -> Vec<u8> {
        let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
        if !methods.is_empty() {
            writer.set_content_methods(methods);
        }
        let archive_entries = entries
            .iter()
            .map(|(name, data)| {
                let mut entry = ArchiveEntry::new_file(name);
                entry.has_stream = !data.is_empty();
                entry.size = data.len() as u64;
                entry
            })
            .collect();
        let readers = entries
            .iter()
            .map(|(_, data)| SourceReader::from(Cursor::new(*data)))
            .collect();
        writer
            .push_archive_entries(archive_entries, readers)
            .unwrap();
        writer.finish().unwrap().into_inner()
    }

    pub fn copy() -> EncoderConfiguration {
        EncoderConfiguration::new(EncoderMethod::COPY)
    }
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures")
        .join(name)
}

fn solid_config() -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_solid_archives(true)
        .with_max_solid_block_memory(100 * 1024 * 1024)
}

#[test]
fn sevenz_non_solid_fixture_is_ok() {
    let report = verify(&fixture("simple.7z"), default_integrity());
    assert_eq!(report.integrity_status(), IntegrityStatus::Pass);
}

#[test]
fn sevenz_solid_fixture_is_incomplete_with_defaults() {
    let path = fixture("solid.7z");

    let report = verify(&path, default_integrity());
    assert_eq!(report.integrity_status(), IntegrityStatus::Incomplete);
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert_eq!(count(&report, IssueCategory::SecurityPolicy), 1);

    let allowed =
        verify_archive_with_options(&path, &solid_config(), &default_integrity()).unwrap();
    assert_eq!(allowed.integrity_status(), IntegrityStatus::Pass);
}

#[test]
fn sevenz_corrupt_solid_block_fails_and_checks_later_entries() {
    let dir = TempDir::new().unwrap();
    let mut bytes = sevenz_fixtures::solid(
        &[("a", GOOD), ("b", OTHER), ("c", GOOD)],
        vec![sevenz_fixtures::copy()],
    );
    flip_first(&mut bytes, GOOD);
    flip_first(&mut bytes, OTHER);
    let path = write(&dir, "a.7z", &bytes);

    let report = verify_archive_with_options(&path, &solid_config(), &default_integrity()).unwrap();
    assert_eq!(report.integrity_status(), IntegrityStatus::Fail);
    assert_eq!(corrupt_paths(&report), ["a", "b"]);
}

#[test]
fn sevenz_over_budget_block_is_incomplete() {
    let dir = TempDir::new().unwrap();
    let bytes = sevenz_fixtures::solid(&[("a", GOOD), ("b", OTHER)], vec![sevenz_fixtures::copy()]);
    let path = write(&dir, "a.7z", &bytes);

    let report = verify_archive_with_options(&path, &solid_config(), &integrity(1)).unwrap();
    assert_eq!(report.integrity_status(), IntegrityStatus::Incomplete);
}

#[test]
fn sevenz_ppmd_over_decoder_memory_is_not_decoded() {
    use sevenz_rust2::encoder_options::PpmdOptions;

    let dir = TempDir::new().unwrap();
    let bytes = sevenz_fixtures::solid(&[("a", GOOD)], vec![PpmdOptions::from_level(4).into()]);
    let path = write(&dir, "a.7z", &bytes);
    let config = SecurityConfig::default().with_max_decoder_memory(1024 * 1024);

    let report = verify_archive_with_options(&path, &config, &default_integrity()).unwrap();
    assert_eq!(report.integrity_status(), IntegrityStatus::Incomplete);
    assert!(count(&report, IssueCategory::QuotaExceeded) >= 1);
}

fn noisy(len: usize) -> Vec<u8> {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            u8::try_from(state & 0xFF).unwrap()
        })
        .collect()
}

#[test]
fn sevenz_lzma2_over_decoder_memory_is_not_decoded() {
    let dir = TempDir::new().unwrap();
    let data = noisy(1024 * 1024);
    let lzma2 = EncoderConfiguration::new(EncoderMethod::LZMA2);
    let path = write(
        &dir,
        "a.7z",
        &sevenz_fixtures::solid(&[("a", data.as_slice())], vec![lzma2]),
    );
    let config = SecurityConfig::default().with_max_decoder_memory(256 * 1024);

    let report = verify_archive_with_options(&path, &config, &default_integrity()).unwrap();
    assert_eq!(report.integrity_status(), IntegrityStatus::Incomplete);
    assert!(count(&report, IssueCategory::QuotaExceeded) >= 1);
}

#[test]
fn sevenz_size_preserving_filter_is_not_charged_twice() {
    let dir = TempDir::new().unwrap();
    let data = noisy(64 * 1024);
    let methods = vec![
        EncoderConfiguration::new(EncoderMethod::BCJ_X86_FILTER),
        EncoderConfiguration::new(EncoderMethod::LZMA2),
    ];
    let path = write(
        &dir,
        "a.7z",
        &sevenz_fixtures::solid(&[("a", data.as_slice())], methods),
    );

    // Summing every coder's output would need about twice the data size; the
    // writer records the BCJ stage a few bytes above the data size.
    let budget = data.len() as u64 + 64;
    let report = verify(&path, integrity(budget));
    assert_eq!(report.integrity_status(), IntegrityStatus::Pass);
}

/// sevenz-rust2 decodes a block as the contiguous span of its stream count, so
/// a stream-less file between the stream files pushes the last one out of the
/// decoder's reach. Verify refuses the block like extract does and counts the
/// payload as unverified, never as `OK`.
#[test]
fn sevenz_interleaved_empty_file_cannot_hide_a_payload_file() {
    for name in ["interleaved-empty.7z", "interleaved-empty-badcrc.7z"] {
        let report =
            verify_archive_with_options(fixture(name), &solid_config(), &default_integrity())
                .unwrap();
        assert_eq!(report.status(), VerificationStatus::Fail, "{name}");
        assert_eq!(count(&report, IssueCategory::InvalidArchive), 1, "{name}");
        assert_eq!(
            report.integrity_status(),
            IntegrityStatus::Incomplete,
            "{name}"
        );
        assert_eq!(
            count(&report, IssueCategory::IntegrityIncomplete),
            1,
            "{name}"
        );
        assert!(
            report
                .issues()
                .iter()
                .any(|i| i.message.contains("not decodable: 3")),
            "{name}"
        );
    }
}

/// A GNU sparse entry whose stored data is 512 bytes but whose real size is
/// 1,000,512 bytes of synthesized zeros.
fn gnu_sparse_tar() -> Vec<u8> {
    let mut header = tar::Header::new_gnu();
    header.set_path("sparse").unwrap();
    header.set_entry_type(tar::EntryType::GNUSparse);
    header.set_size(512);
    header.set_mode(0o644);
    {
        let gnu = header.as_gnu_mut().unwrap();
        gnu.sparse[0].set_offset(1_000_000);
        gnu.sparse[0].set_length(512);
        gnu.set_real_size(1_000_512);
    }
    header.set_cksum();
    let mut tar = header.as_bytes().to_vec();
    tar.extend([7u8; 512]);
    tar.extend([0u8; 1024]);
    tar
}

#[test]
fn tar_gnu_sparse_entry_is_charged_its_real_size() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "sparse.tar", &gnu_sparse_tar());

    let roomy = verify(&path, integrity(2_000_000));
    assert_eq!(roomy.integrity_status(), IntegrityStatus::Pass);

    let tight = verify(&path, integrity(1_000_511));
    assert_eq!(tight.integrity_status(), IntegrityStatus::Incomplete);
    assert!(
        tight
            .issues()
            .iter()
            .any(|i| i.message.contains("over budget: 1"))
    );
}

#[test]
fn tar_archive_trait_verify_reads_the_trailer_within_the_budget() {
    let mut tar = three_entries();
    tar.extend(std::iter::repeat_n(0x55u8, 4096));
    let config = SecurityConfig::default().validate().unwrap();

    let mut archive = TarArchive::new(Cursor::new(tar.clone()));
    let report = archive.verify(&config, &integrity(1024)).unwrap();
    assert_eq!(report.integrity_status(), IntegrityStatus::Incomplete);

    let mut archive = TarArchive::new(Cursor::new(tar));
    let report = archive.verify(&config, &default_integrity()).unwrap();
    assert_eq!(report.integrity_status(), IntegrityStatus::Pass);
}

#[test]
fn zip_directory_entry_carrying_data_is_checked() {
    let dir = TempDir::new().unwrap();
    let mut writer = zip::write::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer.start_file("folder/", options).unwrap();
    writer.write_all(GOOD).unwrap();
    let mut bytes = writer.finish().unwrap().into_inner();
    flip_first(&mut bytes, GOOD);
    let path = write(&dir, "a.zip", &bytes);

    let report = verify(&path, default_integrity());
    assert_eq!(report.integrity_status(), IntegrityStatus::Fail);
    assert_eq!(corrupt_paths(&report), ["folder"]);
}

#[test]
fn zip_over_ratio_entry_is_not_decoded() {
    let dir = TempDir::new().unwrap();
    let zeros = vec![0u8; 1024 * 1024];
    let bytes = zip_fixtures::build(
        &[("zeros", zeros.as_slice())],
        zip::CompressionMethod::Deflated,
    );
    let path = write(&dir, "a.zip", &bytes);

    let report = verify(&path, default_integrity());
    assert_eq!(report.integrity_status(), IntegrityStatus::Incomplete);
    assert_eq!(count(&report, IssueCategory::ZipBomb), 1);
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.message.contains("resource limit: 1"))
    );
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(bytes);
    crc.sum()
}

/// Rewrites bytes of the archive's plain header and refreshes both CRCs.
fn patch_header(bytes: &mut [u8], patch: impl FnOnce(&mut [u8])) {
    let offset = usize::try_from(u64::from_le_bytes(bytes[12..20].try_into().unwrap())).unwrap();
    let size = usize::try_from(u64::from_le_bytes(bytes[20..28].try_into().unwrap())).unwrap();
    let header = 32 + offset..32 + offset + size;
    patch(&mut bytes[header.clone()]);
    let header_crc = crc32(&bytes[header]);
    bytes[28..32].copy_from_slice(&header_crc.to_le_bytes());
    let start_crc = crc32(&bytes[12..32]);
    bytes[8..12].copy_from_slice(&start_crc.to_le_bytes());
}

#[test]
fn sevenz_unknown_coder_is_not_decodable() {
    let dir = TempDir::new().unwrap();
    let mut bytes =
        sevenz_fixtures::solid(&[("a", GOOD), ("b", OTHER)], vec![sevenz_fixtures::copy()]);
    patch_header(&mut bytes, |header| {
        // kFolder, one folder, not external, one coder: id size 1, id 0x00
        // (COPY)
        let at = header
            .windows(6)
            .position(|w| w == [0x0B, 0x01, 0x00, 0x01, 0x01, 0x00])
            .expect("plain header with a COPY coder");
        header[at + 5] = 0x0F;
    });
    let path = write(&dir, "a.7z", &bytes);

    let report = verify_archive_with_options(&path, &solid_config(), &default_integrity()).unwrap();
    assert_eq!(report.integrity_status(), IntegrityStatus::Incomplete);
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.message.contains("not decodable: 2"))
    );
}

/// Replaces the plain header (which ends the archive) and refreshes both CRCs.
fn rewrite_header(bytes: &mut Vec<u8>, rewrite: impl FnOnce(&[u8]) -> Vec<u8>) {
    let offset = usize::try_from(u64::from_le_bytes(bytes[12..20].try_into().unwrap())).unwrap();
    let new_header = rewrite(&bytes[32 + offset..]);
    bytes.truncate(32 + offset);
    bytes.extend_from_slice(&new_header);
    bytes[20..28].copy_from_slice(&(new_header.len() as u64).to_le_bytes());
    bytes[28..32].copy_from_slice(&crc32(&new_header).to_le_bytes());
    let start_crc = crc32(&bytes[12..32]);
    bytes[8..12].copy_from_slice(&start_crc.to_le_bytes());
}

/// The block CRC fires once the whole block was read, so a mismatch belongs to
/// the block's last entry and leaves no spurious unverified count. The header
/// is rewritten so the block carries a (wrong) CRC and no entry has one.
#[test]
fn sevenz_block_crc_mismatch_is_attributed_to_the_last_entry() {
    let dir = TempDir::new().unwrap();
    let block: Vec<u8> = [GOOD, OTHER, GOOD].concat();
    let mut bytes = sevenz_fixtures::solid(
        &[("a", GOOD), ("b", OTHER), ("c", GOOD)],
        vec![sevenz_fixtures::copy()],
    );
    let wrong_crc = (crc32(&block) ^ 1).to_le_bytes();
    rewrite_header(&mut bytes, |header| {
        // kCodersUnpackSize (96 bytes), kEnd of the unpack info
        let unpack_end = header
            .windows(3)
            .position(|w| w == [0x0C, 0x60, 0x00])
            .expect("unpack info of a 96-byte block")
            + 2;
        // kNumUnpackStream 3, kSize 32 32, kCRC all defined + three CRCs
        let entry_crcs = header
            .windows(7)
            .position(|w| w == [0x0D, 0x03, 0x09, 0x20, 0x20, 0x0A, 0x01])
            .expect("sub-streams info with entry CRCs")
            + 5;
        [
            &header[..unpack_end],
            &[0x0A, 0x01],
            &wrong_crc,
            &header[unpack_end..entry_crcs],
            &header[entry_crcs + 14..],
        ]
        .concat()
    });
    let path = write(&dir, "a.7z", &bytes);

    let report = verify_archive_with_options(&path, &solid_config(), &default_integrity()).unwrap();
    assert_eq!(report.integrity_status(), IntegrityStatus::Fail);
    assert_eq!(corrupt_paths(&report), ["c"]);
    assert_eq!(count(&report, IssueCategory::IntegrityIncomplete), 0);
}

fn extract_refusal(path: &Path, config: &SecurityConfig) -> ArchiveError {
    let dest = TempDir::new().unwrap();
    let err = exarch_core::extract_archive(path, dest.path(), config).unwrap_err();
    assert_eq!(std::fs::read_dir(dest.path()).unwrap().count(), 0);
    err
}

#[test]
fn sevenz_extract_refuses_ppmd_over_decoder_memory() {
    use sevenz_rust2::encoder_options::PpmdOptions;

    let dir = TempDir::new().unwrap();
    let bytes = sevenz_fixtures::solid(&[("a", GOOD)], vec![PpmdOptions::from_level(4).into()]);
    let path = write(&dir, "a.7z", &bytes);
    let config = SecurityConfig::default().with_max_decoder_memory(1024 * 1024);

    assert_matches!(
        extract_refusal(&path, &config),
        ArchiveError::QuotaExceeded {
            resource: QuotaResource::DecoderMemory { .. }
        }
    );
}

#[test]
fn sevenz_extract_refuses_lzma2_over_decoder_memory() {
    let dir = TempDir::new().unwrap();
    let data = noisy(1024 * 1024);
    let lzma2 = EncoderConfiguration::new(EncoderMethod::LZMA2);
    let path = write(
        &dir,
        "a.7z",
        &sevenz_fixtures::solid(&[("a", data.as_slice())], vec![lzma2]),
    );
    let config = SecurityConfig::default().with_max_decoder_memory(256 * 1024);

    assert_matches!(
        extract_refusal(&path, &config),
        ArchiveError::QuotaExceeded {
            resource: QuotaResource::DecoderMemory { .. }
        }
    );
}

#[test]
fn sevenz_verify_and_extract_agree_on_every_refusal() {
    let refused = [
        ("solid.7z", SecurityConfig::default()),
        (
            "encrypted-content-plain-header.7z",
            SecurityConfig::default(),
        ),
        ("interleaved-empty.7z", solid_config()),
    ];
    for (name, config) in refused {
        let path = fixture(name);
        extract_refusal(&path, &config);
        for options in [VerificationOptions::default(), default_integrity()] {
            let report = verify_archive_with_options(&path, &config, &options).unwrap();
            assert_eq!(report.status(), VerificationStatus::Fail, "{name}");
        }
    }
}

#[test]
fn sevenz_plain_verify_fails_a_solid_archive_with_one_policy_issue() {
    let path = fixture("solid.7z");

    let report = verify_archive_with_options(
        &path,
        &SecurityConfig::default(),
        &VerificationOptions::default(),
    )
    .unwrap();
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert_eq!(report.issues().len(), 1);
    assert_eq!(count(&report, IssueCategory::SecurityPolicy), 1);

    let allowed =
        verify_archive_with_options(&path, &solid_config(), &VerificationOptions::default())
            .unwrap();
    assert_eq!(allowed.status(), VerificationStatus::Pass);
}

#[test]
fn sevenz_content_encrypted_archive_with_a_plain_header_is_refused() {
    let path = fixture("encrypted-content-plain-header.7z");

    let report = verify(&path, VerificationOptions::default());
    assert_eq!(report.status(), VerificationStatus::Fail);
    // One issue per encrypted block: the fixture holds two non-solid files.
    assert_eq!(count(&report, IssueCategory::SecurityPolicy), 2);
    assert_matches!(
        extract_refusal(&path, &SecurityConfig::default()),
        ArchiveError::SecurityViolation { .. }
    );
}

#[test]
fn integrity_gaps_are_absent_unless_requested_and_empty_when_complete() {
    let path = fixture("simple.7z");

    assert!(
        verify(&path, VerificationOptions::default())
            .integrity_gaps()
            .is_none()
    );
    let report = verify(&path, default_integrity());
    assert!(report.integrity_gaps().unwrap().is_empty());
}

#[test]
fn integrity_gaps_count_and_list_the_unverified_entries_of_a_solid_archive() {
    let report = verify(&fixture("solid.7z"), default_integrity());

    let gaps = report.integrity_gaps().unwrap();
    assert_eq!(gaps.count(UnverifiedReason::SolidPolicy), 10);
    assert_eq!(gaps.total(), 10);
    assert_eq!(gaps.entries().len(), 10);
    assert!(
        gaps.entries()
            .iter()
            .all(|e| e.reason() == UnverifiedReason::SolidPolicy)
    );
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.message.contains("10 item(s)"))
    );
}

#[test]
fn integrity_gaps_of_a_tar_without_end_marker_have_a_count_and_no_path() {
    let dir = TempDir::new().unwrap();
    let tar = three_entries();
    let path = write(&dir, "a.tar", &tar[..tar.len() - 1024]);

    let report = verify(&path, default_integrity());

    let gaps = report.integrity_gaps().unwrap();
    assert_eq!(gaps.count(UnverifiedReason::NoEndMarker), 1);
    assert!(gaps.entries().is_empty());
    assert_eq!(gaps.omitted(), 0);
}

#[test]
fn sevenz_list_shows_every_entry_of_an_interleaved_block() {
    let manifest =
        exarch_core::list_archive(fixture("interleaved-empty.7z"), &SecurityConfig::default())
            .unwrap();

    let paths: Vec<_> = manifest
        .entries()
        .iter()
        .map(|e| e.path.display().to_string())
        .collect();
    assert_eq!(manifest.total_entries(), 4, "{paths:?}");
    assert!(paths.iter().any(|p| p == "d.txt"), "{paths:?}");
}

#[test]
fn sevenz_extract_fails_closed_on_an_interleaved_stream_less_entry() {
    let err = extract_refusal(&fixture("interleaved-empty.7z"), &solid_config());
    assert_matches!(err, ArchiveError::InvalidArchive(_), "{err:?}");
}

#[test]
fn sevenz_dropped_oversized_entry_does_not_misalign_its_solid_block() {
    let dir = TempDir::new().unwrap();
    let long = "a/".repeat(20_000);
    let bytes = sevenz_fixtures::solid(
        &[(&long, GOOD), ("b", OTHER), ("c", GOOD)],
        vec![sevenz_fixtures::copy()],
    );
    let path = write(&dir, "long.7z", &bytes);

    let report = verify_archive_with_options(&path, &solid_config(), &default_integrity()).unwrap();

    assert!(corrupt_paths(&report).is_empty(), "{:?}", report.issues());
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.message.contains("file name too long"))
    );
    assert_eq!(
        report
            .integrity_gaps()
            .unwrap()
            .count(UnverifiedReason::PathTooLong),
        1
    );
}

#[test]
fn zip_entry_dropped_for_its_path_is_an_integrity_gap() {
    let dir = TempDir::new().unwrap();
    let long = "a/".repeat(20_000);
    let bytes = zip_fixtures::stored(&[(&long, GOOD), ("b", OTHER)]);
    let path = write(&dir, "long.zip", &bytes);

    let report = verify(&path, default_integrity());

    assert_eq!(report.status(), VerificationStatus::Fail);
    assert_eq!(report.integrity_status(), IntegrityStatus::Incomplete);
    let gaps = report.integrity_gaps().unwrap();
    assert_eq!(gaps.count(UnverifiedReason::PathTooLong), 1);
    assert_eq!(gaps.total(), 1);
    assert!(gaps.entries().is_empty());
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.message.contains("path too long for the host"))
    );

    let plain = verify(&path, VerificationOptions::default());
    assert!(plain.integrity_gaps().is_none());
}
