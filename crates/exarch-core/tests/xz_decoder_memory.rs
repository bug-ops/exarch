//! The xz decoder is bounded by `max_decoder_memory` (#629).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::assert_matches;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::QuotaResource;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use tempfile::TempDir;

const ONE_MIB: u64 = 1024 * 1024;

fn tar_bytes() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let data = vec![0u8; 4096];
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "a.txt", data.as_slice())
        .unwrap();
    builder.into_inner().unwrap()
}

fn write_tar_xz(dir: &Path, level: u32) -> PathBuf {
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), level);
    encoder.write_all(&tar_bytes()).unwrap();
    let path = dir.join("a.tar.xz");
    std::fs::write(&path, encoder.finish().unwrap()).unwrap();
    path
}

fn write_lzma_alone_named_tar_xz(dir: &Path) -> PathBuf {
    let options = xz2::stream::LzmaOptions::new_preset(6).unwrap();
    let stream = xz2::stream::Stream::new_lzma_encoder(&options).unwrap();
    let mut encoder = xz2::write::XzEncoder::new_stream(Vec::new(), stream);
    encoder.write_all(&tar_bytes()).unwrap();
    let path = dir.join("legacy.tar.xz");
    std::fs::write(&path, encoder.finish().unwrap()).unwrap();
    path
}

fn config_with_limit(limit: u64) -> SecurityConfig {
    SecurityConfig::default().with_max_decoder_memory(limit)
}

fn assert_decoder_memory(err: &ArchiveError, max: u64) {
    assert_matches!(
        err,
        ArchiveError::QuotaExceeded {
            resource: QuotaResource::DecoderMemory { max: reported }
        } if *reported == max
    );
}

#[test]
fn extract_rejects_xz_needing_more_than_decoder_memory() {
    let temp = TempDir::new().unwrap();
    let archive = write_tar_xz(temp.path(), 6);
    let out = TempDir::new().unwrap();

    let err = extract_archive(&archive, out.path(), &config_with_limit(ONE_MIB)).unwrap_err();

    let source = match err {
        ArchiveError::PartialExtraction { source, .. } => *source,
        other => other,
    };
    assert_decoder_memory(&source, ONE_MIB);
}

#[test]
fn list_rejects_xz_needing_more_than_decoder_memory() {
    let temp = TempDir::new().unwrap();
    let archive = write_tar_xz(temp.path(), 6);

    let err = list_archive(&archive, &config_with_limit(ONE_MIB)).unwrap_err();

    assert_decoder_memory(&err, ONE_MIB);
}

#[test]
fn verify_errors_with_decoder_memory_instead_of_reporting_pass() {
    let temp = TempDir::new().unwrap();
    let archive = write_tar_xz(temp.path(), 6);

    let err = verify_archive(&archive, &config_with_limit(ONE_MIB)).unwrap_err();

    assert_decoder_memory(&err, ONE_MIB);
}

#[test]
fn xz_within_decoder_memory_is_accepted() {
    let temp = TempDir::new().unwrap();
    let archive = write_tar_xz(temp.path(), 0);

    let manifest = list_archive(&archive, &config_with_limit(ONE_MIB)).unwrap();

    assert_eq!(manifest.entries().len(), 1);
}

#[test]
fn default_config_accepts_default_level_xz() {
    let temp = TempDir::new().unwrap();
    let archive = write_tar_xz(temp.path(), 6);

    assert!(list_archive(&archive, &SecurityConfig::default()).is_ok());
}

#[test]
fn decoder_memory_boundary_is_exact() {
    let temp = TempDir::new().unwrap();
    let archive = write_tar_xz(temp.path(), 6);

    let accepts = |limit: u64| list_archive(&archive, &config_with_limit(limit)).is_ok();
    let (mut low, mut high) = (1u64, 64 * ONE_MIB);
    assert!(!accepts(low) && accepts(high));
    while high - low > 1 {
        let mid = low + (high - low) / 2;
        if accepts(mid) {
            high = mid;
        } else {
            low = mid;
        }
    }

    assert!(accepts(high));
    assert_decoder_memory(
        &list_archive(&archive, &config_with_limit(high - 1)).unwrap_err(),
        high - 1,
    );
}

#[test]
fn legacy_lzma_alone_stream_is_rejected_as_tar_xz() {
    let temp = TempDir::new().unwrap();
    let archive = write_lzma_alone_named_tar_xz(temp.path());
    let out = TempDir::new().unwrap();
    let config = SecurityConfig::default();

    assert!(list_archive(&archive, &config).is_err());
    assert!(verify_archive(&archive, &config).is_err());
    assert!(extract_archive(&archive, out.path(), &config).is_err());
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[test]
fn legacy_lzma_alone_is_rejected_not_reported_as_memory_quota() {
    let temp = TempDir::new().unwrap();
    let archive = write_lzma_alone_named_tar_xz(temp.path());

    let err = list_archive(&archive, &config_with_limit(ONE_MIB)).unwrap_err();

    assert!(
        !matches!(err, ArchiveError::QuotaExceeded { .. }),
        "format error expected, got {err:?}"
    );
}
