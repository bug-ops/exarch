//! The xz decoder is bounded by `max_decoder_memory` (#629).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::assert_matches;
use std::io::Write;
use std::path::Path;

use exarch_core::ArchiveError;
use exarch_core::QuotaResource;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use tempfile::TempDir;

const ONE_MIB: u64 = 1024 * 1024;

fn write_tar_xz(dir: &Path, level: u32) -> std::path::PathBuf {
    let mut builder = tar::Builder::new(Vec::new());
    let data = vec![0u8; 4096];
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "a.txt", data.as_slice())
        .unwrap();
    let tar_bytes = builder.into_inner().unwrap();

    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), level);
    encoder.write_all(&tar_bytes).unwrap();
    let path = dir.join("a.tar.xz");
    std::fs::write(&path, encoder.finish().unwrap()).unwrap();
    path
}

fn limited_config() -> SecurityConfig {
    SecurityConfig::default().with_max_decoder_memory(ONE_MIB)
}

fn assert_decoder_memory(err: &ArchiveError) {
    assert_matches!(
        err,
        ArchiveError::QuotaExceeded {
            resource: QuotaResource::DecoderMemory { max: ONE_MIB }
        }
    );
}

#[test]
fn extract_rejects_xz_needing_more_than_decoder_memory() {
    let temp = TempDir::new().unwrap();
    let archive = write_tar_xz(temp.path(), 6);
    let out = TempDir::new().unwrap();

    let err = extract_archive(&archive, out.path(), &limited_config()).unwrap_err();

    let source = match err {
        ArchiveError::PartialExtraction { source, .. } => *source,
        other => other,
    };
    assert_decoder_memory(&source);
}

#[test]
fn list_rejects_xz_needing_more_than_decoder_memory() {
    let temp = TempDir::new().unwrap();
    let archive = write_tar_xz(temp.path(), 6);

    let err = list_archive(&archive, &limited_config()).unwrap_err();

    assert_decoder_memory(&err);
}

#[test]
fn verify_does_not_pass_xz_needing_more_than_decoder_memory() {
    let temp = TempDir::new().unwrap();
    let archive = write_tar_xz(temp.path(), 6);

    match verify_archive(&archive, &limited_config()) {
        Err(err) => assert_decoder_memory(&err),
        Ok(report) => assert!(!report.issues().is_empty(), "{report:?}"),
    }
}

#[test]
fn xz_within_decoder_memory_is_accepted() {
    let temp = TempDir::new().unwrap();
    let archive = write_tar_xz(temp.path(), 0);

    let manifest = list_archive(&archive, &limited_config()).unwrap();

    assert_eq!(manifest.entries().len(), 1);
}

#[test]
fn default_config_accepts_default_level_xz() {
    let temp = TempDir::new().unwrap();
    let archive = write_tar_xz(temp.path(), 6);

    assert!(list_archive(&archive, &SecurityConfig::default()).is_ok());
}
