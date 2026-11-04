//! The zstd window is bounded by `max_decoder_memory` for TAR and ZIP (#849).
//!
//! A frame's window must be at most the largest power of two within the
//! limit; a refusal is `QuotaExceeded { DecoderMemory }` in extract, list and
//! verify alike.

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(clippy::disallowed_methods)]

use std::assert_matches;
use std::io::Cursor;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ExtractionOptions;
use exarch_core::NoopProgress;
use exarch_core::QuotaResource;
use exarch_core::SecurityConfig;
use exarch_core::VerificationOptions;
use exarch_core::ZipConsistencyPolicy;
use exarch_core::extract_archive;
use exarch_core::formats::ZipArchive;
use exarch_core::formats::traits::ArchiveFormat;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use exarch_testkit::raw_zip::RawEntry;
use exarch_testkit::raw_zip::RawZip;
use tempfile::TempDir;

const PAYLOAD: &[u8] = b"hello hello hello hello";
const ZSTD_METHOD: u16 = 93;
const POLICIES: [ZipConsistencyPolicy; 2] =
    [ZipConsistencyPolicy::Ignore, ZipConsistencyPolicy::Enforce];

fn zstd_frame(payload: &[u8], window_log: u32, mantissa: u8) -> Vec<u8> {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0).unwrap();
    encoder.include_contentsize(false).unwrap();
    encoder
        .set_parameter(zstd::zstd_safe::CParameter::WindowLog(window_log))
        .unwrap();
    encoder.write_all(payload).unwrap();
    let mut frame = encoder.finish().unwrap();
    // magic (4), frame header descriptor (1), then the window descriptor
    frame[5] |= mantissa;
    frame
}

fn tar_bytes() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(PAYLOAD.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append_data(&mut header, "a.txt", PAYLOAD).unwrap();
    builder.into_inner().unwrap()
}

fn write_tar_zst(dir: &Path, window_log: u32, mantissa: u8) -> PathBuf {
    let path = dir.join(format!("w{window_log}m{mantissa}.tar.zst"));
    std::fs::write(&path, zstd_frame(&tar_bytes(), window_log, mantissa)).unwrap();
    path
}

fn zip_bytes(window_log: u32, mantissa: u8) -> Vec<u8> {
    let mut entry = RawEntry::stored("a.txt", PAYLOAD);
    entry.method = ZSTD_METHOD;
    entry.data = zstd_frame(PAYLOAD, window_log, mantissa);
    RawZip::new(vec![entry]).build().bytes
}

fn write_zip(dir: &Path, window_log: u32, mantissa: u8) -> PathBuf {
    let path = dir.join(format!("w{window_log}m{mantissa}.zip"));
    std::fs::write(&path, zip_bytes(window_log, mantissa)).unwrap();
    path
}

fn config(memory: u64, policy: ZipConsistencyPolicy) -> SecurityConfig {
    SecurityConfig::default()
        .with_max_decoder_memory(std::num::NonZeroU64::new(memory).unwrap())
        .with_zip_consistency(policy)
}

fn unwrapped(err: ArchiveError) -> ArchiveError {
    match err {
        ArchiveError::PartialExtraction(partial) => partial.into_parts().0,
        other => other,
    }
}

fn assert_decoder_memory(err: ArchiveError, max: u64, label: &str) {
    assert_matches!(
        unwrapped(err),
        ArchiveError::QuotaExceeded {
            resource: QuotaResource::DecoderMemory { max: reported }
        } if reported == max,
        "{label}"
    );
}

fn assert_path_operations(
    archive: &Path,
    config: &SecurityConfig,
    refused: Option<u64>,
    label: &str,
) {
    let out = TempDir::new().unwrap();
    let extracted = extract_archive(archive, out.path(), config);
    let listed = list_archive(archive, config);
    let verified = verify_archive(archive, config);
    match refused {
        None => {
            extracted.expect(label);
            listed.expect(label);
            verified.expect(label);
        }
        Some(max) => {
            assert_decoder_memory(extracted.unwrap_err(), max, label);
            assert_decoder_memory(listed.unwrap_err(), max, label);
            assert_decoder_memory(verified.unwrap_err(), max, label);
        }
    }
}

#[test]
fn tar_zst_windows_are_judged_at_the_power_of_two_of_the_limit() {
    for log in [12u32, 16, 20] {
        let dir = TempDir::new().unwrap();
        let at = 1u64 << log;
        let plain = write_tar_zst(dir.path(), log, 0);
        let boundary = [(at, None), (at + at / 2, None), (at - 1, Some(at - 1))];
        for (memory, refused) in boundary {
            let label = format!("tar.zst window 2^{log} limit {memory}");
            let policy = ZipConsistencyPolicy::Enforce;
            assert_path_operations(&plain, &config(memory, policy), refused, &label);
        }

        let wide = write_tar_zst(dir.path(), log, 1);
        let wide_boundary = [
            (at, Some(at)),
            (at * 2, None),
            (at * 2 - 1, Some(at * 2 - 1)),
        ];
        for (memory, refused) in wide_boundary {
            let label = format!("tar.zst window 2^{log}+1/8 limit {memory}");
            let policy = ZipConsistencyPolicy::Enforce;
            assert_path_operations(&wide, &config(memory, policy), refused, &label);
        }
    }
}

#[test]
fn tar_zst_window_27_is_accepted_by_default_and_28_refused() {
    let dir = TempDir::new().unwrap();
    let default = SecurityConfig::default();
    let max = default.max_decoder_memory.get();
    let ok = write_tar_zst(dir.path(), 27, 0);
    assert_path_operations(&ok, &default, None, "2^27");
    let too_wide = write_tar_zst(dir.path(), 28, 0);
    assert_path_operations(&too_wide, &default, Some(max), "2^28");
}

#[test]
fn zip_windows_are_judged_at_the_power_of_two_of_the_limit_under_both_policies() {
    for log in [12u32, 16, 20] {
        let dir = TempDir::new().unwrap();
        let at = 1u64 << log;
        let plain = write_zip(dir.path(), log, 0);
        let wide = write_zip(dir.path(), log, 1);
        for policy in POLICIES {
            for (memory, refused) in [(at, None), (at + at / 2, None), (at - 1, Some(at - 1))] {
                let label = format!("zip window 2^{log} limit {memory} {policy:?}");
                assert_path_operations(&plain, &config(memory, policy), refused, &label);
            }
            for (memory, refused) in [(at, Some(at)), (at * 2, None)] {
                let label = format!("zip window 2^{log}+1/8 limit {memory} {policy:?}");
                assert_path_operations(&wide, &config(memory, policy), refused, &label);
            }
        }
    }
}

#[test]
fn zip_window_27_is_accepted_by_default_and_28_refused() {
    let dir = TempDir::new().unwrap();
    let default = SecurityConfig::default();
    let max = default.max_decoder_memory.get();
    assert_path_operations(&write_zip(dir.path(), 27, 0), &default, None, "2^27");
    assert_path_operations(&write_zip(dir.path(), 28, 0), &default, Some(max), "2^28");
}

#[test]
fn zip_archive_handles_apply_the_limit_of_the_config_they_are_opened_under() {
    let at = 1u64 << 16;
    for policy in POLICIES {
        let strict = config(at - 1, policy);
        let loose = config(at, policy);
        let open = |config: &SecurityConfig| {
            ZipArchive::new(Cursor::new(zip_bytes(16, 0)), config).unwrap()
        };
        let out = TempDir::new().unwrap();

        assert_decoder_memory(
            open(&strict)
                .extract(out.path(), &ExtractionOptions::default(), &mut NoopProgress)
                .unwrap_err(),
            at - 1,
            "extract",
        );
        assert_decoder_memory(open(&strict).list().unwrap_err(), at - 1, "list");
        assert_decoder_memory(
            open(&strict)
                .verify(&VerificationOptions::default())
                .unwrap_err(),
            at - 1,
            "verify",
        );

        open(&loose).list().unwrap();
        open(&loose)
            .verify(&VerificationOptions::default())
            .unwrap();
        open(&loose)
            .extract(out.path(), &ExtractionOptions::default(), &mut NoopProgress)
            .unwrap();
    }
}

fn shared_local_header_zip(window_log: u32) -> Vec<u8> {
    let frame = zstd_frame(PAYLOAD, window_log, 0);
    let entries: Vec<RawEntry> = ["a.txt", "b.txt"]
        .iter()
        .map(|name| {
            let mut entry = RawEntry::stored("a.txt", PAYLOAD).with_central_name(name);
            entry.method = ZSTD_METHOD;
            entry.data.clone_from(&frame);
            entry
        })
        .collect();
    let built = RawZip::new(entries).build();
    let mut bytes = built.bytes.clone();
    let second = bytes[built.directory_start + 1..]
        .windows(4)
        .position(|w| w == b"PK\x01\x02")
        .map(|at| built.directory_start + 1 + at)
        .unwrap();
    let first_offset = u32::try_from(built.local_offsets[0]).unwrap();
    bytes[second + 42..second + 46].copy_from_slice(&first_offset.to_le_bytes());
    bytes
}

#[test]
fn entries_sharing_a_local_header_are_judged_by_their_window_alone() {
    let dir = TempDir::new().unwrap();
    for log in [16u32, 20] {
        let path = dir.path().join(format!("shared{log}.zip"));
        std::fs::write(&path, shared_local_header_zip(log)).unwrap();
        let at = 1u64 << log;
        for policy in POLICIES {
            let refused = config(at - 1, policy);
            assert_decoder_memory(
                list_archive(&path, &refused).unwrap_err(),
                at - 1,
                &format!("list 2^{log} {policy:?}"),
            );
            assert_decoder_memory(
                verify_archive(&path, &refused).unwrap_err(),
                at - 1,
                &format!("verify 2^{log} {policy:?}"),
            );
            let out = TempDir::new().unwrap();
            assert_decoder_memory(
                extract_archive(&path, out.path(), &refused).unwrap_err(),
                at - 1,
                &format!("extract 2^{log} {policy:?}"),
            );
        }
        let ignore = config(at, ZipConsistencyPolicy::Ignore);
        let out = TempDir::new().unwrap();
        extract_archive(&path, out.path(), &ignore).unwrap();
        assert_eq!(list_archive(&path, &ignore).unwrap().entries().len(), 2);
    }
}
