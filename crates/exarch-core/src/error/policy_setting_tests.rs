//! Drift guard: every [`PolicySetting`] has a refusal that reports it.

#![allow(clippy::expect_used)]

use std::ffi::OsStr;
use std::io::Cursor;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

use tempfile::TempDir;

use super::ArchiveError;
use super::PolicySetting;
use crate::SecurityConfig;
use crate::formats::tar_metadata_limit::budgeted_reader;
use crate::security::hardlink::require_hardlinks_allowed;
use crate::types::DestDir;
use crate::types::SafePath;
use crate::types::SafeSymlink;
use crate::types::safe_path::check_windows_component;
use crate::types::safe_symlink::require_symlinks_allowed;

fn expect_err<T>(result: Result<T, ArchiveError>, setting: PolicySetting) -> ArchiveError {
    result
        .err()
        .unwrap_or_else(|| panic!("{setting} refusal did not fire"))
}

/// Builds a refusal caused by `setting`'s default value.
///
/// The `match` has no wildcard, so adding a [`PolicySetting`] variant fails to
/// compile until a refusal for it is registered here.
fn refusal(setting: PolicySetting) -> ArchiveError {
    let temp = TempDir::new().expect("temp dir");
    let dest = DestDir::new(temp.path()).expect("dest dir");
    let config = SecurityConfig::default().validate().expect("valid config");
    match setting {
        PolicySetting::Symlinks => expect_err(require_symlinks_allowed(&config), setting),
        PolicySetting::Hardlinks => expect_err(require_hardlinks_allowed(&config), setting),
        PolicySetting::SolidArchives => {
            let fixture =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/solid.7z");
            expect_err(
                crate::extract_archive(fixture, temp.path(), &SecurityConfig::default()),
                setting,
            )
        }
        PolicySetting::BannedComponents => expect_err(
            SafePath::validate(Path::new(".git/config"), &dest, &config),
            setting,
        ),
        PolicySetting::MaxPathDepth => {
            let deep = ["d"; 64].join("/");
            expect_err(
                SafePath::validate(Path::new(&deep), &dest, &config),
                setting,
            )
        }
        PolicySetting::WindowsReservedNames => {
            expect_err(check_windows_component(OsStr::new("CON"), &config), setting)
        }
        PolicySetting::MaxTarMetadataBytes => {
            let (mut reader, _budget) = budgeted_reader(Cursor::new(vec![b'a'; 11]), 10);
            let err = reader
                .read_to_end(&mut Vec::new())
                .expect_err("budget must trip");
            ArchiveError::from(err)
        }
    }
}

#[test]
fn every_policy_setting_has_a_refusal_that_reports_it() {
    for &setting in PolicySetting::ALL {
        assert_eq!(
            refusal(setting).relaxable_by(),
            Some(setting),
            "{setting} refusal must report itself"
        );
    }
}

#[test]
fn symlink_target_checks_report_their_settings() {
    let temp = TempDir::new().expect("temp dir");
    let dest = DestDir::new(temp.path()).expect("dest dir");
    let config = SecurityConfig::default()
        .with_allow_symlinks(true)
        .validate()
        .expect("valid config");
    let link = SafePath::validate(Path::new("link"), &dest, &config).expect("link path");

    let banned = SafeSymlink::validate(&link, Path::new("sub/.git/x"), &dest, &config);
    assert_eq!(
        expect_err(banned, PolicySetting::BannedComponents).relaxable_by(),
        Some(PolicySetting::BannedComponents)
    );

    let deep_target = ["d"; 64].join("/");
    let deep = SafeSymlink::validate(&link, Path::new(&deep_target), &dest, &config);
    assert_eq!(
        expect_err(deep, PolicySetting::MaxPathDepth).relaxable_by(),
        Some(PolicySetting::MaxPathDepth)
    );
}

#[test]
fn constant_refusals_carry_no_setting() {
    let temp = TempDir::new().expect("temp dir");
    let dest = DestDir::new(temp.path()).expect("dest dir");
    let config = SecurityConfig::default().validate().expect("valid config");
    let err = expect_err(
        SafePath::validate(Path::new("a\0b"), &dest, &config),
        PolicySetting::BannedComponents,
    );
    assert!(matches!(err, ArchiveError::SecurityViolation { .. }));
    assert_eq!(err.relaxable_by(), None);
}

#[test]
fn partial_extraction_delegates_relaxable_by() {
    let err = ArchiveError::PartialExtraction {
        source: Box::new(ArchiveError::relaxable_violation(
            PolicySetting::Hardlinks,
            "hardlinks not allowed".into(),
        )),
        report: crate::ExtractionReport::default(),
        writes: super::PartialWrites::Kept,
    };
    assert_eq!(err.relaxable_by(), Some(PolicySetting::Hardlinks));
    assert_eq!(
        err.to_ffi_message().relaxable_by,
        Some(PolicySetting::Hardlinks)
    );
}
