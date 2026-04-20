//! Integration tests for ZIP-family formats (JAR, APK, WHL, EPUB, VSIX).
//!
//! These exercise real fixture files built by
//! `tests/fixtures/generate_zip_family_fixtures.sh` at the workspace root.
//! Each format shares the ZIP container but has its own shape quirks - the
//! tests below pick the bits that are actually load-bearing for extraction.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use exarch_core::ExtractionError;
use exarch_core::SecurityConfig;
use exarch_core::create_archive;
use exarch_core::creation::CreationConfig;
use exarch_core::extract_archive;
use exarch_core::formats::detect::ArchiveType;
use exarch_core::formats::detect::ZIP_FAMILY_ALIASES;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use std::path::Path;
use std::path::PathBuf;
use tempfile::TempDir;

fn fixture(name: &str) -> PathBuf {
    // Fixtures live at the workspace root, same as the 7z fixtures.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/zip-family")
        .join(name)
}

fn extract(name: &str) -> TempDir {
    let dest = TempDir::new().unwrap();
    let config = SecurityConfig::default();
    extract_archive(fixture(name), dest.path(), &config)
        .unwrap_or_else(|e| panic!("extracting {name}: {e:?}"));
    dest
}

#[test]
fn jar_extracts_with_manifest() {
    let dest = extract("simple.jar");
    let manifest = dest.path().join("META-INF/MANIFEST.MF");
    assert!(
        manifest.exists(),
        "META-INF/MANIFEST.MF should be extracted"
    );
    let contents = std::fs::read_to_string(&manifest).unwrap();
    assert!(contents.contains("Main-Class: com.example.Hello"));
    assert!(dest.path().join("com/example/Hello.class").exists());
}

#[test]
fn apk_extracts_unsigned_payload() {
    let dest = extract("simple.apk");
    // Pick the files any real APK would have. We're not validating them -
    // just that the ZIP layout round-trips.
    assert!(dest.path().join("AndroidManifest.xml").exists());
    assert!(dest.path().join("classes.dex").exists());
    assert!(dest.path().join("resources.arsc").exists());
    assert!(dest.path().join("res/values/strings.xml").exists());
    assert!(dest.path().join("lib/arm64-v8a/libnative.so").exists());
}

#[test]
fn wheel_extracts_with_dist_info_record() {
    let dest = extract("simple.whl");
    let dist_info = dest.path().join("exarch_fixture-0.1.0.dist-info");
    assert!(dist_info.join("METADATA").exists());
    assert!(dist_info.join("WHEEL").exists());
    let record = std::fs::read_to_string(dist_info.join("RECORD")).unwrap();
    assert!(record.contains("exarch_fixture/__init__.py"));
    assert!(record.contains("METADATA"));
    assert!(record.contains("RECORD,,"));
    assert!(dest.path().join("exarch_fixture/__init__.py").exists());
}

#[test]
fn epub_extracts_with_stored_mimetype_first() {
    // The shape that matters for EPUB: first entry is `mimetype`, STORED
    // (no deflate). If exarch's ZIP reader handles a stored entry
    // followed by deflated ones, extraction round-trips cleanly.
    let dest = extract("simple.epub");
    let mimetype = std::fs::read_to_string(dest.path().join("mimetype")).unwrap();
    assert_eq!(mimetype, "application/epub+zip");
    assert!(dest.path().join("META-INF/container.xml").exists());
    assert!(dest.path().join("OEBPS/content.opf").exists());
    assert!(dest.path().join("OEBPS/chapter1.xhtml").exists());
}

#[test]
fn vsix_extracts_with_manifest_and_content_types() {
    let dest = extract("simple.vsix");
    assert!(dest.path().join("extension.vsixmanifest").exists());
    // `[Content_Types].xml` has brackets in the name - worth checking it
    // survives the round-trip.
    assert!(dest.path().join("[Content_Types].xml").exists());
    assert!(dest.path().join("extension/package.json").exists());
}

#[test]
fn list_works_for_every_fixture() {
    let config = SecurityConfig::default();
    for name in [
        "simple.jar",
        "simple.apk",
        "simple.whl",
        "simple.epub",
        "simple.vsix",
    ] {
        let manifest = list_archive(fixture(name), &config)
            .unwrap_or_else(|e| panic!("listing {name}: {e:?}"));
        assert!(
            !manifest.entries.is_empty(),
            "{name} should have entries in its manifest",
        );
    }
}

#[test]
fn verify_works_for_every_fixture() {
    let config = SecurityConfig::default();
    for name in [
        "simple.jar",
        "simple.apk",
        "simple.whl",
        "simple.epub",
        "simple.vsix",
    ] {
        let report = verify_archive(fixture(name), &config)
            .unwrap_or_else(|e| panic!("verifying {name}: {e:?}"));
        assert!(
            report.is_safe(),
            "{name} should verify safe (report: {report:?})",
        );
    }
}

#[test]
fn inferred_creation_is_rejected_for_zip_family() {
    let dest = TempDir::new().unwrap();
    let config = CreationConfig::default();
    for ext in ZIP_FAMILY_ALIASES {
        let output = dest.path().join(format!("out.{ext}"));
        let result = create_archive(&output, &[] as &[&str], &config);
        match result {
            Err(ExtractionError::InvalidArchive(msg)) => {
                assert!(
                    msg.contains(ext),
                    ".{ext} error should mention the extension (got: {msg})",
                );
            }
            other => panic!(".{ext} should be rejected, got {other:?}"),
        }
    }
}

#[test]
fn plain_zip_is_still_creatable() {
    // Sanity: we haven't broken .zip creation by adding the guard.
    let dest = TempDir::new().unwrap();
    let config = CreationConfig::default();
    let src = dest.path().join("source.txt");
    std::fs::write(&src, b"hello").unwrap();
    let output = dest.path().join("out.zip");
    create_archive(&output, &[&src], &config).expect(".zip creation should still work");
    assert!(output.exists());
}

#[test]
fn explicit_format_override_allows_zip_family_creation() {
    // Escape hatch: a caller who sets CreationConfig::format = Some(Zip)
    // takes responsibility for producing a spec-valid file, so we let
    // them through.
    let dest = TempDir::new().unwrap();
    let src = dest.path().join("source.txt");
    std::fs::write(&src, b"hello").unwrap();
    let config = CreationConfig {
        format: Some(ArchiveType::Zip),
        ..CreationConfig::default()
    };
    let output = dest.path().join("out.apk");
    create_archive(&output, &[&src], &config)
        .expect("explicit ArchiveType::Zip should bypass the guard");
    assert!(output.exists());
}
