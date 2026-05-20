//! Integration tests for ZIP-family formats (JAR, APK, WHL, EPUB, VSIX).
//!
//! These exercise real fixture files built by
//! `tests/fixtures/generate_zip_family_fixtures.sh` at the workspace root.
//! Each format shares the ZIP container but has its own shape quirks - the
//! tests below pick the bits that are actually load-bearing for extraction.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]

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

/// Build a ZIP in memory with a valid first entry followed by a path-traversal
/// entry.
///
/// Uses raw byte assembly so the traversal path (`../escape.txt`) bypasses the
/// `zip` crate's own path sanitisation and reaches `exarch-core`'s validator.
fn build_zip_with_traversal() -> Vec<u8> {
    // CRC-32 IEEE 802.3 polynomial — matches the ZIP spec.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }

    struct Entry<'a> {
        name: &'a [u8],
        content: &'a [u8],
    }

    let entries = [
        Entry {
            name: b"safe.txt",
            content: b"safe content",
        },
        Entry {
            name: b"../escape.txt",
            content: b"escaped",
        },
    ];

    let mut buf: Vec<u8> = Vec::new();
    let mut offsets: Vec<u32> = Vec::new();

    for e in &entries {
        let crc = crc32(e.content);
        let name_len = e.name.len() as u16;
        let data_len = e.content.len() as u32;
        offsets.push(buf.len() as u32);

        buf.extend_from_slice(b"PK\x03\x04");
        buf.extend_from_slice(&20u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        buf.extend_from_slice(&0u16.to_le_bytes()); // compression: Stored
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra field len
        buf.extend_from_slice(e.name);
        buf.extend_from_slice(e.content);
    }

    let central_dir_start = buf.len() as u32;

    for (i, e) in entries.iter().enumerate() {
        let crc = crc32(e.content);
        let name_len = e.name.len() as u16;
        let data_len = e.content.len() as u32;

        buf.extend_from_slice(b"PK\x01\x02");
        buf.extend_from_slice(&0x031eu16.to_le_bytes()); // made by Unix
        buf.extend_from_slice(&20u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra len
        buf.extend_from_slice(&0u16.to_le_bytes()); // comment len
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk start
        buf.extend_from_slice(&0u16.to_le_bytes()); // internal attr
        buf.extend_from_slice(&(0o100_644u32 << 16).to_le_bytes()); // external attr
        buf.extend_from_slice(&offsets[i].to_le_bytes());
        buf.extend_from_slice(e.name);
    }

    let central_dir_size = (buf.len() as u32) - central_dir_start;
    let count = entries.len() as u16;

    buf.extend_from_slice(b"PK\x05\x06");
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&count.to_le_bytes());
    buf.extend_from_slice(&count.to_le_bytes());
    buf.extend_from_slice(&central_dir_size.to_le_bytes());
    buf.extend_from_slice(&central_dir_start.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    buf
}

/// ZIP with a valid first entry followed by a path-traversal entry must return
/// `PartialExtraction` wrapping a `PathTraversal` source, with at least one
/// file already written to disk.
#[test]
fn zip_partial_extraction_stops_on_path_traversal() {
    let data = build_zip_with_traversal();

    let archive_dir = TempDir::new().expect("temp dir for archive");
    let archive_path = archive_dir.path().join("traversal.zip");
    std::fs::write(&archive_path, &data).expect("write zip to disk");

    let dest = TempDir::new().expect("temp dir for extraction");
    let config = SecurityConfig::default();

    let result = extract_archive(&archive_path, dest.path(), &config);

    match result {
        Err(ExtractionError::PartialExtraction { source, report }) => {
            assert!(
                matches!(*source, ExtractionError::PathTraversal { .. }),
                "source error must be PathTraversal, got: {source:?}"
            );
            assert!(
                report.files_extracted >= 1,
                "at least one file must have been extracted before the error, got: {}",
                report.files_extracted
            );
            assert!(
                report.bytes_written > 0,
                "bytes_written must be > 0, got: {}",
                report.bytes_written
            );
        }
        other => panic!("expected PartialExtraction, got: {other:?}"),
    }
}
