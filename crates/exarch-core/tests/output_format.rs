//! `OutputFile::with_format` is never silently ignored: an explicit format is
//! written whatever the extension says, and without one the extension decides,
//! refusing what it cannot name.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

use std::fs;
use std::path::Path;

use exarch_core::CreateRequest;
use exarch_core::CreationConfig;
use exarch_core::OutputFile;
use exarch_core::formats::detect::CreatableFormat;
use tempfile::TempDir;

/// The leading bytes (at an offset) that identify the container of `format`.
fn signature(format: CreatableFormat) -> (usize, &'static [u8]) {
    match format {
        CreatableFormat::Tar => (257, b"ustar"),
        CreatableFormat::TarGz => (0, &[0x1f, 0x8b]),
        CreatableFormat::TarBz2 => (0, b"BZh"),
        CreatableFormat::TarXz => (0, &[0xfd, b'7', b'z', b'X', b'Z', 0x00]),
        CreatableFormat::TarZst => (0, &[0x28, 0xb5, 0x2f, 0xfd]),
        CreatableFormat::Zip => (0, b"PK"),
        other => panic!("{other:?} needs a signature row"),
    }
}

fn has_signature(archive: &Path, format: CreatableFormat) -> bool {
    let (offset, expected) = signature(format);
    let bytes = fs::read(archive).unwrap();
    bytes.get(offset..offset + expected.len()) == Some(expected)
}

fn source() -> TempDir {
    let src = TempDir::new().unwrap();
    fs::write(src.path().join("a.txt"), b"alpha").unwrap();
    src
}

fn create(output: &OutputFile, src: &TempDir) -> exarch_core::Result<exarch_core::CreationReport> {
    CreateRequest::new(&CreationConfig::default()).create(output, &[src.path().join("a.txt")])
}

#[test]
fn an_explicit_format_is_written_whatever_the_extension_says() {
    let src = source();
    let dir = TempDir::new().unwrap();
    for &format in CreatableFormat::ALL {
        let archive = dir.path().join(format!("payload-{}.bin", format.as_str()));
        create(&OutputFile::create_new(&archive).with_format(format), &src).unwrap();
        assert!(has_signature(&archive, format), "{format:?}");
    }
}

#[test]
fn an_explicit_format_overrides_a_contradicting_extension() {
    let src = source();
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("looks-like.tar.gz");
    create(
        &OutputFile::create_new(&archive).with_format(CreatableFormat::Zip),
        &src,
    )
    .unwrap();
    assert!(has_signature(&archive, CreatableFormat::Zip));
    assert!(!has_signature(&archive, CreatableFormat::TarGz));
}

#[test]
fn without_a_format_the_extension_decides() {
    let src = source();
    let dir = TempDir::new().unwrap();
    for (name, format) in [
        ("a.tar", CreatableFormat::Tar),
        ("a.tar.gz", CreatableFormat::TarGz),
        ("a.zip", CreatableFormat::Zip),
    ] {
        let archive = dir.path().join(name);
        create(&OutputFile::create_new(&archive), &src).unwrap();
        assert!(has_signature(&archive, format), "{name}");
    }
}

#[test]
fn an_unknown_extension_without_a_format_is_refused_and_leaves_nothing() {
    let src = source();
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("payload.bin");
    assert!(create(&OutputFile::create_new(&archive), &src).is_err());
    assert!(!archive.exists());
}

#[test]
fn zip_based_extensions_are_refused_unless_a_format_is_explicit() {
    let src = source();
    let dir = TempDir::new().unwrap();
    for ext in ["apk", "whl", "epub"] {
        let archive = dir.path().join(format!("bundle.{ext}"));
        assert!(
            create(&OutputFile::create_new(&archive), &src).is_err(),
            "{ext}"
        );
        assert!(!archive.exists(), "{ext}");

        create(
            &OutputFile::create_new(&archive).with_format(CreatableFormat::Zip),
            &src,
        )
        .unwrap();
        assert!(has_signature(&archive, CreatableFormat::Zip), "{ext}");
    }
}
