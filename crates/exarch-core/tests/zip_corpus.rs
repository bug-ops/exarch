//! Legitimate ZIP archives must pass the default `Enforce` policy untouched.
//!
//! The in-process corpus covers the layouts common producers write: stored and
//! deflated entries, data descriptors, ZIP64 local headers, aligned entries,
//! comments, prepended stubs and empty archives. Archives from other tools
//! (Info-ZIP, `ditto`, 7-Zip, `bsdtar`, Go, ...) are checked by the ignored
//! test below when
//! `EXARCH_ZIP_CORPUS_DIR` points at a directory of them; generate one with
//! `scripts/zip-corpus.sh`.
//!
//! Java (`java.util.zip`, `jar`) and Windows (`Compress-Archive`, .NET
//! `ZipFile`) archives are generated at test time. A missing tool skips its
//! producers locally; with `EXARCH_REQUIRE_PRODUCERS=1` (set in CI) it fails.
//! Windows Explorer archives cannot be produced headless in-process, so a
//! committed archive stands in for them on every host. Two `WinRAR` archives
//! (from the Go test data) are committed as well; they cover header shape
//! only, since each holds one empty stored entry.

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(clippy::disallowed_methods)]

use std::assert_matches;
use std::io::Cursor;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;

use exarch_core::ArchiveError;
use exarch_core::IssueCategory;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use tempfile::TempDir;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;
use zip::write::ZipWriter;

const STRUCTURAL: [IssueCategory; 4] = [
    IssueCategory::HeaderMismatch,
    IssueCategory::DuplicateEntry,
    IssueCategory::OverlappingEntries,
    IssueCategory::HiddenEntry,
];

fn options(method: CompressionMethod) -> SimpleFileOptions {
    SimpleFileOptions::default().compression_method(method)
}

fn seekable(method: CompressionMethod, large: bool) -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options = options(method).large_file(large);
    zip.add_directory("dir/", options).unwrap();
    zip.start_file("dir/a.txt", options).unwrap();
    zip.write_all(&b"hello world ".repeat(500)).unwrap();
    zip.start_file("empty", options).unwrap();
    zip.start_file("caf\u{e9}.txt", options).unwrap();
    zip.write_all(b"unicode").unwrap();
    zip.finish().unwrap().into_inner()
}

fn streamed(method: CompressionMethod, large: bool) -> Vec<u8> {
    let mut zip = ZipWriter::new_stream(Vec::new());
    let options = options(method).large_file(large);
    zip.start_file("a.txt", options).unwrap();
    zip.write_all(&b"streamed ".repeat(2000)).unwrap();
    zip.start_file("b.txt", options).unwrap();
    zip.write_all(b"second").unwrap();
    zip.finish().unwrap().into_inner()
}

fn aligned() -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options = options(CompressionMethod::Stored).with_alignment(4096);
    for name in ["lib/a.so", "lib/b.so"] {
        zip.start_file(name, options).unwrap();
        zip.write_all(&[7u8; 3000]).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn commented() -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    zip.set_comment("PK\u{3}\u{4} archive comment").unwrap();
    zip.start_file("a.txt", options(CompressionMethod::Deflated))
        .unwrap();
    zip.write_all(b"data").unwrap();
    zip.finish().unwrap().into_inner()
}

fn many_entries() -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options = options(CompressionMethod::Deflated);
    for i in 0..300 {
        zip.start_file(format!("dir{}/file{i}.txt", i % 7), options)
            .unwrap();
        zip.write_all(format!("entry {i}").as_bytes()).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn with_stub(archive: &[u8]) -> Vec<u8> {
    let mut bytes = b"#!/bin/sh\nexit 0\n".repeat(20);
    bytes.extend_from_slice(archive);
    bytes
}

fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let empty = ZipWriter::new(Cursor::new(Vec::new()))
        .finish()
        .unwrap()
        .into_inner();
    vec![
        ("empty", empty),
        ("stored", seekable(CompressionMethod::Stored, false)),
        ("deflated", seekable(CompressionMethod::Deflated, false)),
        ("zip64", seekable(CompressionMethod::Deflated, true)),
        ("streamed", streamed(CompressionMethod::Deflated, false)),
        (
            "streamed_stored",
            streamed(CompressionMethod::Stored, false),
        ),
        (
            "streamed_zip64",
            streamed(CompressionMethod::Deflated, true),
        ),
        ("aligned", aligned()),
        ("commented", commented()),
        ("many", many_entries()),
        (
            "stub",
            with_stub(&seekable(CompressionMethod::Deflated, false)),
        ),
    ]
}

/// Fails if the archive is rejected or reported for its structure. Other
/// rejections (for example Deflate64, which exarch does not admit) are not
/// structural and are accepted here.
fn assert_no_structural_finding(path: &Path, label: &str) {
    let config = SecurityConfig::default();
    match list_archive(path, &config) {
        Ok(_) => {}
        // Not admitted for a reason other than structure: Deflate64 and the
        // like.
        Err(ArchiveError::SecurityViolation { kind, .. })
            if kind.to_string().starts_with("unsupported") =>
        {
            return;
        }
        Err(e) => panic!("{label}: list rejected: {e}"),
    }
    let report = verify_archive(path, &config).unwrap();
    let findings: Vec<_> = report
        .issues()
        .iter()
        .filter(|i| STRUCTURAL.contains(&i.category))
        .collect();
    assert!(findings.is_empty(), "{label}: {findings:?}");
}

const HARMLESS: &[u8] = b"harmless\n";
const HARMLESS_CRC: u32 = 0x3024_c2ee;
const DATA_LEN: u32 = 9;

// Hand-written: a lone central record for a decoy directory is outside
// `RawZip`, which always writes a whole archive.
fn central_record(name: &[u8], mode: u32, local_offset: u32) -> Vec<u8> {
    let mut record = Vec::new();
    record.extend(0x0201_4B50u32.to_le_bytes());
    record.extend(0x0314u16.to_le_bytes());
    record.extend(20u16.to_le_bytes());
    record.extend(0x800u16.to_le_bytes());
    record.extend([0u8; 4]);
    record.extend(0x21u16.to_le_bytes());
    record.extend(HARMLESS_CRC.to_le_bytes());
    record.extend(DATA_LEN.to_le_bytes());
    record.extend(DATA_LEN.to_le_bytes());
    record.extend(u16::try_from(name.len()).unwrap().to_le_bytes());
    record.extend([0u8; 8]);
    record.extend((mode << 16).to_le_bytes());
    record.extend(local_offset.to_le_bytes());
    record.extend(name);
    record
}

/// A prefixed archive whose real directory is preceded by a complete decoy
/// directory naming the same entry differently. Readers that take the first
/// central record at or after the end record's offset (`zip` up to 9.0.5)
/// parse the decoy; the `zip` 9.1.0 locator parses the real one.
fn decoy_directory_archive(decoy_mode: u32) -> Vec<u8> {
    const PREFIX: usize = 200;
    assert_eq!(HARMLESS.len(), DATA_LEN as usize);
    let mut local = Vec::new();
    local.extend(0x0403_4B50u32.to_le_bytes());
    local.extend(20u16.to_le_bytes());
    local.extend(0x800u16.to_le_bytes());
    local.extend([0u8; 4]);
    local.extend(0x21u16.to_le_bytes());
    local.extend(HARMLESS_CRC.to_le_bytes());
    local.extend(DATA_LEN.to_le_bytes());
    local.extend(DATA_LEN.to_le_bytes());
    local.extend(10u16.to_le_bytes());
    local.extend(0u16.to_le_bytes());
    local.extend(b"readme.txt");
    local.extend(HARMLESS);

    let decoy_len = central_record(b"evil.txt", 0, 0).len();
    let end_record_offset = u32::try_from(local.len() + decoy_len).unwrap();
    let archive_offset = PREFIX + local.len() - end_record_offset as usize;
    let decoy = central_record(
        b"evil.txt",
        decoy_mode,
        u32::try_from(PREFIX - archive_offset).unwrap(),
    );
    let real = central_record(b"readme.txt", 0o100_644, 0);

    let mut bytes = vec![b'S'; PREFIX];
    bytes.extend(local);
    bytes.extend(decoy);
    bytes.extend(&real);
    bytes.extend(0x0605_4B50u32.to_le_bytes());
    bytes.extend([0u8; 4]);
    bytes.extend(1u16.to_le_bytes());
    bytes.extend(1u16.to_le_bytes());
    bytes.extend(u32::try_from(real.len()).unwrap().to_le_bytes());
    bytes.extend(end_record_offset.to_le_bytes());
    bytes.extend(0u16.to_le_bytes());
    bytes
}

#[test]
fn decoy_central_directory_before_a_prefixed_directory_is_reported() {
    let dir = TempDir::new().unwrap();
    for (label, mode) in [("file", 0o100_644), ("symlink", 0o120_777)] {
        let path = dir.path().join(format!("decoy-{label}.zip"));
        std::fs::write(&path, decoy_directory_archive(mode)).unwrap();

        let report = verify_archive(&path, &SecurityConfig::default()).unwrap();
        assert!(
            report
                .issues()
                .iter()
                .any(|i| i.category == IssueCategory::HiddenEntry),
            "{label}: {:?}",
            report.issues()
        );

        let dest = dir.path().join(format!("out-{label}"));
        std::fs::create_dir(&dest).unwrap();
        assert_matches!(
            extract_archive(&path, &dest, &SecurityConfig::default()),
            Err(ArchiveError::SecurityViolation { .. } | ArchiveError::ZipInconsistency { .. }),
            "{label}"
        );
    }
}

#[test]
fn zip64_directory_entry_extracts_under_enforce() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("zip64.zip");
    std::fs::write(&archive, seekable(CompressionMethod::Deflated, true)).unwrap();
    let dest = dir.path().join("out");
    std::fs::create_dir(&dest).unwrap();

    extract_archive(&archive, &dest, &SecurityConfig::default()).unwrap();

    assert!(dest.join("dir").is_dir());
    assert_eq!(std::fs::read(dest.join("dir/a.txt")).unwrap().len(), 6000);
}

#[test]
fn zip64_directory_with_placeholder_local_sizes_is_reported() {
    let mut bytes = seekable(CompressionMethod::Deflated, true);
    // Local header compressed-size field, as zip 9.0.5 wrote it for ZIP64
    // directories.
    bytes[18..22].copy_from_slice(&1u32.to_le_bytes());
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("placeholder.zip");
    std::fs::write(&path, bytes).unwrap();

    let report = verify_archive(&path, &SecurityConfig::default()).unwrap();

    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.category == IssueCategory::HeaderMismatch),
        "{:?}",
        report.issues()
    );
}

#[test]
fn generated_corpus_has_no_structural_findings() {
    let dir = TempDir::new().unwrap();
    for (label, bytes) in corpus() {
        let path = dir.path().join(format!("{label}.zip"));
        std::fs::write(&path, bytes).unwrap();
        assert_no_structural_finding(&path, label);
    }
}

#[test]
#[ignore = "needs EXARCH_ZIP_CORPUS_DIR"]
fn external_corpus_has_no_structural_findings() {
    let dir = std::env::var_os("EXARCH_ZIP_CORPUS_DIR").expect("EXARCH_ZIP_CORPUS_DIR is not set");
    let mut checked = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "zip" || e == "jar") {
            assert_no_structural_finding(&path, &path.display().to_string());
            checked += 1;
        }
    }
    assert!(checked > 0, "EXARCH_ZIP_CORPUS_DIR holds no archives");
}

const REQUIRE_PRODUCERS: &str = "EXARCH_REQUIRE_PRODUCERS";

fn tool_works(tool: &str, probe: &[&str]) -> bool {
    Command::new(tool)
        .args(probe)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Whether `tool` can run; a missing tool is fatal only when producers are
/// required.
fn tool_available(tool: &str, probe: &[&str]) -> bool {
    if tool_works(tool, probe) {
        return true;
    }
    assert!(
        std::env::var_os(REQUIRE_PRODUCERS).is_none(),
        "{REQUIRE_PRODUCERS} is set but `{tool}` is not usable"
    );
    eprintln!("skipping {tool} producers: tool not available");
    false
}

fn run(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn producer_source_tree(root: &Path) -> std::path::PathBuf {
    let src = root.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::create_dir_all(src.join("emptydir")).unwrap();
    std::fs::write(src.join("a.txt"), "hello\n").unwrap();
    std::fs::write(src.join("sub/rep.txt"), "x".repeat(5000)).unwrap();
    std::fs::write(
        src.join("sub/rand.bin"),
        (0..=255u8).cycle().take(200_000).collect::<Vec<_>>(),
    )
    .unwrap();
    std::fs::write(src.join("empty"), "").unwrap();
    std::fs::write(src.join("sub/caf\u{e9}.txt"), "unicode\n").unwrap();
    src
}

fn java_producers(src: &Path, out: &Path) -> usize {
    let mut made = 0;
    if tool_available("java", &["--version"]) {
        let program = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/ZipProducer.java");
        run(Command::new("java").arg(program).arg(out));
        made += 2;
    }
    if tool_available("jar", &["--version"]) {
        for (flags, name) in [("cf", "jar.jar"), ("cf0", "jar_store.jar")] {
            run(Command::new("jar")
                .arg(flags)
                .arg(out.join(name))
                .arg("-C")
                .arg(src)
                .arg("."));
            made += 1;
        }
    }
    made
}

/// Shell.Application `CopyHere` is what Windows Explorer's "Send to compressed
/// folder" uses; it copies asynchronously, so wait for the archive to settle.
#[cfg(windows)]
fn explorer_script(src: &Path, zip: &Path) -> String {
    format!(
        "$zip = '{zip}'; \
         [System.IO.File]::WriteAllBytes($zip, [byte[]](80,75,5,6 + (,0 * 18))); \
         $shell = New-Object -ComObject Shell.Application; \
         $shell.NameSpace($zip).CopyHere($shell.NameSpace('{src}').Items(), 20); \
         $last = -1; $stable = 0; \
         for ($i = 0; $i -lt 120 -and $stable -lt 4; $i++) {{ \
           Start-Sleep -Milliseconds 500; \
           $len = (Get-Item $zip).Length; \
           if ($len -eq $last -and $len -gt 22) {{ $stable++ }} else {{ $stable = 0; $last = $len }} \
         }}; \
         if ($stable -lt 4) {{ throw 'Explorer zip did not settle' }}",
        zip = zip.display(),
        src = src.display()
    )
}

#[cfg(windows)]
fn windows_producers(src: &Path, out: &Path) -> usize {
    let shell = ["pwsh", "powershell"]
        .into_iter()
        .find(|t| tool_works(t, &["-NoProfile", "-Command", "exit 0"]));
    let Some(shell) = shell else {
        assert!(
            std::env::var_os(REQUIRE_PRODUCERS).is_none(),
            "{REQUIRE_PRODUCERS} is set but PowerShell is not usable"
        );
        return 0;
    };
    let scripts = [
        format!(
            "Compress-Archive -Path '{}\\*' -DestinationPath '{}'",
            src.display(),
            out.join("compress_archive.zip").display()
        ),
        format!(
            "Add-Type -AssemblyName System.IO.Compression.FileSystem; \
             [System.IO.Compression.ZipFile]::CreateFromDirectory('{}', '{}')",
            src.display(),
            out.join("dotnet.zip").display()
        ),
        explorer_script(src, &out.join("explorer.zip")),
    ];
    for script in &scripts {
        run(Command::new(shell).args(["-NoProfile", "-Command", script]));
    }
    scripts.len()
}

#[cfg(not(windows))]
fn windows_producers(_src: &Path, _out: &Path) -> usize {
    0
}

#[test]
fn java_and_windows_producers_have_no_structural_findings() {
    let work = TempDir::new().unwrap();
    let src = producer_source_tree(work.path());
    let out = work.path().join("out");
    std::fs::create_dir(&out).unwrap();

    let expected = java_producers(&src, &out) + windows_producers(&src, &out);

    let mut checked = 0;
    for entry in std::fs::read_dir(&out).unwrap() {
        let path = entry.unwrap().path();
        assert_no_structural_finding(&path, &path.display().to_string());
        checked += 1;
    }
    assert_eq!(checked, expected);
}

/// Made by Windows Explorer's `Shell.Application` `CopyHere` on a Windows
/// runner; see `tests/fixtures/PROVENANCE.md`. Its names are CP437 without the
/// UTF-8 flag.
#[test]
fn windows_explorer_fixture_has_no_structural_findings_and_extracts() {
    let archive = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/zip-family/explorer-windows.zip");
    assert_no_structural_finding(&archive, "explorer-windows.zip");

    let out = TempDir::new().unwrap();
    let config = SecurityConfig::default().with_max_compression_ratio(1000.0);
    extract_archive(&archive, out.path(), &config).unwrap();
    assert_eq!(std::fs::read(out.path().join("a.txt")).unwrap(), b"hello\n");
    assert_eq!(std::fs::read(out.path().join("empty")).unwrap(), b"");
    assert_eq!(
        std::fs::read(out.path().join("sub/caf\u{e9}.txt")).unwrap(),
        b"unicode\n"
    );
    assert_eq!(
        std::fs::read(out.path().join("sub/rep.txt")).unwrap(),
        "x".repeat(5000).into_bytes()
    );
    assert_eq!(
        std::fs::read(out.path().join("sub/rand.bin")).unwrap(),
        (0..=255u8).cycle().take(200_000).collect::<Vec<_>>()
    );
}

/// Made by `WinRAR` (version made by `0x001F`, NTFS extra in the central
/// directory only); taken from the Go test data, see
/// `tests/fixtures/PROVENANCE.md`. One empty stored entry, so this covers
/// header shape only.
#[test]
fn winrar_fixtures_have_no_structural_findings_and_extract() {
    for (fixture, name) in [
        ("utf8-winrar.zip", "\u{4e16}\u{754c}"),
        ("time-winrar.zip", "test.txt"),
    ] {
        let archive = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/zip-family")
            .join(fixture);
        assert_no_structural_finding(&archive, fixture);

        let out = TempDir::new().unwrap();
        extract_archive(&archive, out.path(), &SecurityConfig::default()).unwrap();
        assert_eq!(
            std::fs::read(out.path().join(name)).unwrap(),
            b"",
            "{fixture}"
        );
        assert_eq!(
            std::fs::read_dir(out.path()).unwrap().count(),
            1,
            "{fixture}"
        );
    }
}
