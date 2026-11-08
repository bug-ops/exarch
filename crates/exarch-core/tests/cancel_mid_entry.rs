//! A cancellation requested while one large entry is being copied stops that
//! entry, in extraction and creation, instead of waiting for its end (#1045).

#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

mod sink_support;

use std::fs;
use std::path::Path;

use exarch_core::CreateRequest;
use exarch_core::CreationConfig;
use exarch_core::EntryPosition;
use exarch_core::ExtractRequest;
use exarch_core::OutputFile;
use exarch_core::ProgressCallback;
use exarch_core::SecurityConfig;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sevenz_rust2::EncoderConfiguration;
use sevenz_rust2::EncoderMethod;
use sink_support::tar_archive;
use sink_support::tar_file;
use sink_support::zip_archive;
use sink_support::zip_file;
use tempfile::TempDir;

/// Larger than two cancellation poll intervals, so the copy polls at least
/// once while the entry is still being moved.
const BIG: usize = 20 * 1024 * 1024;

/// Says no to the poll before an entry and yes to every poll after it.
#[derive(Debug, Default)]
struct CancelMidEntry {
    started: usize,
    polls_after_start: usize,
}

impl ProgressCallback for CancelMidEntry {
    fn on_entry_start(&mut self, _path: &Path, _position: EntryPosition) {
        self.started += 1;
    }

    fn on_bytes_written(&mut self, _bytes: u64) {}

    fn on_entry_complete(&mut self, _path: &Path) {}

    fn on_complete(&mut self) {}

    fn is_cancelled(&mut self) -> bool {
        if self.started == 0 {
            return false;
        }
        self.polls_after_start += 1;
        true
    }
}

fn extract_cancelled(archive: &Path, config: &SecurityConfig) {
    let work = TempDir::new().unwrap();
    let out = work.path().join("out");
    let mut progress = CancelMidEntry::default();

    let error = ExtractRequest::new(config)
        .with_progress(&mut progress)
        .extract(archive, &out)
        .unwrap_err();

    assert!(error.is_cancelled(), "{error:?}");
    assert_eq!(progress.started, 1);
    assert!(
        progress.polls_after_start >= 1,
        "the copy itself must poll, not only the entry boundary"
    );
    assert!(
        !out.join("big.bin").exists(),
        "a cancelled entry leaves no partial file"
    );
}

#[test]
fn a_tar_entry_is_cancelled_during_its_copy() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.tar");
    fs::write(&archive, tar_archive(&[tar_file("big.bin", &vec![0; BIG])])).unwrap();
    extract_cancelled(&archive, &SecurityConfig::default());
}

#[test]
fn a_zip_entry_is_cancelled_during_its_copy() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.zip");
    fs::write(
        &archive,
        zip_archive(vec![zip_file("big.bin", &vec![0; BIG])]),
    )
    .unwrap();
    extract_cancelled(&archive, &SecurityConfig::default());
}

#[test]
fn a_sevenz_entry_is_cancelled_during_its_copy() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.7z");
    let data = vec![0u8; 9 * 1024 * 1024];
    {
        let mut file = fs::File::create(&archive).unwrap();
        let mut writer = ArchiveWriter::new(&mut file).unwrap();
        writer.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::COPY)]);
        writer
            .push_archive_entry(ArchiveEntry::new_file("big.bin"), Some(data.as_slice()))
            .unwrap();
        writer.finish().unwrap();
    }
    extract_cancelled(&archive, &SecurityConfig::default());
}

#[test]
fn a_creation_is_cancelled_during_one_large_entry() {
    for name in ["out.tar.gz", "out.zip"] {
        let src = TempDir::new().unwrap();
        fs::write(src.path().join("big.bin"), vec![0u8; BIG]).unwrap();
        let out = TempDir::new().unwrap();
        let output = out.path().join(name);
        let config = CreationConfig::default();
        let mut progress = CancelMidEntry::default();

        let error = CreateRequest::new(&config)
            .with_progress(&mut progress)
            .create(&OutputFile::create_new(&output), &[src.path()])
            .unwrap_err();

        assert!(error.is_cancelled(), "{name}: {error:?}");
        assert!(progress.polls_after_start >= 1, "{name}");
        assert!(
            !output.exists(),
            "{name}: a cancelled creation leaves no output"
        );
    }
}
