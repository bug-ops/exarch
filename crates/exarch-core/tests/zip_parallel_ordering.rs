//! `Parallelism::Threads` keeps limits, progress, cancellation and the choice
//! of the failing entry exactly as `Sequential` has them (#1027).

#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

use std::assert_matches;
use std::num::NonZeroU64;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;

use exarch_core::ArchiveError;
use exarch_core::CreateRequest;
use exarch_core::CreationConfig;
use exarch_core::EntryPosition;
use exarch_core::OutputFile;
use exarch_core::Parallelism;
use exarch_core::ProgressCallback;
use exarch_core::SkipKind;
use tempfile::TempDir;

fn modes() -> Vec<Parallelism> {
    let mut modes = vec![Parallelism::Sequential];
    modes.extend(
        [1, 2, 4, 8]
            .into_iter()
            .map(|n| Parallelism::Threads(NonZeroUsize::new(n).unwrap())),
    );
    modes
}

fn tree(files: usize) -> TempDir {
    let src = TempDir::new().unwrap();
    for i in 0..files {
        std::fs::write(
            src.path().join(format!("f{i:03}.txt")),
            format!("entry {i}\n").repeat(50 + i * 7),
        )
        .unwrap();
    }
    src
}

#[derive(Default)]
struct Recorder {
    events: Arc<Mutex<Vec<String>>>,
    cancel_after_entries: Option<usize>,
    started: usize,
}

impl ProgressCallback for Recorder {
    fn on_entry_start(&mut self, path: &Path, _position: EntryPosition) {
        self.started += 1;
        self.events
            .lock()
            .unwrap()
            .push(format!("start {}", path.display()));
    }

    fn on_bytes_written(&mut self, bytes: u64) {
        self.events.lock().unwrap().push(format!("bytes {bytes}"));
    }

    fn on_entry_complete(&mut self, path: &Path) {
        self.events
            .lock()
            .unwrap()
            .push(format!("complete {}", path.display()));
    }

    fn on_complete(&mut self) {
        self.events.lock().unwrap().push("done".to_string());
    }

    fn is_cancelled(&mut self) -> bool {
        self.cancel_after_entries
            .is_some_and(|limit| self.started >= limit)
    }
}

fn create(
    src: &Path,
    out: &Path,
    config: &CreationConfig,
    progress: &mut Recorder,
) -> Result<exarch_core::CreationReport, ArchiveError> {
    CreateRequest::new(config)
        .with_progress(progress)
        .create(&OutputFile::replace(out), &[src])
}

#[test]
fn progress_events_arrive_in_archive_order_in_every_mode() {
    let src = tree(40);
    let mut baseline: Option<Vec<String>> = None;

    for mode in modes() {
        let out = TempDir::new().unwrap();
        let mut recorder = Recorder::default();
        let events = Arc::clone(&recorder.events);

        create(
            src.path(),
            &out.path().join("o.zip"),
            &CreationConfig::default().with_parallelism(mode),
            &mut recorder,
        )
        .unwrap();

        let seen = events.lock().unwrap().clone();
        match &baseline {
            None => baseline = Some(seen),
            Some(expected) => assert_eq!(&seen, expected, "{mode:?}"),
        }
    }
}

#[test]
fn the_file_size_limit_skips_the_same_entries_in_every_mode() {
    let src = tree(40);
    let config = CreationConfig::default().with_max_file_size(NonZeroU64::new(1500).unwrap());
    let mut baseline: Option<(usize, usize, Vec<u8>)> = None;

    for mode in modes() {
        let out = TempDir::new().unwrap();
        let path = out.path().join("o.zip");

        let report = create(
            src.path(),
            &path,
            &config.clone().with_parallelism(mode),
            &mut Recorder::default(),
        )
        .unwrap();

        let seen = (
            report.files_added,
            report.skipped.count(SkipKind::OverMaxFileSize),
            std::fs::read(&path).unwrap(),
        );
        assert!(seen.1 > 0 && seen.0 > 0, "{mode:?}");
        match &baseline {
            None => baseline = Some(seen),
            Some(expected) => assert!(&seen == expected, "{mode:?}"),
        }
    }
}

#[cfg(unix)]
#[test]
fn the_earliest_failing_entry_is_the_one_reported_in_every_mode() {
    use std::os::unix::fs::PermissionsExt;

    let src = tree(40);
    let early = src.path().join("f005.txt");
    let late = src.path().join("f030.txt");
    for locked in [&early, &late] {
        std::fs::set_permissions(locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    if std::fs::File::open(&early).is_ok() {
        return;
    }

    for mode in modes() {
        let out = TempDir::new().unwrap();
        let path = out.path().join("o.zip");

        let error = create(
            src.path(),
            &path,
            &CreationConfig::default().with_parallelism(mode),
            &mut Recorder::default(),
        )
        .unwrap_err();

        assert_matches!(
            &error,
            ArchiveError::SourceNotAccessible { path, .. } if path == &early,
            "{mode:?}: {error:?}"
        );
        assert!(!path.exists(), "{mode:?}");
    }
    for locked in [&early, &late] {
        std::fs::set_permissions(locked, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
}

#[test]
fn cancellation_stops_every_mode_with_no_output() {
    let src = tree(40);

    for mode in modes() {
        let out = TempDir::new().unwrap();
        let path = out.path().join("o.zip");
        let mut recorder = Recorder {
            cancel_after_entries: Some(3),
            ..Recorder::default()
        };

        let result = create(
            src.path(),
            &path,
            &CreationConfig::default().with_parallelism(mode),
            &mut recorder,
        );

        assert_matches!(result, Err(ArchiveError::Cancelled), "{mode:?}: {result:?}");
        assert!(!path.exists(), "{mode:?}");
    }
}
