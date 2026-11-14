//! Creation against sources that change or are not regular files, for every
//! writer. Each run happens on a worker thread with a deadline so a
//! regression fails the test instead of hanging it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::ArchiveError;
use crate::EntryPosition;
use crate::ProgressCallback;
use crate::Result;
use crate::SkipKind;
use crate::creation::config::CreationConfig;
use crate::creation::report::CreationReport;
use crate::creation::staged::ExcludedOutput;
use crate::creation::tar::write_tar;
use crate::creation::zip::write_zip;
use crate::formats::compression::CompressionCodec;
use std::assert_matches;
use std::fs;
use std::io::Cursor;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
enum Writer {
    Tar,
    TarGz,
    Zip,
}

const WRITERS: [Writer; 3] = [Writer::Tar, Writer::TarGz, Writer::Zip];

type Hook = Box<dyn FnMut(&Path) + Send>;

struct Probe {
    on_start: Hook,
    on_bytes: Hook,
}

impl Probe {
    fn idle() -> Self {
        Self {
            on_start: Box::new(|_| {}),
            on_bytes: Box::new(|_| {}),
        }
    }
}

impl ProgressCallback for Probe {
    fn on_entry_start(&mut self, path: &Path, _position: EntryPosition) {
        (self.on_start)(path);
    }

    fn on_bytes_written(&mut self, _bytes: u64) {
        (self.on_bytes)(Path::new(""));
    }

    fn on_entry_complete(&mut self, _path: &Path) {}

    fn on_complete(&mut self) {}
}

fn create(
    writer: Writer,
    source: PathBuf,
    config: CreationConfig,
    mut probe: Probe,
) -> Result<CreationReport> {
    let (done, result) = mpsc::channel();
    std::thread::spawn(move || {
        let sources = [source];
        let excluded = ExcludedOutput::none();
        let outcome = match writer {
            Writer::Tar => write_tar(Vec::new(), None, &sources, &config, &excluded, &mut probe),
            Writer::TarGz => write_tar(
                Vec::new(),
                Some(CompressionCodec::Gzip),
                &sources,
                &config,
                &excluded,
                &mut probe,
            ),
            Writer::Zip => write_zip(
                Cursor::new(Vec::new()),
                &sources,
                &config,
                &excluded,
                &mut probe,
            )
            .map(|(report, _)| report),
        };
        drop(done.send(outcome));
    });
    result
        .recv_timeout(Duration::from_secs(30))
        .expect("creation did not finish")
}

fn config() -> CreationConfig {
    CreationConfig::default().with_include_hidden(true)
}

#[test]
fn a_fifo_in_the_tree_is_left_out_not_read() {
    for writer in WRITERS {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "data").unwrap();
        crate::test_utils::make_fifo(&dir.path().join("pipe"));

        let report = create(writer, dir.path().to_path_buf(), config(), Probe::idle()).unwrap();

        assert_eq!(report.files_added, 1, "{writer:?}");
        assert_eq!(report.skipped.count(SkipKind::SpecialFile), 1, "{writer:?}");
    }
}

#[test]
fn a_fifo_given_as_the_source_is_left_out() {
    for writer in WRITERS {
        let dir = tempfile::tempdir().unwrap();
        let pipe = dir.path().join("pipe");
        crate::test_utils::make_fifo(&pipe);

        let report = create(writer, pipe, config(), Probe::idle()).unwrap();

        assert_eq!(report.files_added, 0, "{writer:?}");
        assert_eq!(report.skipped.count(SkipKind::SpecialFile), 1, "{writer:?}");
    }
}

#[test]
fn a_link_to_a_fifo_is_left_out_when_links_are_followed() {
    for writer in WRITERS {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("tree");
        fs::create_dir(&tree).unwrap();
        let pipe = dir.path().join("pipe");
        crate::test_utils::make_fifo(&pipe);
        std::os::unix::fs::symlink(&pipe, tree.join("link")).unwrap();

        let followed = config().with_follow_symlinks(true);
        let report = create(writer, tree, followed, Probe::idle()).unwrap();

        assert_eq!(report.files_added, 0, "{writer:?}");
        assert_eq!(report.skipped.count(SkipKind::SpecialFile), 1, "{writer:?}");
    }
}

#[test]
fn source_changed_to_a_link_is_refused() {
    for writer in WRITERS {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("tree");
        fs::create_dir(&tree).unwrap();
        fs::write(tree.join("a.txt"), "data").unwrap();
        let outside = dir.path().join("outside.txt");
        fs::write(&outside, "outside").unwrap();

        let target = tree.join("a.txt");
        let change = Probe {
            on_start: Box::new(move |path| {
                if path.ends_with("a.txt") {
                    fs::remove_file(&target).unwrap();
                    std::os::unix::fs::symlink(&outside, &target).unwrap();
                }
            }),
            on_bytes: Box::new(|_| {}),
        };

        let result = create(writer, tree, config(), change);

        assert_matches!(
            result,
            Err(ArchiveError::SourceChanged { .. }),
            "{writer:?}"
        );
    }
}

#[test]
fn source_changed_to_a_fifo_is_refused() {
    for writer in WRITERS {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("tree");
        fs::create_dir(&tree).unwrap();
        fs::write(tree.join("a.txt"), "data").unwrap();

        let target = tree.join("a.txt");
        let change = Probe {
            on_start: Box::new(move |path| {
                if path.ends_with("a.txt") {
                    fs::remove_file(&target).unwrap();
                    crate::test_utils::make_fifo(&target);
                }
            }),
            on_bytes: Box::new(|_| {}),
        };

        let result = create(writer, tree, config(), change);

        assert_matches!(
            result,
            Err(ArchiveError::SourceChanged { .. }),
            "{writer:?}"
        );
    }
}

#[test]
fn a_file_that_grows_during_the_copy_is_refused() {
    for writer in WRITERS {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("tree");
        fs::create_dir(&tree).unwrap();
        let file = tree.join("big.bin");
        fs::write(&file, vec![7u8; 4 * 1024 * 1024]).unwrap();

        let grow = Probe {
            on_start: Box::new(|_| {}),
            on_bytes: Box::new(move |_| {
                let mut open = fs::OpenOptions::new().append(true).open(&file).unwrap();
                open.write_all(b"more").unwrap();
            }),
        };

        let result = create(writer, tree, config(), grow);

        assert_matches!(
            result,
            Err(ArchiveError::SourceChanged { .. }),
            "{writer:?}"
        );
    }
}

#[test]
fn a_file_that_shrinks_during_the_copy_is_refused() {
    for writer in WRITERS {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("tree");
        fs::create_dir(&tree).unwrap();
        let file = tree.join("big.bin");
        fs::write(&file, vec![7u8; 4 * 1024 * 1024]).unwrap();

        let shrink = Probe {
            on_start: Box::new(|_| {}),
            on_bytes: Box::new(move |_| {
                fs::OpenOptions::new()
                    .write(true)
                    .open(&file)
                    .unwrap()
                    .set_len(10)
                    .unwrap();
            }),
        };

        let result = create(writer, tree, config(), shrink);

        assert_matches!(
            result,
            Err(ArchiveError::SourceChanged { .. }),
            "{writer:?}"
        );
    }
}

fn tree_with_subdirectory() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    fs::create_dir_all(tree.join("sub")).unwrap();
    fs::write(tree.join("sub").join("a.txt"), "data").unwrap();
    (dir, tree)
}

#[test]
fn parent_changed_to_a_fifo_is_refused() {
    for writer in WRITERS {
        let (dir, tree) = tree_with_subdirectory();
        let sub = tree.join("sub");
        let aside = dir.path().join("aside");
        let change = Probe {
            on_start: Box::new(move |path| {
                if path.ends_with("a.txt") {
                    fs::rename(&sub, &aside).unwrap();
                    crate::test_utils::make_fifo(&sub);
                }
            }),
            on_bytes: Box::new(|_| {}),
        };

        let result = create(writer, tree, config(), change);

        assert_matches!(
            result,
            Err(ArchiveError::SourceChanged { .. }),
            "{writer:?}"
        );
    }
}

#[test]
fn parent_changed_to_a_link_is_refused() {
    for writer in WRITERS {
        let (dir, tree) = tree_with_subdirectory();
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("a.txt"), "outside").unwrap();
        let sub = tree.join("sub");
        let aside = dir.path().join("aside");
        let change = Probe {
            on_start: Box::new(move |path| {
                if path.ends_with("a.txt") {
                    fs::rename(&sub, &aside).unwrap();
                    std::os::unix::fs::symlink(&outside, &sub).unwrap();
                }
            }),
            on_bytes: Box::new(|_| {}),
        };

        let result = create(writer, tree, config(), change);

        assert_matches!(
            result,
            Err(ArchiveError::SourceChanged { .. }),
            "{writer:?}"
        );
    }
}

#[test]
fn a_file_in_a_search_only_directory_is_archived() {
    use std::os::unix::fs::PermissionsExt;

    for writer in WRITERS {
        let dir = tempfile::tempdir().unwrap();
        let holder = dir.path().join("holder");
        fs::create_dir(&holder).unwrap();
        let file = holder.join("a.txt");
        fs::write(&file, "data").unwrap();
        fs::set_permissions(&holder, fs::Permissions::from_mode(0o311)).unwrap();
        if fs::read_dir(&holder).is_ok() {
            fs::set_permissions(&holder, fs::Permissions::from_mode(0o755)).unwrap();
            return;
        }

        let result = create(writer, file, config(), Probe::idle());

        fs::set_permissions(&holder, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(result.unwrap().files_added, 1, "{writer:?}");
    }
}
