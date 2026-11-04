//! A destination root swapped for a symlink, or replaced by another
//! directory, while extraction runs redirects nothing: the root is opened once
//! and every later write goes through that handle, so the entries land in the
//! directory that was extracted into.

#![cfg(unix)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

use std::io::Cursor;
use std::io::Write as _;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ProgressCallback;
use exarch_core::SecurityConfig;
use tempfile::TempDir;
use zip::CompressionMethod;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

#[derive(Clone, Copy, Debug)]
enum Format {
    Tar,
    Zip,
}

const FORMATS: [Format; 2] = [Format::Tar, Format::Zip];

impl Format {
    fn extension(self) -> &'static str {
        match self {
            Self::Tar => "tar",
            Self::Zip => "zip",
        }
    }

    fn build(self, names: &[&str]) -> Vec<u8> {
        match self {
            Self::Tar => {
                let mut builder = tar::Builder::new(Vec::new());
                for name in names {
                    let mut header = tar::Header::new_gnu();
                    header.set_size(3);
                    header.set_mode(0o644);
                    header.set_cksum();
                    builder.append_data(&mut header, name, &b"abc"[..]).unwrap();
                }
                builder.into_inner().unwrap()
            }
            Self::Zip => {
                let options =
                    SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
                let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
                for name in names {
                    zip.start_file(*name, options).unwrap();
                    zip.write_all(b"abc").unwrap();
                }
                zip.finish().unwrap().into_inner()
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Swap {
    ForSymlink,
    ForNewDirectory,
}

struct SwapRoot {
    after: String,
    dest: PathBuf,
    aside: PathBuf,
    outside: PathBuf,
    swap: Swap,
}

impl ProgressCallback for SwapRoot {
    fn on_entry_start(&mut self, _path: &Path, _position: exarch_core::EntryPosition) {}

    fn on_bytes_written(&mut self, _bytes: u64) {}

    fn on_entry_complete(&mut self, path: &Path) {
        if path != Path::new(&self.after) {
            return;
        }
        std::fs::rename(&self.dest, &self.aside).unwrap();
        match self.swap {
            Swap::ForSymlink => symlink(&self.outside, &self.dest).unwrap(),
            Swap::ForNewDirectory => std::fs::create_dir(&self.dest).unwrap(),
        }
    }

    fn on_complete(&mut self) {}
}

struct Outcome {
    _root: TempDir,
    result: exarch_core::Result<()>,
    outside: PathBuf,
    dest: PathBuf,
    aside: PathBuf,
}

fn run(format: Format, names: &[&str], precreate: Option<&str>, swap: Swap) -> Outcome {
    let root = TempDir::new().unwrap();
    let base = root.path().canonicalize().unwrap();
    let dest = base.join("dest");
    let outside = base.join("outside");
    let aside = base.join("aside");
    std::fs::create_dir(&dest).unwrap();
    std::fs::create_dir(&outside).unwrap();
    if let Some(name) = precreate {
        std::fs::create_dir(outside.join(name)).unwrap();
    }
    let archive = base.join(format!("swap.{}", format.extension()));
    std::fs::write(&archive, format.build(names)).unwrap();
    let mut swapper = SwapRoot {
        after: names[0].to_owned(),
        dest: dest.clone(),
        aside: aside.clone(),
        outside: outside.clone(),
        swap,
    };

    let result = ExtractRequest::new(&SecurityConfig::default())
        .with_options(ExtractionOptions::default())
        .with_progress(&mut swapper)
        .extract(&archive, &dest)
        .map(|_| ());
    Outcome {
        _root: root,
        result,
        outside,
        dest,
        aside,
    }
}

fn files_below(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(files_below(&path));
        } else {
            found.push(path);
        }
    }
    found
}

fn assert_landed_in_aside(outcome: &Outcome, names: &[&str], case: &str) {
    outcome.result.as_ref().unwrap();
    for name in names {
        assert!(outcome.aside.join(name).is_file(), "{case}: {name}");
    }
    let leaked = files_below(&outcome.outside);
    assert!(leaked.is_empty(), "{case}: wrote {leaked:?}");
}

#[test]
fn nested_entries_after_a_root_swap_land_in_the_original_directory() {
    let names = ["a/file1.txt", "a/file2.txt"];
    for format in FORMATS {
        for precreate in [Some("a"), None] {
            let outcome = run(format, &names, precreate, Swap::ForSymlink);
            assert_landed_in_aside(
                &outcome,
                &names,
                &format!("{format:?} precreate={precreate:?}"),
            );
        }
    }
}

#[test]
fn top_level_entries_after_a_root_swap_land_in_the_original_directory() {
    let names = ["file1.txt", "file2.txt"];
    for format in FORMATS {
        let outcome = run(format, &names, None, Swap::ForSymlink);
        assert_landed_in_aside(&outcome, &names, &format!("{format:?}"));
    }
}

#[test]
fn a_directory_recreated_at_the_root_path_receives_nothing() {
    let names = ["a/file1.txt", "a/file2.txt"];
    for format in FORMATS {
        let outcome = run(format, &names, None, Swap::ForNewDirectory);
        assert_landed_in_aside(&outcome, &names, &format!("{format:?}"));
        let replaced = files_below(&outcome.dest);
        assert!(replaced.is_empty(), "{format:?}: wrote {replaced:?}");
    }
}
