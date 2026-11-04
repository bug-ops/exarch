//! A symlink that already sits below the destination is never written
//! through: no path component under the destination resolves through a link
//! the extraction did not create under an allowed policy.

#![cfg(unix)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

use std::io::Cursor;
use std::io::Write as _;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ExtractionOptions;
use exarch_core::ProgressCallback;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive_with_options;
use exarch_core::extract_archive_with_options_and_progress;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use tempfile::TempDir;
use zip::CompressionMethod;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

#[derive(Clone, Copy, Debug)]
enum Format {
    Tar,
    Zip,
    SevenZ,
}

const FORMATS: [Format; 3] = [Format::Tar, Format::Zip, Format::SevenZ];

enum Item<'a> {
    Dir(&'a str),
    File(&'a str, &'a [u8]),
}

impl Format {
    fn extension(self) -> &'static str {
        match self {
            Self::Tar => "tar",
            Self::Zip => "zip",
            Self::SevenZ => "7z",
        }
    }

    fn build(self, items: &[Item<'_>]) -> Vec<u8> {
        match self {
            Self::Tar => build_tar(items),
            Self::Zip => build_zip(items),
            Self::SevenZ => build_sevenz(items),
        }
    }
}

fn build_tar(items: &[Item<'_>]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for item in items {
        let mut header = tar::Header::new_gnu();
        match item {
            Item::Dir(name) => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                header.set_mode(0o755);
                header.set_cksum();
                builder.append_data(&mut header, name, &b""[..]).unwrap();
            }
            Item::File(name, data) => {
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, name, *data).unwrap();
            }
        }
    }
    builder.into_inner().unwrap()
}

fn build_zip(items: &[Item<'_>]) -> Vec<u8> {
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    for item in items {
        match item {
            Item::Dir(name) => zip.add_directory(*name, options).unwrap(),
            Item::File(name, data) => {
                zip.start_file(*name, options).unwrap();
                zip.write_all(data).unwrap();
            }
        }
    }
    zip.finish().unwrap().into_inner()
}

fn build_sevenz(items: &[Item<'_>]) -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    for item in items {
        match item {
            Item::Dir(name) => {
                writer
                    .push_archive_entry::<&[u8]>(ArchiveEntry::new_directory(name), None)
                    .unwrap();
            }
            Item::File(name, data) => {
                let mut entry = ArchiveEntry::new_file(name);
                entry.has_stream = true;
                entry.size = data.len() as u64;
                writer
                    .push_archive_entry(entry, Some(Cursor::new(data.to_vec())))
                    .unwrap();
            }
        }
    }
    writer.finish().unwrap().into_inner()
}

struct Sandbox {
    _root: TempDir,
    archive_dir: TempDir,
    dest: PathBuf,
    outside: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        let dest = root.path().join("dest");
        let outside = root.path().join("outside");
        std::fs::create_dir(&dest).unwrap();
        std::fs::create_dir(&outside).unwrap();
        Self {
            _root: root,
            archive_dir: TempDir::new().unwrap(),
            dest: dest.canonicalize().unwrap(),
            outside: outside.canonicalize().unwrap(),
        }
    }

    fn plant_redirect(&self, at: &str) {
        let link = self.dest.join(at);
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        symlink(&self.outside, link).unwrap();
    }

    fn extract(
        &self,
        format: Format,
        items: &[Item<'_>],
        config: &SecurityConfig,
        options: &ExtractionOptions,
    ) -> exarch_core::Result<exarch_core::ExtractionReport> {
        let archive = self
            .archive_dir
            .path()
            .join(format!("a.{}", format.extension()));
        std::fs::write(&archive, format.build(items)).unwrap();
        extract_archive_with_options(&archive, &self.dest, config, options)
    }

    fn outside_entries(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.outside)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

fn force() -> ExtractionOptions {
    ExtractionOptions::default().with_skip_duplicates(false)
}

fn refuse_and_leave_outside_empty(
    sandbox: &Sandbox,
    format: Format,
    items: &[Item<'_>],
    options: &ExtractionOptions,
) {
    let result = sandbox.extract(format, items, &SecurityConfig::default(), options);
    assert!(result.is_err(), "{format:?}: extraction must be refused");
    assert_eq!(
        sandbox.outside_entries(),
        Vec::<String>::new(),
        "{format:?}: wrote outside the destination"
    );
}

#[test]
fn directory_entry_through_preexisting_symlink_is_refused() {
    for format in FORMATS {
        let sandbox = Sandbox::new();
        sandbox.plant_redirect("redirect");
        refuse_and_leave_outside_empty(
            &sandbox,
            format,
            &[
                Item::Dir("redirect/"),
                Item::File("redirect/pwned.txt", b"x"),
            ],
            &ExtractionOptions::default(),
        );
    }
}

#[test]
fn intermediate_component_symlink_is_refused() {
    for format in FORMATS {
        let sandbox = Sandbox::new();
        sandbox.plant_redirect("a/redirect");
        refuse_and_leave_outside_empty(
            &sandbox,
            format,
            &[
                Item::Dir("a/redirect/"),
                Item::File("a/redirect/pwned.txt", b"x"),
            ],
            &ExtractionOptions::default(),
        );
    }
}

#[test]
fn nested_file_without_directory_entries_is_refused() {
    for format in FORMATS {
        let sandbox = Sandbox::new();
        sandbox.plant_redirect("redirect");
        refuse_and_leave_outside_empty(
            &sandbox,
            format,
            &[Item::File("redirect/sub/pwned.txt", b"x")],
            &ExtractionOptions::default(),
        );
    }
}

#[test]
fn file_directly_below_preexisting_symlink_is_refused() {
    for format in FORMATS {
        let sandbox = Sandbox::new();
        sandbox.plant_redirect("redirect");
        refuse_and_leave_outside_empty(
            &sandbox,
            format,
            &[Item::File("redirect/pwned.txt", b"x")],
            &ExtractionOptions::default(),
        );
    }
}

#[test]
fn force_does_not_overwrite_a_file_behind_a_symlink() {
    for format in FORMATS {
        let sandbox = Sandbox::new();
        sandbox.plant_redirect("redirect");
        let victim = sandbox.outside.join("victim.txt");
        std::fs::write(&victim, b"original").unwrap();

        let result = sandbox.extract(
            format,
            &[
                Item::Dir("redirect/"),
                Item::File("redirect/victim.txt", b"pwned"),
            ],
            &SecurityConfig::default(),
            &force(),
        );

        assert!(result.is_err(), "{format:?}: extraction must be refused");
        assert_eq!(std::fs::read(&victim).unwrap(), b"original", "{format:?}");
        assert_eq!(sandbox.outside_entries(), ["victim.txt"], "{format:?}");
    }
}

#[test]
fn directory_swapped_for_a_symlink_between_runs_is_refused() {
    for format in FORMATS {
        let sandbox = Sandbox::new();
        let items = [Item::Dir("d/"), Item::File("d/f.txt", b"first")];
        sandbox
            .extract(format, &items, &SecurityConfig::default(), &force())
            .unwrap();

        std::fs::remove_dir_all(sandbox.dest.join("d")).unwrap();
        symlink(&sandbox.outside, sandbox.dest.join("d")).unwrap();

        refuse_and_leave_outside_empty(&sandbox, format, &items, &force());
    }
}

#[test]
fn allow_symlinks_still_refuses_a_preexisting_escaping_link() {
    for format in FORMATS {
        let sandbox = Sandbox::new();
        sandbox.plant_redirect("redirect");
        let config = SecurityConfig::default().with_allow_symlinks(true);

        let result = sandbox.extract(
            format,
            &[Item::File("redirect/sub/pwned.txt", b"x")],
            &config,
            &ExtractionOptions::default(),
        );

        assert!(result.is_err(), "{format:?}: extraction must be refused");
        assert_eq!(
            sandbox.outside_entries(),
            Vec::<String>::new(),
            "{format:?}"
        );
    }
}

#[test]
fn nested_extraction_still_works() {
    for format in FORMATS {
        let sandbox = Sandbox::new();
        let report = sandbox
            .extract(
                format,
                &[
                    Item::Dir("a/"),
                    Item::File("a/b/c.txt", b"deep"),
                    Item::File("a/b/d.txt", b"deep2"),
                    Item::File("top.txt", b"top"),
                ],
                &SecurityConfig::default(),
                &ExtractionOptions::default(),
            )
            .unwrap();

        assert_eq!(report.files_extracted, 3, "{format:?}");
        assert_eq!(
            std::fs::read(sandbox.dest.join("a/b/c.txt")).unwrap(),
            b"deep"
        );
        assert_eq!(std::fs::read(sandbox.dest.join("top.txt")).unwrap(), b"top");
    }
}

#[test]
fn reextraction_over_real_directories_still_works() {
    for format in FORMATS {
        let sandbox = Sandbox::new();
        let items = [Item::Dir("d/"), Item::File("d/f.txt", b"v")];
        for _ in 0..2 {
            sandbox
                .extract(format, &items, &SecurityConfig::default(), &force())
                .unwrap();
        }
        assert_eq!(std::fs::read(sandbox.dest.join("d/f.txt")).unwrap(), b"v");
    }
}

struct SwapDirForLink {
    after: &'static str,
    dir: PathBuf,
    outside: PathBuf,
}

impl ProgressCallback for SwapDirForLink {
    fn on_entry_start(&mut self, _path: &Path, _position: exarch_core::EntryPosition) {}

    fn on_bytes_written(&mut self, _bytes: u64) {}

    fn on_entry_complete(&mut self, path: &Path) {
        if path == Path::new(self.after) {
            std::fs::remove_dir_all(&self.dir).unwrap();
            symlink(&self.outside, &self.dir).unwrap();
        }
    }

    fn on_complete(&mut self) {}
}

#[test]
fn directory_swapped_for_a_symlink_mid_run_is_refused() {
    for format in FORMATS {
        let sandbox = Sandbox::new();
        let archive = sandbox
            .archive_dir
            .path()
            .join(format!("swap.{}", format.extension()));
        std::fs::write(
            &archive,
            format.build(&[
                Item::File("a/file1.txt", b"one"),
                Item::File("a/file2.txt", b"two"),
            ]),
        )
        .unwrap();
        let mut swapper = SwapDirForLink {
            after: "a/file1.txt",
            dir: sandbox.dest.join("a"),
            outside: sandbox.outside.clone(),
        };

        let result = extract_archive_with_options_and_progress(
            &archive,
            &sandbox.dest,
            &SecurityConfig::default(),
            &ExtractionOptions::default(),
            &mut swapper,
        );

        assert!(result.is_err(), "{format:?}: extraction must be refused");
        assert_eq!(
            sandbox.outside_entries(),
            Vec::<String>::new(),
            "{format:?}"
        );
    }
}

#[test]
fn allow_symlinks_still_writes_through_a_link_the_archive_created() {
    let sandbox = Sandbox::new();
    let mut builder = tar::Builder::new(Vec::new());
    for (name, kind, link) in [
        ("real/", tar::EntryType::Directory, None),
        ("alias", tar::EntryType::Symlink, Some("real")),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_size(0);
        header.set_mode(0o755);
        if let Some(link) = link {
            header.set_link_name(link).unwrap();
        }
        header.set_cksum();
        builder.append_data(&mut header, name, &b""[..]).unwrap();
    }
    let mut header = tar::Header::new_gnu();
    header.set_size(2);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "alias/f.txt", &b"ok"[..])
        .unwrap();
    let archive = sandbox.archive_dir.path().join("links.tar");
    std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();

    extract_archive_with_options(
        &archive,
        &sandbox.dest,
        &SecurityConfig::default().with_allow_symlinks(true),
        &ExtractionOptions::default(),
    )
    .unwrap();

    assert_eq!(
        std::fs::read(sandbox.dest.join("real/f.txt")).unwrap(),
        b"ok"
    );
}

#[test]
fn symlinked_destination_root_is_still_accepted() {
    for format in FORMATS {
        let sandbox = Sandbox::new();
        let link: PathBuf = sandbox.archive_dir.path().join("dest-link");
        symlink(&sandbox.dest, &link).unwrap();
        let archive = sandbox
            .archive_dir
            .path()
            .join(format!("root.{}", format.extension()));
        std::fs::write(
            &archive,
            format.build(&[Item::Dir("a/"), Item::File("a/b.txt", b"ok")]),
        )
        .unwrap();

        extract_archive_with_options(
            &archive,
            Path::new(&link),
            &SecurityConfig::default(),
            &ExtractionOptions::default(),
        )
        .unwrap();

        assert_eq!(std::fs::read(sandbox.dest.join("a/b.txt")).unwrap(), b"ok");
    }
}
