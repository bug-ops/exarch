//! The link walk reads only the targets it was asked for, from admitted
//! blocks, and degrades decode problems into per-link failures.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::assert_matches;
use std::io::Cursor;

use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sevenz_rust2::EncoderConfiguration;
use sevenz_rust2::EncoderMethod;
use sevenz_rust2::SourceReader;

use super::*;
use crate::test_utils::flip_first;

const SIGNATURE_LEN: usize = 32;

fn writer(stored: bool) -> ArchiveWriter<Cursor<Vec<u8>>> {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    if stored {
        writer.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::COPY)]);
    }
    writer
}

fn entry(name: &str, data: &[u8]) -> ArchiveEntry {
    let mut entry = ArchiveEntry::new_file(name);
    entry.has_stream = !data.is_empty();
    entry.size = data.len() as u64;
    entry
}

fn solid(files: &[(&str, &[u8])], stored: bool) -> Vec<u8> {
    let mut writer = writer(stored);
    let entries = files.iter().map(|(name, data)| entry(name, data)).collect();
    let readers = files
        .iter()
        .map(|(_, data)| SourceReader::from(Cursor::new(data.to_vec())))
        .collect();
    writer.push_archive_entries(entries, readers).unwrap();
    writer.finish().unwrap().into_inner()
}

fn one_block_each(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = writer(true);
    for (name, data) in files {
        let reader = (!data.is_empty()).then(|| Cursor::new(data.to_vec()));
        writer
            .push_archive_entry(entry(name, data), reader)
            .unwrap();
    }
    writer.finish().unwrap().into_inner()
}

struct Parsed {
    archive: Archive,
    compression: Vec<EntryCompression>,
}

fn parse(bytes: &[u8]) -> Parsed {
    let archive = Archive::read(&mut Cursor::new(bytes), &Password::empty()).unwrap();
    let compression = sevenz_entry_compression(&archive, bytes.len() as u64).unwrap();
    Parsed {
        archive,
        compression,
    }
}

fn config(solid: bool) -> SecurityConfig<Validated> {
    SecurityConfig::default()
        .with_allow_solid_archives(solid)
        .with_max_solid_block_memory(100 * 1024 * 1024)
        .validate()
        .unwrap()
}

fn table(indices: &[usize]) -> LinkTable<()> {
    let mut table = LinkTable::default();
    for &index in indices {
        table.push(index, ()).unwrap();
    }
    table
}

fn walk(
    parsed: &Parsed,
    source: Vec<u8>,
    config: &SecurityConfig<Validated>,
    links: &[usize],
) -> Vec<(usize, LinkOutcome)> {
    let mut seen = Vec::new();
    walk_sevenz_links(
        &parsed.archive,
        &mut Cursor::new(source),
        &parsed.compression,
        config,
        &table(links),
        &mut |index, outcome| {
            seen.push((index, outcome));
            Ok(())
        },
    )
    .unwrap();
    seen
}

fn target(path: &str) -> StoredLinkTarget {
    StoredLinkTarget::Read(PathBuf::from(path))
}

#[test]
fn a_link_table_accepts_only_ascending_indices() {
    let mut table = LinkTable::default();
    table.push(2, "a").unwrap();
    table.push(5, "b").unwrap();

    assert_matches!(table.push(5, "c"), Err(ArchiveError::InvalidArchive(_)));
    assert_matches!(table.push(3, "c"), Err(ArchiveError::InvalidArchive(_)));
    assert_eq!(table.get(5), Some(&"b"));
    assert_eq!(table.get(3), None);
    assert_eq!(table.indices().collect::<Vec<_>>(), [2, 5]);
}

#[test]
fn reads_links_of_separate_blocks_in_order() {
    let bytes = one_block_each(&[("a", b"first"), ("x", b"data"), ("b", b"second")]);
    let parsed = parse(&bytes);

    let seen = walk(&parsed, bytes, &config(false), &[0, 2]);

    assert_eq!(seen, [(0, Ok(target("first"))), (2, Ok(target("second")))]);
}

#[test]
fn a_corrupt_checksum_on_a_drained_file_does_not_hide_the_link() {
    let filler = b"FILLERFILLERFILLER";
    let mut bytes = solid(&[("filler", filler), ("link", b"target")], true);
    flip_first(&mut bytes, filler);
    let parsed = parse(&bytes);

    let seen = walk(&parsed, bytes, &config(true), &[1]);

    assert_eq!(seen, [(1, Ok(target("target")))]);
}

#[test]
fn a_decoder_failure_gives_the_remaining_links_a_decode_failure() {
    let filler = vec![b'f'; 1000];
    let bytes = solid(
        &[("one", b"first"), ("filler", &filler), ("two", b"second")],
        true,
    );
    let parsed = parse(&bytes);
    let truncated = bytes[..SIGNATURE_LEN + 100].to_vec();

    let seen = walk(&parsed, truncated, &config(true), &[0, 2]);

    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0], (0, Ok(target("first"))));
    assert_matches!(
        &seen[1],
        (
            2,
            Err(LinkReadFailure::Truncated | LinkReadFailure::Decode(_))
        )
    );
}

#[test]
fn a_checksum_failure_on_a_link_keeps_the_block_aligned() {
    let mut bytes = solid(&[("one", b"FIRSTFIRST"), ("two", b"second")], true);
    flip_first(&mut bytes, b"FIRSTFIRST");
    let parsed = parse(&bytes);

    let seen = walk(&parsed, bytes, &config(true), &[0, 1]);

    assert_eq!(seen[0], (0, Err(LinkReadFailure::Checksum)));
    assert_eq!(seen[1], (1, Ok(target("second"))));
}

#[test]
fn a_refused_block_is_not_decoded() {
    let bytes = solid(&[("a", b"hi"), ("link", b"a")], true);
    let parsed = parse(&bytes);

    let seen = walk(&parsed, Vec::new(), &config(false), &[1]);

    assert_eq!(seen, [(1, Err(LinkReadFailure::BlockRefused))]);
}

#[test]
fn a_block_over_the_ratio_limit_is_not_decoded() {
    let zeros = vec![0u8; 64 * 1024];
    let bytes = solid(&[("zeros", &zeros), ("link", b"a")], false);
    let parsed = parse(&bytes);
    let strict = SecurityConfig::default()
        .with_allow_solid_archives(true)
        .with_max_solid_block_memory(100 * 1024 * 1024)
        .with_max_solid_compression_ratio(10.0)
        .validate()
        .unwrap();

    let seen = walk(&parsed, Vec::new(), &strict, &[1]);

    assert_eq!(seen, [(1, Err(LinkReadFailure::BlockRefused))]);
}

#[test]
fn an_oversized_target_is_not_read() {
    let oversized = vec![b'a'; 70_000];
    let bytes = one_block_each(&[("link", &oversized)]);
    let parsed = parse(&bytes);

    let seen = walk(&parsed, Vec::new(), &config(false), &[0]);

    assert_eq!(
        seen,
        [(0, Ok(StoredLinkTarget::Oversized { bytes: 70_000 }))]
    );
}

#[test]
fn a_link_without_data_has_an_empty_target() {
    let bytes = one_block_each(&[("link", b"")]);
    let parsed = parse(&bytes);

    let seen = walk(&parsed, Vec::new(), &config(false), &[0]);

    assert_eq!(seen, [(0, Ok(target("")))]);
}

#[test]
fn an_error_from_the_receiver_ends_the_walk() {
    let bytes = one_block_each(&[("a", b"first"), ("b", b"second")]);
    let parsed = parse(&bytes);
    let mut calls = 0;

    let result = walk_sevenz_links(
        &parsed.archive,
        &mut Cursor::new(bytes),
        &parsed.compression,
        &config(false),
        &table(&[0, 1]),
        &mut |_, _| {
            calls += 1;
            Err(ArchiveError::InvalidArchive("stop".into()))
        },
    );

    assert_matches!(result, Err(ArchiveError::InvalidArchive(_)));
    assert_eq!(calls, 1);
}

#[test]
fn a_target_that_is_not_utf8_is_a_hard_error() {
    let bytes = one_block_each(&[("link", &[0xFF, 0xFE])]);
    let parsed = parse(&bytes);

    let result = walk_sevenz_links(
        &parsed.archive,
        &mut Cursor::new(bytes),
        &parsed.compression,
        &config(false),
        &table(&[0]),
        &mut |_, _| Ok(()),
    );

    assert_matches!(result, Err(ArchiveError::InvalidArchive(reason)) if reason.contains("UTF-8"));
}

mod bytes_read {
    use std::cell::Cell;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::rc::Rc;

    use super::*;
    use crate::StoredTargets;
    use crate::inspection::list::ListPass;
    use crate::inspection::list::list_sevenz_reader;

    const FILLER_LEN: usize = 300_000;
    const UNIX_SYMLINK_ATTRIBUTES: u32 = 0x8000 | (0o120_777 << 16);

    struct Counting<R> {
        inner: R,
        read: Rc<Cell<u64>>,
    }

    impl<R: Read> Read for Counting<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.read.set(self.read.get() + n as u64);
            Ok(n)
        }
    }

    impl<R: Seek> Seek for Counting<R> {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    /// A stored solid block of a large file followed by one symlink.
    fn solid_block_with_trailing_link() -> Vec<u8> {
        let filler = vec![b'f'; FILLER_LEN];
        let mut link = entry("link", b"filler");
        link.has_windows_attributes = true;
        link.windows_attributes = UNIX_SYMLINK_ATTRIBUTES;
        let mut writer = writer(true);
        writer
            .push_archive_entries(
                vec![entry("filler", &filler), link],
                vec![
                    SourceReader::from(Cursor::new(filler.clone())),
                    SourceReader::from(Cursor::new(b"filler".to_vec())),
                ],
            )
            .unwrap();
        writer.finish().unwrap().into_inner()
    }

    fn counting(bytes: Vec<u8>) -> (Counting<Cursor<Vec<u8>>>, Rc<Cell<u64>>) {
        let read = Rc::new(Cell::new(0));
        let source = Counting {
            inner: Cursor::new(bytes),
            read: Rc::clone(&read),
        };
        (source, read)
    }

    #[test]
    fn listing_decodes_the_link_block_only_when_asked_to_read_targets() {
        let bytes = solid_block_with_trailing_link();
        let config = config(true);

        let (source, skipped) = counting(bytes.clone());
        list_sevenz_reader(source, &config, &mut ListPass::strict()).unwrap();
        let (source, read) = counting(bytes);
        list_sevenz_reader(source, &config, &mut ListPass::Strict(StoredTargets::Read)).unwrap();

        assert!(skipped.get() < 1_000, "{} bytes read", skipped.get());
        assert!(read.get() >= FILLER_LEN as u64, "{} bytes read", read.get());
    }

    #[cfg(unix)]
    #[test]
    fn extraction_reads_each_pack_stream_once() {
        let bytes = solid_block_with_trailing_link();
        let archive_len = bytes.len() as u64;
        let (source, read) = counting(bytes);
        let config = SecurityConfig::default()
            .with_allow_symlinks(true)
            .with_allow_solid_archives(true)
            .with_max_solid_block_memory(100 * 1024 * 1024)
            .validate()
            .unwrap();
        let out = tempfile::TempDir::new().unwrap();

        let report = SevenZArchive::new(source)
            .unwrap()
            .extract(
                out.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.symlinks_created, 1);
        assert!(
            read.get() < archive_len + archive_len / 4,
            "{} bytes read of {archive_len}",
            read.get()
        );
    }
}
