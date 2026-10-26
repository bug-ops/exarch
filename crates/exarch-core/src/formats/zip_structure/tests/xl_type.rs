//! Findings about the file type an `xl` extra field, in the local header or the
//! central record, gives an entry.

use super::*;
use crate::raw_zip::SYMLINK_MODE as LINK;
use crate::raw_zip::XL_FIELD_ID as XL;
use crate::raw_zip::unicode_path_field;
use crate::raw_zip::xl_unix_attributes;

fn with_xl(entry: RawEntry, mode: u32) -> RawEntry {
    entry
        .with_local_unix_host()
        .with_local_extra_field(XL, &xl_unix_attributes(mode))
}

fn with_central_xl(entry: RawEntry, mode: u32) -> RawEntry {
    entry.with_central_extra_field(XL, &xl_unix_attributes(mode))
}

fn divergence(entry: usize, offset: usize) -> ZipInconsistency {
    ZipInconsistency::XlTypeDivergence {
        entry: ZipEntryIndex::new(entry),
        offset: offset as u64,
    }
}

fn three_files(first: RawEntry) -> BuiltZip {
    RawZip::new(vec![
        first,
        RawEntry::stored("b.txt", b"plain b\n"),
        RawEntry::stored("c.txt", b"plain c\n"),
    ])
    .build()
}

#[test]
fn local_symlink_type_against_a_regular_central_record_is_found() {
    let built = three_files(with_xl(
        RawEntry::stored("a.txt", b"../../../../tmp/pwned"),
        LINK,
    ));
    assert_eq!(findings_of(&built), [divergence(0, 0)]);
}

#[test]
fn local_type_of_a_later_entry_is_attributed_to_it() {
    let built = RawZip::new(vec![
        RawEntry::stored("a.txt", b"plain a\n"),
        with_xl(RawEntry::stored("b.txt", b"target"), LINK),
        RawEntry::stored("c.txt", b"plain c\n"),
    ])
    .build();
    assert_eq!(findings_of(&built), [divergence(1, built.local_offsets[1])]);
}

#[test]
fn local_directory_type_against_a_regular_central_record_is_found() {
    let built = three_files(with_xl(RawEntry::stored("a.txt", b"data"), 0o040_755));
    assert_eq!(findings_of(&built), [divergence(0, 0)]);
}

#[test]
fn local_symlink_type_with_a_data_descriptor_is_found() {
    for (signature, zip64) in [(true, false), (false, false), (true, true)] {
        let first =
            with_xl(RawEntry::stored("a.txt", b"../../x"), LINK).with_descriptor(signature, zip64);
        let found = findings_of(&three_files(first));
        assert!(
            found.contains(&divergence(0, 0)),
            "{signature} {zip64}: {found:?}"
        );
    }
}

#[test]
fn local_symlink_type_of_a_deflated_entry_is_found() {
    let built = three_files(with_xl(
        RawEntry::deflated("a.txt", b"../../../../tmp/pwned ../../../../tmp/pwned").unwrap(),
        LINK,
    ));
    assert_eq!(findings_of(&built), [divergence(0, 0)]);
}

#[test]
fn local_symlink_type_is_found_with_duplicate_names_too() {
    let built = RawZip::new(vec![
        RawEntry::stored("a.txt", b"shadowed"),
        with_xl(RawEntry::stored("a.txt", b"target"), LINK),
    ])
    .build();
    let found = findings_of(&built);
    assert!(
        found.contains(&divergence(0, built.local_offsets[1])),
        "{found:?}"
    );
}

#[test]
fn local_type_that_agrees_with_the_central_record_is_not_a_finding() {
    let mut link = with_xl(RawEntry::stored("a.txt", b"target"), LINK);
    link.external_attributes = LINK << 16;
    let mut dir = with_xl(RawEntry::stored("d/", b""), 0o040_755);
    dir.external_attributes = 0o040_755 << 16;
    let regular = with_xl(RawEntry::stored("r.txt", b"data"), 0o100_644);
    let built = RawZip::new(vec![link, dir, regular]).build();
    assert!(findings_of(&built).is_empty());
}

#[test]
fn central_symlink_without_an_xl_type_is_not_a_finding() {
    let mut link = RawEntry::stored("a.txt", b"target");
    link.external_attributes = LINK << 16;
    let built = three_files(link);
    assert!(findings_of(&built).is_empty());
}

#[test]
fn xl_without_attributes_or_on_a_dos_host_is_not_a_finding() {
    let no_attributes = RawEntry::stored("a.txt", b"x").with_local_extra_field(XL, &[1, 0, 0]);
    let dos_host =
        RawEntry::stored("b.txt", b"x").with_local_extra_field(XL, &xl_unix_attributes(LINK));
    let built = RawZip::new(vec![no_attributes, dos_host]).build();
    assert!(findings_of(&built).is_empty());
}

#[test]
fn xl_type_divergence_is_fatal_under_enforce_and_reported_by_verify() {
    let bytes = three_files(with_xl(RawEntry::stored("a.txt", b"../../x"), LINK)).bytes;
    let temp = TempDir::new().unwrap();
    let dest = temp.path().join("out");
    assert_matches!(
        open_bytes(bytes.clone()).extract(
            &dest,
            &config(ZipConsistencyPolicy::Enforce),
            &ExtractionOptions::default(),
            &mut NoopProgress,
        ),
        Err(ArchiveError::ZipInconsistency(
            ZipInconsistency::XlTypeDivergence { .. }
        ))
    );
    assert!(!dest.exists());
    assert_matches!(
        open_bytes(bytes.clone()).list(&config(ZipConsistencyPolicy::Enforce)),
        Err(ArchiveError::ZipInconsistency(
            ZipInconsistency::XlTypeDivergence { .. }
        ))
    );

    for options in [
        VerificationOptions::default(),
        VerificationOptions::default()
            .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT)),
    ] {
        let report = open_bytes(bytes.clone())
            .verify(&config(ZipConsistencyPolicy::Enforce), &options)
            .unwrap();
        assert_eq!(report.status(), VerificationStatus::Fail);
        assert!(report.issues().iter().any(|i| {
            i.category == IssueCategory::HiddenEntry && i.message.contains("gives it a file type")
        }));
    }

    assert!(
        open_bytes(bytes)
            .list(&config(ZipConsistencyPolicy::Ignore))
            .is_ok()
    );
}

#[test]
fn xl_type_findings_keep_their_own_limit() {
    let entries = (0..20)
        .map(|i| with_xl(RawEntry::stored(&format!("f{i}.txt"), b"t"), LINK))
        .collect();
    let archive = open_bytes(RawZip::new(entries).build().bytes);
    let kept = archive
        .structure()
        .findings()
        .iter()
        .filter(|f| matches!(f, ZipInconsistency::XlTypeDivergence { .. }))
        .count();
    assert_eq!(kept, 16);
    assert_eq!(archive.structure().omitted_findings(), 4);
}

#[test]
fn xl_type_is_checked_after_another_finding_kind_is_exhausted() {
    let gap = b"PK\x05\x06".repeat(40);
    let mut first = RawEntry::stored("a.txt", b"x");
    first.padding_after = gap.len();
    let mut built = RawZip::new(vec![
        first,
        with_xl(RawEntry::stored("b.txt", b"target"), LINK),
        RawEntry::stored("c.txt", b"plain c\n"),
    ])
    .build();
    let at = built.local_offsets[1] - gap.len();
    built.bytes[at..at + gap.len()].copy_from_slice(&gap);
    let found = findings_of(&built);
    assert!(
        found.contains(&divergence(1, built.local_offsets[1])),
        "{found:?}"
    );
}

/// Seeks of the underlying reader while opening 2000 central records that
/// share one local header with a 60 KiB name.
fn seeks_for_shared_long_header(first: &RawEntry) -> (usize, Vec<ZipInconsistency>) {
    let mut zip = RawZip::new(vec![first.clone()]);
    zip.extra_central_records = (0..2_000)
        .map(|i| {
            let mut alias = first.clone();
            alias.central_name = Some(format!("alias{i:04}.txt").into_bytes());
            (alias, 0)
        })
        .collect();
    let seeks = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let probe = Probe {
        inner: Cursor::new(zip.build().bytes),
        seeks: seeks.clone(),
    };
    let archive = ZipArchive::new(probe).unwrap();
    let findings = archive.structure().findings().to_vec();
    let count = seeks.lock().unwrap().len();
    (count, findings)
}

#[test]
fn many_entries_sharing_one_local_header_read_it_once_for_the_type_check() {
    let name = "n".repeat(60 * 1024);
    let (without, _) = seeks_for_shared_long_header(&RawEntry::stored(&name, b""));
    let (with, findings) =
        seeks_for_shared_long_header(&with_xl(RawEntry::stored(&name, b""), LINK));
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, ZipInconsistency::XlTypeDivergence { .. }))
    );
    assert!(
        with <= without + 10,
        "type check added {} seeks",
        with.saturating_sub(without)
    );
}

#[test]
fn central_xl_symlink_type_against_regular_central_attributes_is_found() {
    let built = three_files(with_central_xl(
        RawEntry::stored("a.txt", b"../../../../tmp/pwned"),
        LINK,
    ));
    assert_eq!(findings_of(&built), [divergence(0, 0)]);
}

#[test]
fn central_xl_regular_type_against_symlink_central_attributes_is_found() {
    let mut entry = with_central_xl(RawEntry::stored("a.txt", b"target"), 0o100_644);
    entry.external_attributes = LINK << 16;
    assert_eq!(findings_of(&three_files(entry)), [divergence(0, 0)]);
}

#[test]
fn central_xl_directory_type_against_regular_central_attributes_is_found() {
    let built = three_files(with_central_xl(RawEntry::stored("a.txt", b"x"), 0o040_755));
    assert_eq!(findings_of(&built), [divergence(0, 0)]);
}

#[test]
fn central_xl_that_agrees_with_the_central_attributes_is_not_a_finding() {
    let mut link = with_central_xl(RawEntry::stored("a.txt", b"target"), LINK);
    link.external_attributes = LINK << 16;
    let regular = with_central_xl(RawEntry::stored("b.txt", b"x"), 0o100_644);
    assert!(findings_of(&RawZip::new(vec![link, regular]).build()).is_empty());
}

#[test]
fn local_xl_overrides_the_central_xl() {
    let agreeing = with_xl(
        with_central_xl(RawEntry::stored("a.txt", b"x"), LINK),
        0o100_644,
    );
    assert!(findings_of(&three_files(agreeing)).is_empty());
    let diverging = with_xl(
        with_central_xl(RawEntry::stored("a.txt", b"x"), 0o100_644),
        LINK,
    );
    assert_eq!(findings_of(&three_files(diverging)), [divergence(0, 0)]);
}

#[test]
fn local_xl_divergence_is_found_whatever_else_the_central_extra_block_holds() {
    let entry = with_xl(RawEntry::stored("a.txt", b"../../x"), LINK)
        .with_central_extra_field(0x9999, &[1, 2]);
    let built = RawZip::new(vec![entry]).build();
    let archive = ZipArchive::new(Cursor::new(built.bytes)).unwrap();
    assert!(archive.structure().findings().contains(&divergence(0, 0)));
}

#[test]
fn unicode_path_that_ends_in_a_slash_is_a_directory_to_both_sides() {
    let upath = unicode_path_field(b"d", b"d/");
    let mut entry = with_xl(RawEntry::stored("d", b""), 0o100_644);
    entry.local_extra.extend_from_slice(&upath);
    entry.central_extra.extend_from_slice(&upath);
    assert!(findings_of(&three_files(entry)).is_empty());
}

#[test]
fn backslash_name_is_a_file_to_a_unix_host_reader() {
    let unix = with_xl(RawEntry::stored("d\\", b""), 0o100_644);
    assert_eq!(findings_of(&three_files(unix)), [divergence(0, 0)]);
}
