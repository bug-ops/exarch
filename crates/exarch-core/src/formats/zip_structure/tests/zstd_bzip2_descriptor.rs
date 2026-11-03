//! Descriptor entries of bzip2 and zstd are modeled by decoding to the stream
//! end, like deflate, but only when the declared range holds a record
//! signature, so a record behind the stream is found by plain verify, list and
//! extract while honest entries are not decoded; the zstd window limit and
//! frame layouts are the ones the census decoder shares with extraction.

use std::io::Write;

use super::*;
use crate::formats::zip_tail::Compressed;
use crate::formats::zip_tail::StreamEnd;
use crate::formats::zip_tail::stream_end;

const NAME_LEN: usize = 5;
const PAYLOAD: &[u8] = b"hello hello hello hello";
const BZIP2: u16 = 12;
const ZSTD: u16 = 93;
const SKIPPABLE_MAGIC: u32 = 0x184D_2A50;

#[derive(Clone, Copy, Debug)]
enum Layout {
    KnownSize,
    Descriptor,
}

const LAYOUTS: [Layout; 2] = [Layout::KnownSize, Layout::Descriptor];

fn entry(layout: Layout, method: u16, payload: &[u8], data: Vec<u8>) -> RawEntry {
    let mut entry = RawEntry::stored("a.txt", payload);
    if matches!(layout, Layout::Descriptor) {
        entry = entry.with_descriptor(true, false);
    }
    entry.method = method;
    entry.data = data;
    entry
}

fn data_start(built: &BuiltZip) -> usize {
    built.local_offsets[0] + LFH_FIXED_LEN + NAME_LEN
}

fn region(layout: Layout) -> HiddenRegion {
    match layout {
        Layout::KnownSize => HiddenRegion::StreamTail,
        Layout::Descriptor => HiddenRegion::DescriptorTail,
    }
}

fn zstd_frame(payload: &[u8], window_log: Option<u32>) -> Vec<u8> {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0).unwrap();
    encoder.include_contentsize(false).unwrap();
    if let Some(log) = window_log {
        encoder
            .set_parameter(zstd::zstd_safe::CParameter::WindowLog(log))
            .unwrap();
    }
    encoder.write_all(payload).unwrap();
    encoder.finish().unwrap()
}

fn skippable_frame(body: &[u8]) -> Vec<u8> {
    let mut frame = SKIPPABLE_MAGIC.to_le_bytes().to_vec();
    frame.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
    frame.extend_from_slice(body);
    frame
}

fn plain_verify_status(bytes: Vec<u8>) -> VerificationStatus {
    open_bytes(bytes)
        .verify(
            &config(ZipConsistencyPolicy::Enforce),
            &VerificationOptions::default(),
        )
        .unwrap()
        .status()
}

fn extract_to_temp(bytes: Vec<u8>, policy: ZipConsistencyPolicy) -> crate::Result<()> {
    let temp = TempDir::new().unwrap();
    open_bytes(bytes)
        .extract(
            temp.path(),
            &config(policy),
            &ExtractionOptions::default(),
            &mut NoopProgress,
        )
        .map(|_| ())
}

fn list_ok(bytes: Vec<u8>, policy: ZipConsistencyPolicy) -> bool {
    open_bytes(bytes).list(&config(policy)).is_ok()
}

fn assert_accepted_everywhere(built: &BuiltZip, label: &str) {
    assert!(findings_of(built).is_empty(), "{label}");
    assert_eq!(
        plain_verify_status(built.bytes.clone()),
        VerificationStatus::Pass,
        "{label}"
    );
    assert!(
        list_ok(built.bytes.clone(), ZipConsistencyPolicy::Enforce),
        "{label}"
    );
    extract_to_temp(built.bytes.clone(), ZipConsistencyPolicy::Enforce).unwrap();
}

#[test]
fn a_header_behind_the_stream_end_of_a_bzip2_or_zstd_descriptor_entry_is_found() {
    for method in [BZIP2, ZSTD] {
        let stream = compress(method, PAYLOAD);
        let signed = descriptor(PAYLOAD, 0);
        for (tail, skipped) in [
            ([signed.clone(), unmapped_local()].concat(), 16),
            ([signed[4..].to_vec(), unmapped_local()].concat(), 12),
            (unmapped_local(), 0),
        ] {
            let data = [stream.clone(), tail].concat();
            let built = RawZip::new(vec![entry(Layout::Descriptor, method, PAYLOAD, data)]).build();
            let at = data_start(&built) + stream.len() + skipped;
            let label = format!("method {method} skipped {skipped}");
            assert_eq!(
                findings_of(&built),
                [hidden_in(at, HiddenRegion::DescriptorTail)],
                "{label}"
            );
            assert_eq!(
                plain_verify_status(built.bytes.clone()),
                VerificationStatus::Fail,
                "{label}"
            );
            assert!(
                !list_ok(built.bytes.clone(), ZipConsistencyPolicy::Enforce),
                "{label}"
            );
            assert_matches!(
                extract_to_temp(built.bytes.clone(), ZipConsistencyPolicy::Enforce),
                Err(ArchiveError::ZipInconsistency(
                    ZipInconsistency::HiddenLocalHeader { .. }
                )),
                "{label}"
            );
            assert!(
                list_ok(built.bytes, ZipConsistencyPolicy::Ignore),
                "{label}"
            );
        }
    }
}

#[test]
fn a_header_hidden_in_a_bzip2_descriptor_tail_is_found_before_another_entry() {
    let stream = compress(BZIP2, PAYLOAD);
    let built = RawZip::new(vec![
        entry(
            Layout::Descriptor,
            BZIP2,
            PAYLOAD,
            [stream.clone(), unmapped_local()].concat(),
        ),
        RawEntry::stored("b.txt", b"world"),
    ])
    .build();
    let at = data_start(&built) + stream.len();
    assert!(findings_of(&built).contains(&hidden_in(at, HiddenRegion::DescriptorTail)));
}

#[test]
fn honest_bzip2_and_zstd_descriptor_entries_pass_every_operation() {
    for method in [BZIP2, ZSTD] {
        let built = RawZip::new(vec![
            entry(
                Layout::Descriptor,
                method,
                PAYLOAD,
                compress(method, PAYLOAD),
            ),
            RawEntry::stored("b.txt", b"world").with_descriptor(true, false),
        ])
        .build();
        assert_accepted_everywhere(&built, &format!("method {method}"));
    }
}

#[test]
fn a_zstd_window_log_of_27_is_accepted_and_28_refused_by_census_and_extraction() {
    for layout in LAYOUTS {
        for (log, accepted) in [(27, true), (28, false)] {
            let data = zstd_frame(PAYLOAD, Some(log));
            let compressed = data.len() as u64;
            let built = RawZip::new(vec![entry(layout, ZSTD, PAYLOAD, data)]).build();
            let label = format!("{layout:?} window log {log}");
            let mut budget = u64::MAX;
            let end = stream_end(
                &mut Cursor::new(built.bytes.clone()),
                Compressed::Zstd,
                data_start(&built) as u64,
                compressed,
                PAYLOAD.len() as u64,
                &mut budget,
            )
            .unwrap();
            assert_eq!(matches!(end, StreamEnd::At(_)), accepted, "{label}");
            assert_eq!(
                extract_to_temp(built.bytes.clone(), ZipConsistencyPolicy::Ignore).is_ok(),
                accepted,
                "extraction alone, {label}"
            );
            assert_eq!(
                extract_to_temp(built.bytes.clone(), ZipConsistencyPolicy::Enforce).is_ok(),
                accepted,
                "{label}"
            );
            if matches!(layout, Layout::KnownSize) {
                assert_eq!(findings_of(&built).is_empty(), accepted, "{label}");
                assert_eq!(
                    plain_verify_status(built.bytes) == VerificationStatus::Pass,
                    accepted,
                    "{label}"
                );
            }
        }
    }
}

#[test]
fn an_honest_two_frame_zstd_entry_passes_in_both_layouts() {
    let (first, second) = (b"hello hello ".as_slice(), b"world world".as_slice());
    let payload = [first, second].concat();
    let data = [zstd_frame(first, None), zstd_frame(second, None)].concat();
    for layout in LAYOUTS {
        let built = RawZip::new(vec![entry(layout, ZSTD, &payload, data.clone())]).build();
        assert_accepted_everywhere(&built, &format!("{layout:?}"));
    }
}

#[test]
fn an_honest_zstd_entry_with_a_leading_skippable_frame_passes_in_both_layouts() {
    let data = [skippable_frame(b"pzstd"), zstd_frame(PAYLOAD, None)].concat();
    for layout in LAYOUTS {
        let built = RawZip::new(vec![entry(layout, ZSTD, PAYLOAD, data.clone())]).build();
        assert_accepted_everywhere(&built, &format!("{layout:?}"));
    }
}

#[test]
fn a_header_behind_a_two_frame_zstd_entry_is_found_in_both_layouts() {
    let (first, second) = (b"hello hello ".as_slice(), b"world world".as_slice());
    let payload = [first, second].concat();
    let frames = [zstd_frame(first, None), zstd_frame(second, None)].concat();
    for layout in LAYOUTS {
        let data = [frames.clone(), unmapped_local()].concat();
        let built = RawZip::new(vec![entry(layout, ZSTD, &payload, data)]).build();
        let at = data_start(&built) + frames.len();
        let found = findings_of(&built);
        assert!(
            found.contains(&hidden_in(at, region(layout))),
            "{layout:?}: {found:?}"
        );
        assert_eq!(
            plain_verify_status(built.bytes),
            VerificationStatus::Fail,
            "{layout:?}"
        );
    }
}

#[test]
fn a_hidden_header_is_refused_when_the_recheck_allowance_is_spent() {
    for method in [BZIP2, ZSTD] {
        let data = [compress(method, PAYLOAD), unmapped_local()].concat();
        let built = RawZip::new(vec![entry(Layout::Descriptor, method, PAYLOAD, data)]).build();
        let found = super::descriptor_resume::findings_with_budgets(&built, 0, 0);
        assert!(
            found
                .iter()
                .any(|f| matches!(f, ZipInconsistency::DescriptorOverrun { .. })),
            "method {method}: {found:?}"
        );
    }
}
