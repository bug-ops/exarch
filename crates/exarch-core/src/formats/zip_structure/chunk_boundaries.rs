//! The census finds the same things whatever the size of the chunks it reads:
//! a signature that straddles a chunk end is judged exactly once.

#![allow(clippy::unwrap_used)]

use std::io::Cursor;

use proptest::prelude::*;

use super::*;
use crate::raw_zip::RawEntry;
use crate::raw_zip::RawZip;

const LOCAL_SIGNATURE: &[u8] = b"PK\x03\x04";
const CENTRAL_RECORD_LEN: usize = 46 + "a.txt".len();

fn local_header(name_len: u8) -> Vec<u8> {
    let mut header = LOCAL_SIGNATURE.to_vec();
    header.extend_from_slice(&[20, 0]);
    header.extend_from_slice(&[0u8; 24]);
    header[26] = name_len;
    header.extend(std::iter::repeat_n(b'x', usize::from(name_len)));
    header
}

fn noise() -> impl Strategy<Value = Vec<u8>> {
    let piece = prop_oneof![
        3 => Just(LOCAL_SIGNATURE.to_vec()),
        2 => Just(b"PK\x01\x02".to_vec()),
        1 => Just(b"PK\x05\x06".to_vec()),
        1 => Just(b"PK\x06\x06".to_vec()),
        1 => Just(b"PK\x03".to_vec()),
        1 => Just(b"PK".to_vec()),
        2 => prop::collection::vec(any::<u8>(), 0..48),
        3 => prop::collection::vec(Just(0u8), 0..200),
        2 => (1u8..=40).prop_map(local_header),
    ];
    prop::collection::vec(piece, 0..40).prop_map(|pieces| pieces.concat())
}

fn patch_u32(bytes: &mut [u8], at: usize, delta: usize) {
    let old = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let new = old + u32::try_from(delta).unwrap();
    bytes[at..at + 4].copy_from_slice(&new.to_le_bytes());
}

/// Two entries with `between` written between them, `before_directory` before
/// the directory and `prefix` in front of everything.
fn archive(prefix: &[u8], between: &[u8], before_directory: Vec<u8>) -> Vec<u8> {
    let mut zip = RawZip::new(vec![
        RawEntry::stored("a.txt", b"hello"),
        RawEntry::stored("b.txt", b"world"),
    ]);
    zip.before_directory = before_directory;
    let built = zip.build();
    let second = built.local_offsets[1];
    let directory = built.directory_start + between.len();

    let mut bytes = built.bytes[..second].to_vec();
    bytes.extend_from_slice(between);
    bytes.extend_from_slice(&built.bytes[second..]);
    patch_u32(
        &mut bytes,
        directory + CENTRAL_RECORD_LEN + 42,
        between.len(),
    );
    patch_u32(
        &mut bytes,
        directory + 2 * CENTRAL_RECORD_LEN + 16,
        between.len(),
    );

    [prefix, &bytes].concat()
}

fn findings_at(bytes: &[u8], chunks: ChunkSizes) -> Option<Vec<ZipInconsistency>> {
    let (_, structure) = open_chunked(Cursor::new(bytes.to_vec()), chunks).ok()?;
    Some(structure.findings().to_vec())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1_000,
        max_global_rejects: 100_000,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn findings_do_not_depend_on_the_chunk_size(
        prefix in noise(),
        between in noise(),
        before_directory in noise(),
        starts_with_pk in any::<bool>(),
        gap in 1usize..=64,
        prefix_chunk in 1usize..=64,
    ) {
        let prefix = [if starts_with_pk { &b"PK"[..] } else { &[] }, &prefix].concat();
        let bytes = archive(&prefix, &between, before_directory);
        let chunks = ChunkSizes { gap, prefix: prefix_chunk };
        let expected = findings_at(&bytes, ChunkSizes::PRODUCTION);
        prop_assume!(expected.is_some());
        prop_assert_eq!(findings_at(&bytes, chunks), expected);
    }
}
