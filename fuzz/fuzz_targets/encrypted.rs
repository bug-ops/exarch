#![no_main]

//! Encrypted ZIP and 7z input, read with a password.
//!
//! Two properties are checked on every input:
//!
//! 1. Arbitrary bytes, read as ZIP or 7z with and without the password, must
//!    never panic or hang through list, verify or an extraction into memory.
//! 2. Authenticated content cannot be forged. The input is read as a list of
//!    byte edits (offset, xor) applied to a real AES-256 ZIP; whatever the
//!    extraction then delivers to the sink as file content must be one of the
//!    two plaintexts of the original archive. An empty file is accepted only
//!    when the listing of the same bytes reports that path as unencrypted
//!    (entry names are not authenticated, so a renamed directory entry is an
//!    empty file) and never for a path the listing also reports as encrypted;
//!    when the listing fails, empty files are not judged. A flipped ciphertext,
//!    a truncated entry, a forged length or an empty file for an encrypted
//!    entry fails the run.
//!
//! The password of the fixtures is `correct-horse`.

use std::collections::HashSet;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;

use exarch_core::ArchiveReader;
use exarch_core::ArchiveType;
use exarch_core::EntryEncryption;
use exarch_core::ListRequest;
use exarch_core::MemoryEntry;
use exarch_core::MemoryLimit;
use exarch_core::MemorySink;
use exarch_core::Password;
use exarch_core::SinkExtractRequest;
use exarch_core::VerifyRequest;
use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

const AES_ZIP: &[u8] = include_bytes!("../../crates/exarch-core/tests/data/encryption/aes256.zip");
const PLAINTEXTS: [&[u8]; 2] = [b"hello encrypted\n", b"inner payload\n"];

fn password() -> Arc<Password> {
    Arc::new(Password::new(b"correct-horse".to_vec()).expect("the fixture password is valid"))
}

/// Applies the edits `data` spells (two offset bytes and one xor byte each).
fn edited_fixture(data: &[u8]) -> Vec<u8> {
    let mut bytes = AES_ZIP.to_vec();
    let (edits, _) = data.as_chunks::<3>();
    for &[low, high, xor] in edits {
        let offset = usize::from(u16::from_le_bytes([low, high])) % bytes.len();
        if let Some(byte) = bytes.get_mut(offset) {
            *byte ^= xor;
        }
    }
    bytes
}

fn read_all(data: &[u8], archive_type: ArchiveType) {
    let config = common::config();
    let reader = || ArchiveReader::of_type(Cursor::new(data), archive_type);
    for with_password in [false, true] {
        let list = ListRequest::new(config);
        let verify = VerifyRequest::new(config).with_options(common::verification_options());
        let mut sink = MemorySink::new(MemoryLimit::from_config(config));
        let extract = SinkExtractRequest::new(config);
        if with_password {
            let _ = list.with_password(Some(password())).list_reader(reader());
            let _ = verify
                .with_password(Some(password()))
                .verify_reader(reader());
            let _ = extract
                .with_password(Some(password()))
                .extract(reader(), &mut sink);
        } else {
            let _ = list.list_reader(reader());
            let _ = verify.verify_reader(reader());
            let _ = extract.extract(reader(), &mut sink);
        }
    }
}

fn assert_only_authentic_content(bytes: Vec<u8>) {
    let config = common::config_ignoring_zip_structure();
    // A failed listing leaves the empty-file check unjudged: extraction can
    // release entries before it fails on a later one that the listing rejects.
    let listed: Option<HashSet<(PathBuf, EntryEncryption)>> = ListRequest::new(config)
        .with_password(Some(password()))
        .list_reader(ArchiveReader::of_type(
            Cursor::new(bytes.clone()),
            ArchiveType::Zip,
        ))
        .ok()
        .map(|manifest| {
            manifest
                .entries()
                .iter()
                .map(|entry| (entry.path.clone(), entry.encryption))
                .collect()
        });
    let reader = ArchiveReader::of_type(Cursor::new(bytes), ArchiveType::Zip);
    let mut sink = MemorySink::new(MemoryLimit::from_config(config));
    let _ = SinkExtractRequest::new(config)
        .with_password(Some(password()))
        .extract(reader, &mut sink);
    for (path, entry) in sink.iter() {
        if let MemoryEntry::File { data, .. } = entry {
            let empty_file_allowed = listed.as_ref().is_none_or(|listed| {
                listed.contains(&(path.to_path_buf(), EntryEncryption::Plain))
                    && !listed.contains(&(path.to_path_buf(), EntryEncryption::Encrypted))
            });
            assert!(
                PLAINTEXTS.contains(&data.as_slice()) || (data.is_empty() && empty_file_allowed),
                "unauthenticated content released for {path:?}: {} bytes",
                data.len()
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    read_all(data, ArchiveType::Zip);
    read_all(data, ArchiveType::SevenZ);
    assert_only_authentic_content(edited_fixture(data));
});
