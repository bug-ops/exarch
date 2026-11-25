//! Acceptance contract of #1351 and #1352: every encrypted 7z operation
//! derives and keeps its own keys, so one operation never waits for another
//! (not even while the other's source stalls) and two operations with
//! different passwords never evict each other's key.
//!
//! The derivation count is observed through `max_kdf_work`: a budget of
//! exactly one derivation admits an operation only when it derives once.

#![cfg(feature = "encryption")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

mod common;
mod sevenz_patch;

use std::assert_matches;
use std::error::Error;
use std::io::Cursor;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::num::NonZeroU64;
use std::ops::Range;
use std::sync::Arc;
use std::sync::Barrier;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::CallbackError;
use exarch_core::EncryptionRefusal;
use exarch_core::ExtractRequest;
use exarch_core::ListRequest;
use exarch_core::Malformation;
use exarch_core::MemoryExtractRequest;
use exarch_core::NoopProgress;
use exarch_core::Password;
use exarch_core::SecurityConfig;
use exarch_core::SeekableFormat;
use exarch_core::VerifyRequest;
use exarch_core::Violation;
use exarch_core::extract_reader_to_callback;
use sevenz_patch::fixture_bytes;
use sevenz_patch::flipped;
use sevenz_patch::packed_streams_end;
use sevenz_patch::written;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sevenz_rust2::EncoderConfiguration;
use sevenz_rust2::EncoderMethod;
use sevenz_rust2::SourceReader;
use sevenz_rust2::encoder_options::AesEncoderOptions;
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn Error>>;

const POWER: u8 = 10;
const SIGNATURE_HEADER: u64 = 32;
const BLOCKS: usize = 400;
const WAIT: Duration = Duration::from_secs(60);
const RIGHT: &[u8] = b"correct-horse";
/// What an encrypted header reserves for its key, whose power is not known
/// before it is read.
const HEADER_RESERVE: u64 = 1 << 24;

struct Keying<'a> {
    password: &'a str,
    salt: u8,
}

fn aes(keying: &Keying<'_>) -> EncoderConfiguration {
    let mut options = AesEncoderOptions::new(sevenz_rust2::Password::new(keying.password));
    options.salt = [keying.salt; 16];
    options.num_cycles_power = POWER;
    options.into()
}

/// A non-solid archive of `files` 64-byte entries, one AES block each, all
/// under one key.
fn archive(files: usize, keying: &Keying<'_>, encrypt_header: bool) -> Vec<u8> {
    write_archive(
        files,
        encrypt_header,
        vec![aes(keying), EncoderMethod::COPY.into()],
    )
}

fn write_archive(
    files: usize,
    encrypt_header: bool,
    methods: Vec<EncoderConfiguration>,
) -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    writer.set_encrypt_header(encrypt_header);
    writer.set_content_methods(methods);
    for index in 0..files {
        let mut entry = ArchiveEntry::new_file(&format!("f{index}.bin"));
        entry.has_stream = true;
        entry.size = 64;
        let body = vec![7u8; 64];
        writer
            .push_archive_entry(entry, Some(SourceReader::from(Cursor::new(body))))
            .unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn request(budget: u64, secret: &[u8]) -> MemoryExtractRequest {
    let config = SecurityConfig::default().with_max_kdf_work(NonZeroU64::new(budget).unwrap());
    MemoryExtractRequest::default()
        .with_config(config)
        .with_password(Some(Arc::new(Password::new(secret.to_vec()).unwrap())))
}

/// Extracts `source` to a callback under `budget`; returns the number of
/// entries handed over.
fn extract_from(
    source: impl Read + Seek + Send + 'static,
    budget: u64,
    secret: &[u8],
    mut each: impl FnMut() -> std::io::Result<()>,
) -> Result<usize, ArchiveError> {
    let reader = ArchiveReader::seekable(source, SeekableFormat::SevenZ);
    let mut seen = 0;
    extract_reader_to_callback(
        reader,
        &request(budget, secret),
        |_, _| {
            seen += 1;
            each()
        },
        &mut NoopProgress,
    )
    .map_err(|error| match error {
        CallbackError::Archive(error) => error,
        CallbackError::Callback(error) => ArchiveError::Io(error),
    })?;
    Ok(seen)
}

fn extract(bytes: Vec<u8>, budget: u64, secret: &[u8]) -> Result<usize, ArchiveError> {
    extract_from(Cursor::new(bytes), budget, secret, || Ok(()))
}

fn cause(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    }
}

fn is_kdf_refusal(error: &ArchiveError) -> bool {
    matches!(
        cause(error),
        ArchiveError::SecurityViolation {
            kind: Violation::Encrypted {
                reason: EncryptionRefusal::KdfCostExceeded,
                ..
            },
            ..
        }
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StallOn {
    Read,
    Seek,
}

/// A source that blocks on its first read (or first seek) inside the packed
/// streams, which is the encrypted header's access for an archive with an
/// encrypted header and the first block's access otherwise.
struct StallingSource {
    inner: Cursor<Vec<u8>>,
    packed: Range<u64>,
    on: StallOn,
    skip: usize,
    stall: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
}

impl StallingSource {
    fn new(
        bytes: Vec<u8>,
        (on, skip): (StallOn, usize),
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    ) -> Self {
        let next_header_offset = u64::from_le_bytes(*bytes[12..20].as_array().unwrap());
        Self {
            inner: Cursor::new(bytes),
            packed: SIGNATURE_HEADER..SIGNATURE_HEADER + next_header_offset,
            on,
            skip,
            stall: Some((entered, release)),
        }
    }

    fn stall_if_packed(&mut self, position: u64) {
        if !self.packed.contains(&position) {
            return;
        }
        if self.skip > 0 {
            self.skip -= 1;
        } else if let Some((entered, release)) = self.stall.take() {
            entered.send(()).unwrap();
            let _ = release.recv_timeout(WAIT);
        }
    }
}

impl Read for StallingSource {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.on == StallOn::Read {
            self.stall_if_packed(self.inner.position());
        }
        self.inner.read(buf)
    }
}

impl Seek for StallingSource {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        let landed = self.inner.seek(position)?;
        if self.on == StallOn::Seek {
            self.stall_if_packed(landed);
        }
        Ok(landed)
    }
}

#[test]
fn extract_with_a_stalled_source_does_not_block_another_encrypted_extraction() -> TestResult {
    let mut stalls = 0;
    let points = [StallOn::Read, StallOn::Seek]
        .into_iter()
        .flat_map(|on| (0..3).map(move |skip| (on, skip)));
    for (encrypt_header, point) in [true, false]
        .into_iter()
        .flat_map(|header| points.clone().map(move |point| (header, point)))
    {
        let label = format!("encrypted header: {encrypt_header}, stall on {point:?}");
        let stalled = archive(
            3,
            &Keying {
                password: "alpha",
                salt: 1,
            },
            encrypt_header,
        );
        let other = archive(
            3,
            &Keying {
                password: "bravo",
                salt: 2,
            },
            false,
        );
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let (stalled_done_tx, stalled_done) = mpsc::channel();
        thread::spawn(move || {
            let source = StallingSource::new(stalled, point, entered_tx, release);
            let outcome = extract_from(source, 1 << 27, b"alpha", || Ok(()));
            let _ = stalled_done_tx.send(outcome.map_err(|error| error.to_string()));
        });
        let reached = loop {
            if entered.recv_timeout(Duration::from_millis(20)).is_ok() {
                break true;
            }
            if let Ok(done) = stalled_done.try_recv() {
                assert_eq!(done, Ok(3), "{label}");
                break false;
            }
        };
        if !reached {
            continue;
        }
        stalls += 1;

        let (other_done_tx, other_done) = mpsc::channel();
        thread::spawn(move || {
            let outcome = extract(other, 1 << 27, b"bravo");
            let _ = other_done_tx.send(outcome.map_err(|error| error.to_string()));
        });
        let other_outcome = other_done.recv_timeout(WAIT);
        release_tx.send(()).unwrap();

        let other_outcome = other_outcome.map_err(|_| {
            format!("an extraction was blocked by an unrelated stalled source ({label})")
        })?;
        assert_eq!(other_outcome, Ok(3), "{label}");
        assert_eq!(stalled_done.recv_timeout(WAIT)?, Ok(3), "{label}");
    }
    assert!(stalls >= 4, "only {stalls} stall points were reached");
    Ok(())
}

#[test]
fn extract_with_different_passwords_on_two_threads_derives_once_per_operation() {
    let one_derivation = 1u64 << POWER;
    let operations = [
        (
            archive(
                BLOCKS,
                &Keying {
                    password: "alpha",
                    salt: 1,
                },
                false,
            ),
            b"alpha",
        ),
        (
            archive(
                BLOCKS,
                &Keying {
                    password: "bravo",
                    salt: 2,
                },
                false,
            ),
            b"bravo",
        ),
    ];
    let start = Barrier::new(operations.len());
    let outcomes: Vec<Result<usize, String>> = thread::scope(|scope| {
        let workers: Vec<_> = operations
            .iter()
            .map(|(bytes, secret)| {
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    let mut last = Ok(0);
                    for _ in 0..3 {
                        last = extract_from(
                            Cursor::new(bytes.clone()),
                            one_derivation,
                            secret.as_slice(),
                            || {
                                thread::yield_now();
                                Ok(())
                            },
                        )
                        .map_err(|error| error.to_string());
                    }
                    last
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap_or_else(|_| Err("panicked".into())))
            .collect()
    });
    assert_eq!(outcomes, [Ok(BLOCKS), Ok(BLOCKS)]);
}

#[test]
fn extract_nested_operation_with_another_key_costs_the_outer_one_nothing() -> TestResult {
    let one_derivation = 1u64 << POWER;
    let outer = archive(
        3,
        &Keying {
            password: "alpha",
            salt: 1,
        },
        false,
    );
    let inner = archive(
        2,
        &Keying {
            password: "bravo",
            salt: 2,
        },
        false,
    );
    let mut nested = Some(inner);
    let seen = extract_from(Cursor::new(outer), one_derivation, b"alpha", || {
        if let Some(inner) = nested.take() {
            let seen = extract(inner, one_derivation, b"bravo").map_err(std::io::Error::other)?;
            assert_eq!(seen, 2);
        }
        Ok(())
    })?;
    assert_eq!(seen, 3);
    Ok(())
}

#[test]
fn extract_encrypted_header_archive_derives_its_key_once() -> TestResult {
    let one_derivation = HEADER_RESERVE + (1u64 << POWER);
    let bytes = archive(
        BLOCKS,
        &Keying {
            password: "alpha",
            salt: 3,
        },
        true,
    );
    assert_eq!(extract(bytes.clone(), one_derivation, b"alpha")?, BLOCKS);
    let refused = extract(bytes, one_derivation - 1, b"alpha").unwrap_err();
    assert!(is_kdf_refusal(&refused), "{refused:?}");
    Ok(())
}

#[test]
fn extract_block_with_aes_coders_of_different_keys_is_an_unsupported_coder() {
    let bytes = write_archive(
        2,
        false,
        vec![
            aes(&Keying {
                password: "alpha",
                salt: 1,
            }),
            aes(&Keying {
                password: "alpha",
                salt: 2,
            }),
            EncoderMethod::COPY.into(),
        ],
    );

    let error = extract(bytes, 1 << 27, b"alpha").unwrap_err();

    assert_matches!(
        cause(&error),
        ArchiveError::InvalidArchive(Malformation::SevenZUnsupportedCoder),
        "{error:?}"
    );
}

#[derive(Debug, PartialEq, Eq)]
enum Failure {
    Encryption(EncryptionRefusal),
    HeaderUnreadable,
    Other(String),
}

fn classify(error: &ArchiveError) -> Failure {
    match cause(error) {
        ArchiveError::SecurityViolation {
            kind: Violation::Encrypted { reason, .. },
            ..
        } => Failure::Encryption(*reason),
        ArchiveError::InvalidArchive(Malformation::SevenZHeaderUnreadable { .. }) => {
            Failure::HeaderUnreadable
        }
        other => Failure::Other(other.to_string()),
    }
}

/// How extract, list and verify fail for the archive at `path`, opened with
/// the right password.
fn header_failures(path: &std::path::Path) -> [Failure; 3] {
    let config = SecurityConfig::default();
    let password = Some(Arc::new(Password::new(RIGHT.to_vec()).unwrap()));
    let dest = TempDir::new().unwrap();
    [
        ExtractRequest::new(&config)
            .with_password(password.clone())
            .extract(path, dest.path())
            .unwrap_err(),
        ListRequest::new(&config)
            .with_password(password.clone())
            .list(path)
            .unwrap_err(),
        VerifyRequest::new(&config)
            .with_password(password)
            .verify(path)
            .unwrap_err(),
    ]
    .map(|error| classify(&error))
}

/// A corrupt original header never opens, and is classified as it was before
/// the header was read through a derived key: a wrong next-header checksum or
/// a corrupt encrypted header body is a wrong password or corrupt data, a
/// corrupt plain record is an unreadable header.
#[test]
fn open_encrypted_header_with_a_corrupt_original_checksum_still_fails_as_before() {
    let dir = TempDir::new().unwrap();
    let mut crc_flipped = fixture_bytes("header.7z");
    crc_flipped[28] ^= 1;
    let start_crc = common::crc32(&crc_flipped[12..32]);
    crc_flipped[8..12].copy_from_slice(&start_crc.to_le_bytes());
    let record_flipped = {
        let bytes = fixture_bytes("header.7z");
        let at = packed_streams_end(&bytes);
        flipped(bytes, at)
    };
    let body_flipped = {
        let bytes = fixture_bytes("header.7z");
        let at = packed_streams_end(&bytes) - 1;
        flipped(bytes, at)
    };

    for (name, bytes, expected) in [
        (
            "crc",
            crc_flipped,
            Failure::Encryption(EncryptionRefusal::WrongPasswordOrCorrupt),
        ),
        ("record", record_flipped, Failure::HeaderUnreadable),
        (
            "body",
            body_flipped,
            Failure::Encryption(EncryptionRefusal::WrongPasswordOrCorrupt),
        ),
    ] {
        let path = written(dir.path(), name, &bytes);
        let [extracted, listed, verified] = header_failures(&path);
        assert_eq!(extracted, expected, "{name}: extract");
        assert_eq!(listed, expected, "{name}: list");
        assert_eq!(verified, expected, "{name}: verify");
    }
}
