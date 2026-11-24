//! Each password-protected 7z operation derives and keeps its own keys, so
//! what other operations do in between (on other threads, or nested in an
//! entry callback, under any key) neither costs it a derivation nor refuses
//! it: `max_kdf_work` bounds the derivations of one operation only.

#![cfg(feature = "encryption")]

use std::error::Error;
use std::io::Cursor;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::thread;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::CallbackError;
use exarch_core::EncryptionRefusal;
use exarch_core::ListRequest;
use exarch_core::MemoryExtractRequest;
use exarch_core::NoopProgress;
use exarch_core::Password;
use exarch_core::SecurityConfig;
use exarch_core::SeekableFormat;
use exarch_core::Violation;
use exarch_core::extract_reader_to_callback;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sevenz_rust2::EncoderMethod;
use sevenz_rust2::SourceReader;
use sevenz_rust2::encoder_options::AesEncoderOptions;

type TestResult = Result<(), Box<dyn Error>>;

const POWER: u8 = 10;

/// A non-solid archive: one AES block per file, all under one key salt.
fn archive(salt: u8, power: u8, files: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    archive_filled(salt, power, files, salt)
}

/// Like [`archive`], with the entries' content set apart from the key salt.
fn archive_filled(salt: u8, power: u8, files: usize, fill: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    archive_keyed(salt, power, files, fill, "secret")
}

/// Like [`archive_filled`], protected by `password`.
fn archive_keyed(
    salt: u8,
    power: u8,
    files: usize,
    fill: u8,
    password: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    archive_with_header(salt, power, files, fill, password, false)
}

/// Like [`archive_keyed`], optionally with an encrypted header under the same
/// key settings.
fn archive_with_header(
    salt: u8,
    power: u8,
    files: usize,
    fill: u8,
    password: &str,
    encrypt_header: bool,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut options = AesEncoderOptions::new(sevenz_rust2::Password::new(password));
    options.salt = [salt; 16];
    options.num_cycles_power = power;
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new()))?;
    writer.set_encrypt_header(encrypt_header);
    writer.set_content_methods(vec![options.into(), EncoderMethod::COPY.into()]);
    for index in 0..files {
        let mut entry = ArchiveEntry::new_file(&format!("f{index}.bin"));
        entry.has_stream = true;
        entry.size = 64;
        let body = vec![fill; 64];
        writer.push_archive_entry(entry, Some(SourceReader::from(Cursor::new(body))))?;
    }
    Ok(writer.finish()?.into_inner())
}

fn request(budget: u64, secret: &[u8]) -> Result<MemoryExtractRequest, Box<dyn Error>> {
    let config = SecurityConfig::default()
        .with_max_kdf_work(NonZeroU64::new(budget).ok_or("a kdf budget is not zero")?);
    let password = Arc::new(Password::new(secret.to_vec())?);
    Ok(MemoryExtractRequest::default()
        .with_config(config)
        .with_password(Some(password)))
}

/// Extracts `bytes` under `budget`, calling `each` for every entry; returns
/// the number of entries handed over.
fn extract(
    bytes: Vec<u8>,
    budget: u64,
    each: impl FnMut(usize) -> std::io::Result<()>,
) -> Result<usize, Box<dyn Error>> {
    extract_with(bytes, budget, b"secret", each)
}

fn extract_with(
    bytes: Vec<u8>,
    budget: u64,
    secret: &[u8],
    mut each: impl FnMut(usize) -> std::io::Result<()>,
) -> Result<usize, Box<dyn Error>> {
    let reader = ArchiveReader::seekable(Cursor::new(bytes), SeekableFormat::SevenZ);
    let mut seen = 0;
    extract_reader_to_callback(
        reader,
        &request(budget, secret)?,
        |_, _| {
            seen += 1;
            each(seen)
        },
        &mut NoopProgress,
    )?;
    Ok(seen)
}

fn is_kdf_refusal(error: &(dyn Error + 'static)) -> bool {
    let Some(CallbackError::Archive(error)) = error.downcast_ref::<CallbackError<std::io::Error>>()
    else {
        return false;
    };
    let cause = match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    };
    matches!(
        cause,
        ArchiveError::SecurityViolation {
            kind: Violation::Encrypted {
                reason: EncryptionRefusal::KdfCostExceeded,
                ..
            },
            ..
        }
    )
}

fn expect_kdf_refusal(result: Result<usize, Box<dyn Error>>) -> TestResult {
    match result {
        Err(error) if is_kdf_refusal(error.as_ref()) => Ok(()),
        Err(error) => Err(format!("expected a key derivation refusal, got: {error}").into()),
        Ok(seen) => Err(format!("expected a key derivation refusal, {seen} entries passed").into()),
    }
}

#[test]
fn blocks_of_one_pair_are_charged_once_when_nothing_interleaves() -> TestResult {
    let seen = extract(archive(1, POWER, 40)?, 1 << POWER, |_| Ok(()))?;
    assert_eq!(seen, 40);
    Ok(())
}

/// Lists an archive with an encrypted header under (salt, POWER, "secret") on
/// this thread, from inside the outer operation's first entry callback.
fn list_header_once(salt: u8) -> impl FnMut(usize) -> std::io::Result<()> {
    let mut done = false;
    move |_| {
        if std::mem::replace(&mut done, true) {
            return Ok(());
        }
        let bytes = archive_with_header(salt, POWER, 1, 99, "secret", true)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let reader = ArchiveReader::seekable(Cursor::new(bytes), SeekableFormat::SevenZ);
        let secret = Password::new(b"secret".to_vec()).map_err(std::io::Error::other)?;
        ListRequest::new(&SecurityConfig::default())
            .with_password(Some(Arc::new(secret)))
            .list_reader(reader)
            .map(drop)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

#[test]
fn threads_extracting_with_one_key_all_finish_within_one_derivation() -> TestResult {
    let archives = (0u8..4)
        .map(|fill| archive_filled(1, POWER, 12, fill))
        .collect::<Result<Vec<_>, _>>()?;
    let seen: Vec<Result<usize, String>> = thread::scope(|scope| {
        #[expect(
            clippy::needless_collect,
            reason = "every worker must start before the first join"
        )]
        let workers: Vec<_> = archives
            .into_iter()
            .map(|bytes| {
                scope.spawn(move || {
                    let mut seen = Ok(0);
                    for _ in 0..3 {
                        seen = extract(bytes.clone(), 1 << POWER, |_| {
                            thread::yield_now();
                            Ok(())
                        })
                        .map_err(|error| error.to_string());
                    }
                    seen
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap_or_else(|_| Err("panicked".into())))
            .collect()
    });
    for outcome in seen {
        assert_eq!(outcome, Ok(12));
    }
    Ok(())
}

#[test]
fn listing_an_encrypted_header_under_another_key_costs_the_outer_extraction_nothing() -> TestResult
{
    let alone = 1u64 << POWER;
    for salt in [1, 2] {
        let seen = extract(archive(1, POWER, 3)?, alone, list_header_once(salt))?;
        assert_eq!(seen, 3);
    }
    Ok(())
}

#[test]
fn an_operation_over_its_own_budget_is_still_refused() -> TestResult {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new()))?;
    writer.set_encrypt_header(false);
    for (salt, name) in [(1u8, "a"), (2, "b")] {
        let mut options = AesEncoderOptions::new(sevenz_rust2::Password::new("secret"));
        options.salt = [salt; 16];
        options.num_cycles_power = POWER;
        writer.set_content_methods(vec![options.into(), EncoderMethod::COPY.into()]);
        let mut entry = ArchiveEntry::new_file(name);
        entry.has_stream = true;
        entry.size = 4;
        writer.push_archive_entry(entry, Some(SourceReader::from(Cursor::new(vec![0u8; 4]))))?;
    }
    let bytes = writer.finish()?.into_inner();
    expect_kdf_refusal(extract(bytes.clone(), 1 << POWER, |_| Ok(())))?;
    assert_eq!(extract(bytes, 2 << POWER, |_| Ok(()))?, 2);
    Ok(())
}
