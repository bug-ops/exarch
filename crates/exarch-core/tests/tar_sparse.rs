//! Old GNU sparse TAR entries (typeflag `S`, issue #1349): refused by
//! default, expanded to regular files of their real size under
//! `TarSparsePolicy::Expand`, and only when the map is one that every reader
//! (`bsdtar`, Python `tarfile`, the `tar` crate) reads the same way.

#![expect(clippy::disallowed_methods, reason = "test fixture setup")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

mod tar_sparse_support;

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use exarch_core::ArchiveError;
use exarch_core::SecurityConfig;
use exarch_core::SparseMapDefect;
use exarch_core::TarAmbiguity;
use exarch_core::TarHeaderField;
use exarch_core::TarSparsePolicy;
use exarch_core::VerificationStatus;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use tar_sparse_support::Chain;
use tar_sparse_support::EMPTY_SLOT;
use tar_sparse_support::Sparse;
use tar_sparse_support::accepted;
use tar_sparse_support::expanded;
use tar_sparse_support::filled;
use tar_sparse_support::number;
use tar_sparse_support::pax_header;
use tar_sparse_support::regular;
use tar_sparse_support::slot;
use tar_sparse_support::slot_of;
use tar_sparse_support::tar_of;
use tempfile::TempDir;

fn expand() -> SecurityConfig {
    SecurityConfig::default().with_tar_sparse(TarSparsePolicy::Expand)
}

fn write_archive(dir: &TempDir, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join("a.tar");
    std::fs::write(&path, bytes).unwrap();
    path
}

fn root(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => root(partial.cause()),
        other => other,
    }
}

/// The archive's sparse member followed by a regular one, which an accepted
/// map must leave readable.
fn with_follower(sparse: &Sparse) -> Vec<u8> {
    tar_of(&[sparse.bytes(), regular("after.txt", b"hello")])
}

fn extract_to(bytes: &[u8], config: &SecurityConfig) -> Result<(TempDir, PathBuf), ArchiveError> {
    let archive_dir = TempDir::new().unwrap();
    let archive = write_archive(&archive_dir, bytes);
    let dest = TempDir::new().unwrap();
    let out = dest.path().join("out");
    extract_archive(&archive, &out, config)?;
    Ok((dest, out))
}

#[test]
fn extract_with_the_default_policy_refuses_a_well_formed_sparse_entry() {
    let bytes = with_follower(&Sparse::well_formed(
        "sparse.bin",
        &[(0, b"hello".to_vec())],
        1000,
    ));
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &bytes);

    for (label, config) in [
        ("default", SecurityConfig::default()),
        (
            "refuse",
            SecurityConfig::default().with_tar_sparse(TarSparsePolicy::Refuse),
        ),
        ("permissive", SecurityConfig::permissive()),
    ] {
        let errors = [
            list_archive(&archive, &config).unwrap_err(),
            verify_archive(&archive, &config).unwrap_err(),
            extract_archive(&archive, dir.path().join("out"), &config).unwrap_err(),
        ];
        for error in &errors {
            assert!(
                matches!(
                    root(error),
                    ArchiveError::TarAmbiguity(TarAmbiguity::SparseEntry)
                ),
                "{label}: {error:?}"
            );
        }
    }
}

fn tool_works(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn bsdtar_extract(archive: &Path, out: &Path) {
    std::fs::create_dir_all(out).unwrap();
    let status = Command::new("bsdtar")
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(out)
        .status()
        .unwrap();
    assert!(status.success(), "bsdtar failed on {}", archive.display());
}

fn tarfile_extract(archive: &Path, out: &Path) {
    std::fs::create_dir_all(out).unwrap();
    let status = Command::new("python3")
        .args([
            "-I",
            "-c",
            "import sys, tarfile; \
             tarfile.open(sys.argv[1]).extractall(sys.argv[2], filter='data')",
        ])
        .arg(archive)
        .arg(out)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "python tarfile failed on {}",
        archive.display()
    );
}

#[test]
fn extract_with_expand_reads_accepted_maps_like_bsdtar_and_tarfile() {
    let bsdtar = tool_works("bsdtar", &["--version"]);
    let tarfile = tool_works(
        "python3",
        &[
            "-I",
            "-c",
            "import sys, tarfile; sys.exit(not hasattr(tarfile, 'data_filter'))",
        ],
    );
    if !bsdtar {
        eprintln!("skipping the bsdtar comparison: bsdtar is not installed");
    }
    if !tarfile {
        eprintln!("skipping the tarfile comparison: python3 with tarfile filters is missing");
    }

    for case in accepted() {
        let expected = expanded(&case.regions, case.realsize);
        let bytes = with_follower(&Sparse::well_formed(
            "sparse.bin",
            &case.regions,
            case.realsize,
        ));
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, &bytes);

        let (_dest, out) = extract_to(&bytes, &expand()).unwrap_or_else(|e| {
            panic!("{}: {e:?}", case.label);
        });
        assert_eq!(
            std::fs::read(out.join("sparse.bin")).unwrap(),
            expected,
            "{}",
            case.label
        );
        assert_eq!(
            std::fs::read(out.join("after.txt")).unwrap(),
            b"hello",
            "{}",
            case.label
        );

        let manifest = list_archive(&archive, &expand()).unwrap();
        let sizes: Vec<u64> = manifest.entries().iter().map(|e| e.kind.size()).collect();
        assert_eq!(sizes, [case.realsize, 5], "{}", case.label);
        let report = verify_archive(&archive, &expand()).unwrap();
        assert_eq!(report.status(), VerificationStatus::Pass, "{}", case.label);

        if bsdtar {
            let out = dir.path().join("bsdtar");
            bsdtar_extract(&archive, &out);
            assert_eq!(
                std::fs::read(out.join("sparse.bin")).unwrap(),
                expected,
                "bsdtar: {}",
                case.label
            );
        }
        if tarfile {
            let out = dir.path().join("tarfile");
            tarfile_extract(&archive, &out);
            assert_eq!(
                std::fs::read(out.join("sparse.bin")).unwrap(),
                expected,
                "tarfile: {}",
                case.label
            );
        }
    }
}

#[test]
fn extract_with_expand_counts_the_real_size_against_max_file_size() {
    let bytes = with_follower(&Sparse::well_formed(
        "sparse.bin",
        &[(0, b"hello".to_vec())],
        1000,
    ));
    let at = |limit: u64| expand().with_max_file_size(std::num::NonZeroU64::new(limit).unwrap());

    let error = extract_to(&bytes, &at(999)).unwrap_err();
    assert!(
        matches!(root(&error), ArchiveError::QuotaExceeded { .. }),
        "{error:?}"
    );
    let (_dest, out) = extract_to(&bytes, &at(1000)).unwrap();
    assert_eq!(
        std::fs::metadata(out.join("sparse.bin")).unwrap().len(),
        1000
    );
}

#[test]
fn extract_with_expand_counts_the_real_size_against_max_total_size() {
    let member = |name| Sparse::well_formed(name, &[(0, b"hello".to_vec())], 600).bytes();
    let bytes = tar_of(&[member("a.bin"), member("b.bin")]);
    let at = |limit: u64| expand().with_max_total_size(std::num::NonZeroU64::new(limit).unwrap());

    let error = extract_to(&bytes, &at(1000)).unwrap_err();
    assert!(
        matches!(root(&error), ArchiveError::QuotaExceeded { .. }),
        "{error:?}"
    );
    extract_to(&bytes, &at(1200)).unwrap();
}

/// Predicate over the root cause of a refusal.
type Want = fn(&ArchiveError) -> bool;

macro_rules! defect {
    ($defect:ident) => {
        |error: &ArchiveError| {
            matches!(
                error,
                ArchiveError::TarAmbiguity(TarAmbiguity::SparseMap {
                    defect: SparseMapDefect::$defect
                })
            )
        }
    };
}

/// `list`, `verify` and `extract` all refuse `bytes` under `Expand`, for a
/// reason `want` accepts, and extraction writes nothing.
fn assert_refused_everywhere(label: &str, bytes: &[u8], want: Want) {
    let (_dir, out) = refuse_all(label, bytes, want);
    assert!(
        !out.join("sparse.bin").exists(),
        "{label}: the sparse member was extracted"
    );
}

/// Like [`assert_refused_everywhere`], for a defect only visible after the
/// entry's data (the next header is misread): the member may already be
/// written when the extraction fails.
fn assert_refused_late(label: &str, bytes: &[u8], want: Want) {
    refuse_all(label, bytes, want);
}

fn refuse_all(label: &str, bytes: &[u8], want: Want) -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, bytes);
    let config = expand();
    let out = dir.path().join("out");

    let errors = [
        list_archive(&archive, &config).unwrap_err(),
        verify_archive(&archive, &config).unwrap_err(),
        extract_archive(&archive, &out, &config).unwrap_err(),
    ];
    for error in &errors {
        assert!(want(root(error)), "{label}: {error:?}");
    }
    (dir, out)
}

fn two_regions() -> Sparse {
    Sparse::well_formed(
        "sparse.bin",
        &[(0, filled(b'A', 512)), (1024, filled(b'B', 512))],
        1536,
    )
}

fn six_regions() -> Sparse {
    let regions: Vec<_> = (0..6)
        .map(|index| {
            (
                index * 1024,
                filled(b'a' + u8::try_from(index).unwrap(), 512),
            )
        })
        .collect();
    Sparse::well_formed("sparse.bin", &regions, 5 * 1024 + 512)
}

fn is_a_refusal(error: &ArchiveError) -> bool {
    matches!(
        error,
        ArchiveError::TarAmbiguity(_) | ArchiveError::InvalidArchive(_)
    )
}

fn plus_prefixed(mut field: [u8; 12]) -> [u8; 12] {
    field[0] = b'+';
    field
}

#[test]
fn extract_with_expand_refuses_a_used_slot_after_an_unused_one() {
    // tar-rs skips the empty slot and reads 1536 bytes with B at 1024,
    // bsdtar stops at the empty slot and reads a damaged archive.
    let header_slots = [slot(0, 512), EMPTY_SLOT, slot(1024, 512)];
    let bytes = with_follower(&two_regions().with_header_slots(&header_slots));
    assert_refused_everywhere("slot after end", &bytes, defect!(SlotAfterEnd));

    let mut chained = six_regions();
    let mut chain_slots = vec![chained.header_slots[3]];
    chain_slots.extend(chained.chain[0].slots.clone());
    chained.header_slots[3] = EMPTY_SLOT;
    chained.chain[0].slots = chain_slots;
    assert_refused_everywhere(
        "chain used after an unused header slot",
        &with_follower(&chained),
        defect!(SlotAfterEnd),
    );

    let mut gapped = six_regions();
    let first = gapped.chain[0].slots[0];
    gapped.chain[0].slots[0] = EMPTY_SLOT;
    gapped.chain[0].slots.insert(1, first);
    assert_refused_everywhere(
        "used slot after an unused chain slot",
        &with_follower(&gapped),
        defect!(SlotAfterEnd),
    );
}

#[test]
fn extract_with_expand_refuses_a_slot_with_only_one_empty_field() {
    let missing_offset = slot_of([0; 12], number(512));
    let missing_length = slot_of(number(1024), [0; 12]);
    for (label, partial) in [("offset", missing_offset), ("length", missing_length)] {
        let header_slots = [slot(0, 512), partial, slot(1024, 512)];
        let bytes = with_follower(&two_regions().with_header_slots(&header_slots));
        assert_refused_everywhere(label, &bytes, defect!(PartialSlot));
    }
}

#[test]
fn extract_with_expand_refuses_an_extended_flag_that_is_not_zero_or_one() {
    for flag in [2, b'1', 0xFF] {
        let bytes = with_follower(&two_regions().with_extended(flag));
        assert_refused_everywhere(
            &format!("header flag {flag}"),
            &bytes,
            defect!(ExtendedFlag),
        );
    }

    let mut chained = six_regions();
    chained.chain[0].extended = 2;
    assert_refused_everywhere(
        "chain block flag 2",
        &with_follower(&chained),
        defect!(ExtendedFlag),
    );
}

#[test]
fn extract_with_expand_refuses_a_chain_that_does_not_match_its_flags() {
    let missing = six_regions().with_chain(Vec::new());
    assert_refused_everywhere(
        "flag without a block",
        &with_follower(&missing),
        is_a_refusal,
    );

    let extra = two_regions().with_chain(vec![Chain {
        slots: Vec::new(),
        extended: 0,
    }]);
    assert_refused_late("block without a flag", &with_follower(&extra), is_a_refusal);
}

#[test]
fn extract_with_expand_refuses_non_canonical_map_numbers() {
    let mut offset = two_regions();
    offset.header_slots[1] = slot_of(plus_prefixed(number(1024)), number(512));
    assert_refused_everywhere("offset", &with_follower(&offset), |error| {
        matches!(
            error,
            ArchiveError::TarAmbiguity(TarAmbiguity::NonCanonicalNumber {
                field: TarHeaderField::SparseOffset
            })
        )
    });

    let mut length = two_regions();
    length.header_slots[0] = slot_of(number(0), plus_prefixed(number(512)));
    assert_refused_everywhere("length", &with_follower(&length), |error| {
        matches!(
            error,
            ArchiveError::TarAmbiguity(TarAmbiguity::NonCanonicalNumber {
                field: TarHeaderField::SparseLength
            })
        )
    });

    let mut realsize_field = number(1536);
    realsize_field[0] = 0x0b;
    let realsize = two_regions().with_realsize(realsize_field);
    assert_refused_everywhere("realsize", &with_follower(&realsize), |error| {
        matches!(
            error,
            ArchiveError::TarAmbiguity(TarAmbiguity::NonCanonicalNumber {
                field: TarHeaderField::RealSize
            })
        )
    });
}

#[test]
fn extract_with_expand_refuses_a_used_zero_offset_slot_in_an_extension_block() {
    // The header holds four used zero-length slots at offset 0 and the data
    // sits behind a slot (0, 512) of the extension block. tar-rs and bsdtar
    // read 512 `D` bytes, `tarfile` drops the extension slot and reads zeros.
    let mut smuggled = Sparse::well_formed("sparse.bin", &[(0, filled(b'D', 512))], 512)
        .with_header_slots(&[slot(0, 0); 4])
        .with_extended(1)
        .with_chain(vec![Chain {
            slots: vec![slot(0, 512)],
            extended: 0,
        }]);
    smuggled.realsize = number(512);
    assert_refused_everywhere(
        "zero offset extension",
        &with_follower(&smuggled),
        |error| {
            matches!(
                error,
                ArchiveError::TarAmbiguity(TarAmbiguity::SparseMap {
                    defect: SparseMapDefect::ZeroOffsetExtension
                        | SparseMapDefect::InteriorZeroLength
                })
            )
        },
    );
}

#[test]
fn extract_with_expand_refuses_a_zero_length_slot_that_is_not_the_last() {
    let regions = [
        (0, filled(b'A', 512)),
        (512, Vec::new()),
        (512, filled(b'B', 512)),
    ];
    let sparse = Sparse::well_formed("sparse.bin", &regions, 1024);
    assert_refused_everywhere(
        "interior zero length",
        &with_follower(&sparse),
        defect!(InteriorZeroLength),
    );
}

#[test]
fn extract_with_expand_refuses_a_pax_size_record_on_a_sparse_entry() {
    let sparse = Sparse::well_formed("sparse.bin", &[(0, filled(b'A', 512))], 1024);
    let bytes = tar_of(&[pax_header(&[("size", "512")]), sparse.bytes()]);
    assert_refused_everywhere("pax size", &bytes, |error| {
        matches!(
            error,
            ArchiveError::TarAmbiguity(TarAmbiguity::UnsupportedRecord { key }) if key == "size"
        )
    });
}

#[test]
fn extract_with_expand_still_refuses_pax_sparse_records() {
    for key in [
        "GNU.sparse.name",
        "GNU.sparse.major",
        "GNU.sparse.map",
        "SCHILY.realsize",
        "SUN.holesdata",
    ] {
        let bytes = tar_of(&[pax_header(&[(key, "1")]), regular("a.txt", b"x")]);
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, &bytes);
        let error = list_archive(&archive, &expand()).unwrap_err();
        assert!(
            matches!(
                root(&error),
                ArchiveError::TarAmbiguity(TarAmbiguity::UnsupportedRecord { key: found })
                    if found == key
            ),
            "{key}: {error:?}"
        );
    }
}

#[test]
fn extract_with_expand_refuses_a_sparse_entry_named_like_a_directory() {
    let sparse = Sparse::well_formed("dir/", &[(0, filled(b'A', 512))], 1024);
    assert_refused_everywhere("directory name", &with_follower(&sparse), |error| {
        matches!(
            error,
            ArchiveError::TarAmbiguity(TarAmbiguity::DirectoryNamedPayload { .. })
        )
    });
}
