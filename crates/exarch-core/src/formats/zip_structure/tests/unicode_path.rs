//! The validation messages of the `zip` crate's Unicode Path check, one fixture
//! per refusal site: the census names each as a typed [`ZipHeaderField`], and
//! `list`, `verify` and `extract` agree on every archive.

use super::*;
use crate::raw_zip::unicode_path_field;

const LANGUAGE_ENCODING_FLAG: u16 = 0x0800;

/// A Unicode Path field over the file name `name`, and what the operations do
/// with it.
struct Case {
    site: &'static str,
    name: &'static [u8],
    upath: &'static [u8],
    flags: u16,
    /// The refusal the census records, or `None` when the reader ignores the
    /// field and every operation accepts the archive.
    refusal: Option<ZipHeaderField>,
}

const fn refused(
    site: &'static str,
    name: &'static [u8],
    upath: &'static [u8],
    field: ZipHeaderField,
) -> Case {
    Case {
        site,
        name,
        upath,
        flags: 0,
        refusal: Some(field),
    }
}

fn cases() -> [Case; 11] {
    use ZipHeaderField as F;
    [
        Case {
            flags: LANGUAGE_ENCODING_FLAG,
            ..refused(
                "language-encoding flag set and the path differs",
                b"a.txt",
                b"b.txt",
                F::UnicodePathLanguageEncoding,
            )
        },
        refused("NUL in the path", b"a.txt", b"a\0.txt", F::FileNameNul),
        refused(
            "directory status",
            b"d",
            b"d/",
            F::UnicodePathDirectoryStatus,
        ),
        Case {
            refusal: None,
            ..refused(
                "not UTF-8 (the crate ignores the field)",
                b"a.txt",
                b"\xFF.txt",
                F::UnicodePathNotUtf8,
            )
        },
        refused(
            "fullwidth full stop",
            b"a.txt",
            "a\u{FF0E}txt".as_bytes(),
            F::UnicodePathIllegalCharacter,
        ),
        refused(
            "component count",
            b"a/b.txt",
            b"ab.txt",
            F::UnicodePathComponents,
        ),
        refused(
            "component kind",
            b"x/a.txt",
            b"./a.txt",
            F::UnicodePathComponents,
        ),
        refused(
            "trailing dot",
            b"a.txt",
            b"a.txt.",
            F::UnicodePathTrailingDotsOrSpaces,
        ),
        refused(
            "ASCII component differs",
            b"a.txt",
            b"b.txt",
            F::UnicodePathComponents,
        ),
        refused(
            "non-ASCII component without a fallback match",
            b"zzz.txt",
            "\u{e9}.doc".as_bytes(),
            F::UnicodePathComponents,
        ),
        refused(
            "extension differs behind a DOS alias",
            b"LONGFI~1.TXT",
            b"LongFileName.doc",
            F::UnicodePathExtension,
        ),
    ]
}

fn built_for(case: &Case) -> BuiltZip {
    let field = unicode_path_field(case.name, case.upath);
    let mut entry = RawEntry::stored("a.txt", b"");
    entry.name = case.name.to_vec();
    entry.flags = case.flags;
    entry.local_extra = field.clone();
    entry.central_extra = field;
    RawZip::new(vec![entry, RawEntry::stored("z.txt", b"tail")]).build()
}

/// The reader names an entry by its Unicode Path, so the finding carries it.
fn finding(case: &Case, field: ZipHeaderField) -> ZipInconsistency {
    ZipInconsistency::HeaderMismatch {
        entry: ZipEntryIndex::new(0),
        field,
        name: crate::bytes_text(case.upath),
    }
}

fn enforce() -> SecurityConfig {
    config(ZipConsistencyPolicy::Enforce)
}

#[test]
fn every_refusal_site_is_a_typed_finding() {
    for case in cases() {
        let found = findings_of(&built_for(&case));
        match case.refusal {
            Some(field) => assert_eq!(found, [finding(&case, field)], "{}", case.site),
            None => assert!(found.is_empty(), "{}: {found:?}", case.site),
        }
    }
}

#[test]
fn list_verify_and_extract_agree() {
    for case in cases() {
        let built = built_for(&case);
        let temp = TempDir::new().unwrap();
        let dest = temp.path().join("out");

        let listed = open_bytes(built.bytes.clone(), &enforce()).list();
        let report = open_bytes(built.bytes.clone(), &enforce())
            .verify(VerificationOptions::default())
            .unwrap();
        let extracted = open_bytes(built.bytes, &enforce()).extract(
            &dest,
            &ExtractionOptions::default(),
            &mut NoopProgress,
        );

        if let Some(field) = case.refusal {
            let expected = finding(&case, field);
            assert_matches!(
                listed,
                Err(ArchiveError::ZipInconsistency(ref found)) if *found == expected,
                "list: {}",
                case.site
            );
            assert_ne!(
                report.status(),
                VerificationStatus::Pass,
                "verify: {}",
                case.site
            );
            assert_matches!(
                extracted,
                Err(ArchiveError::ZipInconsistency(ref found)) if *found == expected,
                "extract: {}",
                case.site
            );
            assert!(!dest.exists(), "{}", case.site);
        } else {
            listed.unwrap();
            assert_eq!(report.status(), VerificationStatus::Pass, "{}", case.site);
            extracted.unwrap();
            assert!(dest.join("a.txt").exists(), "{}", case.site);
        }
    }
}

#[test]
fn the_crates_own_messages_map_to_their_fields() {
    let prefix = HEADER_INCONSISTENCY_PREFIX;
    let named = |text: &str| classify(&ZipError::InvalidArchive(format!("{prefix}{text}").into()));
    for (text, field) in [
        (
            "compression flags mismatch for 'a'",
            ZipHeaderField::CompressionFlags,
        ),
        (
            "AES encryption metadata mismatch for 'a'",
            ZipHeaderField::AesMetadata,
        ),
        (
            "UnicodePath (0x7075) is not valid UTF-8",
            ZipHeaderField::UnicodePathNotUtf8,
        ),
    ] {
        assert_eq!(named(text), HeaderFault::Mismatch(field), "{text}");
    }
    assert_eq!(
        named("UnicodePath (0x7075) is a message of a later release"),
        HeaderFault::Uncomparable(ZipUncomparable::Unrecognized)
    );
}
