//! Names of existing entries, judged as the file system stores them.
//!
//! A spelling in the 8.3 short-name shape that the parent directory does not
//! list under that name is an alternate spelling of another entry, and is
//! refused. The decision (`judge`) is pure and platform-independent; only
//! listing the parent is Windows-only. Elsewhere a name is its own stored name.

use std::ffi::OsStr;
use std::io;
use std::path::Path;

use crate::Result;
use crate::Violation;
use crate::formats::pinned_dir::Leaf;
use crate::formats::pinned_dir::PinnedRoot;
use crate::formats::pinned_dir::VettedDir;
use crate::types::safe_path::escaped_component;

#[cfg(any(windows, test))]
const MAX_STEM_CHARS: usize = 6;
#[cfg(any(windows, test))]
const MAX_EXTENSION_CHARS: usize = 3;

/// A name in the 8.3 shape: `^[^.]{1,6}~[0-9]+(\.[^.]{0,3})?$`.
///
/// The shape alone proves nothing; it only marks a spelling worth comparing
/// with the parent's listing.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct ShortNameShape<'a>(&'a str);

#[cfg(any(windows, test))]
impl<'a> ShortNameShape<'a> {
    /// `name` as a short-name shape, or `None` when it cannot be one.
    pub(crate) fn of(name: &'a OsStr) -> Option<Self> {
        let text = name.to_str()?;
        let (base, extension) = text
            .split_once('.')
            .map_or((text, None), |(base, ext)| (base, Some(ext)));
        if extension
            .is_some_and(|ext| ext.contains('.') || ext.chars().count() > MAX_EXTENSION_CHARS)
        {
            return None;
        }
        let before_digits = base.trim_end_matches(|c: char| c.is_ascii_digit());
        let stem = before_digits.strip_suffix('~')?;
        let has_digits = before_digits.len() < base.len();
        let stem_len = stem.chars().count();
        (has_digits && (1..=MAX_STEM_CHARS).contains(&stem_len)).then_some(Self(text))
    }
}

/// How the spelling of an existing entry relates to its parent's listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Spelling {
    /// The parent lists the name as spelled.
    AsListed,
    /// The parent does not list the name: it spells another entry.
    #[cfg_attr(
        not(any(windows, test)),
        expect(dead_code, reason = "only Windows lists a directory")
    )]
    Alternate,
}

/// Decides whether `shape`, the spelling of an existing entry, is listed by
/// its parent. The comparison is exact, so a directory that tells names apart
/// by case fails closed.
#[cfg(any(windows, test))]
pub(crate) fn judge(shape: ShortNameShape<'_>, listing: &[Vec<u16>]) -> Spelling {
    let spelled: Vec<u16> = shape.0.encode_utf16().collect();
    if listing.contains(&spelled) {
        Spelling::AsListed
    } else {
        Spelling::Alternate
    }
}

/// [`judge`] for `name`, listing the parent only when the name has the
/// short-name shape and `known_own` does not already vouch for this exact
/// spelling. A listing that finds the name is remembered with `remember`, so a
/// revisited name costs one listing, not one per visit.
#[cfg(any(windows, test))]
pub(crate) fn judge_lazily(
    name: &OsStr,
    known_own: impl FnOnce() -> bool,
    list: impl FnOnce() -> io::Result<Vec<Vec<u16>>>,
    remember: impl FnOnce(),
) -> io::Result<Spelling> {
    let Some(shape) = ShortNameShape::of(name) else {
        return Ok(Spelling::AsListed);
    };
    if known_own() {
        return Ok(Spelling::AsListed);
    }
    let spelling = judge(shape, &list()?);
    if spelling == Spelling::AsListed {
        remember();
    }
    Ok(spelling)
}

/// How the existing entry `leaf` of `parent`, at `rel` below the root, is
/// spelled.
///
/// # Errors
///
/// The I/O error of listing `parent`.
#[cfg(windows)]
pub(crate) fn spelling(
    root: &PinnedRoot,
    parent: &VettedDir,
    rel: &Path,
    leaf: Leaf<'_>,
) -> io::Result<Spelling> {
    judge_lazily(
        leaf.as_os_str(),
        || root.created().knows_spelling(rel),
        || parent.names(),
        || root.created().note_spelling(rel),
    )
}

/// Names are their own stored names on this host.
#[cfg(not(windows))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "same signature as the Windows reader, which can fail"
)]
pub(crate) const fn spelling(
    _root: &PinnedRoot,
    _parent: &VettedDir,
    _rel: &Path,
    _leaf: Leaf<'_>,
) -> io::Result<Spelling> {
    Ok(Spelling::AsListed)
}

impl Spelling {
    /// Refuses an alternate spelling of `name`.
    ///
    /// # Errors
    ///
    /// `ShortNameAlias` for [`Spelling::Alternate`].
    pub(crate) fn refuse_alternate(self, name: &OsStr) -> Result<()> {
        match self {
            Self::AsListed => Ok(()),
            Self::Alternate => Err(Violation::ShortNameAlias {
                component: escaped_component(name).into(),
            }
            .into()),
        }
    }
}

/// Refuses the existing entry `leaf` of `parent`, at `rel` below the root, when
/// it is spelled as an alternate name.
///
/// # Errors
///
/// `ShortNameAlias`, or the I/O error of listing `parent`.
pub(crate) fn vet(root: &PinnedRoot, parent: &VettedDir, rel: &Path, leaf: Leaf<'_>) -> Result<()> {
    spelling(root, parent, rel, leaf)?.refuse_alternate(leaf.as_os_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shaped(name: &str) -> bool {
        ShortNameShape::of(OsStr::new(name)).is_some()
    }

    fn listing(names: &[&str]) -> Vec<Vec<u16>> {
        names
            .iter()
            .map(|name| name.encode_utf16().collect())
            .collect()
    }

    fn judged(spelled: &str, stored: &[&str]) -> Spelling {
        judge(
            ShortNameShape::of(OsStr::new(spelled)).unwrap(),
            &listing(stored),
        )
    }

    #[test]
    fn short_name_shapes_are_recognized() {
        for name in [
            "ABCDEF~1",
            "abcdef~1",
            "LONGNA~1",
            "ABC~12",
            "A~1",
            "LONGNA~1.TXT",
            "A~1.",
            "A~1.X",
        ] {
            assert!(shaped(name), "{name}");
        }
    }

    #[test]
    fn other_names_are_not_short_name_shapes() {
        for name in [
            "",
            "~1",
            "ABC~",
            "ABC",
            "ABCDEFG~1",
            "A~1.TXTX",
            "A~1.b.c",
            ".A~1",
            "A.B~1",
            "A~1x",
            "A~x1",
        ] {
            assert!(!shaped(name), "{name}");
        }
    }

    #[test]
    fn a_name_the_parent_does_not_list_is_an_alternate_spelling() {
        assert_eq!(
            judged("LONGNA~1", &["longnamedirectory", "other"]),
            Spelling::Alternate
        );
        assert_eq!(judged("LONGNA~1", &[]), Spelling::Alternate);
    }

    #[test]
    fn a_listed_name_is_its_own_spelling_and_the_comparison_is_exact() {
        assert_eq!(
            judged("LONGNA~1", &["other", "LONGNA~1"]),
            Spelling::AsListed
        );
        assert_eq!(judged("longna~1", &["LONGNA~1"]), Spelling::Alternate);
    }

    #[test]
    fn a_name_longer_than_a_listed_prefix_is_not_listed() {
        assert_eq!(judged("ABC~1", &["ABC~12"]), Spelling::Alternate);
    }

    fn lazily(
        record: &crate::formats::run_record::RunRecord,
        rel: &str,
        lists: &std::cell::Cell<u32>,
    ) -> Spelling {
        let rel = std::path::Path::new(rel);
        let name = rel.file_name().unwrap();
        judge_lazily(
            name,
            || record.knows_spelling(rel),
            || {
                lists.set(lists.get() + 1);
                Ok(listing(&["longnamedirectory", "ABCDEF~1"]))
            },
            || record.note_spelling(rel),
        )
        .unwrap()
    }

    fn record() -> crate::formats::run_record::RunRecord {
        crate::formats::run_record::RunRecord::new(crate::formats::run_record::RecordBudget::Full)
    }

    #[test]
    fn a_plain_name_is_never_listed() {
        let lists = std::cell::Cell::new(0);

        assert_eq!(lazily(&record(), "d/plain", &lists), Spelling::AsListed);
        assert_eq!(lists.get(), 0);
    }

    #[test]
    fn an_exact_spelling_the_run_created_is_not_listed() {
        let (record, lists) = (record(), std::cell::Cell::new(0));
        record.note_spelling(std::path::Path::new("d/X~1"));

        assert_eq!(lazily(&record, "d/X~1", &lists), Spelling::AsListed);
        assert_eq!(lists.get(), 0);
    }

    #[test]
    fn another_spelling_of_an_entry_the_run_created_is_listed_and_refused() {
        let (record, lists) = (record(), std::cell::Cell::new(0));
        record.note_spelling(std::path::Path::new("d/longnamedirectory"));
        record.note_spelling(std::path::Path::new("d/X~1"));

        assert_eq!(lazily(&record, "d/LONGNA~1", &lists), Spelling::Alternate);
        assert_eq!(lists.get(), 1);
        assert_eq!(lazily(&record, "d/LONGNA~1", &lists), Spelling::Alternate);
        assert_eq!(lists.get(), 2, "a refusal is never cached");
    }

    #[test]
    fn a_listed_spelling_is_listed_once_per_run() {
        let (record, lists) = (record(), std::cell::Cell::new(0));

        for _ in 0..1000 {
            assert_eq!(lazily(&record, "d/ABCDEF~1", &lists), Spelling::AsListed);
        }

        assert_eq!(lists.get(), 1);
    }

    #[test]
    fn an_alternate_spelling_is_refused_as_a_short_name_alias() {
        let name = OsStr::new("LONGNA~1");

        assert!(Spelling::AsListed.refuse_alternate(name).is_ok());
        std::assert_matches!(
            Spelling::Alternate.refuse_alternate(name),
            Err(crate::ArchiveError::SecurityViolation {
                kind: Violation::ShortNameAlias { .. }
            })
        );
    }
}

#[cfg(all(test, windows))]
#[expect(clippy::unwrap_used, reason = "tests assert by panicking")]
mod windows_tests {
    use super::*;
    use crate::ArchiveError;
    use crate::SecurityConfig;
    use crate::formats::dir_walker::DirWalker;
    use crate::formats::handle_resolution::LinkCursor;
    use crate::formats::handle_resolution::Refusal;
    use crate::formats::pinned_dir::PinnedRoot;
    use crate::security::fs_view::LinkBase;
    use crate::test_utils::short_spelling;
    use crate::types::SafePath;
    use crate::types::safe_path::Resolved;
    use std::ffi::OsString;
    use std::path::Path;
    use tempfile::TempDir;

    const DIRECTORY: &str = "exarchlongdirectoryname";
    const FILE: &str = "exarchlongfilename.txt";

    /// A root holding a directory and a file with long names, and the short
    /// spellings of both, or `None` when the volume has no 8.3 names.
    fn fixture() -> Option<(TempDir, PinnedRoot, OsString, OsString)> {
        let temp = TempDir::new().unwrap();
        let directory = temp.path().join(DIRECTORY);
        std::fs::create_dir(&directory).unwrap();
        let file = temp.path().join(FILE);
        std::fs::write(&file, b"x").unwrap();
        let (Some(short_dir), Some(short_file)) =
            (short_spelling(&directory), short_spelling(&file))
        else {
            eprintln!("skipping: the volume has no 8.3 names");
            return None;
        };
        let root = PinnedRoot::open_for_test(temp.path()).unwrap();
        Some((
            temp,
            root,
            short_dir.file_name()?.to_os_string(),
            short_file.file_name()?.to_os_string(),
        ))
    }

    fn leaf_of(name: &OsStr) -> Leaf<'_> {
        Leaf::of_name(name).unwrap()
    }

    fn refused(result: &Result<()>) -> bool {
        matches!(
            result,
            Err(ArchiveError::SecurityViolation {
                kind: Violation::ShortNameAlias { .. }
            })
        )
    }

    #[test]
    fn the_listing_of_a_parent_decides_whether_a_spelling_is_its_own() {
        let Some((_temp, root, dir_alias, file_alias)) = fixture() else {
            return;
        };

        assert_eq!(
            spelling(
                &root,
                root.dir(),
                Path::new(&dir_alias),
                leaf_of(&dir_alias)
            )
            .unwrap(),
            Spelling::Alternate
        );
        assert_eq!(
            spelling(
                &root,
                root.dir(),
                Path::new(&file_alias),
                leaf_of(&file_alias)
            )
            .unwrap(),
            Spelling::Alternate
        );
        assert_eq!(
            spelling(
                &root,
                root.dir(),
                Path::new(DIRECTORY),
                leaf_of(OsStr::new(DIRECTORY))
            )
            .unwrap(),
            Spelling::AsListed
        );
    }

    #[test]
    fn the_walker_refuses_an_alternate_spelling_of_a_directory() {
        let Some((_temp, root, dir_alias, _)) = fixture() else {
            return;
        };
        let config = SecurityConfig::default();
        let walker = DirWalker::new(&config);
        let rel =
            SafePath::<Resolved>::for_test(&Path::new(&dir_alias).join("inner").to_string_lossy());

        assert!(refused(&walker.ensure_dir(&root, &rel).map(drop)));
        let long = SafePath::<Resolved>::for_test(&format!("{DIRECTORY}/inner"));
        assert!(walker.ensure_dir(&root, &long).is_ok());
    }

    #[test]
    fn an_alternate_spelling_of_a_directory_the_run_created_is_refused() {
        let Some((temp, root, _, _)) = fixture() else {
            return;
        };
        let config = SecurityConfig::default();
        let walker = DirWalker::new(&config);
        let created = "exarchcreatedbytherun";
        let long = SafePath::<Resolved>::for_test(created);
        walker.ensure_dir(&root, &long).unwrap();
        let Some(short) = short_spelling(&temp.path().join(created)) else {
            eprintln!("skipping: the volume has no 8.3 names");
            return;
        };
        let alias = short.file_name().unwrap().to_string_lossy().into_owned();
        let rel = SafePath::<Resolved>::for_test(&format!("{alias}/inner"));

        assert!(refused(&walker.ensure_dir(&root, &rel).map(drop)));
        assert!(walker.ensure_dir(&root, &long).is_ok());
    }

    #[test]
    fn an_alternate_spelling_of_a_file_is_refused() {
        let Some((_temp, root, _, file_alias)) = fixture() else {
            return;
        };

        assert!(refused(&vet(
            &root,
            root.dir(),
            Path::new(&file_alias),
            leaf_of(&file_alias)
        )));
        assert!(
            vet(
                &root,
                root.dir(),
                Path::new(FILE),
                leaf_of(OsStr::new(FILE))
            )
            .is_ok()
        );
    }

    #[test]
    fn a_link_target_through_an_alternate_spelling_is_refused() {
        let Some((_temp, root, dir_alias, file_alias)) = fixture() else {
            return;
        };
        let resolve = |target: &Path| {
            LinkCursor::for_target(&root, Path::new("link"), LinkBase::LinkDirectory, target)
        };

        std::assert_matches!(resolve(Path::new(&dir_alias)), Err(Refusal::Unresolvable));
        std::assert_matches!(resolve(Path::new(&file_alias)), Err(Refusal::Unresolvable));
        assert!(resolve(Path::new(DIRECTORY)).is_ok());
        assert!(resolve(Path::new(FILE)).is_ok());
    }
}
