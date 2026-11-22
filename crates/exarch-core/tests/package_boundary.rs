//! Acceptance contract of #1229: no packaged `.rs` file of `exarch-core`
//! reaches outside the package, and every fixture a packaged source names ships
//! with the package.

#![expect(clippy::unwrap_used, reason = "integration test helpers")]

use std::path::Path;
use std::path::PathBuf;

/// Mirrors `exclude` in `Cargo.toml`: paths relative to the package root that
/// are not packaged, so they may read what the package does not ship.
const EXCLUDED: &[&str] = &["tests/data/tar-minefield", "tests/tar_minefield.rs"];

/// This file spells the forbidden forms in its self-test.
const SELF: &str = "tests/package_boundary.rs";

#[derive(Debug, PartialEq, Eq)]
enum Escape {
    ParentLiteral,
    JoinParent,
    ManifestParent,
}

fn escapes(source: &str) -> Vec<Escape> {
    let mut found = Vec::new();
    let parent_literal = ["\"", "../"].concat();
    let reaches_workspace = source.match_indices(&parent_literal).any(|(at, _)| {
        let literal = source[at + 1..].split('"').next().unwrap_or_default();
        ["tests/", "crates/", "exarch-"]
            .iter()
            .any(|marker| literal.contains(marker))
    });
    if reaches_workspace {
        found.push(Escape::ParentLiteral);
    }
    let join_parent = ["join(\"", "..", "\")"].concat();
    if source.contains(&join_parent) {
        found.push(Escape::JoinParent);
    }
    let mut rest = source;
    while let Some(at) = rest.find("CARGO_MANIFEST_DIR") {
        let statement = &rest[at..];
        let end = statement.find(';').unwrap_or(statement.len());
        if statement[..end].contains(".parent()") {
            found.push(Escape::ManifestParent);
            break;
        }
        rest = &statement["CARGO_MANIFEST_DIR".len()..];
    }
    found
}

fn package_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn is_excluded(relative: &str) -> bool {
    relative == SELF
        || EXCLUDED
            .iter()
            .any(|e| relative == *e || relative.starts_with(&format!("{e}/")))
}

fn packaged_sources() -> Vec<(String, String)> {
    fn visit(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if is_excluded(&relative) {
                continue;
            }
            if path.is_dir() {
                visit(root, &path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push((relative, std::fs::read_to_string(&path).unwrap()));
            }
        }
    }
    let root = package_root();
    let mut out = Vec::new();
    for top in ["src", "tests", "benches"] {
        visit(&root, &root.join(top), &mut out);
    }
    out
}

#[test]
fn scanner_flags_a_parent_directory_literal() {
    let source = [
        "let p = Path::new(",
        "\"",
        "../../tests/fixtures/x.7z",
        "\");",
    ]
    .concat();
    assert_eq!(escapes(&source), [Escape::ParentLiteral]);
}

#[test]
fn scanner_ignores_a_traversal_payload_literal() {
    let source = ["let payload = ", "\"", "../outside", "\";"].concat();
    assert!(escapes(&source).is_empty());
    let deep = ["let payload = ", "\"", "../../../etc/passwd", "\";"].concat();
    assert!(escapes(&deep).is_empty());
}

#[test]
fn scanner_flags_a_join_of_the_parent() {
    let source = ["let p = base.join(", "\"", "..", "\"", ");"].concat();
    assert!(escapes(&source).contains(&Escape::JoinParent), "{source}");
}

#[test]
fn scanner_flags_a_manifest_dir_followed_by_parent_in_one_statement() {
    let source =
        "let root = Path::new(env!(\"CARGO_MANIFEST_DIR\"))\n    .parent()\n    .unwrap();";
    assert_eq!(escapes(source), [Escape::ManifestParent]);
}

#[test]
fn scanner_accepts_a_manifest_dir_without_parent_and_a_parent_in_another_statement() {
    let ok = "let a = concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/tests/fixtures/x.7z\");\nlet b = dir.parent();";
    assert!(escapes(ok).is_empty());
}

#[test]
fn packaged_sources_never_reach_outside_the_package() {
    let offenders: Vec<_> = packaged_sources()
        .into_iter()
        .filter_map(|(path, source)| {
            let found = escapes(&source);
            (!found.is_empty()).then(|| format!("{path}: {found:?}"))
        })
        .collect();

    assert!(offenders.is_empty(), "{offenders:#?}");
}

#[test]
fn excluded_list_mirrors_cargo_toml() {
    let manifest = std::fs::read_to_string(package_root().join("Cargo.toml")).unwrap();
    let at = manifest
        .find("\nexclude")
        .unwrap_or_else(|| panic!("Cargo.toml has an exclude list"));
    let list = manifest[at..].split(']').next().unwrap();
    let listed: Vec<&str> = list
        .split('"')
        .skip(1)
        .step_by(2)
        .map(|item| item.trim_end_matches('/'))
        .collect();

    assert_eq!(listed, EXCLUDED);
}

#[test]
fn fixtures_named_by_packaged_sources_exist_inside_the_package() {
    let marker = "/tests/fixtures/";
    let mut missing = Vec::new();
    for (path, source) in packaged_sources() {
        for (at, _) in source.match_indices(marker) {
            let name: String = source[at + marker.len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
                .collect();
            if !name.is_empty()
                && !name.ends_with('/')
                && !package_root().join("tests/fixtures").join(&name).exists()
            {
                missing.push(format!("{path}: tests/fixtures/{name}"));
            }
        }
    }

    assert!(missing.is_empty(), "{missing:#?}");
}

#[test]
fn the_workspace_level_fixture_directory_is_gone() {
    let workspace = package_root().ancestors().nth(2).map(Path::to_path_buf);

    if let Some(workspace) = workspace {
        assert!(
            !workspace.join("tests").join("fixtures").exists(),
            "fixtures must live in crates/exarch-core/tests/fixtures"
        );
    }
}

#[test]
fn the_package_fixture_directory_holds_the_generators_and_provenance() {
    let dir = package_root().join("tests/fixtures");

    assert!(dir.join("PROVENANCE.md").exists() || dir.join("PROVENANCE").exists());
    assert!(
        std::fs::read_dir(&dir)
            .unwrap()
            .any(|e| { e.unwrap().path().extension().is_some_and(|ext| ext == "7z") })
    );
}
