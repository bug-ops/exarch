//! Acceptance contract of #1237: `exarch-core` packages and tests itself
//! without the unpublished testkit crate. The fixture builders live in
//! `src/testkit/` and are included by path, so no packaged `.rs` file and no
//! manifest entry names the testkit crate.

#![expect(clippy::unwrap_used, reason = "integration test helpers")]

use std::path::Path;
use std::path::PathBuf;

fn package_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Built from parts so that this file does not contain the name it forbids.
fn crate_name() -> String {
    ["exarch", "_testkit"].concat()
}

fn package_name() -> String {
    ["exarch", "-testkit"].concat()
}

fn rust_sources() -> Vec<(String, String)> {
    fn visit(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((relative, std::fs::read_to_string(&path).unwrap()));
            }
        }
    }
    let root = package_root();
    let mut out = Vec::new();
    for top in ["src", "tests", "benches"] {
        let dir = root.join(top);
        if dir.exists() {
            visit(&root, &dir, &mut out);
        }
    }
    out
}

#[test]
fn no_packaged_source_names_the_testkit_crate() {
    let needle = crate_name();

    let offenders: Vec<_> = rust_sources()
        .into_iter()
        .filter(|(_, source)| source.contains(&needle))
        .map(|(path, _)| path)
        .collect();

    assert!(offenders.is_empty(), "{offenders:#?}");
}

#[test]
fn the_manifest_has_no_testkit_dependency() {
    let manifest = std::fs::read_to_string(package_root().join("Cargo.toml")).unwrap();

    assert!(!manifest.contains(&package_name()), "{manifest}");
}

#[test]
fn the_fixture_builders_ship_inside_the_package() {
    for file in ["mod.rs", "raw_zip.rs", "pax.rs"] {
        let path = package_root().join("src/testkit").join(file);

        assert!(path.is_file(), "{}", path.display());
    }
}

#[test]
fn the_testkit_module_is_compiled_for_tests_only() {
    let lib = std::fs::read_to_string(package_root().join("src/lib.rs")).unwrap();

    let declaration = lib
        .lines()
        .position(|line| line.trim() == "mod testkit;")
        .unwrap_or_else(|| panic!("src/lib.rs declares `mod testkit;`"));

    assert_eq!(
        lib.lines().nth(declaration - 1).unwrap().trim(),
        "#[cfg(test)]"
    );
}
