//! Acceptance contract of #1027: the bytes of a ZIP (and of every other
//! format) do not depend on `Parallelism`, and a failure is the same error in
//! every mode.

#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

use std::num::NonZeroUsize;
use std::path::Path;

use exarch_core::CreationConfig;
use exarch_core::Parallelism;
use exarch_core::create_archive;
use tempfile::TempDir;

const LARGE: usize = 9 * 1024 * 1024;

fn modes() -> Vec<Parallelism> {
    let mut modes = vec![Parallelism::Sequential];
    modes.extend(
        [1, 2, 4, 8]
            .into_iter()
            .map(|n| Parallelism::Threads(NonZeroUsize::new(n).unwrap())),
    );
    modes
}

fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 56) as u8
        })
        .collect()
}

fn tree() -> TempDir {
    let src = TempDir::new().unwrap();
    let root = src.path();
    std::fs::create_dir_all(root.join("sub/deeper")).unwrap();
    std::fs::create_dir(root.join("empty")).unwrap();
    std::fs::write(root.join("zero"), b"").unwrap();
    for i in 0..40 {
        std::fs::write(
            root.join(format!("sub/small{i:02}.txt")),
            format!("small file number {i}\n").repeat(i + 1),
        )
        .unwrap();
    }
    std::fs::write(
        root.join("sub/deeper/random.bin"),
        pseudo_random(300_000, 7),
    )
    .unwrap();
    std::fs::write(root.join("compressible.txt"), vec![b'z'; 2_000_000]).unwrap();
    std::fs::write(root.join("large-streamed.bin"), {
        let mut bytes = pseudo_random(LARGE / 2, 11);
        bytes.extend(std::iter::repeat_n(b'q', LARGE / 2));
        bytes
    })
    .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("compressible.txt", root.join("link")).unwrap();
    src
}

fn create(
    src: &Path,
    name: &str,
    config: &CreationConfig,
) -> Result<Vec<u8>, exarch_core::ArchiveError> {
    let out = TempDir::new().unwrap();
    let path = out.path().join(name);
    create_archive(&path, &[src], config)?;
    Ok(std::fs::read(path).unwrap())
}

#[test]
fn create_zip_bytes_are_equal_across_sequential_and_every_thread_count() {
    let src = tree();
    let baseline = create(src.path(), "out.zip", &CreationConfig::default()).unwrap();

    for mode in modes() {
        let bytes = create(
            src.path(),
            "out.zip",
            &CreationConfig::default().with_parallelism(mode),
        )
        .unwrap();

        assert!(
            bytes == baseline,
            "{mode:?}: ZIP bytes differ from Sequential"
        );
    }
}

#[test]
fn create_other_formats_ignore_parallelism() {
    let src = tree();
    for name in ["out.tar.gz", "out.tar"] {
        let baseline = create(src.path(), name, &CreationConfig::default()).unwrap();

        for mode in modes() {
            let bytes = create(
                src.path(),
                name,
                &CreationConfig::default().with_parallelism(mode),
            )
            .unwrap();

            assert!(bytes == baseline, "{name} {mode:?}");
        }
    }
}

#[cfg(unix)]
#[test]
fn create_zip_unreadable_source_is_the_same_error_in_every_mode() {
    use std::os::unix::fs::PermissionsExt;

    let src = tree();
    let locked = src.path().join("sub/small07.txt");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&locked).is_ok() {
        return;
    }
    let expected = create(src.path(), "out.zip", &CreationConfig::default())
        .unwrap_err()
        .error_code();

    for mode in modes() {
        let error = create(
            src.path(),
            "out.zip",
            &CreationConfig::default().with_parallelism(mode),
        )
        .unwrap_err();

        assert_eq!(error.error_code(), expected, "{mode:?}");
    }
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
fn create_zip_leaves_no_output_when_a_source_is_missing_in_every_mode() {
    let src = tree();
    for mode in modes() {
        let out = TempDir::new().unwrap();
        let path = out.path().join("out.zip");

        let result = create_archive(
            &path,
            &[src.path(), &src.path().join("does-not-exist")],
            &CreationConfig::default().with_parallelism(mode),
        );

        assert!(result.is_err(), "{mode:?}");
        assert!(!path.exists(), "{mode:?}");
    }
}

#[test]
fn creation_config_default_parallelism_is_sequential() {
    assert_eq!(
        CreationConfig::default().parallelism,
        Parallelism::Sequential
    );
}
