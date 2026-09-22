#![no_main]

use std::io::Write as _;

use exarch_core::extract_archive_with_options;
use exarch_core::ExtractionOptions;
use libfuzzer_sys::fuzz_target;
use tempfile::NamedTempFile;
use tempfile::TempDir;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    let config = common::unvalidated();
    // Atomic extraction (rename-into-place) is also this pipeline's default
    // in most callers and was the path GHSA-x8wr lived in; exercise it here
    // rather than only the non-atomic write-in-place path.
    let options = ExtractionOptions::default().with_atomic(true);

    // Extensionless by construction: format detection must fall through to
    // magic-byte sniffing, and raw fixture bytes seed this target unmodified.
    let Ok(mut input) = NamedTempFile::new() else {
        return;
    };
    if input.write_all(data).is_err() {
        return;
    }

    // The extraction target lives inside its own iteration root, one level
    // below it, and is never pre-created (atomic mode fails if the rename
    // target already exists; non-atomic mode creates it via
    // `DestDir::new_or_create`). libFuzzer only detects panic/ASan/OOM/
    // timeout, so a path-traversal or symlink escape that *succeeds* in
    // writing outside `output` would otherwise pass silently -- checking
    // that the iteration root contains nothing but `output` after the call
    // turns that into a crash libFuzzer reports.
    let Ok(iteration_root) = TempDir::new() else {
        return;
    };
    let output = iteration_root.path().join("out");

    let _ = extract_archive_with_options(input.path(), &output, config, &options);

    let mut entries = std::fs::read_dir(iteration_root.path())
        .into_iter()
        .flatten()
        .filter_map(Result::ok);
    match (entries.next(), entries.next()) {
        (None, _) => {}
        (Some(only), None) if only.path() == output => {}
        _ => panic!("extraction wrote outside the intended output directory"),
    }
});
