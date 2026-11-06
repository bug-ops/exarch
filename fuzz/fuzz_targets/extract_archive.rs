#![no_main]

use std::io::Write as _;
use std::num::NonZeroU64;

use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::PathRewrite;
use exarch_core::SecurityConfig;
use exarch_core::Staging;
use exarch_core::StripComponents;
use libfuzzer_sys::fuzz_target;
use tempfile::NamedTempFile;
use tempfile::TempDir;

#[path = "common.rs"]
mod common;

/// A selection derived from the first input byte, so the stripped, flattened
/// and filtered paths are fuzzed with the same archives as the plain one.
fn selected_config(selector: u8) -> SecurityConfig {
    let config = common::config().clone();
    let rewrite = match selector % 5 {
        0 => PathRewrite::Keep,
        4 => PathRewrite::Flatten,
        count => NonZeroU64::new(u64::from(count))
            .and_then(|count| StripComponents::new(count, config.max_path_depth).ok())
            .map_or(PathRewrite::Keep, PathRewrite::Strip),
    };
    let config = config.with_path_rewrite(rewrite);
    match selector / 5 % 3 {
        0 => config,
        1 => config
            .try_add_include("a")
            .unwrap_or_else(|_| common::config().clone()),
        _ => config
            .try_add_exclude("a")
            .unwrap_or_else(|_| common::config().clone()),
    }
}

fuzz_target!(|data: &[u8]| {
    let config = common::config();
    // Atomic extraction (rename-into-place) is also this pipeline's default
    // in most callers and was the path GHSA-x8wr lived in; exercise it here
    // rather than only the non-atomic write-in-place path.
    let options = ExtractionOptions::default().with_staging(Staging::Atomic);

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
    let selected_output = iteration_root.path().join("selected");

    let _ = ExtractRequest::new(config)
        .with_options(options.clone())
        .extract(input.path(), &output);
    let _ = ExtractRequest::new(&selected_config(data.first().copied().unwrap_or(0)))
        .with_options(ExtractionOptions::default())
        .extract(input.path(), &selected_output);

    let outside = std::fs::read_dir(iteration_root.path())
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .any(|entry| entry.path() != output && entry.path() != selected_output);
    assert!(
        !outside,
        "extraction wrote outside the intended output directory"
    );
});
