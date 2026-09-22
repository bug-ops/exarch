#![no_main]

use std::path::PathBuf;
use std::sync::OnceLock;

use exarch_core::types::DestDir;
use exarch_core::types::SafePath;
use libfuzzer_sys::fuzz_target;
use tempfile::TempDir;

#[path = "common.rs"]
mod common;

fn dest() -> &'static DestDir {
    static DEST: OnceLock<(TempDir, DestDir)> = OnceLock::new();
    let (_temp, dest) = DEST.get_or_init(|| {
        let temp = TempDir::new().expect("failed to create fuzz temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to build DestDir");
        (temp, dest)
    });
    dest
}

fuzz_target!(|data: &[u8]| {
    let config = common::validated();

    #[cfg(unix)]
    let path = {
        use std::os::unix::ffi::OsStrExt as _;
        PathBuf::from(std::ffi::OsStr::from_bytes(data))
    };
    #[cfg(not(unix))]
    let path = PathBuf::from(String::from_utf8_lossy(data).into_owned());

    let _ = SafePath::validate(&path, dest(), config);
});
