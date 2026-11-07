#![no_main]

use std::path::Path;

use exarch_core::ExcludePattern;
use libfuzzer_sys::fuzz_target;

fn path_of(bytes: &[u8]) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStrExt as _;
    std::path::PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
}

fuzz_target!(|data: &[u8]| {
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let (pattern_bytes, path_bytes) = rest.split_at(usize::from(split).min(rest.len()));
    let Ok(text) = std::str::from_utf8(pattern_bytes) else {
        return;
    };
    let Ok(pattern) = ExcludePattern::try_from(text) else {
        return;
    };

    let shown = pattern.to_string();
    let reparsed = ExcludePattern::try_from(shown.as_str());
    assert_eq!(
        reparsed.as_ref().ok(),
        Some(&pattern),
        "{text:?} -> {shown:?}"
    );

    let path = path_of(path_bytes);
    let matched = pattern.matches(&path);

    // A pattern without `/` and `**` can only match through one component.
    let single_component = !text.contains(['/', '\\']) && !text.contains("**");
    let only_normal = !path_bytes.contains(&b'\\')
        && path_bytes
            .split(|b| *b == b'/')
            .all(|segment| !segment.is_empty() && segment != b"." && segment != b"..");
    if matched && single_component && only_normal {
        let through_one = path
            .components()
            .any(|component| pattern.matches(Path::new(component.as_os_str())));
        assert!(
            through_one,
            "{text:?} matched {path:?} without a matching component"
        );
    }
});
