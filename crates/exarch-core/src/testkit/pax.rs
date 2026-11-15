//! Builder for PAX extended-header records.

/// Decimal digits in `n`, without allocating.
fn digits(n: usize) -> usize {
    n.checked_ilog10().map_or(1, |d| d as usize + 1)
}

/// Encodes one PAX record, `"<len> <key>=<value>\n"`, where `<len>` counts its
/// own decimal digits (the self-referential length format of POSIX.1-2001).
#[must_use]
pub fn record(key: &[u8], value: &[u8]) -> Vec<u8> {
    let base = key.len() + value.len() + 3;
    let mut len = base + 1;
    while digits(len) + base != len {
        len = digits(len) + base;
    }
    let mut out = format!("{len} ").into_bytes();
    out.extend_from_slice(key);
    out.push(b'=');
    out.extend_from_slice(value);
    out.push(b'\n');
    out
}
