//! Builder for PAX extended-header records.

/// Decimal digits in `n`, without allocating.
fn digits(n: usize) -> usize {
    n.checked_ilog10().map_or(1, |d| d as usize + 1)
}

/// Encodes one PAX record, `"<len> <key>=<value>\n"`, where `<len>` counts its
/// own decimal digits (the self-referential length format of POSIX.1-2001).
///
/// # Examples
///
/// ```
/// assert_eq!(
///     exarch_testkit::pax::record(b"path", b"a/b"),
///     b"12 path=a/b\n"
/// );
/// ```
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::record;

    #[test]
    fn the_length_prefix_counts_its_own_digits_at_every_rollover() {
        for value_len in (0..1200).chain(999_980..1_000_020) {
            let built = record(b"k", &vec![b'v'; value_len]);
            let space = built.iter().position(|&b| b == b' ').unwrap();
            let declared: usize = std::str::from_utf8(&built[..space])
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(declared, built.len(), "value length {value_len}");
        }
    }
}
