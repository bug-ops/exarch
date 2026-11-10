//! The macOS `com.apple.quarantine` value: parsing the archive's and
//! rendering the one each extracted file gets.

use std::hash::BuildHasher;
use std::hash::RandomState;

/// Longest value read from an archive file; a longer one is malformed.
pub(super) const MAX_LEN: usize = 256;

/// The flag bits that are carried over: download, sandbox and hard quarantine.
/// The user-approved bit and every unknown bit are dropped, so a copy is never
/// less restrictive than a fresh download.
const CARRIED_FLAGS: u16 = 0x0007;
const DOWNLOAD_FLAG: u16 = 0x0001;

/// The agent name written for a propagated mark.
const AGENT: &str = "exarch";

/// The parts of a source quarantine value a propagated mark keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Quarantine {
    flags: u16,
    timestamp: u32,
}

impl Quarantine {
    /// The mark written when the source attribute exists but cannot be read as
    /// a quarantine value: a plain download, stamped now.
    pub(super) fn fallback() -> Self {
        Self {
            flags: DOWNLOAD_FLAG,
            timestamp: now(),
        }
    }

    /// The mark a source value stands for: `flags;timestamp;agent;uuid`, the
    /// first two hexadecimal.
    ///
    /// A value that exists is a mark, so each part that cannot be read falls
    /// back on its own (flags to a plain download, timestamp to now) and a
    /// value that is not ASCII falls back entirely.
    pub(super) fn of_value(value: &[u8]) -> Self {
        let prefix = value.get(..MAX_LEN).unwrap_or(value);
        let Some(text) = std::str::from_utf8(prefix)
            .ok()
            .filter(|text| text.is_ascii())
        else {
            return Self::fallback();
        };
        let mut fields = text.split(';');
        let carried = fields
            .next()
            .and_then(|field| hex(field, 4))
            .and_then(|flags| u16::try_from(flags).ok())
            .map_or(0, |flags| flags & CARRIED_FLAGS);
        Self {
            flags: if carried == 0 { DOWNLOAD_FLAG } else { carried },
            timestamp: fields
                .next()
                .and_then(|field| hex(field, 8))
                .unwrap_or_else(now),
        }
    }

    /// The value for one extracted object: the carried flags and timestamp
    /// with a fresh identifier, never a byte copy of the source.
    pub(super) fn render(self) -> String {
        self.render_with(fresh_uuid())
    }

    fn render_with(self, uuid: u128) -> String {
        let [time_low, time_mid, version, variant, node] = uuid_groups(uuid);
        format!(
            "{:04x};{:08x};{AGENT};{time_low:08X}-{time_mid:04X}-{version:04X}-{variant:04X}-{node:012X}",
            self.flags, self.timestamp
        )
    }
}

fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| u32::try_from(elapsed.as_secs()).unwrap_or(0))
}

fn hex(field: &str, max_digits: usize) -> Option<u32> {
    if field.is_empty() || field.len() > max_digits {
        return None;
    }
    u32::from_str_radix(field, 16).ok()
}

/// A random version 4 UUID from the standard library's per-process random
/// hasher keys.
fn fresh_uuid() -> u128 {
    let high = RandomState::new().hash_one(0_u8);
    let low = RandomState::new().hash_one(1_u8);
    let bits = (u128::from(high) << 64) | u128::from(low);
    let versioned = (bits & !(0xF_u128 << 76)) | (0x4_u128 << 76);
    (versioned & !(0x3_u128 << 62)) | (0x2_u128 << 62)
}

fn uuid_groups(uuid: u128) -> [u128; 5] {
    [
        uuid >> 96,
        (uuid >> 80) & 0xFFFF,
        (uuid >> 64) & 0xFFFF,
        (uuid >> 48) & 0xFFFF,
        uuid & 0xFFFF_FFFF_FFFF,
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::assert_matches;

    use super::*;

    fn fixed(flags: u16, timestamp: u32) -> Quarantine {
        Quarantine { flags, timestamp }
    }

    #[test]
    fn reads_a_browser_value_and_keeps_flags_and_timestamp() {
        let q = Quarantine::of_value(b"0083;5f3c8d11;Safari;3F2D5A10-1111-4222-8333-444455556666");
        assert_eq!(q, fixed(0x0003, 0x5f3c_8d11));
    }

    #[test]
    fn user_approved_and_unknown_bits_are_dropped() {
        assert_eq!(
            Quarantine::of_value(b"00c0;5f3c8d11;;").flags,
            DOWNLOAD_FLAG
        );
    }

    #[test]
    fn an_unreadable_part_falls_back_on_its_own() {
        assert_eq!(Quarantine::of_value(b"0083;zz;a;b").flags, 0x0003);
        assert_eq!(
            Quarantine::of_value(b"zz;5f3c8d11;a;b"),
            fixed(DOWNLOAD_FLAG, 0x5f3c_8d11)
        );
        assert_eq!(Quarantine::of_value(b"00830;5f3c8d11").flags, DOWNLOAD_FLAG);
    }

    #[test]
    fn a_value_that_is_not_a_quarantine_value_is_still_a_mark() {
        for odd in [
            &b""[..],
            b"0083",
            b"not a quarantine value",
            "0083;5f3c8d11;\u{e9};b".as_bytes(),
            &[b'0'; MAX_LEN * 2],
        ] {
            assert_eq!(
                Quarantine::of_value(odd).flags & !CARRIED_FLAGS,
                0,
                "{odd:?}"
            );
            assert_ne!(Quarantine::of_value(odd).flags, 0, "{odd:?}");
        }
        assert_eq!(Quarantine::fallback().flags, DOWNLOAD_FLAG);
    }

    #[test]
    fn rendered_value_has_the_four_fields_and_a_valid_uuid() {
        let q = Quarantine {
            flags: 0x0003,
            timestamp: 0x5f3c_8d11,
        };
        let value = q.render_with(fresh_uuid());
        let fields: Vec<_> = value.split(';').collect();
        assert_eq!(&fields[..3], ["0003", "5f3c8d11", AGENT]);
        let uuid = fields[3];
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.as_bytes()[14], b'4');
        assert_matches!(uuid.as_bytes()[19], b'8' | b'9' | b'A' | b'B');
    }

    #[test]
    fn every_rendering_has_a_fresh_identifier() {
        let q = Quarantine {
            flags: 1,
            timestamp: 0,
        };
        assert_ne!(q.render(), q.render());
    }

    #[test]
    fn a_rendered_value_parses_back_to_the_same_mark() {
        let q = Quarantine {
            flags: 0x0005,
            timestamp: 0x1234_5678,
        };
        assert_eq!(Quarantine::of_value(q.render().as_bytes()), q);
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn any_bytes_give_a_conservative_mark(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
                let mark = Quarantine::of_value(&bytes);
                prop_assert!(mark.flags != 0);
                prop_assert_eq!(mark.flags & !CARRIED_FLAGS, 0);
            }

            #[test]
            fn a_rendered_mark_reads_back(flags in 1_u16..8, timestamp in any::<u32>()) {
                let mark = Quarantine { flags, timestamp };
                prop_assert_eq!(Quarantine::of_value(mark.render().as_bytes()), mark);
            }
        }
    }
}
