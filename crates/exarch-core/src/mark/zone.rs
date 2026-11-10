//! The Windows `Zone.Identifier` stream: reading the archive's and rendering
//! the one each extracted file gets.

/// How much of the source stream is looked at; the rest is ignored, so a long
/// stream never rejects the mark.
pub(super) const MAX_LEN: usize = 4096;

/// The highest zone Windows defines (0 local, 1 intranet, 2 trusted, 3
/// internet, 4 restricted).
const MAX_ZONE: u8 = 4;

/// The zone of a source stream, the only field a propagated mark keeps: the
/// referrer and host URLs name where the file came from and are not copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Zone(u8);

impl Zone {
    /// The zone written when a stream is present but names none: the internet.
    pub(super) const INTERNET: Self = Self(3);

    /// The zone of a source stream: the `ZoneId` of its `[ZoneTransfer]`
    /// section within the first [`MAX_LEN`] bytes, else
    /// [`INTERNET`](Self::INTERNET).
    ///
    /// A stream that exists is a mark, so content that cannot be read as one
    /// (too long, not text, no or an invalid `ZoneId`) still yields the
    /// conservative zone instead of no mark.
    pub(super) fn of_stream(content: &[u8]) -> Self {
        Self::parse(content).unwrap_or(Self::INTERNET)
    }

    fn parse(content: &[u8]) -> Option<Self> {
        let content = content.get(..MAX_LEN).unwrap_or(content);
        let content = content.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(content);
        let mut in_section = false;
        for line in content.split(|byte| *byte == b'\n').map(<[u8]>::trim_ascii) {
            if line.first() == Some(&b'[') {
                in_section = line.eq_ignore_ascii_case(b"[ZoneTransfer]");
            } else if in_section
                && let Some(at) = line.iter().position(|byte| *byte == b'=')
                && let (key, value) = line.split_at(at)
                && key.trim_ascii().eq_ignore_ascii_case(b"ZoneId")
            {
                return std::str::from_utf8(value.get(1..)?.trim_ascii())
                    .ok()?
                    .parse::<u8>()
                    .ok()
                    .filter(|zone| *zone <= MAX_ZONE)
                    .map(Self);
            }
        }
        None
    }

    /// The stream content of one extracted file.
    pub(super) fn render(self) -> String {
        format!("[ZoneTransfer]\r\nZoneId={}\r\n", self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_zone_and_ignores_urls() {
        let content = b"[ZoneTransfer]\r\nZoneId=2\r\nReferrerUrl=https://a.example/\r\nHostUrl=https://b.example/f.zip\r\n";
        assert_eq!(Zone::of_stream(content), Zone(2));
    }

    #[test]
    fn a_byte_order_mark_and_lf_endings_are_accepted() {
        assert_eq!(
            Zone::of_stream(b"\xEF\xBB\xBF[ZoneTransfer]\nZoneId=1\n"),
            Zone(1)
        );
    }

    #[test]
    fn a_stream_that_names_no_valid_zone_is_the_internet() {
        for bad in [
            &b""[..],
            b"ZoneId=0\r\n",
            b"[Other]\r\nZoneId=0\r\n",
            b"[ZoneTransfer]\r\nZoneId=5\r\n",
            b"[ZoneTransfer]\r\nZoneId=x\r\n",
            b"[ZoneTransfer]\r\nHostUrl=a\r\n",
            b"\xFF\xFE[\0Z\0",
        ] {
            assert_eq!(Zone::of_stream(bad), Zone::INTERNET, "{bad:?}");
        }
    }

    #[test]
    fn non_ascii_text_elsewhere_does_not_hide_the_zone() {
        let content = "[ZoneTransfer]\r\nHostUrl=https://\u{e9}.example/\r\nZoneId=0\r\n";
        assert_eq!(Zone::of_stream(content.as_bytes()), Zone(0));
    }

    #[test]
    fn a_long_stream_is_read_from_its_prefix() {
        let mut content = b"[ZoneTransfer]\r\nZoneId=0\r\n".to_vec();
        content.resize(MAX_LEN * 3, b'a');
        assert_eq!(Zone::of_stream(&content), Zone(0));

        let mut late = vec![b'a'; MAX_LEN];
        late.extend_from_slice(b"\n[ZoneTransfer]\nZoneId=0\n");
        assert_eq!(Zone::of_stream(&late), Zone::INTERNET);
    }

    #[test]
    fn a_rendered_stream_parses_back_to_the_same_zone() {
        let zone = Zone(3);
        assert_eq!(zone.render(), "[ZoneTransfer]\r\nZoneId=3\r\n");
        assert_eq!(Zone::of_stream(zone.render().as_bytes()), zone);
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn any_bytes_give_a_defined_zone(bytes in proptest::collection::vec(any::<u8>(), 0..6000)) {
                prop_assert!(Zone::of_stream(&bytes).0 <= MAX_ZONE);
            }

            #[test]
            fn a_rendered_zone_reads_back(zone in 0_u8..=MAX_ZONE) {
                prop_assert_eq!(Zone::of_stream(Zone(zone).render().as_bytes()), Zone(zone));
            }
        }
    }
}
