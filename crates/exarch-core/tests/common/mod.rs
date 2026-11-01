//! Helpers shared by the integration tests.

#![allow(dead_code, clippy::expect_used)]

/// Flips the low bit of the first byte of `marker` found in `bytes`, so stored
/// data fails its checksum.
pub fn flip_first(bytes: &mut [u8], marker: &[u8]) {
    let at = bytes
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("marker present");
    bytes[at] ^= 0x01;
}

/// An entry of [`solid_copy_7z`].
#[derive(Clone, Copy)]
pub enum RawEntry<'a> {
    File(&'a str, &'a [u8]),
    Link(&'a str, &'a [u8]),
    Dir(&'a str),
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(data);
    crc.sum()
}

/// A 7z number below 0x4000.
fn number(value: usize) -> Vec<u8> {
    assert!(value < 0x4000, "number too large for the helper");
    let [high, low] = u16::try_from(value).expect("below 0x4000").to_be_bytes();
    if value < 0x80 {
        vec![low]
    } else {
        vec![0x80 | high, low]
    }
}

fn bit_vector(flags: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; flags.len().div_ceil(8)];
    for (i, _) in flags.iter().enumerate().filter(|(_, set)| **set) {
        out[i / 8] |= 0x80 >> (i % 8);
    }
    out
}

/// Writes a stored (Copy) 7z archive with one solid block holding a sub-stream
/// per file or link, and a stream-less entry for every directory, wherever it
/// stands in the entry order, as 7-Zip lays it out. The `sevenz-rust2` writer
/// cannot do this: it gives a directory in a solid block a sub-stream of its
/// own.
pub fn solid_copy_7z(entries: &[RawEntry<'_>]) -> Vec<u8> {
    let streamed: Vec<&[u8]> = entries
        .iter()
        .filter_map(|e| match e {
            RawEntry::File(_, data) | RawEntry::Link(_, data) => Some(*data),
            RawEntry::Dir(_) => None,
        })
        .collect();
    let data = streamed.concat();

    let mut h = vec![0x01, 0x04, 0x06];
    h.extend(number(0));
    h.extend(number(1));
    h.push(0x09);
    h.extend(number(data.len()));
    h.extend([0x00, 0x07, 0x0B]);
    h.extend(number(1));
    h.push(0x00);
    h.extend(number(1));
    h.extend([0x01, 0x00, 0x0C]);
    h.extend(number(data.len()));
    h.extend([0x00, 0x08, 0x0D]);
    h.extend(number(streamed.len()));
    if streamed.len() > 1 {
        h.push(0x09);
        for part in &streamed[..streamed.len() - 1] {
            h.extend(number(part.len()));
        }
    }
    h.extend([0x00, 0x00, 0x05]);
    h.extend(number(entries.len()));

    let empty_stream: Vec<bool> = entries
        .iter()
        .map(|e| matches!(e, RawEntry::Dir(_)))
        .collect();
    if empty_stream.contains(&true) {
        let bits = bit_vector(&empty_stream);
        h.push(0x0E);
        h.extend(number(bits.len()));
        h.extend(bits);
    }

    let mut names = vec![0u8];
    let mut attributes = vec![0x01, 0x00];
    for entry in entries {
        let (name, attribute) = match entry {
            RawEntry::File(name, _) => (name, 0x20 | 0x8000 | (0o100_644u32 << 16)),
            RawEntry::Link(name, _) => (name, 0x8000 | (0o120_777u32 << 16)),
            RawEntry::Dir(name) => (name, 0x10 | 0x8000 | (0o040_755u32 << 16)),
        };
        for unit in name.encode_utf16().chain([0]) {
            names.extend(unit.to_le_bytes());
        }
        attributes.extend(attribute.to_le_bytes());
    }
    h.push(0x11);
    h.extend(number(names.len()));
    h.extend(names);
    h.push(0x15);
    h.extend(number(attributes.len()));
    h.extend(attributes);
    h.extend([0x00, 0x00]);

    let mut start = Vec::new();
    start.extend((data.len() as u64).to_le_bytes());
    start.extend((h.len() as u64).to_le_bytes());
    start.extend(crc32(&h).to_le_bytes());

    let mut out = vec![b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    out.extend(crc32(&start).to_le_bytes());
    out.extend(start);
    out.extend(data);
    out.extend(h);
    out
}
