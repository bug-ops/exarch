//! Raw builders for old GNU sparse TAR entries (typeflag `S`), shared by the
//! sparse acceptance tests. Every field of the map can be set to a malformed
//! value, so the tests build both well-formed and refused archives here.

#![allow(dead_code, reason = "helpers are used by only some test binaries")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

pub const BLOCK: usize = 512;
pub const HEADER_SLOTS: usize = 4;
pub const CHAIN_SLOTS: usize = 21;

const SPARSE_AT: usize = 386;
const ISEXTENDED_AT: usize = 482;
const REALSIZE_AT: usize = 483;
const CHECKSUM: std::ops::Range<usize> = 148..156;
const CHAIN_ISEXTENDED_AT: usize = CHAIN_SLOTS * 24;

pub type Slot = [u8; 24];
pub type Number = [u8; 12];

pub const EMPTY_SLOT: Slot = [0; 24];

/// `value` as a 12-byte numeric field: octal when it fits, base-256
/// otherwise.
pub fn number(value: u64) -> Number {
    let digits = format!("{value:o}");
    let mut field = [0u8; 12];
    if digits.len() <= 11 {
        let padded = format!("{digits:0>11}");
        field[..11].copy_from_slice(padded.as_bytes());
    } else {
        field[4..].copy_from_slice(&value.to_be_bytes());
        field[0] = 0x80;
    }
    field
}

pub fn slot(offset: u64, length: u64) -> Slot {
    slot_of(number(offset), number(length))
}

pub fn slot_of(offset: Number, length: Number) -> Slot {
    let mut slot = [0u8; 24];
    slot[..12].copy_from_slice(&offset);
    slot[12..].copy_from_slice(&length);
    slot
}

/// One extension block of the map.
#[derive(Clone)]
pub struct Chain {
    pub slots: Vec<Slot>,
    pub extended: u8,
}

/// An old GNU sparse member with every field spelled out.
#[derive(Clone)]
pub struct Sparse {
    pub name: String,
    pub header_slots: Vec<Slot>,
    pub extended: u8,
    pub chain: Vec<Chain>,
    pub realsize: Number,
    pub archived: u64,
    pub data: Vec<u8>,
}

impl Sparse {
    /// A well-formed member: `regions` are `(offset, bytes)` in ascending
    /// order and `realsize` is the real size. A trailing hole is marked by a
    /// zero-length slot at `realsize`, as GNU tar writes it.
    pub fn well_formed(name: &str, regions: &[(u64, Vec<u8>)], realsize: u64) -> Self {
        let mut slots: Vec<Slot> = regions
            .iter()
            .map(|(offset, bytes)| slot(*offset, bytes.len() as u64))
            .collect();
        let end = regions
            .last()
            .map_or(0, |(offset, bytes)| offset + bytes.len() as u64);
        if end < realsize {
            slots.push(slot(realsize, 0));
        }
        let data: Vec<u8> = regions
            .iter()
            .flat_map(|(_, bytes)| bytes.clone())
            .collect();
        let rest = slots.split_off(slots.len().min(HEADER_SLOTS));
        let blocks: Vec<&[Slot]> = rest.chunks(CHAIN_SLOTS).collect();
        let chain = blocks
            .iter()
            .enumerate()
            .map(|(index, slots)| Chain {
                slots: slots.to_vec(),
                extended: u8::from(index + 1 < blocks.len()),
            })
            .collect();
        Self {
            name: name.into(),
            header_slots: slots,
            extended: u8::from(!rest.is_empty()),
            chain,
            realsize: number(realsize),
            archived: data.len() as u64,
            data,
        }
    }

    /// The member's bytes: header, extension blocks, padded data.
    pub fn bytes(&self) -> Vec<u8> {
        let mut header = vec![0u8; BLOCK];
        header[..self.name.len()].copy_from_slice(self.name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(&number(self.archived));
        header[136..148].copy_from_slice(&number(0));
        header[156] = b'S';
        header[257..265].copy_from_slice(b"ustar  \0");
        for (index, slot) in self.header_slots.iter().enumerate() {
            let at = SPARSE_AT + index * 24;
            header[at..at + 24].copy_from_slice(slot);
        }
        header[ISEXTENDED_AT] = self.extended;
        header[REALSIZE_AT..REALSIZE_AT + 12].copy_from_slice(&self.realsize);
        refresh_checksum(&mut header);

        let mut bytes = header;
        for block in &self.chain {
            let mut raw = vec![0u8; BLOCK];
            for (index, slot) in block.slots.iter().enumerate() {
                raw[index * 24..index * 24 + 24].copy_from_slice(slot);
            }
            raw[CHAIN_ISEXTENDED_AT] = block.extended;
            bytes.extend(raw);
        }
        bytes.extend_from_slice(&self.data);
        bytes.resize(bytes.len().next_multiple_of(BLOCK), 0);
        bytes
    }

    pub fn with_header_slots(mut self, slots: &[Slot]) -> Self {
        self.header_slots = slots.to_vec();
        self
    }

    pub fn with_extended(mut self, flag: u8) -> Self {
        self.extended = flag;
        self
    }

    pub fn with_chain(mut self, chain: Vec<Chain>) -> Self {
        self.chain = chain;
        self
    }

    pub fn with_realsize(mut self, field: Number) -> Self {
        self.realsize = field;
        self
    }
}

fn refresh_checksum(header: &mut [u8]) {
    header[CHECKSUM].fill(b' ');
    let sum: u32 = header.iter().map(|&byte| u32::from(byte)).sum();
    header[CHECKSUM].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

/// A regular member, header plus padded data.
pub fn regular(name: &str, data: &[u8]) -> Vec<u8> {
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    header.set_size(data.len() as u64);
    header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(data);
    bytes.resize(bytes.len().next_multiple_of(BLOCK), 0);
    bytes
}

/// `"<len> <key>=<value>\n"` with the self-referential length resolved.
pub fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let body = key.len() + value.len() + 3;
    let mut len = body;
    while len.to_string().len() + body != len {
        len = len.to_string().len() + body;
    }
    format!("{len} {key}={value}\n").into_bytes()
}

/// A local PAX header member carrying `records`.
pub fn pax_header(records: &[(&str, &str)]) -> Vec<u8> {
    let body: Vec<u8> = records
        .iter()
        .flat_map(|(key, value)| pax_record(key, value))
        .collect();
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    header.set_size(body.len() as u64);
    header.as_old_mut().name[..3].copy_from_slice(b"pax");
    header.set_entry_type(tar::EntryType::XHeader);
    header.set_cksum();
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend(body);
    bytes.resize(bytes.len().next_multiple_of(BLOCK), 0);
    bytes
}

/// `members` followed by the end-of-archive blocks.
pub fn tar_of(members: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = members.concat();
    bytes.resize(bytes.len() + 2 * BLOCK, 0);
    bytes
}

/// What a sparse member extracts to: the regions placed in a zero-filled
/// file of `realsize` bytes.
pub fn expanded(regions: &[(u64, Vec<u8>)], realsize: u64) -> Vec<u8> {
    let mut file = vec![0u8; usize::try_from(realsize).unwrap()];
    for (offset, bytes) in regions {
        let at = usize::try_from(*offset).unwrap();
        file[at..at + bytes.len()].copy_from_slice(bytes);
    }
    file
}

/// A block of `len` copies of `fill`.
pub fn filled(fill: u8, len: usize) -> Vec<u8> {
    vec![fill; len]
}

/// A map the `Expand` policy accepts: its label, regions and real size.
pub struct Accepted {
    pub label: &'static str,
    pub regions: Vec<(u64, Vec<u8>)>,
    pub realsize: u64,
}

fn regions_at(count: usize, step: u64) -> Vec<(u64, Vec<u8>)> {
    (0..count)
        .map(|index| {
            let fill = b'a' + u8::try_from(index % 26).unwrap();
            (index as u64 * step, filled(fill, BLOCK))
        })
        .collect()
}

/// Maps that bsdtar, Python `tarfile` and the `tar` crate all read the same
/// way: one region with a trailing hole, a leading hole, an interior hole,
/// a full header, and extension chains of one and two blocks.
pub fn accepted() -> Vec<Accepted> {
    vec![
        Accepted {
            label: "one region then a hole",
            regions: vec![(0, b"hello".to_vec())],
            realsize: 1000,
        },
        Accepted {
            label: "leading hole",
            regions: vec![(4096, filled(b'Z', BLOCK))],
            realsize: 4096 + BLOCK as u64,
        },
        Accepted {
            label: "interior hole and trailing hole",
            regions: vec![(0, filled(b'A', BLOCK)), (2048, filled(b'B', BLOCK))],
            realsize: 4096,
        },
        Accepted {
            label: "four regions fill the header",
            regions: regions_at(4, 1024),
            realsize: 3 * 1024 + BLOCK as u64,
        },
        Accepted {
            label: "six regions need one extension block",
            regions: regions_at(6, 1024),
            realsize: 6 * 1024 + 100,
        },
        Accepted {
            label: "thirty regions need two extension blocks",
            regions: regions_at(30, 1024),
            realsize: 30 * 1024,
        },
    ]
}
