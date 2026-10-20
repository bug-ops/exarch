//! Hand-built ZIP archives for structural tests.
//!
//! Every field of the local header, central directory record and end record is
//! under the caller's control, so tests can build archives whose copies of the
//! same metadata disagree, hide records, or leave gaps between entries.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

/// Data descriptor written after an entry's data.
#[derive(Debug, Clone, Copy)]
pub struct Descriptor {
    pub signature: bool,
    pub zip64: bool,
}

/// One entry with independent local and central metadata.
#[derive(Debug, Clone)]
pub struct RawEntry {
    pub name: Vec<u8>,
    pub central_name: Option<Vec<u8>>,
    pub data: Vec<u8>,
    pub method: u16,
    pub crc: u32,
    pub size: u64,
    pub flags: u16,
    pub time: u16,
    pub local_extra: Vec<u8>,
    pub central_extra: Vec<u8>,
    pub external_attributes: u32,
    pub descriptor: Option<Descriptor>,
    pub padding_after: usize,
    /// Compressed size to declare instead of the length of `data`.
    pub declared_compressed: Option<u64>,
}

impl RawEntry {
    /// A stored entry holding `data`.
    pub(crate) fn stored(name: &str, data: &[u8]) -> Self {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        Self {
            name: name.as_bytes().to_vec(),
            central_name: None,
            data: data.to_vec(),
            method: 0,
            crc: crc.sum(),
            size: data.len() as u64,
            flags: 0,
            time: 0,
            local_extra: Vec::new(),
            central_extra: Vec::new(),
            external_attributes: 0o100_644 << 16,
            descriptor: None,
            padding_after: 0,
            declared_compressed: None,
        }
    }

    /// Writes the sizes and CRC after the data in a descriptor instead of in
    /// the local header.
    pub(crate) fn with_descriptor(mut self, signature: bool, zip64: bool) -> Self {
        self.flags |= 0x0008;
        if zip64 {
            let mut extra = 1u16.to_le_bytes().to_vec();
            extra.extend_from_slice(&16u16.to_le_bytes());
            extra.extend_from_slice(&[0; 16]);
            self.local_extra.extend(extra);
        }
        self.descriptor = Some(Descriptor { signature, zip64 });
        self
    }

    /// Different name in the central directory than in the local header.
    pub(crate) fn with_central_name(mut self, name: &str) -> Self {
        self.central_name = Some(name.as_bytes().to_vec());
        self
    }

    /// Raw bytes that follow this entry (and its descriptor) before the next
    /// local header.
    pub(crate) const fn with_padding_after(mut self, bytes: usize) -> Self {
        self.padding_after = bytes;
        self
    }

    fn compressed_len(&self) -> u64 {
        self.declared_compressed.unwrap_or(self.data.len() as u64)
    }
}

/// A whole archive.
#[derive(Debug, Clone, Default)]
pub struct RawZip {
    pub entries: Vec<RawEntry>,
    /// Raw bytes written between the last entry and the central directory.
    pub before_directory: Vec<u8>,
    /// Overrides the entry count in the end record.
    pub end_count: Option<u16>,
    /// Extra central directory records, appended verbatim after the entries'.
    pub extra_central_records: Vec<(RawEntry, usize)>,
    /// Archive comment written after the end record.
    pub comment: Vec<u8>,
}

/// A built archive and where each local header sits.
#[derive(Debug, Clone)]
pub struct BuiltZip {
    pub bytes: Vec<u8>,
    pub local_offsets: Vec<usize>,
    pub directory_start: usize,
}

impl RawZip {
    pub(crate) fn new(entries: Vec<RawEntry>) -> Self {
        Self {
            entries,
            ..Self::default()
        }
    }

    pub(crate) fn build(&self) -> BuiltZip {
        let mut bytes = Vec::new();
        let mut local_offsets = Vec::new();
        for entry in &self.entries {
            local_offsets.push(bytes.len());
            write_local(&mut bytes, entry);
        }
        bytes.extend_from_slice(&self.before_directory);

        let directory_start = bytes.len();
        for (entry, offset) in self.entries.iter().zip(&local_offsets) {
            write_central(&mut bytes, entry, *offset);
        }
        for (entry, offset) in &self.extra_central_records {
            write_central(&mut bytes, entry, *offset);
        }
        let directory_len = bytes.len() - directory_start;

        let count = self
            .end_count
            .unwrap_or((self.entries.len() + self.extra_central_records.len()) as u16);
        bytes.extend_from_slice(b"PK\x05\x06");
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.extend_from_slice(&(directory_len as u32).to_le_bytes());
        bytes.extend_from_slice(&(directory_start as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.comment.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&self.comment);
        BuiltZip {
            bytes,
            local_offsets,
            directory_start,
        }
    }
}

fn write_local(out: &mut Vec<u8>, entry: &RawEntry) {
    let (crc, compressed, size) = if entry.descriptor.is_some() {
        (0, 0, 0)
    } else {
        (entry.crc, entry.compressed_len(), entry.size)
    };
    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&entry.flags.to_le_bytes());
    out.extend_from_slice(&entry.method.to_le_bytes());
    out.extend_from_slice(&entry.time.to_le_bytes());
    out.extend_from_slice(&0x21u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(compressed as u32).to_le_bytes());
    out.extend_from_slice(&(size as u32).to_le_bytes());
    out.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entry.local_extra.len() as u16).to_le_bytes());
    out.extend_from_slice(&entry.name);
    out.extend_from_slice(&entry.local_extra);
    out.extend_from_slice(&entry.data);

    if let Some(descriptor) = entry.descriptor {
        if descriptor.signature {
            out.extend_from_slice(b"PK\x07\x08");
        }
        out.extend_from_slice(&entry.crc.to_le_bytes());
        if descriptor.zip64 {
            out.extend_from_slice(&entry.compressed_len().to_le_bytes());
            out.extend_from_slice(&entry.size.to_le_bytes());
        } else {
            out.extend_from_slice(&(entry.compressed_len() as u32).to_le_bytes());
            out.extend_from_slice(&(entry.size as u32).to_le_bytes());
        }
    }
    out.extend(std::iter::repeat_n(0u8, entry.padding_after));
}

fn write_central(out: &mut Vec<u8>, entry: &RawEntry, local_offset: usize) {
    let name = entry.central_name.as_ref().unwrap_or(&entry.name);
    out.extend_from_slice(b"PK\x01\x02");
    out.extend_from_slice(&0x031eu16.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&entry.flags.to_le_bytes());
    out.extend_from_slice(&entry.method.to_le_bytes());
    out.extend_from_slice(&entry.time.to_le_bytes());
    out.extend_from_slice(&0x21u16.to_le_bytes());
    out.extend_from_slice(&entry.crc.to_le_bytes());
    out.extend_from_slice(&(entry.compressed_len() as u32).to_le_bytes());
    out.extend_from_slice(&(entry.size as u32).to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entry.central_extra.len() as u16).to_le_bytes());
    out.extend_from_slice(&[0; 2]);
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&entry.external_attributes.to_le_bytes());
    out.extend_from_slice(&(local_offset as u32).to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&entry.central_extra);
}

/// Raw DEFLATE data that inflates to `len` zero bytes, using fixed Huffman
/// codes: one literal, then matches of length 258 at distance 1.
pub fn deflate_zeros(len: u64) -> Vec<u8> {
    struct Bits {
        out: Vec<u8>,
        acc: u32,
        used: u32,
    }
    impl Bits {
        fn put(&mut self, value: u32, count: u32) {
            for i in 0..count {
                self.acc |= ((value >> i) & 1) << self.used;
                self.used += 1;
                if self.used == 8 {
                    self.out.push(self.acc as u8);
                    self.acc = 0;
                    self.used = 0;
                }
            }
        }

        // Huffman codes are packed most significant bit first.
        fn code(&mut self, value: u32, count: u32) {
            for i in (0..count).rev() {
                self.put((value >> i) & 1, 1);
            }
        }
    }

    assert!(len >= 1);
    let mut bits = Bits {
        out: Vec::new(),
        acc: 0,
        used: 0,
    };
    bits.put(1, 1);
    bits.put(1, 2);
    bits.code(0x30, 8);
    let rest = len - 1;
    for _ in 0..rest / 258 {
        bits.code(0xC5, 8);
        bits.code(0, 5);
    }
    for _ in 0..rest % 258 {
        bits.code(0x30, 8);
    }
    bits.code(0, 7);
    if bits.used > 0 {
        bits.out.push(bits.acc as u8);
    }
    bits.out
}
