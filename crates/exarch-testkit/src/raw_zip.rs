//! Hand-built ZIP archives for structural tests.
//!
//! Every field of the local header, central directory record and end record is
//! under the caller's control, so tests can build archives whose copies of the
//! same metadata disagree, hide records, or leave gaps between entries.

#![allow(
    clippy::cast_possible_truncation,
    clippy::must_use_candidate,
    clippy::return_self_not_must_use,
    clippy::missing_panics_doc
)]

/// DOS date of a new entry: 1980-01-01.
const DEFAULT_DATE: u16 = 0x21;

/// Data descriptor written after an entry's data.
#[derive(Debug, Clone)]
pub enum Descriptor {
    /// Written from the entry's CRC and sizes.
    Standard {
        /// Starts with the `PK\x07\x08` signature.
        signature: bool,
        /// Sizes are 8 bytes wide instead of 4.
        zip64: bool,
    },
    /// Written verbatim.
    Raw(Vec<u8>),
}

/// One entry with independent local and central metadata.
#[derive(Debug, Clone)]
pub struct RawEntry {
    /// Name in the local header (and the central record unless
    /// `central_name` is set).
    pub name: Vec<u8>,
    /// Different name for the central record.
    pub central_name: Option<Vec<u8>>,
    /// Bytes written after the local header, already compressed.
    pub data: Vec<u8>,
    /// Compression method id.
    pub method: u16,
    /// CRC-32 of the uncompressed data.
    pub crc: u32,
    /// Uncompressed size.
    pub size: u64,
    /// General purpose flag bits, in both headers.
    pub flags: u16,
    /// DOS modification time.
    pub time: u16,
    /// DOS modification date.
    pub date: u16,
    /// Extra field bytes of the local header.
    pub local_extra: Vec<u8>,
    /// Extra field bytes of the central record.
    pub central_extra: Vec<u8>,
    /// External attributes of the central record.
    pub external_attributes: u32,
    /// Data descriptor written after the data.
    pub descriptor: Option<Descriptor>,
    /// Zero bytes written after the entry and its descriptor.
    pub padding_after: usize,
    /// Compressed size to declare instead of the length of `data`.
    pub declared_compressed: Option<u64>,
    /// Compressed and uncompressed size to write in the local header instead of
    /// the entry's own (or zero when a descriptor follows).
    pub local_sizes: Option<(u32, u32)>,
    /// "Version needed to extract" written in the local header; its high byte
    /// names the host system.
    pub local_version: u16,
    /// "Version made by" of the central record; its high byte names the host
    /// system.
    pub made_by: u16,
    /// "Version needed to extract" of the central record.
    pub central_version: u16,
}

impl RawEntry {
    /// A stored entry holding `data`.
    pub fn stored(name: &str, data: &[u8]) -> Self {
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
            date: DEFAULT_DATE,
            local_extra: Vec::new(),
            central_extra: Vec::new(),
            external_attributes: 0o100_644 << 16,
            descriptor: None,
            padding_after: 0,
            declared_compressed: None,
            local_sizes: None,
            local_version: 20,
            made_by: 0x031e,
            central_version: 20,
        }
    }

    /// A deflated entry holding `data`.
    ///
    /// # Errors
    ///
    /// Returns the encoder's I/O error; writing to memory does not produce
    /// one in practice.
    pub fn deflated(name: &str, data: &[u8]) -> std::io::Result<Self> {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, data)?;
        Ok(Self {
            method: 8,
            data: encoder.finish()?,
            ..Self::stored(name, data)
        })
    }

    /// Writes the sizes and CRC after the data in a descriptor instead of in
    /// the local header.
    pub fn with_descriptor(mut self, signature: bool, zip64: bool) -> Self {
        self.flags |= 0x0008;
        if zip64 {
            let mut extra = 1u16.to_le_bytes().to_vec();
            extra.extend_from_slice(&16u16.to_le_bytes());
            extra.extend_from_slice(&[0; 16]);
            self.local_extra.extend(extra);
        }
        self.descriptor = Some(Descriptor::Standard { signature, zip64 });
        self
    }

    /// Like [`Self::with_descriptor`], with the descriptor bytes given
    /// verbatim.
    pub fn with_raw_descriptor(mut self, bytes: &[u8]) -> Self {
        self.flags |= 0x0008;
        self.descriptor = Some(Descriptor::Raw(bytes.to_vec()));
        self
    }

    /// Writes these sizes in the local header, whatever the entry declares.
    pub const fn with_local_sizes(mut self, compressed: u32, size: u32) -> Self {
        self.local_sizes = Some((compressed, size));
        self
    }

    /// Appends an extra field with the given id to the local header.
    pub fn with_local_extra_field(mut self, id: u16, body: &[u8]) -> Self {
        self.local_extra.extend(extra_field(id, body));
        self
    }

    /// Appends an extra field with the given id to the central record.
    pub fn with_central_extra_field(mut self, id: u16, body: &[u8]) -> Self {
        self.central_extra.extend(extra_field(id, body));
        self
    }

    /// Marks the local header as written on a Unix host.
    pub const fn with_local_unix_host(mut self) -> Self {
        self.local_version = 0x031e;
        self
    }

    /// Different name in the central directory than in the local header.
    pub fn with_central_name(mut self, name: &str) -> Self {
        self.central_name = Some(name.as_bytes().to_vec());
        self
    }

    /// Raw bytes that follow this entry (and its descriptor) before the next
    /// local header.
    pub const fn with_padding_after(mut self, bytes: usize) -> Self {
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
    /// Entries written in order, each with a central record.
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
    /// The archive.
    pub bytes: Vec<u8>,
    /// Offset of each entry's local header, in entry order.
    pub local_offsets: Vec<usize>,
    /// Offset of the first central record.
    pub directory_start: usize,
}

impl RawZip {
    /// An archive of `entries` with no gaps, no comment and a matching end
    /// record.
    pub fn new(entries: Vec<RawEntry>) -> Self {
        Self {
            entries,
            ..Self::default()
        }
    }

    /// Serializes the archive: local entries, the bytes before the directory,
    /// the central records and the end record.
    pub fn build(&self) -> BuiltZip {
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
        (entry.crc, entry.compressed_len() as u32, entry.size as u32)
    };
    let (compressed, size) = entry.local_sizes.unwrap_or((compressed, size));
    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&entry.local_version.to_le_bytes());
    out.extend_from_slice(&entry.flags.to_le_bytes());
    out.extend_from_slice(&entry.method.to_le_bytes());
    out.extend_from_slice(&entry.time.to_le_bytes());
    out.extend_from_slice(&entry.date.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&compressed.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entry.local_extra.len() as u16).to_le_bytes());
    out.extend_from_slice(&entry.name);
    out.extend_from_slice(&entry.local_extra);
    out.extend_from_slice(&entry.data);

    match &entry.descriptor {
        Some(Descriptor::Standard { signature, zip64 }) => {
            if *signature {
                out.extend_from_slice(b"PK\x07\x08");
            }
            out.extend_from_slice(&entry.crc.to_le_bytes());
            if *zip64 {
                out.extend_from_slice(&entry.compressed_len().to_le_bytes());
                out.extend_from_slice(&entry.size.to_le_bytes());
            } else {
                out.extend_from_slice(&(entry.compressed_len() as u32).to_le_bytes());
                out.extend_from_slice(&(entry.size as u32).to_le_bytes());
            }
        }
        Some(Descriptor::Raw(bytes)) => out.extend_from_slice(bytes),
        None => {}
    }
    out.extend(std::iter::repeat_n(0u8, entry.padding_after));
}

fn write_central(out: &mut Vec<u8>, entry: &RawEntry, local_offset: usize) {
    let name = entry.central_name.as_ref().unwrap_or(&entry.name);
    out.extend_from_slice(b"PK\x01\x02");
    out.extend_from_slice(&entry.made_by.to_le_bytes());
    out.extend_from_slice(&entry.central_version.to_le_bytes());
    out.extend_from_slice(&entry.flags.to_le_bytes());
    out.extend_from_slice(&entry.method.to_le_bytes());
    out.extend_from_slice(&entry.time.to_le_bytes());
    out.extend_from_slice(&entry.date.to_le_bytes());
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

/// Extra field id of the experimental `xl` field.
pub const XL_FIELD_ID: u16 = 0x6C78;

/// Unix mode of a symlink with all permissions.
pub const SYMLINK_MODE: u32 = 0o120_777;

/// An extra field: id, length and `body`.
pub fn extra_field(id: u16, body: &[u8]) -> Vec<u8> {
    let mut field = id.to_le_bytes().to_vec();
    field.extend_from_slice(&(body.len() as u16).to_le_bytes());
    field.extend_from_slice(body);
    field
}

/// Body of an `xl` field that carries only the external attributes of a Unix
/// entry with the given mode.
pub fn xl_unix_attributes(mode: u32) -> Vec<u8> {
    let mut body = vec![4u8];
    body.extend_from_slice(&(mode << 16).to_le_bytes());
    body
}

/// A Unicode Path extra field that replaces `raw` by `replacement`.
pub fn unicode_path_field(raw: &[u8], replacement: &[u8]) -> Vec<u8> {
    let mut crc = flate2::Crc::new();
    crc.update(raw);
    let mut body = vec![1u8];
    body.extend_from_slice(&crc.sum().to_le_bytes());
    body.extend_from_slice(replacement);
    extra_field(0x7075, &body)
}
