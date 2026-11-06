//! Helpers shared by the integration tests.

#![allow(dead_code, clippy::expect_used, clippy::disallowed_methods)]

/// Flips the low bit of the first byte of `marker` found in `bytes`, so stored
/// data fails its checksum.
pub fn flip_first(bytes: &mut [u8], marker: &[u8]) {
    let at = bytes
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("marker present");
    bytes[at] ^= 0x01;
}

/// Text of `len` bytes drawn from a small vocabulary by a seeded xorshift, so
/// it deflates to a quarter of its size, far below the default ratio limit.
pub fn wordy(seed: usize, len: usize) -> Vec<u8> {
    const WORDS: [&str; 16] = [
        "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa",
        "lambda", "mu", "nu", "xi", "omicron", "pi",
    ];
    let mut state = 0x9E37_79B9_u32.wrapping_add(u32::try_from(seed).expect("small seed"));
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.extend_from_slice(WORDS[state as usize % WORDS.len()].as_bytes());
        out.push(b' ');
    }
    out.truncate(len);
    out
}

/// A ZIP of `entries` deflated files named `dir/file{i}.txt`, each holding
/// `wordy(i, entry_len)`.
pub fn deflated_zip(entries: usize, entry_len: usize) -> Vec<u8> {
    use std::io::Write;

    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644);
    for index in 0..entries {
        zip.start_file(format!("dir/file{index}.txt"), options)
            .expect("start entry");
        zip.write_all(&wordy(index, entry_len))
            .expect("write entry");
    }
    zip.finish().expect("finish archive").into_inner()
}

/// The files of [`mixed_zip`] with their contents.
pub fn mixed_zip_files() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("stored.txt", wordy(1, 5000)),
        ("deflated.txt", wordy(2, 30_000)),
        ("empty-deflated.txt", Vec::new()),
        ("empty-stored.txt", Vec::new()),
        ("bzip2.txt", wordy(3, 20_000)),
        ("deflated-again.txt", wordy(4, 7000)),
    ]
}

/// A ZIP mixing stored, deflated, bzip2 and zero-length entries.
pub fn mixed_zip() -> Vec<u8> {
    use std::io::Write;
    use zip::CompressionMethod;

    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, data) in mixed_zip_files() {
        let method = match name {
            "stored.txt" | "empty-stored.txt" => CompressionMethod::Stored,
            "bzip2.txt" => CompressionMethod::Bzip2,
            _ => CompressionMethod::Deflated,
        };
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(method)
            .unix_permissions(0o644);
        zip.start_file(name, options).expect("start entry");
        zip.write_all(&data).expect("write entry");
    }
    zip.finish().expect("finish archive").into_inner()
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

/// An archive held in memory that [`ArchiveBytes::extract`] extracts through
/// the public request API, by writing it to a scratch file first.
pub struct ArchiveBytes {
    file_name: &'static str,
    bytes: Vec<u8>,
    config: exarch_core::SecurityConfig,
}

impl ArchiveBytes {
    fn new(
        file_name: &'static str,
        mut reader: impl std::io::Read,
        config: &exarch_core::SecurityConfig,
    ) -> Self {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).expect("read archive bytes");
        Self {
            file_name,
            bytes,
            config: config.clone(),
        }
    }

    /// Extracts into `output_dir` under the config the bytes were wrapped with.
    pub fn extract(
        self,
        output_dir: &std::path::Path,
        options: &exarch_core::ExtractionOptions,
        progress: &mut dyn exarch_core::ProgressCallback,
    ) -> exarch_core::Result<exarch_core::ExtractionReport> {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let path = scratch.path().join(self.file_name);
        std::fs::write(&path, &self.bytes).expect("write archive");
        exarch_core::ExtractRequest::new(&self.config)
            .with_options(options.clone())
            .with_progress(progress)
            .extract(&path, output_dir)
    }
}

/// A plain TAR stream, extracted by path as `archive.tar`.
pub fn tar_archive(
    reader: impl std::io::Read,
    config: &exarch_core::SecurityConfig,
) -> ArchiveBytes {
    ArchiveBytes::new("archive.tar", reader, config)
}

/// A ZIP archive, extracted by path as `archive.zip`.
pub fn zip_archive(
    reader: impl std::io::Read,
    config: &exarch_core::SecurityConfig,
) -> ArchiveBytes {
    ArchiveBytes::new("archive.zip", reader, config)
}

/// A 7z archive, extracted by path as `archive.7z`.
pub fn sevenz_archive(
    reader: impl std::io::Read,
    config: &exarch_core::SecurityConfig,
) -> ArchiveBytes {
    ArchiveBytes::new("archive.7z", reader, config)
}
