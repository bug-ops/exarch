//! Compression codec support for archive formats.
//!
//! This module provides unified handling of compression codecs used with
//! TAR archives. The same compression codecs can be used for both reading
//! (decompression) and writing (compression).
//!
//! # Supported Codecs
//!
//! - **Gzip** (.tar.gz, .tgz): Fast compression with good compatibility
//! - **Bzip2** (.tar.bz2, .tbz2): Better compression ratio, slower
//! - **Xz** (.tar.xz, .txz): Best compression ratio, slowest
//! - **Zstd** (.tar.zst, .tzst): Modern codec with good speed/ratio balance

use std::io;
use std::io::BufRead;
use std::io::Read;
use std::io::Write;

use crate::Result;
use crate::creation::compression::compression_level_to_bzip2;
use crate::creation::compression::compression_level_to_flate2;
use crate::creation::compression::compression_level_to_xz;
use crate::creation::compression::compression_level_to_zstd;
use crate::formats::tar_metadata_limit::DecoderMemoryExceeded;

/// Compression codec for archive files.
///
/// Represents the compression algorithm used for compressed archives.
/// Each codec has different trade-offs between compression ratio,
/// speed, and compatibility.
///
/// # Performance Characteristics
///
/// | Codec | Compression | Decompression | Ratio | Compatibility |
/// |-------|-------------|---------------|-------|---------------|
/// | Gzip  | Fast        | Fast          | Good  | Excellent     |
/// | Bzip2 | Slow        | Medium        | Better| Good          |
/// | Xz    | Very Slow   | Medium        | Best  | Good          |
/// | Zstd  | Fast        | Very Fast     | Good  | Modern        |
///
/// # Examples
///
/// ```
/// use exarch_core::formats::compression::CompressionCodec;
///
/// // Choose codec based on requirements
/// let fast_codec = CompressionCodec::Gzip; // Fast compression
/// let best_codec = CompressionCodec::Xz; // Best compression ratio
/// let modern_codec = CompressionCodec::Zstd; // Modern balanced approach
/// ```
///
/// `#[non_exhaustive]` so support for a new compression codec is not a
/// breaking change for downstream matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CompressionCodec {
    /// Gzip compression (deflate algorithm).
    ///
    /// Fast compression and decompression with widespread support.
    /// Good default choice for most use cases.
    Gzip,

    /// Bzip2 compression (Burrows-Wheeler algorithm).
    ///
    /// Better compression ratio than gzip but slower.
    /// Good for archives that will be distributed.
    Bzip2,

    /// Xz compression (LZMA2 algorithm).
    ///
    /// Best compression ratio but slowest.
    /// Good for long-term storage or bandwidth-constrained transfers.
    Xz,

    /// Zstd compression (Zstandard algorithm).
    ///
    /// Modern codec with excellent speed and good compression ratio.
    /// Good for archives that need fast decompression.
    Zstd,
}

impl CompressionCodec {
    /// Returns the typical file extension for this codec when used with TAR.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::formats::compression::CompressionCodec;
    ///
    /// assert_eq!(CompressionCodec::Gzip.extension(), "tar.gz");
    /// assert_eq!(CompressionCodec::Bzip2.extension(), "tar.bz2");
    /// assert_eq!(CompressionCodec::Xz.extension(), "tar.xz");
    /// assert_eq!(CompressionCodec::Zstd.extension(), "tar.zst");
    /// ```
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Gzip => "tar.gz",
            Self::Bzip2 => "tar.bz2",
            Self::Xz => "tar.xz",
            Self::Zstd => "tar.zst",
        }
    }

    /// Wraps `input` in this codec's decoder.
    ///
    /// This is the only codec-to-decoder mapping used for reading TAR
    /// streams. The `bufread` decoders take the caller's buffer as-is, so
    /// the caller decides the buffering once instead of each decoder adding
    /// its own. `max_decoder_memory` bounds the xz decoder only; the other
    /// codecs are bounded by their format.
    ///
    /// Every gzip member, bzip2 stream and xz stream is decoded, and at least
    /// one is required. After the last one an all-zero tail is accepted (xz:
    /// a multiple of four bytes, as the format requires); any other trailing
    /// bytes are an error.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the decoder cannot be initialised.
    pub(crate) fn decoder<'r, R>(
        self,
        input: R,
        max_decoder_memory: u64,
    ) -> Result<Box<dyn Read + Send + 'r>>
    where
        R: BufRead + Send + 'r,
    {
        Ok(match self {
            Self::Gzip => Box::new(MultiMember::<_, flate2::bufread::GzDecoder<R>>::new(input)),
            Self::Bzip2 => Box::new(MultiMember::<_, bzip2::bufread::BzDecoder<R>>::new(input)),
            Self::Xz => {
                let stream = xz2::stream::Stream::new_stream_decoder(
                    max_decoder_memory,
                    xz2::stream::CONCATENATED,
                )
                .map_err(io::Error::from)?;
                Box::new(XzLimited {
                    inner: xz2::bufread::XzDecoder::new_stream(input, stream),
                    max: max_decoder_memory,
                })
            }
            Self::Zstd => Box::new(zstd::Decoder::with_buffer(input)?),
        })
    }

    /// Wraps `out` in this codec's encoder.
    ///
    /// Write-side mirror of [`decoder`](Self::decoder) and the only
    /// codec-to-encoder mapping used for creating TAR streams. `level` is the
    /// user-facing 1-9 scale (`None` selects the codec default).
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the encoder cannot be initialised.
    pub(crate) fn encoder<W: Write>(self, out: W, level: Option<u8>) -> Result<TarEncoder<W>> {
        Ok(match self {
            Self::Gzip => TarEncoder::Gzip(flate2::write::GzEncoder::new(
                out,
                compression_level_to_flate2(level),
            )),
            Self::Bzip2 => TarEncoder::Bzip2(bzip2::write::BzEncoder::new(
                out,
                compression_level_to_bzip2(level),
            )),
            Self::Xz => TarEncoder::Xz(xz2::write::XzEncoder::new(
                out,
                compression_level_to_xz(level),
            )),
            Self::Zstd => {
                let mut enc = zstd::Encoder::new(out, compression_level_to_zstd(level))?;
                enc.include_checksum(true)?;
                TarEncoder::Zstd(enc)
            }
        })
    }

    /// Returns a human-readable name for this codec.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::formats::compression::CompressionCodec;
    ///
    /// assert_eq!(CompressionCodec::Gzip.name(), "gzip");
    /// assert_eq!(CompressionCodec::Bzip2.name(), "bzip2");
    /// ```
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
        }
    }
}

/// A decoder for exactly one member of a concatenated stream.
trait Member<R>: Read {
    fn start(input: R) -> Self;
    fn finish(self) -> R;
}

impl<R: BufRead> Member<R> for flate2::bufread::GzDecoder<R> {
    fn start(input: R) -> Self {
        Self::new(input)
    }

    fn finish(self) -> R {
        self.into_inner()
    }
}

impl<R: BufRead> Member<R> for bzip2::bufread::BzDecoder<R> {
    fn start(input: R) -> Self {
        Self::new(input)
    }

    fn finish(self) -> R {
        self.into_inner()
    }
}

enum MemberState<R, D> {
    Between(R),
    Active(D),
    Done,
    /// A non-transient error; replayed on every later read so a retry can
    /// never look like a clean end of stream.
    Failed(io::ErrorKind, String),
}

enum Step {
    Data(usize),
    Eof,
    Continue,
}

/// Decodes every member of a gzip or bzip2 stream, as `gzip -dc` and
/// `bzip2 -dc` do, so entries in later members are never silently dropped.
///
/// At least one member is required: an empty or all-zero input is not a
/// compressed stream. After the last member an all-zero tail (tape padding) is
/// accepted; any other trailing bytes are an error. xz is stricter about the
/// padding: the format only allows multiples of four zero bytes.
struct MultiMember<R, D> {
    state: MemberState<R, D>,
    seen_member: bool,
}

impl<R, D> MultiMember<R, D> {
    const fn new(input: R) -> Self {
        Self {
            state: MemberState::Between(input),
            seen_member: false,
        }
    }
}

fn consume_zero_tail<R: BufRead>(input: &mut R) -> io::Result<()> {
    loop {
        let buf = input.fill_buf()?;
        if buf.is_empty() {
            return Ok(());
        }
        if buf.iter().any(|&b| b != 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing data after the last compressed member",
            ));
        }
        let n = buf.len();
        input.consume(n);
    }
}

impl<R: BufRead, D: Member<R>> MultiMember<R, D> {
    fn step(&mut self, out: &mut [u8]) -> io::Result<Step> {
        match &mut self.state {
            MemberState::Done => Ok(Step::Eof),
            MemberState::Failed(kind, message) => Err(io::Error::new(*kind, message.clone())),
            MemberState::Between(input) => {
                let first = input.fill_buf()?.first().copied();
                match first {
                    None | Some(0) if !self.seen_member => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "no compressed member found",
                    )),
                    None => {
                        self.state = MemberState::Done;
                        Ok(Step::Eof)
                    }
                    Some(0) => {
                        consume_zero_tail(input)?;
                        self.state = MemberState::Done;
                        Ok(Step::Eof)
                    }
                    Some(_) => {
                        self.seen_member = true;
                        if let MemberState::Between(input) =
                            std::mem::replace(&mut self.state, MemberState::Done)
                        {
                            self.state = MemberState::Active(D::start(input));
                        }
                        Ok(Step::Continue)
                    }
                }
            }
            MemberState::Active(decoder) => {
                let n = decoder.read(out)?;
                if n > 0 {
                    return Ok(Step::Data(n));
                }
                if let MemberState::Active(decoder) =
                    std::mem::replace(&mut self.state, MemberState::Done)
                {
                    self.state = MemberState::Between(decoder.finish());
                }
                Ok(Step::Continue)
            }
        }
    }
}

impl<R: BufRead, D: Member<R>> Read for MultiMember<R, D> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            match self.step(out) {
                Ok(Step::Data(n)) => return Ok(n),
                Ok(Step::Eof) => return Ok(0),
                Ok(Step::Continue) => {}
                Err(e) => {
                    // Interrupted is transient: the state is intact and a retry
                    // resumes.
                    if e.kind() != io::ErrorKind::Interrupted
                        && !matches!(self.state, MemberState::Failed(..))
                    {
                        self.state = MemberState::Failed(e.kind(), e.to_string());
                    }
                    return Err(e);
                }
            }
        }
    }
}

/// xz decoder that reports liblzma's memory-limit error as a typed
/// [`DecoderMemoryExceeded`] so `budget_violation` can classify it.
struct XzLimited<R> {
    inner: xz2::bufread::XzDecoder<R>,
    max: u64,
}

impl<R: BufRead> Read for XzLimited<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).map_err(|e| {
            let mem_limit = e
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<xz2::stream::Error>())
                .is_some_and(|err| matches!(err, xz2::stream::Error::MemLimit));
            if mem_limit {
                io::Error::other(DecoderMemoryExceeded { max: self.max })
            } else {
                e
            }
        })
    }
}

/// A compressing writer for one of the [`CompressionCodec`]s.
///
/// Must be closed with [`finish`](Self::finish): dropping it can lose the
/// trailing frame and any flush error.
pub(crate) enum TarEncoder<W: Write> {
    Gzip(flate2::write::GzEncoder<W>),
    Bzip2(bzip2::write::BzEncoder<W>),
    Xz(xz2::write::XzEncoder<W>),
    Zstd(zstd::Encoder<'static, W>),
}

impl<W: Write> TarEncoder<W> {
    /// Writes the trailer, flushes, and returns the inner writer.
    pub(crate) fn finish(self) -> io::Result<W> {
        match self {
            Self::Gzip(e) => e.finish(),
            Self::Bzip2(e) => e.finish(),
            Self::Xz(e) => e.finish(),
            Self::Zstd(e) => e.finish(),
        }
    }
}

impl<W: Write> Write for TarEncoder<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Gzip(e) => e.write(buf),
            Self::Bzip2(e) => e.write(buf),
            Self::Xz(e) => e.write(buf),
            Self::Zstd(e) => e.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Gzip(e) => e.flush(),
            Self::Bzip2(e) => e.flush(),
            Self::Xz(e) => e.flush(),
            Self::Zstd(e) => e.flush(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_extension() {
        assert_eq!(CompressionCodec::Gzip.extension(), "tar.gz");
        assert_eq!(CompressionCodec::Bzip2.extension(), "tar.bz2");
        assert_eq!(CompressionCodec::Xz.extension(), "tar.xz");
        assert_eq!(CompressionCodec::Zstd.extension(), "tar.zst");
    }

    #[test]
    fn test_codec_name() {
        assert_eq!(CompressionCodec::Gzip.name(), "gzip");
        assert_eq!(CompressionCodec::Bzip2.name(), "bzip2");
        assert_eq!(CompressionCodec::Xz.name(), "xz");
        assert_eq!(CompressionCodec::Zstd.name(), "zstd");
    }

    fn encode(codec: CompressionCodec, data: &[u8]) -> Vec<u8> {
        use std::io::Write;

        match codec {
            CompressionCodec::Gzip => {
                let mut enc =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                enc.write_all(data).unwrap();
                enc.finish().unwrap()
            }
            CompressionCodec::Bzip2 => {
                let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
                enc.write_all(data).unwrap();
                enc.finish().unwrap()
            }
            CompressionCodec::Xz => {
                let mut enc = xz2::write::XzEncoder::new(Vec::new(), 1);
                enc.write_all(data).unwrap();
                enc.finish().unwrap()
            }
            CompressionCodec::Zstd => zstd::encode_all(data, 1).unwrap(),
        }
    }

    const TEST_MEM: u64 = 256 * 1024 * 1024;

    const ALL_CODECS: [CompressionCodec; 4] = [
        CompressionCodec::Gzip,
        CompressionCodec::Bzip2,
        CompressionCodec::Xz,
        CompressionCodec::Zstd,
    ];

    #[test]
    fn test_decoder_round_trips_every_codec() {
        let data = b"hello decoder ".repeat(1000);
        for codec in ALL_CODECS {
            let mut out = Vec::new();
            codec
                .decoder(std::io::Cursor::new(encode(codec, &data)), TEST_MEM)
                .unwrap()
                .read_to_end(&mut out)
                .unwrap();
            assert_eq!(out, data, "{}", codec.name());
        }
    }

    #[test]
    fn test_encoder_round_trips_every_codec_and_level() {
        let data = b"hello encoder ".repeat(1000);
        for codec in ALL_CODECS {
            for level in [None, Some(1), Some(9)] {
                let mut enc = codec.encoder(Vec::new(), level).unwrap();
                enc.write_all(&data).unwrap();
                let encoded = enc.finish().unwrap();
                let mut out = Vec::new();
                codec
                    .decoder(std::io::Cursor::new(encoded), TEST_MEM)
                    .unwrap()
                    .read_to_end(&mut out)
                    .unwrap();
                assert_eq!(out, data, "{} {level:?}", codec.name());
            }
        }
    }

    fn decode_all(codec: CompressionCodec, bytes: Vec<u8>, mem: u64) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        codec
            .decoder(std::io::Cursor::new(bytes), mem)
            .unwrap()
            .read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn test_decoder_reads_every_concatenated_member() {
        for codec in ALL_CODECS {
            let mut encoded = encode(codec, b"first-");
            encoded.extend_from_slice(&encode(codec, b"second-"));
            encoded.extend_from_slice(&encode(codec, b"third"));
            assert_eq!(
                decode_all(codec, encoded, TEST_MEM).unwrap(),
                b"first-second-third",
                "{}",
                codec.name()
            );
        }
    }

    #[test]
    fn test_decoder_accepts_zero_padding_after_last_member() {
        for codec in [
            CompressionCodec::Gzip,
            CompressionCodec::Bzip2,
            CompressionCodec::Xz,
        ] {
            let mut encoded = encode(codec, b"a");
            encoded.extend_from_slice(&encode(codec, b"b"));
            encoded.extend_from_slice(&[0u8; 512]);
            assert_eq!(
                decode_all(codec, encoded, TEST_MEM).unwrap(),
                b"ab",
                "{}",
                codec.name()
            );
        }
    }

    struct FailsOnce<R> {
        inner: R,
        error: Option<io::ErrorKind>,
    }

    impl<R: Read> Read for FailsOnce<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.error.take() {
                Some(kind) => Err(io::Error::from(kind)),
                None => self.inner.read(buf),
            }
        }
    }

    impl<R: BufRead> BufRead for FailsOnce<R> {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            match self.error.take() {
                Some(kind) => Err(io::Error::from(kind)),
                None => self.inner.fill_buf(),
            }
        }

        fn consume(&mut self, amt: usize) {
            self.inner.consume(amt);
        }
    }

    #[test]
    fn test_read_error_never_turns_into_a_clean_eof() {
        let mut encoded = encode(CompressionCodec::Gzip, b"first-");
        encoded.extend_from_slice(&encode(CompressionCodec::Gzip, b"second"));
        for kind in [io::ErrorKind::Interrupted, io::ErrorKind::BrokenPipe] {
            let input = FailsOnce {
                inner: std::io::Cursor::new(encoded.clone()),
                error: Some(kind),
            };
            let mut decoder = CompressionCodec::Gzip.decoder(input, TEST_MEM).unwrap();
            let mut out = Vec::new();
            let mut buf = [0u8; 64];
            let mut errors = 0;
            loop {
                match decoder.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => out.extend_from_slice(&buf[..n]),
                    Err(e) => {
                        assert_eq!(e.kind(), kind);
                        errors += 1;
                        if kind != io::ErrorKind::Interrupted {
                            assert_eq!(decoder.read(&mut buf).unwrap_err().kind(), kind);
                            return;
                        }
                    }
                }
            }
            assert_eq!(errors, 1);
            assert_eq!(out, b"first-second");
        }
    }

    #[test]
    fn test_decoder_rejects_input_without_a_first_member() {
        for codec in [
            CompressionCodec::Gzip,
            CompressionCodec::Bzip2,
            CompressionCodec::Xz,
        ] {
            for input in [Vec::new(), vec![0u8; 64]] {
                assert!(
                    decode_all(codec, input, TEST_MEM).is_err(),
                    "{}",
                    codec.name()
                );
            }
        }
    }

    #[test]
    fn test_decoder_rejects_trailing_garbage() {
        for codec in [
            CompressionCodec::Gzip,
            CompressionCodec::Bzip2,
            CompressionCodec::Xz,
        ] {
            for tail in [&b"TRAILING-BYTES"[..], &b"\0\0\0\0garbage"[..]] {
                let mut encoded = encode(codec, b"payload");
                encoded.extend_from_slice(tail);
                assert!(
                    decode_all(codec, encoded, TEST_MEM).is_err(),
                    "{} {tail:?}",
                    codec.name()
                );
            }
        }
    }

    #[test]
    fn test_xz_memlimit_applies_to_later_stream() {
        let encode_at = |preset: u32, data: &[u8]| {
            let mut enc = xz2::write::XzEncoder::new(Vec::new(), preset);
            enc.write_all(data).unwrap();
            enc.finish().unwrap()
        };
        let mut encoded = encode_at(0, b"first");
        encoded.extend_from_slice(&encode_at(9, b"second"));
        let err = decode_all(CompressionCodec::Xz, encoded, 16 * 1024 * 1024).unwrap_err();
        assert!(
            err.get_ref()
                .is_some_and(<dyn std::error::Error + Send + Sync>::is::<DecoderMemoryExceeded>)
        );
    }

    #[test]
    fn test_decoder_reads_concatenated_zstd_frames() {
        let mut encoded = encode(CompressionCodec::Zstd, b"first-");
        encoded.extend_from_slice(&encode(CompressionCodec::Zstd, b"second"));
        let mut out = Vec::new();
        CompressionCodec::Zstd
            .decoder(std::io::Cursor::new(encoded), TEST_MEM)
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"first-second");
    }

    #[test]
    fn test_codec_equality() {
        assert_eq!(CompressionCodec::Gzip, CompressionCodec::Gzip);
        assert_ne!(CompressionCodec::Gzip, CompressionCodec::Bzip2);
    }

    #[test]
    fn test_codec_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(CompressionCodec::Gzip);
        set.insert(CompressionCodec::Bzip2);
        set.insert(CompressionCodec::Gzip); // Duplicate

        assert_eq!(set.len(), 2);
        assert!(set.contains(&CompressionCodec::Gzip));
        assert!(set.contains(&CompressionCodec::Bzip2));
    }
}
