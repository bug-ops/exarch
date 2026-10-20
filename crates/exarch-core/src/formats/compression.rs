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
            Self::Gzip => Box::new(flate2::bufread::GzDecoder::new(input)),
            Self::Bzip2 => Box::new(bzip2::bufread::BzDecoder::new(input)),
            Self::Xz => {
                let stream = xz2::stream::Stream::new_stream_decoder(max_decoder_memory, 0)
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

    #[test]
    fn test_decoder_ignores_bytes_after_a_single_stream() {
        let data = b"payload".repeat(100);
        for codec in [CompressionCodec::Gzip, CompressionCodec::Bzip2] {
            let mut encoded = encode(codec, &data);
            encoded.extend_from_slice(b"TRAILING-BYTES");
            let mut out = Vec::new();
            codec
                .decoder(std::io::Cursor::new(encoded), TEST_MEM)
                .unwrap()
                .read_to_end(&mut out)
                .unwrap();
            assert_eq!(out, data, "{}", codec.name());
        }
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
