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
use std::num::NonZeroU64;

use crate::Result;
use crate::Validated;
use crate::config::SecurityConfig;
use crate::creation::CompressionLevel;
use crate::formats::tar_metadata_limit::CompressedMembersExceeded;
use crate::formats::tar_metadata_limit::DecoderMemoryExceeded;
use crate::formats::zstd_window::ZstdWindowLog;

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

/// Bytes of decoded output that each earn a gzip or bzip2 stream one more
/// member beyond the base allowance.
///
/// Writers that flush per record (bgzf, at most 64 KiB per block) stay under
/// the allowance at any output size when they average this much per member;
/// an empty member adds nothing to the output, so a flood of them stays near
/// the base.
const MEMBER_OUTPUT_BYTES: u64 = 16 * 1024;

/// How many gzip or bzip2 members a stream may hold: a configured base, plus
/// one per [`MEMBER_OUTPUT_BYTES`] of output decoded so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MemberAllowance(NonZeroU64);

impl MemberAllowance {
    pub(crate) const UNBOUNDED: Self = Self(NonZeroU64::MAX);

    pub(crate) fn of(config: &SecurityConfig<Validated>) -> Self {
        Self::of_base(config.compressed_member_allowance)
    }

    const fn of_base(base: NonZeroU64) -> Self {
        Self(base)
    }

    /// The most members a stream may have started once it produced `produced`
    /// bytes.
    fn at(self, produced: u64) -> u64 {
        self.0.get().saturating_add(produced / MEMBER_OUTPUT_BYTES)
    }
}

/// What the decoders of one operation may use, taken once from the config the
/// operation runs under so every codec reads the same limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DecoderLimits {
    /// Memory the xz decoder may use, in bytes.
    pub(crate) memory: u64,
    /// Largest window a zstd frame may declare.
    pub(crate) zstd_window: ZstdWindowLog,
    /// How many gzip or bzip2 members a stream may hold.
    pub(crate) members: MemberAllowance,
}

impl DecoderLimits {
    /// No limit beyond what the formats themselves impose.
    pub(crate) const UNBOUNDED: Self = Self {
        memory: u64::MAX,
        zstd_window: ZstdWindowLog::LIBZSTD_DEFAULT,
        members: MemberAllowance::UNBOUNDED,
    };

    pub(crate) fn of(config: &SecurityConfig<Validated>) -> Self {
        Self {
            memory: config.max_decoder_memory,
            zstd_window: ZstdWindowLog::of(config),
            members: MemberAllowance::of(config),
        }
    }

    /// Whether a stream decoded under `other` would also decode under `self`.
    pub(crate) const fn covers(self, other: Self) -> bool {
        self.memory >= other.memory
            && self.zstd_window.get() >= other.zstd_window.get()
            && self.members.0.get() >= other.members.0.get()
    }

    #[cfg(test)]
    pub(crate) const fn for_tests() -> Self {
        Self {
            memory: 256 * 1024 * 1024,
            zstd_window: ZstdWindowLog::LIBZSTD_DEFAULT,
            members: MemberAllowance::of_base(crate::config::DEFAULT_MEMBER_ALLOWANCE),
        }
    }
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
    /// its own. `limits.memory` bounds the xz decoder and `limits.zstd_window`
    /// the zstd window; the other codecs are bounded by their format.
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
        limits: DecoderLimits,
    ) -> Result<Box<dyn Read + Send + 'r>>
    where
        R: BufRead + Send + 'r,
    {
        Ok(match self {
            Self::Gzip => Box::new(MultiMember::<_, flate2::bufread::GzDecoder<R>>::new(
                input,
                limits.members,
            )),
            Self::Bzip2 => Box::new(MultiMember::<_, bzip2::bufread::BzDecoder<R>>::new(
                input,
                limits.members,
            )),
            Self::Xz => {
                let stream = liblzma::stream::Stream::new_stream_decoder(
                    limits.memory,
                    liblzma::stream::CONCATENATED,
                )
                .map_err(io::Error::from)?;
                Box::new(XzLimited {
                    inner: liblzma::bufread::XzDecoder::new_stream(input, stream),
                    max: limits.memory,
                })
            }
            Self::Zstd => {
                let mut decoder = zstd::Decoder::with_buffer(input)?;
                decoder.window_log_max(limits.zstd_window.get())?;
                Box::new(ZstdLimited {
                    inner: decoder,
                    max: limits.memory,
                })
            }
        })
    }

    /// Wraps `out` in this codec's encoder.
    ///
    /// Write-side mirror of [`decoder`](Self::decoder) and the only
    /// codec-to-encoder mapping used for creating TAR streams. `level` is the
    /// user-facing 1-9 scale.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the encoder cannot be initialised.
    pub(crate) fn encoder<W: Write>(
        self,
        out: W,
        level: CompressionLevel,
    ) -> Result<TarEncoder<W>> {
        Ok(match self {
            Self::Gzip => TarEncoder::Gzip(flate2::write::GzEncoder::new(out, level.to_flate2())),
            Self::Bzip2 => TarEncoder::Bzip2(bzip2::write::BzEncoder::new(out, level.to_bzip2())),
            Self::Xz => TarEncoder::Xz(liblzma::write::XzEncoder::new(out, level.to_xz())),
            Self::Zstd => {
                let mut enc = zstd::Encoder::new(out, level.to_zstd())?;
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
    Failed(Replay),
}

/// A failure kept so every later read repeats it with the same type.
enum Replay {
    MemberCap(CompressedMembersExceeded),
    TrailingData,
    Other(io::ErrorKind, String),
}

impl Replay {
    fn of(error: &io::Error) -> Self {
        if let Some(cap) = error
            .get_ref()
            .and_then(|e| e.downcast_ref::<CompressedMembersExceeded>())
        {
            return Self::MemberCap(*cap);
        }
        if is_trailing_data(error) {
            return Self::TrailingData;
        }
        Self::Other(error.kind(), error.to_string())
    }

    fn error(&self) -> io::Error {
        match self {
            Self::MemberCap(cap) => io::Error::other(*cap),
            Self::TrailingData => io::Error::new(io::ErrorKind::InvalidData, TrailingData),
            Self::Other(kind, message) => io::Error::new(*kind, message.clone()),
        }
    }
}

/// Marker error for bytes after the last compressed member that are neither
/// another member nor zero padding.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TrailingData;

impl std::fmt::Display for TrailingData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("trailing data after the last compressed member")
    }
}

impl std::error::Error for TrailingData {}

/// Whether `error` is the [`TrailingData`] marker.
pub(crate) fn is_trailing_data(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(<dyn std::error::Error + Send + Sync>::is::<TrailingData>)
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
///
/// Member `n` may start only while `n` is within the allowance for the bytes
/// decoded so far, so a stream cannot be made of members that each cost a
/// decoder setup but earn no output.
struct MultiMember<R, D> {
    state: MemberState<R, D>,
    allowance: MemberAllowance,
    members: u64,
    produced: u64,
}

impl<R, D> MultiMember<R, D> {
    const fn new(input: R, allowance: MemberAllowance) -> Self {
        Self {
            state: MemberState::Between(input),
            allowance,
            members: 0,
            produced: 0,
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
            return Err(io::Error::new(io::ErrorKind::InvalidData, TrailingData));
        }
        let n = buf.len();
        input.consume(n);
    }
}

impl<R: BufRead, D: Member<R>> MultiMember<R, D> {
    fn step(&mut self, out: &mut [u8]) -> io::Result<Step> {
        match &mut self.state {
            MemberState::Done => Ok(Step::Eof),
            MemberState::Failed(replay) => Err(replay.error()),
            MemberState::Between(input) => {
                let first = input.fill_buf()?.first().copied();
                match first {
                    None | Some(0) if self.members == 0 => Err(io::Error::new(
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
                        let members = self.members.saturating_add(1);
                        let allowance = self.allowance.at(self.produced);
                        if members > allowance {
                            return Err(io::Error::other(CompressedMembersExceeded {
                                members,
                                allowance,
                            }));
                        }
                        self.members = members;
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
                    self.produced = self
                        .produced
                        .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
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
                        self.state = MemberState::Failed(Replay::of(&e));
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
    inner: liblzma::bufread::XzDecoder<R>,
    max: u64,
}

impl<R: BufRead> Read for XzLimited<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).map_err(|e| {
            let mem_limit = e
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<liblzma::stream::Error>())
                .is_some_and(|err| matches!(err, liblzma::stream::Error::MemLimit));
            if mem_limit {
                io::Error::other(DecoderMemoryExceeded { max: self.max })
            } else {
                e
            }
        })
    }
}

/// zstd decoder that reports a frame whose window exceeds the limit as a typed
/// [`DecoderMemoryExceeded`] so `budget_violation` can classify it.
struct ZstdLimited<'a, R: BufRead> {
    inner: zstd::Decoder<'a, R>,
    max: u64,
}

impl<R: BufRead> Read for ZstdLimited<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).map_err(|e| {
            if is_window_too_large(&e) {
                io::Error::other(DecoderMemoryExceeded { max: self.max })
            } else {
                e
            }
        })
    }
}

/// Whether `e` is libzstd's `frameParameter_windowTooLarge` error.
///
/// The `zstd` crate flattens libzstd error codes into a message, so the
/// message of that one code is the only handle on it.
fn is_window_too_large(e: &io::Error) -> bool {
    let code = zstd::zstd_safe::zstd_sys::ZSTD_ErrorCode::ZSTD_error_frameParameter_windowTooLarge
        as usize;
    let expected = zstd::zstd_safe::get_error_name(code.wrapping_neg());
    e.get_ref()
        .is_some_and(|inner| inner.to_string() == expected)
}

/// A compressing writer for one of the [`CompressionCodec`]s.
///
/// Must be closed with [`finish`](Self::finish): dropping it can lose the
/// trailing frame and any flush error.
pub(crate) enum TarEncoder<W: Write> {
    Gzip(flate2::write::GzEncoder<W>),
    Bzip2(bzip2::write::BzEncoder<W>),
    Xz(liblzma::write::XzEncoder<W>),
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
    use crate::creation::CompressionLevel;

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
                let mut enc = liblzma::write::XzEncoder::new(Vec::new(), 1);
                enc.write_all(data).unwrap();
                enc.finish().unwrap()
            }
            CompressionCodec::Zstd => zstd::encode_all(data, 1).unwrap(),
        }
    }

    const TEST_MEM: DecoderLimits = DecoderLimits::for_tests();

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
            for level in [
                CompressionLevel::default(),
                CompressionLevel::try_from(1u8).unwrap(),
                CompressionLevel::try_from(9u8).unwrap(),
            ] {
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

    fn decode_all(
        codec: CompressionCodec,
        bytes: Vec<u8>,
        mem: DecoderLimits,
    ) -> io::Result<Vec<u8>> {
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
            let mut enc = liblzma::write::XzEncoder::new(Vec::new(), preset);
            enc.write_all(data).unwrap();
            enc.finish().unwrap()
        };
        let mut encoded = encode_at(0, b"first");
        encoded.extend_from_slice(&encode_at(9, b"second"));
        let err = decode_all(
            CompressionCodec::Xz,
            encoded,
            DecoderLimits {
                memory: 16 * 1024 * 1024,
                ..TEST_MEM
            },
        )
        .unwrap_err();
        assert!(
            err.get_ref()
                .is_some_and(<dyn std::error::Error + Send + Sync>::is::<DecoderMemoryExceeded>)
        );
    }

    fn zstd_with_window_log(log: u32) -> Vec<u8> {
        let mut enc = zstd::Encoder::new(Vec::new(), 1).unwrap();
        enc.include_contentsize(false).unwrap();
        enc.set_parameter(zstd::zstd_safe::CParameter::WindowLog(log))
            .unwrap();
        enc.write_all(b"payload").unwrap();
        enc.finish().unwrap()
    }

    fn zstd_limits(memory: u64) -> DecoderLimits {
        DecoderLimits {
            memory,
            zstd_window: ZstdWindowLog::for_memory(memory),
            ..TEST_MEM
        }
    }

    #[test]
    fn test_zstd_window_above_the_limit_is_a_typed_memory_refusal() {
        let encoded = zstd_with_window_log(20);
        for (memory, accepted) in [(1 << 20, true), ((1 << 20) - 1, false)] {
            let result = decode_all(CompressionCodec::Zstd, encoded.clone(), zstd_limits(memory));
            if accepted {
                assert_eq!(result.unwrap(), b"payload");
            } else {
                let err = result.unwrap_err();
                let exceeded = err
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<DecoderMemoryExceeded>())
                    .unwrap();
                assert_eq!(exceeded.max, memory);
            }
        }
    }

    #[test]
    fn test_zstd_corruption_is_not_reported_as_a_memory_refusal() {
        let mut encoded = zstd_with_window_log(16);
        let last = encoded.len() - 1;
        encoded.truncate(last / 2);
        let err = decode_all(CompressionCodec::Zstd, encoded, TEST_MEM).unwrap_err();
        assert!(
            err.get_ref()
                .is_none_or(|inner| !inner.is::<DecoderMemoryExceeded>())
        );
    }

    fn gzip_members(count: usize) -> Vec<u8> {
        (0..count)
            .flat_map(|_| encode(CompressionCodec::Gzip, b""))
            .collect()
    }

    fn limits_with_base(base: u64) -> DecoderLimits {
        DecoderLimits {
            members: MemberAllowance::of_base(NonZeroU64::new(base).unwrap()),
            ..TEST_MEM
        }
    }

    fn member_cap(err: &io::Error) -> Option<CompressedMembersExceeded> {
        err.get_ref()
            .and_then(|inner| inner.downcast_ref::<CompressedMembersExceeded>())
            .copied()
    }

    #[test]
    fn test_empty_members_stop_at_the_base_allowance() {
        for codec in [CompressionCodec::Gzip, CompressionCodec::Bzip2] {
            let members =
                |n: usize| -> Vec<u8> { (0..n).flat_map(|_| encode(codec, b"")).collect() };
            assert!(decode_all(codec, members(5), limits_with_base(5)).is_ok());
            let err = decode_all(codec, members(6), limits_with_base(5)).unwrap_err();
            assert_eq!(
                member_cap(&err),
                Some(CompressedMembersExceeded {
                    members: 6,
                    allowance: 5
                }),
                "{}",
                codec.name()
            );
        }
    }

    #[test]
    fn test_member_failure_keeps_its_type_when_read_again() {
        let mut decoder = CompressionCodec::Gzip
            .decoder(std::io::Cursor::new(gzip_members(4)), limits_with_base(2))
            .unwrap();
        let mut buf = [0u8; 16];
        let first = decoder.read(&mut buf).unwrap_err();
        let second = decoder.read(&mut buf).unwrap_err();
        assert_eq!(member_cap(&first), member_cap(&second));
        assert!(member_cap(&second).is_some());
    }

    #[test]
    fn test_trailing_data_failure_keeps_its_type_when_read_again() {
        let mut encoded = encode(CompressionCodec::Gzip, b"x");
        encoded.extend_from_slice(b"\0\0\0garbage");
        let mut decoder = CompressionCodec::Gzip
            .decoder(std::io::Cursor::new(encoded), TEST_MEM)
            .unwrap();
        let mut sink = Vec::new();
        let first = decoder.read_to_end(&mut sink).unwrap_err();
        let second = decoder.read_to_end(&mut sink).unwrap_err();
        for err in [first, second] {
            assert!(is_trailing_data(&err));
        }
    }

    #[test]
    fn test_the_allowance_gains_one_member_per_16_kib_exactly() {
        let base = MemberAllowance::of_base(NonZeroU64::new(5).unwrap());
        assert_eq!(base.at(16 * 1024 - 1), 5);
        assert_eq!(base.at(16 * 1024), 6);
        assert_eq!(base.at(32 * 1024 - 1), 6);
        assert_eq!(base.at(32 * 1024), 7);
    }

    #[test]
    fn test_a_legacy_zstd_frame_is_refused_by_the_decoder() {
        for magic in [0xFD2F_B51Eu32, 0xFD2F_B522, 0xFD2F_B527] {
            let mut bytes = magic.to_le_bytes().to_vec();
            bytes.extend_from_slice(&[0u8; 32]);
            let code =
                zstd::zstd_safe::zstd_sys::ZSTD_ErrorCode::ZSTD_error_prefix_unknown as usize;
            let expected = zstd::zstd_safe::get_error_name(code.wrapping_neg());
            let err = decode_all(CompressionCodec::Zstd, bytes, TEST_MEM).unwrap_err();
            assert_eq!(err.to_string(), expected, "{magic:#x}");
        }
    }

    #[test]
    fn test_the_allowance_follows_the_configured_base() {
        let base = NonZeroU64::new(7).unwrap();
        let config = SecurityConfig::default()
            .with_compressed_member_allowance(base)
            .validate()
            .unwrap();
        assert_eq!(config.compressed_member_allowance, base);
        assert_eq!(MemberAllowance::of(&config), MemberAllowance::of_base(base));
        assert_eq!(DecoderLimits::of(&config).members.at(0), 7);
        assert_eq!(
            DecoderLimits::of(&SecurityConfig::default().validate().unwrap())
                .members
                .at(0),
            10_000
        );
    }

    #[test]
    fn test_the_allowance_grows_with_output_and_never_overflows() {
        let base = MemberAllowance::of_base(NonZeroU64::new(3).unwrap());
        assert_eq!(base.at(0), 3);
        assert_eq!(base.at(MEMBER_OUTPUT_BYTES - 1), 3);
        assert_eq!(base.at(MEMBER_OUTPUT_BYTES), 4);
        assert_eq!(base.at(10 * MEMBER_OUTPUT_BYTES), 13);
        assert_eq!(MemberAllowance::UNBOUNDED.at(u64::MAX), u64::MAX);
        let huge = limits_with_base(u64::MAX);
        assert!(decode_all(CompressionCodec::Gzip, gzip_members(50), huge).is_ok());
    }

    #[test]
    fn test_limits_cover_componentwise() {
        let low = zstd_limits(1 << 20);
        let high = zstd_limits(1 << 24);
        assert!(high.covers(low) && high.covers(high));
        assert!(!low.covers(high));
        let mixed = DecoderLimits {
            memory: high.memory,
            zstd_window: low.zstd_window,
            ..high
        };
        assert!(!mixed.covers(high) && high.covers(mixed));
        assert!(!limits_with_base(5).covers(limits_with_base(6)));
        assert!(limits_with_base(6).covers(limits_with_base(5)));
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
