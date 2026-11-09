//! CLI argument parsing using clap.

use crate::operation::ATOMIC_FORCE_REFUSED;
use crate::operation::Flag;
use crate::operation::join_words;
use clap::Parser;
use clap::Subcommand;
use clap_complete::Shell;
use exarch_core::ArchiveError;
use exarch_core::CompressionLevel;
use exarch_core::ConfigSetting;
use exarch_core::DecodeReuse;
use exarch_core::DecompressionBudget;
use exarch_core::Limit;
use exarch_core::ParallelDecode;
use exarch_core::PathComponentName;
use exarch_core::PathRewrite;
use exarch_core::RatioLimit;
use exarch_core::RequestedLevel;
use exarch_core::ReuseLimit;
use exarch_core::SecurityConfig;
use exarch_core::SolidLimits;
use exarch_core::StripComponents;
use exarch_core::ZipConsistencyPolicy;
use exarch_core::non_zero_u64;
use exarch_core::positive_from_i128;
use std::num::NonZeroU64;
use std::num::NonZeroUsize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "exarch")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Suppress non-error output
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Output results in JSON format
    #[arg(short, long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Extract archive contents
    Extract(ExtractArgs),
    /// Create a new archive
    #[command(after_help = create_after_help())]
    Create(CreateArgs),
    /// List archive contents without extraction
    List(ListArgs),
    /// Verify archive security without extracting
    Verify(VerifyArgs),
    /// Generate shell completions
    Completion(CompletionArgs),
}

#[derive(clap::Args)]
pub struct CompletionArgs {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub shell: Shell,
}

/// Link policy flags shared by `extract`, `list` and `verify`, so the three
/// commands accept and reject the same archives.
#[derive(clap::Args, Clone, Copy)]
pub struct LinkPolicyArgs {
    /// Allow symlinks (within extraction directory)
    #[arg(long)]
    pub allow_symlinks: bool,

    /// Allow hardlinks (within extraction directory)
    #[arg(long)]
    pub allow_hardlinks: bool,
}

impl LinkPolicyArgs {
    /// Applies the link policy to `config`.
    pub fn apply(self, config: SecurityConfig) -> SecurityConfig {
        config
            .with_allow_symlinks(self.allow_symlinks)
            .with_allow_hardlinks(self.allow_hardlinks)
    }
}

/// Which entries `extract`, `list` and `verify` act on and where they land.
///
/// clap checks syntax only; [`apply`](Self::apply) hands the values to core,
/// which refuses a pattern or count it cannot use as `InvalidConfiguration`
/// naming the setting. Patterns match the entry's normalized path before any
/// component is stripped.
#[derive(clap::Args, Clone, Default)]
pub struct SelectionArgs {
    /// Act only on entries matching PATTERN (repeatable); a pattern that
    /// matches no entry is an error. Same pattern grammar as `create
    /// --exclude`: globs such as `docs`, `*.rs`, `src/**/*.rs` or
    /// `src/c/t?o.rs`; a name matches at any depth, a pattern with a `/` from
    /// the archive root, and a match also selects everything below it. Quote
    /// the pattern so the shell does not expand it.
    #[arg(long = "include", value_name = "PATTERN")]
    pub include: Vec<String>,

    /// Leave out entries matching PATTERN (repeatable); applied after
    /// `--include`, and a pattern that matches nothing is not an error.
    #[arg(long = "exclude", value_name = "PATTERN")]
    pub exclude: Vec<String>,

    /// Drop the first N path components of every entry; entries with N or
    /// fewer components are skipped, as `tar --strip-components` does
    #[arg(
        long,
        value_name = "N",
        allow_negative_numbers = true,
        conflicts_with = "flatten"
    )]
    pub strip_components: Option<i64>,

    /// Land every file directly in the destination under its final name;
    /// directories are skipped and a link entry is refused
    #[arg(long)]
    pub flatten: bool,
}

impl SelectionArgs {
    /// Applies the flags that were given to `config`.
    ///
    /// Call it after the path-depth limit is set: a strip count above that
    /// depth is refused.
    ///
    /// # Errors
    ///
    /// Returns `InvalidConfiguration` naming `entry_include`,
    /// `entry_exclude` or `strip_components` for a value core refuses.
    pub fn apply(&self, config: SecurityConfig) -> Result<SecurityConfig, ArchiveError> {
        let mut config = config;
        for pattern in &self.include {
            config = config.try_add_include(pattern)?;
        }
        for pattern in &self.exclude {
            config = config.try_add_exclude(pattern)?;
        }
        let rewrite = match (self.strip_components, self.flatten) {
            (Some(count), _) => {
                let count = positive_from_i128(ConfigSetting::StripComponents, i128::from(count))?;
                PathRewrite::Strip(StripComponents::new(count, config.max_path_depth)?)
            }
            (None, true) => PathRewrite::Flatten,
            (None, false) => PathRewrite::Keep,
        };
        Ok(config.with_path_rewrite(rewrite))
    }
}

/// `bytes` spelled as help and hints give sizes: whole MiB (`256 MiB`), or the
/// exact byte count when it is not a whole number of MiB.
fn mib_text(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    if bytes.is_multiple_of(MIB) {
        format!("{} MiB", bytes / MIB)
    } else {
        format!("{bytes} bytes")
    }
}

/// The ratio an entry is held to by default, spelled as in help and hints
/// (`100x`); read from core so the text follows a changed default.
fn default_ratio_text() -> String {
    format!("{}x", SecurityConfig::default().max_compression_ratio.get())
}

/// After-help of `create`: what a high-ratio ZIP entry costs at extraction.
fn create_after_help() -> String {
    format!(
        "A ZIP entry that compresses more than {} is refused by default extraction as a zip \
         bomb (create warns when it writes one); extract it with {} set to the ratio the \
         warning names.",
        default_ratio_text(),
        Flag::MaxCompressionRatio.long()
    )
}

/// Help of `--parallel-decode-memory`, naming the lookahead core applies by
/// default.
fn parallel_decode_help() -> String {
    format!(
        "Memory for decoding independent LZMA2 runs of a 7z block ahead on worker threads \
         (K, M, G, T suffixes), or `off` to decode on one thread (default: {}). A stock 7-Zip \
         archive has 64 MiB runs, about 100 MiB per extra concurrent run; archives with small \
         runs need far less.",
        mib_text(ParallelDecode::DEFAULT_BYTES.get())
    )
}

/// Help of `--decode-reuse`, naming the limits core applies.
fn decode_reuse_help() -> String {
    format!(
        "Where to keep what the ZIP structure check decodes, so compressed entries are not \
         decoded a second time (default: memory, up to {reuse}, never more than {total} or the \
         {decoder} decoder memory limit). It has no effect under {zip} ignore, which skips that \
         decode. With temp-file the decoded plaintext sits in an unnamed file in the temporary \
         directory until extraction ends; on a tmpfs that is memory too, and on a disk it is \
         often no faster than memory or off. Entries that do not fit are decoded again.",
        reuse = mib_text(ReuseLimit::MAX.get()),
        total = Flag::MaxTotalSize.long(),
        decoder = mib_text(SecurityConfig::default().max_decoder_memory.get()),
        zip = Flag::ZipConsistency.long(),
    )
}

/// Help of `--decompression-budget`, naming the default budget core applies.
fn decompression_budget_help() -> String {
    format!(
        "Extra bytes {} may decode beyond listing (K, M, G, T suffixes; default {}, \
         independent of {})",
        Flag::CheckIntegrity.long(),
        mib_text(DecompressionBudget::DEFAULT.get()),
        Flag::MaxTotalSize.long()
    )
}

/// Help of `--compression-level`, naming the range core accepts.
fn compression_level_help() -> String {
    format!(
        "Compression level ({}-{})",
        CompressionLevel::MIN.get(),
        CompressionLevel::MAX.get()
    )
}

/// The ratio a whole solid 7z block is held to, spelled as in help and hints
/// (`1000x`); fixed by core, not by a flag.
pub fn solid_ratio_text() -> String {
    format!("{}x", SolidLimits::DEFAULT.max_ratio.get())
}

/// The default ban list core applies, comma-separated, as help and hints
/// spell it.
pub fn default_banned_components_text() -> String {
    SecurityConfig::default()
        .banned_path_components
        .iter()
        .map(PathComponentName::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Long help of `--atomic`, naming the flags `--atomic --force` refuses.
fn atomic_long_help() -> String {
    format!(
        "Extract atomically: stage in a private directory next to the destination, rename on \
         success, remove it on failure.\n\nWith {force} the existing destination directory is \
         replaced as a whole: it is renamed aside, the staged content is renamed into its \
         place, and only then is the old destination removed, so a failure at any point leaves \
         either the old or the new content under the destination name. {atomic} {force} \
         refuses {refused}. On Unix, {force} also needs search (execute) permission on the \
         destination's parent directory; the destination itself need not be readable.",
        force = Flag::Force.long(),
        atomic = Flag::Atomic.long(),
        refused = join_words("and", &ATOMIC_FORCE_REFUSED.map(Flag::long))
    )
}

/// Long help of `--banned-component`, naming the default list core applies.
fn banned_component_help() -> String {
    let defaults = default_banned_components_text();
    format!(
        "Banned path component; can be repeated or comma-separated.\n\nWhen specified, \
         replaces the default ban list ({defaults}). Use an exactly empty value (\"\") to \
         allow all components; a value that is only commas or blanks is an error."
    )
}

/// The flags `extract`, `list` and `verify` share, as far as each declares
/// them.
///
/// A flag a command does not declare is `None`;
/// [`crate::commands::security_config`] is the one place that applies them, in
/// the order that matters (the path-depth limit before the selection).
pub trait PolicyFlags {
    /// Quota and ratio flags.
    fn limits(&self) -> LimitArgs;
    /// ZIP structure policy.
    fn zip(&self) -> ZipPolicyArgs;
    /// Entry selection and path rewrite.
    fn selection(&self) -> &SelectionArgs;
    /// Link policy, for the commands that extract or check links.
    fn links(&self) -> Option<LinkPolicyArgs> {
        None
    }
    /// Lookahead memory, for the commands that decode 7z payloads.
    fn parallel(&self) -> Option<ParallelDecodeArgs> {
        None
    }
    /// `--max-path-depth`, for the command that declares it.
    fn max_path_depth(&self) -> Option<usize> {
        None
    }
}

/// Quota and ratio flags shared by `extract`, `list` and `verify`.
///
/// clap checks syntax only into raw values: a whole number, with a K/M/G/T
/// suffix for sizes, or a number for the ratio. A value that does not parse
/// (`--max-files 2.5`, `--max-total-size abc`) is a usage error with exit
/// status 2. [`apply`](Self::apply) hands what parsed to core, which refuses
/// zero and a ratio that is zero, negative or not finite as
/// `InvalidConfiguration`, so every such refusal is one JSON-safe error with
/// exit status 1. A flag that is omitted leaves the core default in place.
#[derive(clap::Args, Clone, Copy)]
pub struct LimitArgs {
    /// Maximum number of entries
    #[arg(long, value_name = "COUNT")]
    pub max_files: Option<usize>,

    /// Maximum total size in bytes (K, M, G, T suffixes)
    #[arg(long, value_name = "SIZE", value_parser = parse_byte_size)]
    pub max_total_size: Option<u64>,

    /// Maximum size of any single entry in bytes (K, M, G, T suffixes)
    #[arg(long, value_name = "SIZE", value_parser = parse_byte_size)]
    pub max_file_size: Option<u64>,

    #[arg(
        long,
        value_name = "RATIO",
        value_parser = parse_ratio,
        help = format!(
            "Maximum compression ratio, fractions allowed (not applied to solid 7z blocks, \
             fixed {})",
            solid_ratio_text()
        )
    )]
    pub max_compression_ratio: Option<f64>,

    /// Allow solid 7z archives (multiple files compressed as one block)
    #[arg(long)]
    pub allow_solid_archives: bool,
}

impl LimitArgs {
    /// Applies the flags that were given to `config`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidConfiguration` naming the setting for a zero count or
    /// size, and for a ratio that is zero, negative or not finite.
    pub fn apply(self, config: SecurityConfig) -> Result<SecurityConfig, ArchiveError> {
        let mut config = config;
        if let Some(count) = self.max_files {
            config = config.with_max_file_count(Limit::<NonZeroUsize>::parse(
                ConfigSetting::MaxFileCount,
                count,
            )?);
        }
        if let Some(bytes) = self.max_total_size {
            config = config.with_max_total_size(Limit::<NonZeroU64>::parse(
                ConfigSetting::MaxTotalSize,
                bytes,
            )?);
        }
        if let Some(bytes) = self.max_file_size {
            config = config.with_max_file_size(Limit::<NonZeroU64>::parse(
                ConfigSetting::MaxFileSize,
                bytes,
            )?);
        }
        if let Some(ratio) = self.max_compression_ratio {
            config = config.with_max_compression_ratio(RatioLimit::parse(
                ConfigSetting::MaxCompressionRatio,
                ratio,
            )?);
        }
        if self.allow_solid_archives {
            config = config.with_allow_solid_archives(true);
        }
        Ok(config)
    }
}

/// How ZIP archives whose structure different readers interpret differently
/// are handled.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZipConsistencyArg {
    /// Reject (extract, list) or report (verify) such archives
    Enforce,
    /// Use the central directory interpretation without structural findings
    Ignore,
}

impl ZipConsistencyArg {
    /// The value as the command line spells it (`--zip-consistency <VALUE>`).
    pub fn value_name(self) -> String {
        use clap::ValueEnum as _;
        self.to_possible_value()
            .map_or_default(|value| value.get_name().to_owned())
    }
}

impl From<ZipConsistencyArg> for ZipConsistencyPolicy {
    fn from(arg: ZipConsistencyArg) -> Self {
        match arg {
            ZipConsistencyArg::Enforce => Self::Enforce,
            ZipConsistencyArg::Ignore => Self::Ignore,
        }
    }
}

/// Where `extract` keeps the output of the ZIP structure check so deflate
/// entries are decoded once.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeReuseArg {
    /// Keep nothing; compressed entries are decoded twice
    Off,
    /// Keep the decoded entries in memory
    Memory,
    /// Keep the decoded entries in an unnamed temporary file
    TempFile,
}

impl DecodeReuseArg {
    /// The mode of the flag, or the most core allows in memory when it is
    /// omitted.
    pub const fn resolve(arg: Option<Self>) -> DecodeReuse {
        match arg {
            Some(Self::Off) => DecodeReuse::Off,
            Some(Self::TempFile) => DecodeReuse::TempFile(ReuseLimit::MAX),
            Some(Self::Memory) | None => DecodeReuse::Memory(ReuseLimit::MAX),
        }
    }
}

/// ZIP structure policy flag shared by `extract`, `list` and `verify`, so all
/// three accept and reject the same archives.
#[derive(clap::Args, Clone, Copy)]
pub struct ZipPolicyArgs {
    /// How to treat ZIP archives whose local and central headers disagree,
    /// that repeat a name, overlap entries or hide records. Relax only for
    /// archives from a producer known to write benign differences.
    #[arg(long, value_enum, default_value_t = ZipConsistencyArg::Enforce)]
    pub zip_consistency: ZipConsistencyArg,
}

impl ZipPolicyArgs {
    /// Applies the ZIP structure policy to `config`.
    pub fn apply(self, config: SecurityConfig) -> SecurityConfig {
        config.with_zip_consistency(self.zip_consistency.into())
    }
}

/// Lookahead memory flag shared by the commands that decode 7z payloads.
#[derive(clap::Args, Clone, Copy)]
pub struct ParallelDecodeArgs {
    #[arg(
        long,
        value_name = "SIZE|off",
        value_parser = parse_parallel_decode,
        help = parallel_decode_help()
    )]
    pub parallel_decode_memory: Option<ParallelDecodeValue>,
}

/// The raw value of `--parallel-decode-memory`: `off`, or a byte count that
/// core still has to accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParallelDecodeValue {
    /// Decode on one thread.
    Off,
    /// A lookahead memory of this many bytes.
    Bytes(u64),
}

impl ParallelDecodeArgs {
    /// Applies the flag to `config`, leaving the default when it is omitted.
    ///
    /// # Errors
    ///
    /// Returns `InvalidConfiguration` naming `parallel_decode_memory` for a
    /// size of zero (`off` is the way to decode on one thread).
    pub fn apply(self, config: SecurityConfig) -> Result<SecurityConfig, ArchiveError> {
        Ok(match self.parallel_decode_memory {
            None => config,
            Some(ParallelDecodeValue::Off) => {
                config.with_parallel_decode(ParallelDecode::Sequential)
            }
            Some(ParallelDecodeValue::Bytes(bytes)) => {
                config.with_parallel_decode(ParallelDecode::from_bytes(Some(non_zero_u64(
                    ConfigSetting::ParallelDecodeMemory,
                    bytes,
                )?)))
            }
        })
    }
}

#[derive(clap::Args)]
pub struct ExtractArgs {
    /// Path to the archive file
    #[arg(value_name = "ARCHIVE")]
    pub archive: PathBuf,

    /// Output directory (default: current directory)
    #[arg(value_name = "OUTPUT_DIR")]
    pub output_dir: Option<PathBuf>,

    #[command(flatten)]
    pub limits: LimitArgs,

    #[command(flatten)]
    pub selection: SelectionArgs,

    #[command(flatten)]
    pub links: LinkPolicyArgs,

    #[command(flatten)]
    pub zip: ZipPolicyArgs,

    #[command(flatten)]
    pub parallel: ParallelDecodeArgs,

    #[arg(long, value_enum, value_name = "MODE", help = decode_reuse_help())]
    pub decode_reuse: Option<DecodeReuseArg>,

    /// Maximum path depth allowed (minimum: 1; the security policy default
    /// applies when omitted)
    #[arg(long, value_name = "DEPTH")]
    pub max_path_depth: Option<usize>,

    #[arg(
        long = "banned-component",
        value_name = "COMPONENT",
        value_delimiter = ',',
        value_parser = parse_list_token,
        help = "Banned path component; can be repeated or comma-separated",
        long_help = banned_component_help()
    )]
    pub banned_components: Vec<ListToken>,

    /// Allow absolute paths in archive entries
    #[arg(long)]
    pub allow_absolute_paths: bool,

    /// Allow world-writable files in extracted archives
    #[arg(long)]
    pub allow_world_writable: bool,

    /// Preserve file permissions from archive
    #[arg(long)]
    pub preserve_permissions: bool,

    /// Overwrite existing files
    #[arg(long)]
    pub force: bool,

    /// Extract atomically: stage in a private directory next to the
    /// destination, rename on success, remove it on failure.
    #[arg(long, long_help = atomic_long_help())]
    pub atomic: bool,

    /// Only extract files whose extension is in this list.
    ///
    /// Can be repeated (`--allowed-extensions txt --allowed-extensions pdf`) or
    /// comma-separated (`--allowed-extensions txt,pdf`). The leading dot is
    /// optional and matching is case-insensitive. When omitted, all extensions
    /// are allowed.
    #[arg(
        long = "allowed-extensions",
        value_name = "EXT",
        value_delimiter = ',',
        value_parser = parse_list_token
    )]
    pub allowed_extensions: Vec<ListToken>,
}

impl PolicyFlags for ExtractArgs {
    fn limits(&self) -> LimitArgs {
        self.limits
    }

    fn zip(&self) -> ZipPolicyArgs {
        self.zip
    }

    fn selection(&self) -> &SelectionArgs {
        &self.selection
    }

    fn links(&self) -> Option<LinkPolicyArgs> {
        Some(self.links)
    }

    fn parallel(&self) -> Option<ParallelDecodeArgs> {
        Some(self.parallel)
    }

    fn max_path_depth(&self) -> Option<usize> {
        self.max_path_depth
    }
}

#[derive(clap::Args)]
pub struct CreateArgs {
    /// Output archive file path
    #[arg(value_name = "OUTPUT")]
    pub output: PathBuf,

    /// Source files or directories to archive
    #[arg(value_name = "SOURCE", required = true)]
    pub sources: Vec<PathBuf>,

    #[arg(
        short = 'l',
        long,
        value_name = "LEVEL",
        allow_negative_numbers = true,
        value_parser = parse_requested_level,
        help = compression_level_help()
    )]
    pub compression_level: Option<RequestedLevel>,

    /// Follow symbolic links
    #[arg(long)]
    pub follow_symlinks: bool,

    /// Include hidden files
    #[arg(long)]
    pub include_hidden: bool,

    /// Exclude glob pattern, can be repeated: a name (`*.tmp`, `node_modules`)
    /// matches any path component, a pattern with a `/` (`build/out`,
    /// `src/**/*.o`) matches from the archive root; a match also excludes
    /// everything below it. Quote the pattern so the shell does not expand it
    #[arg(long = "exclude", short = 'x', value_name = "PATTERN")]
    pub exclude: Vec<String>,

    /// Strip path prefix from entries
    #[arg(long, value_name = "PREFIX")]
    pub strip_prefix: Option<PathBuf>,

    /// Maximum size for a single file in bytes (supports K, M, G, T suffixes)
    #[arg(long, value_name = "BYTES", value_parser = parse_byte_size)]
    pub max_file_size: Option<u64>,

    /// Preserve file permissions when creating the archive.
    ///
    /// Pass `--preserve-permissions=false` to create a portable archive
    /// without platform-specific permission bits.
    #[arg(long, action = clap::ArgAction::Set, default_value_t = true)]
    pub preserve_permissions: bool,

    /// Overwrite output file if exists
    #[arg(short = 'f', long)]
    pub force: bool,
}

#[derive(clap::Args)]
pub struct ListArgs {
    /// Path to the archive file
    #[arg(value_name = "ARCHIVE")]
    pub archive: PathBuf,

    /// Show detailed file information
    #[arg(short, long)]
    pub long: bool,

    /// Show sizes in human-readable format (requires --long)
    #[arg(short = 'H', long, requires = "long")]
    pub human_readable: bool,

    #[command(flatten)]
    pub limits: LimitArgs,

    #[command(flatten)]
    pub selection: SelectionArgs,

    #[command(flatten)]
    pub links: LinkPolicyArgs,

    /// Read 7z symlink targets, which decodes the blocks that hold them
    /// (implied by --allow-symlinks)
    #[arg(long)]
    pub read_link_targets: bool,

    #[command(flatten)]
    pub zip: ZipPolicyArgs,
}

impl PolicyFlags for ListArgs {
    fn limits(&self) -> LimitArgs {
        self.limits
    }

    fn zip(&self) -> ZipPolicyArgs {
        self.zip
    }

    fn selection(&self) -> &SelectionArgs {
        &self.selection
    }

    fn links(&self) -> Option<LinkPolicyArgs> {
        Some(self.links)
    }
}

#[derive(clap::Args)]
pub struct VerifyArgs {
    /// Path to the archive file
    #[arg(value_name = "ARCHIVE")]
    pub archive: PathBuf,

    #[command(flatten)]
    pub limits: LimitArgs,

    #[command(flatten)]
    pub selection: SelectionArgs,

    #[command(flatten)]
    pub links: LinkPolicyArgs,

    #[command(flatten)]
    pub zip: ZipPolicyArgs,

    #[command(flatten)]
    pub parallel: ParallelDecodeArgs,

    /// Decode the payload to its end to verify checksums and codec framing
    ///
    /// Integrity is INCOMPLETE when part of the payload could not be verified
    /// (budget, resource limit, solid 7z without --allow-solid-archives, TAR
    /// without an end-of-archive marker). Exit code 0 does not mean integrity
    /// OK: use --strict to exit with status 3 on INCOMPLETE.
    #[arg(long)]
    pub check_integrity: bool,

    #[arg(
        long,
        value_name = "SIZE",
        value_parser = parse_byte_size,
        requires = "check_integrity",
        help = decompression_budget_help()
    )]
    pub decompression_budget: Option<u64>,

    /// Treat warnings as errors and exit with status code 3
    #[arg(long)]
    pub strict: bool,
}

impl PolicyFlags for VerifyArgs {
    fn limits(&self) -> LimitArgs {
        self.limits
    }

    fn zip(&self) -> ZipPolicyArgs {
        self.zip
    }

    fn selection(&self) -> &SelectionArgs {
        &self.selection
    }

    fn links(&self) -> Option<LinkPolicyArgs> {
        Some(self.links)
    }

    fn parallel(&self) -> Option<ParallelDecodeArgs> {
        Some(self.parallel)
    }
}

/// One comma-separated item of a list flag, trimmed.
///
/// clap splits and trims; whether an item is a valid value, and what a list
/// with no usable item means, is decided by the command so the refusal is
/// the same JSON-safe error as every other flag value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListToken {
    /// A non-blank item.
    Item(String),
    /// An item that is exactly empty (`--flag ""`).
    Empty,
    /// An item of whitespace only.
    Blank,
}

#[expect(clippy::unnecessary_wraps, reason = "clap value parsers return Result")]
fn parse_list_token(s: &str) -> Result<ListToken, String> {
    let trimmed = s.trim();
    Ok(if s.is_empty() {
        ListToken::Empty
    } else if trimmed.is_empty() {
        ListToken::Blank
    } else {
        ListToken::Item(trimmed.to_owned())
    })
}

/// What `--banned-component` asks for: the default ban list, or a list that
/// replaces it.
#[derive(Debug, PartialEq, Eq)]
pub enum BannedComponentsArg {
    /// The flag was not given.
    Default,
    /// The flag's own components, possibly none (`--banned-component ""`).
    Replace(Vec<ListToken>),
}

impl BannedComponentsArg {
    /// Classifies the raw items of the flag.
    pub fn of(tokens: &[ListToken]) -> Self {
        if tokens.is_empty() {
            Self::Default
        } else {
            Self::Replace(tokens.to_vec())
        }
    }
}

/// Parses `--compression-level` into what the user asked for, so a whole number
/// of any size reaches core's range check instead of failing as a usage error.
fn parse_requested_level(s: &str) -> Result<RequestedLevel, String> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("`{s}` is not a whole number"));
    }
    Ok(s.parse()
        .map_or(RequestedLevel::OutOfRange, RequestedLevel::Integer))
}

fn parse_ratio(s: &str) -> Result<f64, String> {
    s.trim()
        .parse()
        .map_err(|_| format!("`{s}` is not a number"))
}

fn parse_parallel_decode(s: &str) -> Result<ParallelDecodeValue, String> {
    if s.trim().eq_ignore_ascii_case("off") {
        return Ok(ParallelDecodeValue::Off);
    }
    parse_byte_size(s).map(ParallelDecodeValue::Bytes)
}

/// Splits a trailing binary-unit suffix (K, M, G or T, in either case) off
/// `s` and returns the remaining digits with the unit's multiplier.
fn split_size_suffix(s: &str) -> (&str, u64) {
    const UNITS: [(char, u32); 4] = [('T', 4), ('G', 3), ('M', 2), ('K', 1)];
    s.char_indices()
        .next_back()
        .and_then(|(at, last)| {
            UNITS
                .iter()
                .find(|(unit, _)| unit.eq_ignore_ascii_case(&last))
                .map(|&(_, power)| (&s[..at], 1024_u64.pow(power)))
        })
        .unwrap_or((s, 1))
}

/// Parse byte size with optional suffix (K, M, G, T, case-insensitive)
fn parse_byte_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty byte size".to_string());
    }

    let (num_str, multiplier) = split_size_suffix(s);

    num_str
        .parse::<u64>()
        .map_err(|_| format!("invalid byte size: {s}"))
        .and_then(|n| {
            n.checked_mul(multiplier)
                .ok_or_else(|| format!("byte size overflow: {s}"))
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_budget_help_spells_the_flag_it_belongs_to() {
        assert!(decompression_budget_help().contains(Flag::CheckIntegrity.long()));
        assert!(atomic_long_help().contains(Flag::Force.long()));
    }

    #[test]
    fn a_size_that_is_not_whole_mib_keeps_its_bytes() {
        assert_eq!(mib_text(256 * 1024 * 1024), "256 MiB");
        assert_eq!(mib_text(1024 * 1024 + 1), "1048577 bytes");
        assert_eq!(mib_text(0), "0 MiB");
    }

    #[test]
    fn a_compression_level_keeps_what_was_asked_for() {
        assert_eq!(parse_requested_level("7"), Ok(RequestedLevel::Integer(7)));
        assert_eq!(parse_requested_level("-3"), Ok(RequestedLevel::Integer(-3)));
        assert_eq!(parse_requested_level("+5"), Ok(RequestedLevel::Integer(5)));
        assert_eq!(
            parse_requested_level("99999999999999999999"),
            Ok(RequestedLevel::OutOfRange)
        );
        assert_eq!(
            parse_requested_level("-99999999999999999999"),
            Ok(RequestedLevel::OutOfRange)
        );
        for text in ["", "-", "+", "1.5", "abc", " 1"] {
            assert!(parse_requested_level(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn byte_size_suffixes_are_case_insensitive() {
        assert_eq!(parse_byte_size("1k").unwrap(), 1024);
        assert_eq!(parse_byte_size("2m").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_byte_size("3g").unwrap(), 3 * 1024 * 1024 * 1024);
        assert_eq!(parse_byte_size("1t").unwrap(), 1024_u64.pow(4));
    }

    #[test]
    fn test_parse_byte_size() {
        assert_eq!(parse_byte_size("100").unwrap(), 100);
        assert_eq!(parse_byte_size("1K").unwrap(), 1024);
        assert_eq!(parse_byte_size("2M").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_byte_size("3G").unwrap(), 3 * 1024 * 1024 * 1024);
        assert_eq!(parse_byte_size("1T").unwrap(), 1024_u64.pow(4));
        assert!(parse_byte_size("invalid").is_err());
        assert!(parse_byte_size("").is_err());
    }

    fn reuse_of(args: &[&str]) -> DecodeReuse {
        let cli = Cli::try_parse_from(args).unwrap();
        let Commands::Extract(args) = cli.command else {
            panic!("expected Extract command");
        };
        DecodeReuseArg::resolve(args.decode_reuse)
    }

    #[test]
    fn decode_reuse_defaults_to_256_mib_in_memory() {
        assert_eq!(
            reuse_of(&["exarch", "extract", "a.zip"]),
            DecodeReuse::Memory(ReuseLimit::MAX)
        );
    }

    #[test]
    fn decode_reuse_flag_selects_each_mode() {
        let with = |mode| reuse_of(&["exarch", "extract", "a.zip", "--decode-reuse", mode]);
        assert_eq!(with("off"), DecodeReuse::Off);
        assert_eq!(with("memory"), DecodeReuse::Memory(ReuseLimit::MAX));
        assert_eq!(with("temp-file"), DecodeReuse::TempFile(ReuseLimit::MAX));
        assert!(
            Cli::try_parse_from(["exarch", "extract", "a.zip", "--decode-reuse", "disk"]).is_err()
        );
    }

    fn limits_of(args: &[&str]) -> LimitArgs {
        let Commands::Extract(args) = Cli::parse_from(args).command else {
            panic!("expected extract command");
        };
        args.limits
    }

    #[test]
    fn limits_leave_the_core_defaults_when_no_flag_is_given() {
        let config = limits_of(&["exarch", "extract", "a.zip"])
            .apply(SecurityConfig::default())
            .unwrap();
        let defaults = SecurityConfig::default();
        assert_eq!(config.max_file_count, defaults.max_file_count);
        assert_eq!(config.max_total_size, defaults.max_total_size);
        assert_eq!(config.max_file_size, defaults.max_file_size);
        assert_eq!(config.max_compression_ratio, defaults.max_compression_ratio);
    }

    #[test]
    fn limits_apply_only_what_was_given() {
        let defaults = SecurityConfig::default();
        let config = limits_of(&[
            "exarch",
            "extract",
            "a.zip",
            "--max-total-size",
            "1K",
            "--max-compression-ratio",
            "2.5",
        ])
        .apply(SecurityConfig::default())
        .unwrap();
        assert_eq!(config.max_total_size.ceiling(), 1024);
        assert_eq!(config.max_compression_ratio.get(), 2.5);
        assert_eq!(config.max_file_count, defaults.max_file_count);
        assert_eq!(config.max_file_size, defaults.max_file_size);
    }

    #[test]
    fn limits_refuse_zero_and_non_finite_values_naming_the_setting() {
        for (flag, value, setting) in [
            ("--max-files", "0", "max_file_count"),
            ("--max-total-size", "0", "max_total_size"),
            ("--max-file-size", "0", "max_file_size"),
            ("--max-compression-ratio", "0", "max_compression_ratio"),
            ("--max-compression-ratio", "nan", "max_compression_ratio"),
            ("--max-compression-ratio", "-1", "max_compression_ratio"),
        ] {
            let flag = format!("{flag}={value}");
            let cli = Cli::try_parse_from(["exarch", "extract", "a.zip", flag.as_str()]).unwrap();
            let Commands::Extract(args) = cli.command else {
                panic!("expected extract command");
            };
            let err = args.limits.apply(SecurityConfig::default()).unwrap_err();
            assert_eq!(err.ffi_kind().setting().unwrap().as_str(), setting);
        }
    }

    #[test]
    fn every_limit_flag_is_shared_by_extract_list_and_verify() {
        for sub in ["extract", "list", "verify"] {
            let cli = Cli::try_parse_from([
                "exarch",
                sub,
                "a.zip",
                "--max-files",
                "7",
                "--max-total-size",
                "1M",
                "--max-file-size",
                "2K",
                "--max-compression-ratio",
                "1.5",
                "--allow-solid-archives",
            ])
            .unwrap();
            let limits = match cli.command {
                Commands::Extract(a) => a.limits,
                Commands::List(a) => a.limits,
                Commands::Verify(a) => a.limits,
                _ => panic!("unexpected command"),
            };
            assert_eq!(limits.max_files, Some(7));
            assert_eq!(limits.max_total_size, Some(1 << 20));
            assert_eq!(limits.max_file_size, Some(2048));
            assert_eq!(limits.max_compression_ratio, Some(1.5));
            assert!(limits.allow_solid_archives);
        }
    }

    #[test]
    fn test_allow_solid_archives_flag() {
        let cli =
            Cli::try_parse_from(["exarch", "extract", "a.7z", "--allow-solid-archives"]).unwrap();
        let Commands::Extract(args) = cli.command else {
            panic!("expected Extract command");
        };
        assert!(args.limits.allow_solid_archives);
    }

    #[test]
    fn test_max_path_depth_default() {
        let cli = Cli::parse_from(["exarch", "extract", "archive.tar.gz"]);
        let Commands::Extract(args) = cli.command else {
            panic!("expected Extract command");
        };
        assert_eq!(args.max_path_depth, None);
    }

    #[test]
    fn test_max_path_depth_override() {
        let cli = Cli::parse_from([
            "exarch",
            "extract",
            "--max-path-depth",
            "8",
            "archive.tar.gz",
        ]);
        let Commands::Extract(args) = cli.command else {
            panic!("expected Extract command");
        };
        assert_eq!(args.max_path_depth, Some(8));
    }

    #[test]
    fn test_banned_component_repeatable() {
        let cli = Cli::parse_from([
            "exarch",
            "extract",
            "--banned-component",
            ".secrets",
            "--banned-component",
            ".private",
            "archive.tar.gz",
        ]);
        let Commands::Extract(args) = cli.command else {
            panic!("expected Extract command");
        };
        assert_eq!(
            args.banned_components,
            vec![
                ListToken::Item(".secrets".to_owned()),
                ListToken::Item(".private".to_owned())
            ]
        );
    }

    #[test]
    fn test_banned_component_empty_by_default() {
        let cli = Cli::parse_from(["exarch", "extract", "archive.tar.gz"]);
        let Commands::Extract(args) = cli.command else {
            panic!("expected Extract command");
        };
        assert!(args.banned_components.is_empty());
    }

    #[test]
    fn list_flags_split_on_commas_and_trim() {
        let cli = Cli::parse_from([
            "exarch",
            "extract",
            "--allowed-extensions",
            " txt ,pdf,, ",
            "--allowed-extensions",
            "",
            "archive.tar.gz",
        ]);
        let Commands::Extract(args) = cli.command else {
            panic!("expected Extract command");
        };
        assert_eq!(
            args.allowed_extensions,
            vec![
                ListToken::Item("txt".to_owned()),
                ListToken::Item("pdf".to_owned()),
                ListToken::Empty,
                ListToken::Blank,
                ListToken::Empty,
            ]
        );
    }

    #[test]
    fn banned_components_arg_tells_absent_from_present() {
        assert_eq!(BannedComponentsArg::of(&[]), BannedComponentsArg::Default);
        assert_eq!(
            BannedComponentsArg::of(&[ListToken::Empty]),
            BannedComponentsArg::Replace(vec![ListToken::Empty])
        );
    }

    #[test]
    fn test_allow_absolute_paths_flag() {
        let cli = Cli::parse_from([
            "exarch",
            "extract",
            "--allow-absolute-paths",
            "archive.tar.gz",
        ]);
        let Commands::Extract(args) = cli.command else {
            panic!("expected Extract command");
        };
        assert!(args.allow_absolute_paths);
    }

    #[test]
    fn test_allow_absolute_paths_default_false() {
        let cli = Cli::parse_from(["exarch", "extract", "archive.tar.gz"]);
        let Commands::Extract(args) = cli.command else {
            panic!("expected Extract command");
        };
        assert!(!args.allow_absolute_paths);
    }

    #[test]
    fn test_parse_byte_size_overflow() {
        // Test overflow scenarios
        assert!(parse_byte_size("18446744073709551615K").is_err()); // u64::MAX / 1024 + 1
        assert!(parse_byte_size("18014398509481984M").is_err()); // u64::MAX / (1024^2) + 1
        assert!(parse_byte_size("17592186044416G").is_err()); // u64::MAX / (1024^3) + 1
    }

    #[test]
    fn test_list_args_default_max_files() {
        let cli = Cli::parse_from(["exarch", "list", "archive.zip"]);
        let Commands::List(args) = cli.command else {
            panic!("expected list command");
        };
        assert_eq!(args.limits.max_files, None);
        assert!(args.limits.max_total_size.is_none());
    }

    #[test]
    fn test_list_args_max_files_override() {
        let cli = Cli::parse_from(["exarch", "list", "--max-files", "99999", "archive.zip"]);
        let Commands::List(args) = cli.command else {
            panic!("expected list command");
        };
        assert_eq!(args.limits.max_files, Some(99999));
    }

    #[test]
    fn test_list_args_max_total_size_override() {
        let cli = Cli::parse_from(["exarch", "list", "--max-total-size", "2G", "archive.zip"]);
        let Commands::List(args) = cli.command else {
            panic!("expected list command");
        };
        assert_eq!(args.limits.max_total_size, Some(2 * 1024 * 1024 * 1024));
    }

    #[test]
    fn test_verify_args_default_max_files() {
        let cli = Cli::parse_from(["exarch", "verify", "archive.zip"]);
        let Commands::Verify(args) = cli.command else {
            panic!("expected verify command");
        };
        assert_eq!(args.limits.max_files, None);
        assert!(args.limits.max_total_size.is_none());
    }

    #[test]
    fn test_verify_args_max_files_override() {
        let cli = Cli::parse_from(["exarch", "verify", "--max-files", "65537", "archive.zip"]);
        let Commands::Verify(args) = cli.command else {
            panic!("expected verify command");
        };
        assert_eq!(args.limits.max_files, Some(65537));
    }

    #[test]
    fn test_verify_args_max_total_size_override() {
        let cli = Cli::parse_from([
            "exarch",
            "verify",
            "--max-total-size",
            "500M",
            "archive.zip",
        ]);
        let Commands::Verify(args) = cli.command else {
            panic!("expected verify command");
        };
        assert_eq!(args.limits.max_total_size, Some(500 * 1024 * 1024));
    }

    #[test]
    fn test_verify_integrity_flags_parse() {
        let cli = Cli::parse_from([
            "exarch",
            "verify",
            "--check-integrity",
            "--decompression-budget",
            "2M",
            "archive.zip",
        ]);
        let Commands::Verify(args) = cli.command else {
            panic!("expected verify command");
        };
        assert!(args.check_integrity);
        assert_eq!(args.decompression_budget, Some(2 * 1024 * 1024));
    }

    #[test]
    fn test_verify_integrity_is_opt_in() {
        let cli = Cli::parse_from(["exarch", "verify", "archive.zip"]);
        let Commands::Verify(args) = cli.command else {
            panic!("expected verify command");
        };
        assert!(!args.check_integrity);
        assert!(args.decompression_budget.is_none());
    }

    #[test]
    fn test_verify_budget_requires_check_integrity() {
        let result = Cli::try_parse_from([
            "exarch",
            "verify",
            "--decompression-budget",
            "1M",
            "archive.zip",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_zero_budget_parses_and_is_refused_by_core() {
        let Commands::Verify(args) = Cli::parse_from([
            "exarch",
            "verify",
            "--check-integrity",
            "--decompression-budget",
            "0",
            "archive.zip",
        ])
        .command
        else {
            panic!("expected verify command");
        };
        assert_eq!(args.decompression_budget, Some(0));
    }

    #[test]
    fn test_list_args_max_file_size_override() {
        let cli = Cli::parse_from(["exarch", "list", "--max-file-size", "100M", "archive.zip"]);
        let Commands::List(args) = cli.command else {
            panic!("expected list command");
        };
        assert_eq!(args.limits.max_file_size, Some(100 * 1024 * 1024));
    }

    #[test]
    fn test_verify_args_max_file_size_override() {
        let cli = Cli::parse_from(["exarch", "verify", "--max-file-size", "100M", "archive.zip"]);
        let Commands::Verify(args) = cli.command else {
            panic!("expected verify command");
        };
        assert_eq!(args.limits.max_file_size, Some(100 * 1024 * 1024));
    }

    #[test]
    fn test_parallel_decode_memory_parses_sizes_and_off() {
        assert_eq!(
            parse_parallel_decode("256M"),
            Ok(ParallelDecodeValue::Bytes(256 * 1024 * 1024))
        );
        assert_eq!(parse_parallel_decode("off"), Ok(ParallelDecodeValue::Off));
        assert_eq!(parse_parallel_decode("OFF"), Ok(ParallelDecodeValue::Off));
        assert_eq!(
            parse_parallel_decode("0"),
            Ok(ParallelDecodeValue::Bytes(0))
        );
        assert!(parse_parallel_decode("lots").is_err());
    }

    #[test]
    fn a_zero_parallel_decode_memory_is_refused_by_core_naming_its_setting() {
        let args = ParallelDecodeArgs {
            parallel_decode_memory: Some(ParallelDecodeValue::Bytes(0)),
        };
        let err = args.apply(SecurityConfig::default()).unwrap_err();
        assert_eq!(
            err.ffi_kind().setting().unwrap().as_str(),
            "parallel_decode_memory"
        );
    }

    #[test]
    fn test_parallel_decode_memory_applies_to_extract_and_verify_only_when_given() {
        let default = SecurityConfig::default().parallel_decode;
        let Commands::Extract(args) = Cli::parse_from(["exarch", "extract", "a.7z"]).command else {
            panic!("expected extract command");
        };
        assert_eq!(
            args.parallel
                .apply(SecurityConfig::default())
                .unwrap()
                .parallel_decode,
            default
        );

        let Commands::Extract(args) = Cli::parse_from([
            "exarch",
            "extract",
            "--parallel-decode-memory",
            "off",
            "a.7z",
        ])
        .command
        else {
            panic!("expected extract command");
        };
        let config = args.parallel.apply(SecurityConfig::default()).unwrap();
        assert_eq!(config.parallel_decode, ParallelDecode::Sequential);

        let Commands::Verify(args) =
            Cli::parse_from(["exarch", "verify", "--parallel-decode-memory", "1G", "a.7z"]).command
        else {
            panic!("expected verify command");
        };
        let config = args.parallel.apply(SecurityConfig::default()).unwrap();
        assert_eq!(
            config.parallel_decode,
            ParallelDecode::Bounded(NonZeroU64::new(1 << 30).unwrap())
        );
    }

    #[test]
    fn test_list_args_both_flags() {
        let cli = Cli::parse_from([
            "exarch",
            "list",
            "--max-files",
            "1000000",
            "--max-total-size",
            "10G",
            "archive.zip",
        ]);
        let Commands::List(args) = cli.command else {
            panic!("expected list command");
        };
        assert_eq!(args.limits.max_files, Some(1_000_000));
        assert_eq!(args.limits.max_total_size, Some(10 * 1024 * 1024 * 1024));
    }

    #[test]
    fn test_create_args_max_file_size_parsed() {
        let cli = Cli::parse_from([
            "exarch",
            "create",
            "--max-file-size",
            "50M",
            "out.tar.gz",
            "src/",
        ]);
        let Commands::Create(args) = cli.command else {
            panic!("expected Create command");
        };
        assert_eq!(args.max_file_size, Some(50 * 1024 * 1024));
    }

    #[test]
    fn test_create_args_preserve_permissions_default() {
        let cli = Cli::parse_from(["exarch", "create", "out.tar.gz", "src/"]);
        let Commands::Create(args) = cli.command else {
            panic!("expected Create command");
        };
        assert!(args.preserve_permissions);
    }

    #[test]
    fn test_create_args_preserve_permissions_explicit() {
        let cli = Cli::parse_from([
            "exarch",
            "create",
            "--preserve-permissions=true",
            "out.tar.gz",
            "src/",
        ]);
        let Commands::Create(args) = cli.command else {
            panic!("expected Create command");
        };
        assert!(args.preserve_permissions);
    }

    #[test]
    fn test_create_args_preserve_permissions_false() {
        let cli = Cli::parse_from([
            "exarch",
            "create",
            "--preserve-permissions=false",
            "out.tar.gz",
            "src/",
        ]);
        let Commands::Create(args) = cli.command else {
            panic!("expected Create command");
        };
        assert!(!args.preserve_permissions);
    }
}
