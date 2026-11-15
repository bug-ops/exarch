// Hand-maintained loader: one literal require per addon the package ships
// (napi.targets in package.json). Never resolves a package name, so a platform
// without a bundled addon fails here instead of loading code from the registry.
// scripts/check-package.mjs enforces this on the packed tarball.

const addons = {
  'darwin-x64': () => require('./exarch-rs.darwin-x64.node'),
  'darwin-arm64': () => require('./exarch-rs.darwin-arm64.node'),
  'win32-x64': () => require('./exarch-rs.win32-x64-msvc.node'),
  'linux-x64': () => require('./exarch-rs.linux-x64-gnu.node'),
  'linux-arm64': () => require('./exarch-rs.linux-arm64-gnu.node'),
};

// Musl only on positive evidence: a report that exists but names no glibc.
// Runtimes without process.report fall through to the glibc addon require.
function isMusl() {
  let report;
  try {
    report = process.report?.getReport?.();
  } catch {
    return false;
  }
  return report !== undefined && typeof report.header?.glibcVersionRuntime !== 'string';
}

function platformKey() {
  const key = `${process.platform}-${process.arch}`;
  if (process.platform === 'linux' && isMusl()) {
    throw new Error(`exarch-rs: unsupported platform ${key}-musl; only glibc Linux is bundled`);
  }
  if (process.platform === 'win32' && process.arch !== 'x64') {
    throw new Error(`exarch-rs: unsupported platform ${key}`);
  }
  return key;
}

function loadAddon() {
  const key = platformKey();
  const load = Object.hasOwn(addons, key) ? addons[key] : undefined;
  if (load === undefined) {
    throw new Error(`exarch-rs: unsupported platform ${key}`);
  }
  try {
    return load();
  } catch (cause) {
    throw new Error(`exarch-rs: failed to load the addon for ${key}`, { cause });
  }
}

const addon = loadAddon();

// Explicit assignments keep the named exports visible to ESM `import {...}` (cjs-module-lexer).
module.exports.listArchive = addon.listArchive;
module.exports.createArchive = addon.createArchive;
module.exports.verifyArchive = addon.verifyArchive;
module.exports.extractArchive = addon.extractArchive;
module.exports.listArchiveSync = addon.listArchiveSync;
module.exports.createArchiveSync = addon.createArchiveSync;
module.exports.verifyArchiveSync = addon.verifyArchiveSync;
module.exports.extractArchiveSync = addon.extractArchiveSync;
module.exports.createArchiveWithProgress = addon.createArchiveWithProgress;
module.exports.extractArchiveWithProgress = addon.extractArchiveWithProgress;
module.exports.IoKind = addon.IoKind;
module.exports.ErrorCode = addon.ErrorCode;
module.exports.QuotaSubCode = addon.QuotaSubCode;
module.exports.ConfigSetting = addon.ConfigSetting;
module.exports.PartialWrites = addon.PartialWrites;
module.exports.PolicySetting = addon.PolicySetting;
module.exports.ProtectedPath = addon.ProtectedPath;
module.exports.RestoreOutcome = addon.RestoreOutcome;
module.exports.ZipBombSubCode = addon.ZipBombSubCode;
module.exports.DestinationStep = addon.DestinationStep;
module.exports.InvalidArchiveSubCode = addon.InvalidArchiveSubCode;
module.exports.SecurityViolationSubCode = addon.SecurityViolationSubCode;
module.exports.listArchiveBytes = addon.listArchiveBytes;
module.exports.verifyArchiveBytes = addon.verifyArchiveBytes;
module.exports.listArchiveBytesSync = addon.listArchiveBytesSync;
module.exports.verifyArchiveBytesSync = addon.verifyArchiveBytesSync;
module.exports.listArchiveBytesWithProgress = addon.listArchiveBytesWithProgress;
module.exports.verifyArchiveBytesWithProgress = addon.verifyArchiveBytesWithProgress;
module.exports.listArchiveBytesWithProgressSync = addon.listArchiveBytesWithProgressSync;
module.exports.verifyArchiveBytesWithProgressSync = addon.verifyArchiveBytesWithProgressSync;
module.exports.FileKind = addon.FileKind;
module.exports.PathModel = addon.PathModel;
module.exports.SymlinkKind = addon.SymlinkKind;
module.exports.HardlinkKind = addon.HardlinkKind;
module.exports.DirectoryKind = addon.DirectoryKind;
module.exports.createArchiveToBytes = addon.createArchiveToBytes;
module.exports.extractArchiveToMemory = addon.extractArchiveToMemory;
module.exports.createArchiveToBytesSync = addon.createArchiveToBytesSync;
module.exports.extractArchiveToMemorySync = addon.extractArchiveToMemorySync;
module.exports.extractArchiveToMemoryWithProgress = addon.extractArchiveToMemoryWithProgress;
module.exports.extractArchiveToMemoryWithProgressSync =
  addon.extractArchiveToMemoryWithProgressSync;
module.exports.SkipKind = addon.SkipKind;
module.exports.Durability = addon.Durability;
module.exports.ArchiveType = addon.ArchiveType;
module.exports.CheckStatus = addon.CheckStatus;
module.exports.IssueCategory = addon.IssueCategory;
module.exports.IssueSeverity = addon.IssueSeverity;
module.exports.BackupIdentity = addon.BackupIdentity;
module.exports.CreatableFormat = addon.CreatableFormat;
module.exports.DispositionKind = addon.DispositionKind;
module.exports.IntegrityStatus = addon.IntegrityStatus;
module.exports.LinkTargetState = addon.LinkTargetState;
module.exports.NarrowingReason = addon.NarrowingReason;
module.exports.UnverifiedReason = addon.UnverifiedReason;
module.exports.ManifestEntryType = addon.ManifestEntryType;
module.exports.VerificationStatus = addon.VerificationStatus;
module.exports.CreationWarningKind = addon.CreationWarningKind;
module.exports.ExtractionWarningKind = addon.ExtractionWarningKind;
module.exports.extractArchiveToCallback = addon.extractArchiveToCallback;
module.exports.extractArchiveToCallbackSync = addon.extractArchiveToCallbackSync;
module.exports.Staging = addon.Staging;
module.exports.ExistingFiles = addon.ExistingFiles;
module.exports.StoredTargets = addon.StoredTargets;
module.exports.DecodeReuseKind = addon.DecodeReuseKind;
module.exports.MarkPropagation = addon.MarkPropagation;
module.exports.ZipConsistencyPolicy = addon.ZipConsistencyPolicy;
module.exports.VerificationOptions = addon.VerificationOptions;
module.exports.ListOptions = addon.ListOptions;
module.exports.CreationConfig = addon.CreationConfig;
module.exports.ExtractionOptions = addon.ExtractionOptions;
module.exports.SinkOptions = addon.SinkOptions;
module.exports.SecurityConfig = addon.SecurityConfig;
