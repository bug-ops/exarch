/**
 * Report field parity (#1052), the exact-count / size-clamp contract (#1055),
 * and the relaxable settings the bindings expose (#1056).
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  ListOptions,
  SecurityConfig,
  VerificationOptions,
  createArchiveSync,
  extractArchiveSync,
  listArchiveSync,
  verifyArchiveSync,
} = require('../index.js');

const FIXTURES = path.join(__dirname, '..', '..', '..', 'tests', 'fixtures');
const SYMLINK_7Z = path.join(FIXTURES, 'symlink-mode.7z');
const SOLID_7Z = path.join(FIXTURES, 'solid.7z');

const keys = (value) => Object.keys(value).sort();

describe('report fields', () => {
  let tempDir;
  let archive;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-test-'));
    const source = path.join(tempDir, 'source');
    fs.mkdirSync(source);
    fs.writeFileSync(path.join(source, 'a.txt'), 'hello');
    archive = path.join(tempDir, 'out.tar.gz');
    createArchiveSync(archive, [source]);
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('extraction report fields', () => {
    const report = extractArchiveSync(archive, path.join(tempDir, 'dest'));
    assert.deepStrictEqual(keys(report), [
      'bytesWritten',
      'directoriesCreated',
      'durationMs',
      'filesExtracted',
      'filesSkipped',
      'sizeClamped',
      'skipped',
      'symlinksCreated',
      'warnings',
    ]);
    assert.strictEqual(report.sizeClamped, false);
    assert.deepStrictEqual(keys(report.skipped), ['counts', 'sample', 'total']);
    assert.strictEqual(report.skipped.total, 0);
  });

  it('creation report fields', () => {
    const report = createArchiveSync(path.join(tempDir, 'again.tar.gz'), [
      path.join(tempDir, 'source'),
    ]);
    assert.deepStrictEqual(keys(report), [
      'bytesCompressed',
      'bytesWritten',
      'directoriesAdded',
      'durationMs',
      'filesAdded',
      'filesSkipped',
      'sizeClamped',
      'skipped',
      'symlinksAdded',
      'warnings',
    ]);
    assert.strictEqual(report.sizeClamped, false);
  });

  it('manifest and entry fields', () => {
    const manifest = listArchiveSync(archive);
    assert.deepStrictEqual(keys(manifest), [
      'dispositions',
      'entries',
      'format',
      'sizeClamped',
      'totalEntries',
      'totalSize',
    ]);
    const file = manifest.entries.find((entry) => entry.entryType === 'File');
    assert.strictEqual(file.sizeClamped, false);
    assert.strictEqual(file.size, 5);
  });

  it('verification report fields', () => {
    const report = verifyArchiveSync(archive);
    assert.deepStrictEqual(keys(report), [
      'format',
      'integrityStatus',
      'issues',
      'securityStatus',
      'sizeClamped',
      'status',
      'suspiciousEntries',
      'totalEntries',
      'totalSize',
    ]);
    assert.strictEqual(report.sizeClamped, false);
    assert.strictEqual(report.format, 'TarGz');
  });

  it('integrity gaps carry the total over all reasons', () => {
    const options = new VerificationOptions().withIntegrityCheck();
    const report = verifyArchiveSync(SOLID_7Z, null, options);
    assert.deepStrictEqual(keys(report.integrityGaps), ['counts', 'entries', 'omitted', 'total']);
    assert.strictEqual(report.integrityGaps.total, 10);
  });
});

describe('ListOptions', () => {
  it('defaults to leaving 7z link targets unread', () => {
    assert.strictEqual(new ListOptions().storedTargets, 'skip');
    const link = listArchiveSync(SYMLINK_7Z).entries.find((e) => e.entryType === 'Symlink');
    assert.deepStrictEqual(link.target, { state: 'unread' });
  });

  it("withStoredTargets('read') reads them", () => {
    const options = new ListOptions().withStoredTargets('read');
    assert.strictEqual(options.storedTargets, 'read');
    const link = listArchiveSync(SYMLINK_7Z, null, options).entries.find(
      (e) => e.entryType === 'Symlink'
    );
    assert.strictEqual(link.target.state, 'recorded');
  });
});

describe('relaxable SecurityConfig settings', () => {
  it('windows reserved names are denied until allowed', () => {
    const config = new SecurityConfig();
    assert.strictEqual(config.allowWindowsReservedNames, false);
    assert.strictEqual(config.withAllowWindowsReservedNames(true).allowWindowsReservedNames, true);
  });

  it('TAR metadata budget and decoder memory round trip', () => {
    const config = new SecurityConfig();
    assert.strictEqual(config.maxTarMetadataBytes, 4 * 1024 * 1024);
    assert.strictEqual(config.maxDecoderMemory, 256 * 1024 * 1024);
    config.withMaxTarMetadataBytes(1 << 20).withMaxDecoderMemory(1 << 26);
    assert.strictEqual(config.maxTarMetadataBytes, 1 << 20);
    assert.strictEqual(config.maxDecoderMemory, 1 << 26);
    assert.strictEqual(config.compressedMemberAllowance, 10000);
    assert.strictEqual(config.withCompressedMemberAllowance(500).compressedMemberAllowance, 500);
  });

  for (const [method, setting] of [
    ['withMaxTarMetadataBytes', 'max_tar_metadata_bytes'],
    ['withMaxDecoderMemory', 'max_decoder_memory'],
    ['withCompressedMemberAllowance', 'compressed_member_allowance'],
  ]) {
    it(`${method} refuses zero naming ${setting}`, () => {
      assert.throws(() => new SecurityConfig()[method](0), {
        code: 'INVALID_CONFIGURATION',
        setting,
      });
    });
  }

  it('the solid ratio exists only while solid archives are allowed', () => {
    const config = new SecurityConfig();
    assert.strictEqual(config.maxSolidCompressionRatio, null);
    assert.throws(() => config.withMaxSolidCompressionRatio(50), {
      code: 'INVALID_CONFIGURATION',
      setting: 'max_solid_compression_ratio',
    });
    config.withAllowSolidArchives(true).withMaxSolidCompressionRatio(50);
    assert.strictEqual(config.maxSolidCompressionRatio, 50);
    assert.throws(() => config.withMaxSolidCompressionRatio(0), {
      code: 'INVALID_CONFIGURATION',
      setting: 'max_solid_compression_ratio',
    });
  });
});
