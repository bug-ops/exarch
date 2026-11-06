/**
 * Tests for listArchiveBytes and verifyArchiveBytes (archives held in memory)
 */
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  listArchive,
  listArchiveBytes,
  listArchiveBytesSync,
  verifyArchiveBytes,
  verifyArchiveBytesSync,
  createArchiveSync,
  SecurityConfig,
  VerificationOptions,
} = require('../index.js');

const FIXTURES = path.join(__dirname, '..', '..', '..', 'tests', 'fixtures');
const EXTENSIONS = {
  Tar: 'tar',
  TarGz: 'tar.gz',
  TarBz2: 'tar.bz2',
  TarXz: 'tar.xz',
  TarZst: 'tar.zst',
  Zip: 'zip',
};

describe('archive bytes', () => {
  let tempDir;
  let archives;

  before(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-bytes-'));
    const source = path.join(tempDir, 'source');
    fs.mkdirSync(source);
    fs.writeFileSync(path.join(source, 'a.txt'), 'alpha');
    fs.writeFileSync(path.join(source, 'b.txt'), 'bravo');
    archives = {};
    for (const [format, extension] of Object.entries(EXTENSIONS)) {
      const archivePath = path.join(tempDir, `archive.${extension}`);
      createArchiveSync(archivePath, [source]);
      archives[format] = { path: archivePath, bytes: fs.readFileSync(archivePath) };
    }
    const sevenZ = path.join(FIXTURES, 'solid.7z');
    archives.SevenZ = { path: sevenZ, bytes: fs.readFileSync(sevenZ) };
  });

  after(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('detects every format', async () => {
    for (const [format, archive] of Object.entries(archives)) {
      const manifest = await listArchiveBytes(archive.bytes);
      assert.strictEqual(manifest.format, format);
      assert.ok(manifest.entries.length > 0, format);
      assert.strictEqual(listArchiveBytesSync(archive.bytes).format, format);
    }
  });

  it('lists the same entries as the path API', async () => {
    for (const [format, archive] of Object.entries(archives)) {
      const expected = await listArchive(archive.path);
      const actual = await listArchiveBytes(archive.bytes);
      assert.deepStrictEqual(
        actual.entries.map((entry) => entry.path),
        expected.entries.map((entry) => entry.path),
        format
      );
    }
  });

  it('accepts a plain Uint8Array', async () => {
    const bytes = new Uint8Array(archives.Zip.bytes);
    assert.strictEqual((await listArchiveBytes(bytes)).format, 'Zip');
  });

  it('honours an explicit format', async () => {
    const manifest = await listArchiveBytes(archives.Tar.bytes, null, 'Tar');
    assert.strictEqual(manifest.format, 'Tar');
  });

  it('rejects an explicit format that does not match the bytes', async () => {
    await assert.rejects(listArchiveBytes(archives.Zip.bytes, null, 'Tar'));
  });

  it('rejects an unknown format name at the argument boundary', () => {
    assert.throws(() => listArchiveBytes(archives.Tar.bytes, null, 'tar.gz'), {
      code: 'InvalidArg',
    });
  });

  it('rejects undetectable bytes as UNKNOWN_FORMAT', async () => {
    for (const bytes of [Buffer.alloc(0), Buffer.from('not an archive'), Buffer.alloc(1024)]) {
      await assert.rejects(listArchiveBytes(bytes), { code: 'UNKNOWN_FORMAT' });
      assert.throws(() => listArchiveBytesSync(bytes), { code: 'UNKNOWN_FORMAT' });
    }
  });

  it('honours the SecurityConfig', async () => {
    const config = new SecurityConfig().withMaxFileCount(1);
    await assert.rejects(listArchiveBytes(archives.Tar.bytes, config), {
      code: 'QUOTA_EXCEEDED',
    });
  });

  it('verifies a clean archive', async () => {
    for (const format of ['Tar', 'TarGz', 'Zip']) {
      const report = await verifyArchiveBytes(archives[format].bytes);
      assert.strictEqual(report.status, 'PASS', format);
      assert.strictEqual(report.integrityStatus, 'SKIPPED', format);
      assert.strictEqual(verifyArchiveBytesSync(archives[format].bytes).status, 'PASS');
    }
  });

  it('verifies with options and an explicit format', async () => {
    const options = new VerificationOptions().withIntegrityCheck();
    const report = await verifyArchiveBytes(archives.Zip.bytes, null, options, 'Zip');
    assert.strictEqual(report.integrityStatus, 'OK');
  });
});
