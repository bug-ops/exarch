/**
 * Tests for listArchive and verifyArchive functions
 */
const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  listArchive,
  listArchiveSync,
  verifyArchive,
  verifyArchiveSync,
  createArchiveSync,
  SecurityConfig,
} = require('../index.js');

function createTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-test-'));
}

function createValidArchive(archivePath, tempDir) {
  // Create source files
  const sourceDir = path.join(tempDir, 'source');
  fs.mkdirSync(sourceDir);
  fs.writeFileSync(path.join(sourceDir, 'hello.txt'), 'Hello, World!');

  // Create archive using our library
  createArchiveSync(archivePath, [sourceDir]);
}

describe('listArchive (async)', () => {
  let tempDir;
  let archivePath;

  beforeEach(() => {
    tempDir = createTempDir();
    archivePath = path.join(tempDir, 'test.tar.gz');
  });

  it('should list archive contents', async () => {
    createValidArchive(archivePath, tempDir);

    const manifest = await listArchive(archivePath);

    assert.ok(manifest.totalEntries >= 1);
    assert.ok(manifest.entries.length >= 1);
    // Find the hello.txt entry
    const helloEntry = manifest.entries.find(e => e.path.endsWith('hello.txt'));
    assert.ok(helloEntry, 'should find hello.txt in archive');
    assert.strictEqual(helloEntry.entryType, 'File');
    assert.strictEqual(helloEntry.size, 13);
  });

  it('should accept custom SecurityConfig', async () => {
    createValidArchive(archivePath, tempDir);

    const config = new SecurityConfig();
    const manifest = await listArchive(archivePath, config);

    assert.ok(manifest.totalEntries >= 1);
  });

  it('should throw on non-existent archive', async () => {
    await assert.rejects(
      listArchive('/nonexistent/archive.tar.gz'),
      /IO_ERROR|No such file|not found/i
    );
  });
});

describe('listArchiveSync', () => {
  let tempDir;
  let archivePath;

  beforeEach(() => {
    tempDir = createTempDir();
    archivePath = path.join(tempDir, 'test.tar.gz');
  });

  it('should list archive contents synchronously', () => {
    createValidArchive(archivePath, tempDir);

    const manifest = listArchiveSync(archivePath);

    assert.ok(manifest.totalEntries >= 1);
    const helloEntry = manifest.entries.find(e => e.path.endsWith('hello.txt'));
    assert.ok(helloEntry, 'should find hello.txt in archive');
  });
});

describe('verifyArchive (async)', () => {
  let tempDir;
  let archivePath;

  beforeEach(() => {
    tempDir = createTempDir();
    archivePath = path.join(tempDir, 'test.tar.gz');
  });

  it('should verify a valid archive', async () => {
    createValidArchive(archivePath, tempDir);

    const report = await verifyArchive(archivePath);

    assert.ok(['PASS', 'WARNING'].includes(report.status));
    assert.ok(report.totalEntries >= 1);
    assert.ok(report.integrityStatus);
    assert.ok(report.securityStatus);
    assert.ok(Array.isArray(report.issues));
  });

  it('should accept custom SecurityConfig', async () => {
    createValidArchive(archivePath, tempDir);

    const config = new SecurityConfig();
    config.setMaxFileSize(1024);
    const report = await verifyArchive(archivePath, config);

    assert.ok(report.status);
  });

  it('should throw on non-existent archive', async () => {
    await assert.rejects(
      verifyArchive('/nonexistent/archive.tar.gz'),
      /IO_ERROR|No such file|not found/i
    );
  });
});

describe('verifyArchiveSync', () => {
  let tempDir;
  let archivePath;

  beforeEach(() => {
    tempDir = createTempDir();
    archivePath = path.join(tempDir, 'test.tar.gz');
  });

  it('should verify archive synchronously', () => {
    createValidArchive(archivePath, tempDir);

    const report = verifyArchiveSync(archivePath);

    assert.ok(['PASS', 'WARNING'].includes(report.status));
    assert.ok(report.totalEntries >= 1);
  });
});
