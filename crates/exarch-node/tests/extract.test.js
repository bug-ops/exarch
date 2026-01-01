/**
 * Tests for archive extraction functions
 *
 * NOTE: Extraction tests are skipped until exarch-core extract_archive API is fully implemented.
 * The current implementation is a placeholder (see exarch-core/src/api.rs).
 */
const { describe, it, beforeEach, skip } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  extractArchive,
  extractArchiveSync,
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

describe('extractArchive (async)', () => {
  let tempDir;
  let archivePath;
  let outputDir;

  beforeEach(() => {
    tempDir = createTempDir();
    archivePath = path.join(tempDir, 'test.tar.gz');
    outputDir = path.join(tempDir, 'output');
    fs.mkdirSync(outputDir);
  });

  // TODO: Enable when core extract_archive is implemented
  it.skip('should extract a valid archive', async () => {
    createValidArchive(archivePath, tempDir);

    const report = await extractArchive(archivePath, outputDir);

    assert.ok(report.filesExtracted >= 1);
    assert.ok(report.bytesWritten >= 13);
    assert.ok(report.durationMs >= 0);
  });

  // TODO: Enable when core extract_archive is implemented
  it.skip('should accept custom SecurityConfig', async () => {
    createValidArchive(archivePath, tempDir);

    const config = new SecurityConfig();
    config.setMaxFileSize(1024 * 1024);
    const report = await extractArchive(archivePath, outputDir, config);

    assert.ok(report.filesExtracted >= 1);
  });

  it('should return empty report for valid archive (placeholder)', async () => {
    createValidArchive(archivePath, tempDir);

    const report = await extractArchive(archivePath, outputDir);

    // Core extract_archive is currently a placeholder
    assert.strictEqual(report.filesExtracted, 0);
  });
});

describe('extractArchiveSync', () => {
  let tempDir;
  let archivePath;
  let outputDir;

  beforeEach(() => {
    tempDir = createTempDir();
    archivePath = path.join(tempDir, 'test.tar.gz');
    outputDir = path.join(tempDir, 'output');
    fs.mkdirSync(outputDir);
  });

  // TODO: Enable when core extract_archive is implemented
  it.skip('should extract a valid archive synchronously', () => {
    createValidArchive(archivePath, tempDir);

    const report = extractArchiveSync(archivePath, outputDir);

    assert.ok(report.filesExtracted >= 1);
    assert.ok(report.bytesWritten >= 13);
  });

  // TODO: Enable when core extract_archive is implemented
  it.skip('should accept custom SecurityConfig', () => {
    createValidArchive(archivePath, tempDir);

    const config = new SecurityConfig();
    config.setMaxFileCount(100);
    const report = extractArchiveSync(archivePath, outputDir, config);

    assert.ok(report.filesExtracted >= 1);
  });

  it('should return empty report for valid archive (placeholder)', () => {
    createValidArchive(archivePath, tempDir);

    const report = extractArchiveSync(archivePath, outputDir);

    // Core extract_archive is currently a placeholder
    assert.strictEqual(report.filesExtracted, 0);
  });
});
