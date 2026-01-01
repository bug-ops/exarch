/**
 * Tests for archive extraction functions
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
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

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('should extract a valid archive', async () => {
    createValidArchive(archivePath, tempDir);

    const report = await extractArchive(archivePath, outputDir);

    assert.strictEqual(report.filesExtracted, 1);
    assert.ok(report.bytesWritten >= 13);
    assert.ok(report.durationMs >= 0);

    // Verify extracted file exists and has correct content
    const extractedFile = path.join(outputDir, 'hello.txt');
    assert.ok(fs.existsSync(extractedFile), 'Extracted file should exist');
    const content = fs.readFileSync(extractedFile, 'utf8');
    assert.strictEqual(content, 'Hello, World!');
  });

  it('should accept custom SecurityConfig', async () => {
    createValidArchive(archivePath, tempDir);

    const config = new SecurityConfig();
    config.setMaxFileSize(1024 * 1024);
    const report = await extractArchive(archivePath, outputDir, config);

    assert.ok(report.filesExtracted >= 1);
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

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('should extract a valid archive synchronously', () => {
    createValidArchive(archivePath, tempDir);

    const report = extractArchiveSync(archivePath, outputDir);

    assert.strictEqual(report.filesExtracted, 1);
    assert.ok(report.bytesWritten >= 13);

    // Verify extracted file exists and has correct content
    const extractedFile = path.join(outputDir, 'hello.txt');
    assert.ok(fs.existsSync(extractedFile), 'Extracted file should exist');
    const content = fs.readFileSync(extractedFile, 'utf8');
    assert.strictEqual(content, 'Hello, World!');
  });

  it('should accept custom SecurityConfig', () => {
    createValidArchive(archivePath, tempDir);

    const config = new SecurityConfig();
    config.setMaxFileCount(100);
    const report = extractArchiveSync(archivePath, outputDir, config);

    assert.ok(report.filesExtracted >= 1);
  });
});
