/**
 * Tests for archive creation functions
 */
const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  createArchive,
  createArchiveSync,
  listArchiveSync,
  CreationConfig,
} = require('../index.js');

function createTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-test-'));
}

function createTestFiles(dir) {
  fs.writeFileSync(path.join(dir, 'file1.txt'), 'Content of file 1');
  fs.writeFileSync(path.join(dir, 'file2.txt'), 'Content of file 2');

  const subdir = path.join(dir, 'subdir');
  fs.mkdirSync(subdir);
  fs.writeFileSync(path.join(subdir, 'nested.txt'), 'Nested file content');
}

describe('createArchive (async)', () => {
  let tempDir;
  let sourceDir;
  let outputPath;

  beforeEach(() => {
    tempDir = createTempDir();
    sourceDir = path.join(tempDir, 'source');
    fs.mkdirSync(sourceDir);
    createTestFiles(sourceDir);
    outputPath = path.join(tempDir, 'output.tar.gz');
  });

  it('should create a tar.gz archive', async () => {
    const report = await createArchive(outputPath, [sourceDir]);

    assert.ok(report.filesAdded >= 3);
    assert.ok(report.bytesWritten > 0);
    assert.ok(report.durationMs >= 0);
    assert.ok(fs.existsSync(outputPath));
    assert.ok(fs.statSync(outputPath).size > 0);
  });

  it('should create archive from multiple sources', async () => {
    const file1 = path.join(sourceDir, 'file1.txt');
    const file2 = path.join(sourceDir, 'file2.txt');

    const report = await createArchive(outputPath, [file1, file2]);

    assert.strictEqual(report.filesAdded, 2);
  });

  it('should accept custom CreationConfig', async () => {
    const config = new CreationConfig();
    config.setCompressionLevel(9);
    config.setIncludeHidden(false);

    const report = await createArchive(outputPath, [sourceDir], config);

    assert.ok(report.filesAdded > 0);
  });

  it('should throw on invalid source path', async () => {
    await assert.rejects(
      createArchive(outputPath, ['/nonexistent/path']),
      /IO_ERROR|No such file|not found/i
    );
  });

  it('should report warnings array', async () => {
    const report = await createArchive(outputPath, [sourceDir]);

    assert.ok(Array.isArray(report.warnings));
  });
});

describe('createArchiveSync', () => {
  let tempDir;
  let sourceDir;
  let outputPath;

  beforeEach(() => {
    tempDir = createTempDir();
    sourceDir = path.join(tempDir, 'source');
    fs.mkdirSync(sourceDir);
    createTestFiles(sourceDir);
    outputPath = path.join(tempDir, 'output.tar.gz');
  });

  it('should create archive synchronously', () => {
    const report = createArchiveSync(outputPath, [sourceDir]);

    assert.ok(report.filesAdded >= 3);
    assert.ok(fs.existsSync(outputPath));
  });

  it('should accept custom CreationConfig', () => {
    const config = new CreationConfig();
    config.setCompressionLevel(1);
    const report = createArchiveSync(outputPath, [sourceDir], config);

    assert.ok(report.filesAdded > 0);
  });

  it('should support exclude patterns', () => {
    fs.writeFileSync(path.join(sourceDir, 'debug.log'), 'log content');

    const config = new CreationConfig();
    config.addExcludePattern('*.log');
    const report = createArchiveSync(outputPath, [sourceDir], config);

    const manifest = listArchiveSync(outputPath);
    const logEntries = manifest.entries.filter(e => e.path.endsWith('.log'));
    assert.strictEqual(logEntries.length, 0);
  });
});
