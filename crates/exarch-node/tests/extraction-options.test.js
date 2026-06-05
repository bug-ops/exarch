/**
 * Tests for ExtractionOptions class
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  ExtractionOptions,
  extractArchiveSync,
  createArchiveSync,
} = require('../index.js');

function createTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-test-'));
}

function createValidArchive(archivePath, tempDir) {
  const sourceDir = path.join(tempDir, 'source');
  fs.mkdirSync(sourceDir);
  fs.writeFileSync(path.join(sourceDir, 'hello.txt'), 'Hello, World!');
  createArchiveSync(archivePath, [sourceDir]);
}

describe('ExtractionOptions', () => {
  describe('constructor', () => {
    it('should create options with skipDuplicates defaulting to true', () => {
      const opts = new ExtractionOptions();
      assert.strictEqual(opts.skipDuplicates, true);
    });
  });

  describe('static default()', () => {
    it('should return options equivalent to constructor', () => {
      const opts = ExtractionOptions.default();
      assert.strictEqual(opts.skipDuplicates, true);
    });
  });

  describe('withSkipDuplicates()', () => {
    it('should set skipDuplicates to false', () => {
      const opts = new ExtractionOptions();
      opts.withSkipDuplicates(false);
      assert.strictEqual(opts.skipDuplicates, false);
    });

    it('should set skipDuplicates to true', () => {
      const opts = new ExtractionOptions();
      opts.withSkipDuplicates(false);
      opts.withSkipDuplicates(true);
      assert.strictEqual(opts.skipDuplicates, true);
    });

    it('should default to true when called with no argument', () => {
      const opts = new ExtractionOptions();
      opts.withSkipDuplicates(false);
      opts.withSkipDuplicates();
      assert.strictEqual(opts.skipDuplicates, true);
    });
  });

  describe('build()', () => {
    it('should return self for builder consistency', () => {
      const opts = new ExtractionOptions();
      const result = opts.build();
      assert.strictEqual(result, opts);
    });
  });
});

describe('extractArchiveSync with ExtractionOptions', () => {
  let tempDir;
  let archivePath;
  let outputDir;

  beforeEach(() => {
    tempDir = createTempDir();
    archivePath = path.join(tempDir, 'test.tar.gz');
    outputDir = path.join(tempDir, 'output');
    fs.mkdirSync(outputDir);
    createValidArchive(archivePath, tempDir);
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('should extract with default ExtractionOptions', () => {
    const opts = new ExtractionOptions();
    const report = extractArchiveSync(archivePath, outputDir, null, opts);

    assert.strictEqual(report.filesExtracted, 1);
    assert.ok(report.bytesWritten >= 13);
  });

  it('should extract with skip_duplicates=false on non-duplicate archive', () => {
    const opts = new ExtractionOptions();
    opts.withSkipDuplicates(false);
    const report = extractArchiveSync(archivePath, outputDir, null, opts);

    assert.strictEqual(report.filesExtracted, 1);
  });

  it('should extract without options (null) as before', () => {
    const report = extractArchiveSync(archivePath, outputDir, null, null);
    assert.strictEqual(report.filesExtracted, 1);
  });
});
