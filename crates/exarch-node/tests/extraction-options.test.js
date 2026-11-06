/**
 * Tests for ExtractionOptions class
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { ExtractionOptions, extractArchiveSync, createArchiveSync } = require('../index.js');

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
    it("should create options with existingFiles defaulting to 'skip'", () => {
      const opts = new ExtractionOptions();
      assert.strictEqual(opts.existingFiles, 'skip');
    });
  });

  describe('static default()', () => {
    it('should return options equivalent to constructor', () => {
      const opts = ExtractionOptions.default();
      assert.strictEqual(opts.existingFiles, 'skip');
    });
  });

  describe('withExistingFiles()', () => {
    it('should accept every policy and read it back', () => {
      const opts = new ExtractionOptions();
      for (const policy of ['overwrite', 'refuse', 'skip']) {
        assert.strictEqual(opts.withExistingFiles(policy), opts);
        assert.strictEqual(opts.existingFiles, policy);
      }
    });

    it('should throw on a missing, null or unknown policy and keep the previous one', () => {
      const opts = new ExtractionOptions();
      opts.withExistingFiles('refuse');
      assert.throws(() => opts.withExistingFiles());
      assert.throws(() => opts.withExistingFiles(undefined));
      assert.throws(() => opts.withExistingFiles(null));
      assert.throws(() => opts.withExistingFiles('replace'), { code: 'InvalidArg' });
      assert.strictEqual(
        opts.existingFiles,
        'refuse',
        'a rejected call must not silently change the policy'
      );
    });

    it('should no longer expose the skipDuplicates boolean', () => {
      const opts = new ExtractionOptions();
      assert.strictEqual('skipDuplicates' in opts, false);
      assert.strictEqual(typeof opts.withSkipDuplicates, 'undefined');
    });
  });

  describe('build()', () => {
    it('should return self for builder consistency', () => {
      const opts = new ExtractionOptions();
      const result = opts.build();
      assert.strictEqual(result, opts);
    });
  });

  describe('withAtomic()', () => {
    it('should have atomic defaulting to false', () => {
      const opts = new ExtractionOptions();
      assert.strictEqual(opts.atomic, false);
    });

    it('should set atomic to true via withAtomic', () => {
      const opts = new ExtractionOptions();
      opts.withAtomic(true);
      assert.strictEqual(opts.atomic, true);
    });

    it('should set atomic back to false via withAtomic', () => {
      const opts = new ExtractionOptions();
      opts.withAtomic(true);
      opts.withAtomic(false);
      assert.strictEqual(opts.atomic, false);
    });

    it('should throw when withAtomic is called with no argument, undefined, or null', () => {
      const opts = new ExtractionOptions();
      opts.withAtomic(true);

      assert.throws(() => opts.withAtomic());
      assert.throws(() => opts.withAtomic(undefined));
      assert.throws(() => opts.withAtomic(null));
      assert.strictEqual(opts.atomic, true, 'a rejected call must not silently flip the flag');
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

  it("should extract with existingFiles 'overwrite' on a non-duplicate archive", () => {
    const opts = new ExtractionOptions();
    opts.withExistingFiles('overwrite');
    const report = extractArchiveSync(archivePath, outputDir, null, opts);

    assert.strictEqual(report.filesExtracted, 1);
  });

  it('should extract without options (null) as before', () => {
    const report = extractArchiveSync(archivePath, outputDir, null, null);
    assert.strictEqual(report.filesExtracted, 1);
  });
});
