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

function tarEntry(name, text) {
  const data = Buffer.from(text);
  const header = Buffer.alloc(512);
  header.write(name, 0);
  header.write('0000644\0', 100);
  header.write('0000000\0', 108);
  header.write('0000000\0', 116);
  header.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  header.write('00000000000\0', 136);
  header.write('0', 156);
  header.write('ustar\0', 257);
  header.write('00', 263);
  header.fill(0x20, 148, 156);
  const sum = header.reduce((acc, byte) => acc + byte, 0);
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
  const padded = Buffer.alloc(Math.ceil(data.length / 512) * 512);
  data.copy(padded);
  return Buffer.concat([header, padded]);
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

  describe('withMarkPropagation()', () => {
    it("should default to 'never'", () => {
      assert.strictEqual(new ExtractionOptions().markPropagation, 'never');
      assert.strictEqual(ExtractionOptions.default().markPropagation, 'never');
    });

    it('should accept every policy and read it back', () => {
      const opts = new ExtractionOptions();
      for (const policy of ['when_marked', 'never']) {
        assert.strictEqual(opts.withMarkPropagation(policy), opts);
        assert.strictEqual(opts.markPropagation, policy);
      }
    });

    it('should throw on a missing, null or unknown policy and keep the previous one', () => {
      const opts = new ExtractionOptions().withMarkPropagation('when_marked');
      assert.throws(() => opts.withMarkPropagation());
      assert.throws(() => opts.withMarkPropagation(null));
      assert.throws(() => opts.withMarkPropagation('when-marked'), { code: 'InvalidArg' });
      assert.throws(() => opts.withMarkPropagation('always'), { code: 'InvalidArg' });
      assert.strictEqual(opts.markPropagation, 'when_marked');
    });

    it('should report not_requested by default and a stated source otherwise', () => {
      const tempDir = createTempDir();
      try {
        const archive = path.join(tempDir, 'a.tar.gz');
        createValidArchive(archive, tempDir);

        const plain = extractArchiveSync(archive, path.join(tempDir, 'plain'));
        assert.strictEqual(plain.markPropagation, 'not_requested');

        const options = new ExtractionOptions().withMarkPropagation('when_marked');
        const marked = extractArchiveSync(archive, path.join(tempDir, 'marked'), null, options);
        assert.ok(['unmarked', 'unsupported_platform'].includes(marked.markPropagation));
        assert.strictEqual(marked.marksWritten, 0);
        assert.strictEqual(marked.marksFailed, 0);
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });

  describe('withStaging()', () => {
    it("should default to 'in_place'", () => {
      assert.strictEqual(new ExtractionOptions().staging, 'in_place');
    });

    it('should accept every mode and read it back', () => {
      const opts = new ExtractionOptions();
      for (const mode of ['atomic', 'atomic_replace', 'in_place']) {
        assert.strictEqual(opts.withStaging(mode), opts);
        assert.strictEqual(opts.staging, mode);
      }
    });

    it('should throw on a missing, null or unknown mode and keep the previous one', () => {
      const opts = new ExtractionOptions().withStaging('atomic');
      assert.throws(() => opts.withStaging());
      assert.throws(() => opts.withStaging(undefined));
      assert.throws(() => opts.withStaging(null));
      assert.throws(() => opts.withStaging(true), { code: 'StringExpected' });
      assert.throws(() => opts.withStaging('swap'), { code: 'InvalidArg' });
      assert.strictEqual(opts.staging, 'atomic', 'a rejected call must not change the mode');
    });

    it('should no longer expose the atomic boolean', () => {
      const opts = new ExtractionOptions();
      assert.strictEqual('atomic' in opts, false);
      assert.strictEqual(typeof opts.withAtomic, 'undefined');
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

  describe('existingFiles on a populated destination', () => {
    function extractWith(policy) {
      const options = new ExtractionOptions().withExistingFiles(policy);
      return extractArchiveSync(archivePath, outputDir, null, options);
    }

    beforeEach(() => {
      extractArchiveSync(archivePath, outputDir);
    });

    it("'skip' keeps the occupant and counts a skip", () => {
      const report = extractWith('skip');
      assert.strictEqual(report.filesExtracted, 0);
      assert.strictEqual(report.filesSkipped, 1);
    });

    it("'overwrite' replaces the occupant", () => {
      const report = extractWith('overwrite');
      assert.strictEqual(report.filesExtracted, 1);
    });

    it("'refuse' fails with OUTPUT_EXISTS and leaves the occupant untouched", () => {
      const occupant = path.join(outputDir, 'hello.txt');
      fs.writeFileSync(occupant, 'mine');
      assert.throws(
        () => extractWith('refuse'),
        (err) => {
          assert.strictEqual(err.code, 'OUTPUT_EXISTS');
          assert.strictEqual(path.basename(err.path), path.basename(outputDir));
          assert.deepStrictEqual(err.conflicts, ['hello.txt']);
          return true;
        }
      );
      assert.strictEqual(fs.readFileSync(occupant, 'utf8'), 'mine');
    });
  });

  describe('staging on a populated destination', () => {
    function extractWith(mode, destination = outputDir) {
      const options = new ExtractionOptions().withStaging(mode);
      return extractArchiveSync(archivePath, destination, null, options);
    }

    it("'atomic' refuses a destination that holds content before extracting", () => {
      fs.writeFileSync(path.join(outputDir, 'stale.txt'), 'old');
      assert.throws(() => extractWith('atomic'), { code: 'OUTPUT_EXISTS' });
      assert.deepStrictEqual(fs.readdirSync(outputDir), ['stale.txt']);
    });

    it("'atomic' extracts into a destination that does not exist", () => {
      const fresh = path.join(tempDir, 'fresh');
      assert.strictEqual(extractWith('atomic', fresh).filesExtracted, 1);
      assert.ok(fs.existsSync(path.join(fresh, 'hello.txt')));
    });

    it("'atomic_replace' swaps the staged tree over an existing destination", () => {
      const destination = path.join(tempDir, 'replace-me');
      fs.mkdirSync(destination);
      fs.writeFileSync(path.join(destination, 'stale.txt'), 'old');
      const report = extractWith('atomic_replace', destination);
      assert.strictEqual(report.filesExtracted, 1);
      assert.deepStrictEqual(fs.readdirSync(destination), ['hello.txt']);
    });

    it("'atomic_replace' refuses a directory that contains the archive", () => {
      assert.throws(
        () => extractWith('atomic_replace', tempDir),
        (err) => {
          assert.strictEqual(err.code, 'INVALID_CONFIGURATION');
          assert.strictEqual(err.setting, 'output_path');
          assert.strictEqual(err.protectedPath, 'archive_ancestor');
          return true;
        }
      );
      assert.ok(fs.existsSync(archivePath), 'the archive must survive');
    });
  });

  describe('refuse semantics', () => {
    it('lists the conflicting entries and leaves the occupant untouched', () => {
      extractArchiveSync(archivePath, outputDir);
      const occupant = path.join(outputDir, 'hello.txt');
      fs.writeFileSync(occupant, 'mine');
      const options = new ExtractionOptions().withExistingFiles('refuse');
      assert.throws(
        () => extractArchiveSync(archivePath, outputDir, null, options),
        (err) => {
          assert.strictEqual(err.code, 'OUTPUT_EXISTS');
          assert.deepStrictEqual(err.conflicts, ['hello.txt']);
          return true;
        }
      );
      assert.strictEqual(fs.readFileSync(occupant, 'utf8'), 'mine');
    });

    it('skips and counts an in-archive duplicate instead of refusing it', () => {
      const duplicates = path.join(tempDir, 'dup.tar');
      fs.writeFileSync(
        duplicates,
        Buffer.concat([tarEntry('a.txt', 'first'), tarEntry('a.txt', 'second'), Buffer.alloc(1024)])
      );
      const options = new ExtractionOptions().withExistingFiles('refuse');
      const report = extractArchiveSync(duplicates, outputDir, null, options);
      assert.strictEqual(report.filesExtracted, 1);
      assert.strictEqual(report.filesSkipped, 1);
      assert.strictEqual(fs.readFileSync(path.join(outputDir, 'a.txt'), 'utf8'), 'first');
    });
  });

  it('should extract without options (null) as before', () => {
    const report = extractArchiveSync(archivePath, outputDir, null, null);
    assert.strictEqual(report.filesExtracted, 1);
  });
});
