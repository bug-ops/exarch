/**
 * Tests for archive creation functions
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
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

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
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

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
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
    createArchiveSync(outputPath, [sourceDir], config);

    const manifest = listArchiveSync(outputPath);
    const logEntries = manifest.entries.filter((e) => e.path.endsWith('.log'));
    assert.strictEqual(logEntries.length, 0);
  });
});

describe('createArchive output handling', () => {
  let tempDir;
  let sourceDir;

  beforeEach(() => {
    tempDir = createTempDir();
    sourceDir = path.join(tempDir, 'source');
    fs.mkdirSync(sourceDir);
    createTestFiles(sourceDir);
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('leaves no archive behind when a source is missing', () => {
    const outputPath = path.join(tempDir, 'failed.tar.gz');
    assert.throws(() => createArchiveSync(outputPath, [path.join(tempDir, 'nope')]));
    assert.strictEqual(fs.existsSync(outputPath), false);
  });

  it('keeps an existing archive when creation fails', () => {
    const outputPath = path.join(tempDir, 'keep.tar.gz');
    fs.writeFileSync(outputPath, 'previous');
    assert.throws(() => createArchiveSync(outputPath, [path.join(tempDir, 'nope')]));
    assert.strictEqual(fs.readFileSync(outputPath, 'utf8'), 'previous');
  });

  it('reports excluded entries by reason', () => {
    fs.writeFileSync(path.join(sourceDir, 'debug.log'), 'log content');
    const config = new CreationConfig();
    config.addExcludePattern('*.log');
    const report = createArchiveSync(path.join(tempDir, 'skips.tar.gz'), [sourceDir], config);
    assert.ok(report.filesSkipped >= 1);
    assert.deepStrictEqual(
      report.skipped.counts.find((c) => c.kind === 'excluded'),
      { kind: 'excluded', count: report.filesSkipped }
    );
    assert.ok(
      report.skipped.sample.some((s) => s.path.endsWith('debug.log') && s.kind === 'excluded')
    );
  });

  for (const shape of ['*.m*', '?.txt', '[a', '{a,b}', '!a.txt', ' .env', 'a,b', '', '../x']) {
    it(`refuses the exclude pattern ${JSON.stringify(shape)} instead of silently excluding nothing`, () => {
      const config = new CreationConfig();
      const before = config.excludePatterns;
      assert.throws(() => config.addExcludePattern(shape), {
        code: 'INVALID_CONFIGURATION',
        setting: 'exclude_pattern',
      });
      assert.deepStrictEqual(config.excludePatterns, before);
    });
  }

  it('accepts the documented exclude pattern shapes', () => {
    const config = new CreationConfig();
    for (const shape of ['.git', 'temp*', '*.tmp', 'build/out']) {
      config.addExcludePattern(shape);
    }
    assert.ok(config.excludePatterns.includes('build/out'));
  });

  it('replaces an existing archive on success', () => {
    const outputPath = path.join(tempDir, 'replace.tar.gz');
    fs.writeFileSync(outputPath, 'previous');
    createArchiveSync(outputPath, [sourceDir]);
    assert.ok(listArchiveSync(outputPath).entries.length > 0);
  });

  it('overwrite: false refuses an existing output with OUTPUT_EXISTS', async () => {
    const outputPath = path.join(tempDir, 'exists.tar.gz');
    fs.writeFileSync(outputPath, 'previous');
    assert.throws(() => createArchiveSync(outputPath, [sourceDir], null, { overwrite: false }), {
      code: 'OUTPUT_EXISTS',
    });
    await assert.rejects(createArchive(outputPath, [sourceDir], null, { overwrite: false }), {
      code: 'OUTPUT_EXISTS',
    });
    assert.strictEqual(fs.readFileSync(outputPath, 'utf8'), 'previous');
  });

  it('overwrite: false creates a new output', () => {
    const outputPath = path.join(tempDir, 'fresh.tar.gz');
    createArchiveSync(outputPath, [sourceDir], null, { overwrite: false });
    assert.ok(listArchiveSync(outputPath).entries.length > 0);
  });

  it('format overrides the extension, so a ZIP-based name is written as a plain ZIP', () => {
    const outputPath = path.join(tempDir, 'bundle.apk');
    assert.throws(() => createArchiveSync(outputPath, [sourceDir]));
    createArchiveSync(outputPath, [sourceDir], null, { format: 'Zip' });
    assert.strictEqual(listArchiveSync(outputPath).format, 'Zip');
  });

  it('format SevenZ is not a creatable format and is refused at the boundary', () => {
    assert.throws(
      () => createArchiveSync(path.join(tempDir, 'a.7z'), [sourceDir], null, { format: 'SevenZ' }),
      { code: 'InvalidArg', message: /SevenZ.*CreatableFormat/ }
    );
  });

  for (const durability of ['synced', 'unsynced']) {
    it(`durability ${durability} creates the archive`, () => {
      const outputPath = path.join(tempDir, `${durability}.tar.gz`);
      createArchiveSync(outputPath, [sourceDir], null, { durability });
      assert.ok(listArchiveSync(outputPath).entries.length > 0);
    });
  }

  it('an unknown durability is refused at the boundary and writes nothing', () => {
    const outputPath = path.join(tempDir, 'never.tar.gz');
    assert.throws(() => createArchiveSync(outputPath, [sourceDir], null, { durability: 'fsync' }), {
      code: 'InvalidArg',
      message: /fsync.*Durability/,
    });
    assert.ok(!fs.existsSync(outputPath));
  });
});
