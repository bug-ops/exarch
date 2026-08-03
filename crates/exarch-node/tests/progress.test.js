/**
 * Tests for the *WithProgress functions (extractArchiveWithProgress,
 * createArchiveWithProgress, createArchiveWithProgressSync).
 *
 * Covers both the callback-invoked path (per-entry callback shape) and the
 * progress=null/undefined path (callback omission must not throw).
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  extractArchiveWithProgress,
  createArchiveWithProgress,
  createArchiveWithProgressSync,
  createArchiveSync,
} = require('../index.js');

function createTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-progress-test-'));
}

function createTestFiles(dir) {
  fs.writeFileSync(path.join(dir, 'file1.txt'), 'Content of file 1');
  fs.writeFileSync(path.join(dir, 'file2.txt'), 'Content of file 2');
}

// The progress ThreadsafeFunction uses the standard napi (err, arg) calling
// convention: err is always null (Ok is used on the Rust side), and arg is
// the [path, total, current, bytesWritten] tuple documented in index.d.ts.
function assertProgressCallShape(err, arg) {
  assert.strictEqual(err, null);
  const [entryPath, total, current, bytesWritten] = arg;
  assert.strictEqual(typeof entryPath, 'string');
  assert.strictEqual(typeof total, 'number');
  assert.strictEqual(typeof current, 'number');
  assert.strictEqual(typeof bytesWritten, 'number');
}

// ThreadsafeFunction dispatches callbacks via NonBlocking mode, so calls
// queued during a *Sync function are only flushed on later event loop turns
// even though the Rust call itself already returned. Poll until the queued
// callbacks have run instead of guessing how many turns are needed.
async function waitUntil(conditionFn, { timeoutMs = 2000, intervalMs = 5 } = {}) {
  const start = Date.now();
  while (!conditionFn()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error('timed out waiting for condition');
    }
    await new Promise((resolve) => {
      setTimeout(resolve, intervalMs);
    });
  }
}

describe('extractArchiveWithProgress', () => {
  let tempDir;
  let archivePath;
  let outputDir;

  beforeEach(() => {
    tempDir = createTempDir();
    archivePath = path.join(tempDir, 'test.tar.gz');
    outputDir = path.join(tempDir, 'output');
    fs.mkdirSync(outputDir);

    const sourceDir = path.join(tempDir, 'source');
    fs.mkdirSync(sourceDir);
    createTestFiles(sourceDir);
    createArchiveSync(archivePath, [sourceDir]);
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('invokes the callback exactly once per entry with (path, total, current, bytesWritten)', async () => {
    const calls = [];
    const report = await extractArchiveWithProgress(
      archivePath,
      outputDir,
      null,
      null,
      (err, arg) => {
        calls.push(arg);
        assertProgressCallShape(err, arg);
      }
    );

    assert.ok(report.filesExtracted >= 1);
    // Fixture has exactly the 2 files from createTestFiles; extraction does
    // not surface a directory entry, so the callback fires exactly twice.
    assert.strictEqual(calls.length, 2, 'expected exactly one callback per extracted entry');

    // current is a 1-based, gapless sequence in call order.
    const currents = calls.map(([, , current]) => current);
    assert.deepStrictEqual(currents, [1, 2]);
  });

  it('extracts normally when progress is null', async () => {
    const report = await extractArchiveWithProgress(archivePath, outputDir, null, null, null);

    assert.ok(report.filesExtracted >= 1);
    assert.ok(fs.existsSync(path.join(outputDir, 'file1.txt')));
  });

  it('extracts normally when progress is undefined', async () => {
    const report = await extractArchiveWithProgress(archivePath, outputDir);

    assert.ok(report.filesExtracted >= 1);
    assert.ok(fs.existsSync(path.join(outputDir, 'file1.txt')));
  });
});

describe('createArchiveWithProgress (async)', () => {
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

  it('invokes the callback exactly once per entry with (path, total, current, bytesWritten)', async () => {
    const calls = [];
    const report = await createArchiveWithProgress(outputPath, [sourceDir], null, (err, arg) => {
      calls.push(arg);
      assertProgressCallShape(err, arg);
    });

    assert.ok(report.filesAdded >= 2);
    assert.ok(fs.existsSync(outputPath));
    // Fixture has the 2 files from createTestFiles plus the source directory
    // itself, which creation also emits an entry for (unlike extraction).
    assert.strictEqual(calls.length, 3, 'expected exactly one callback per created entry');

    const currents = calls.map(([, , current]) => current);
    assert.deepStrictEqual(currents, [1, 2, 3]);
  });

  it('creates the archive normally when progress is null', async () => {
    const report = await createArchiveWithProgress(outputPath, [sourceDir], null, null);

    assert.ok(report.filesAdded >= 2);
    assert.ok(fs.existsSync(outputPath));
  });

  it('creates the archive normally when progress is undefined', async () => {
    const report = await createArchiveWithProgress(outputPath, [sourceDir]);

    assert.ok(report.filesAdded >= 2);
    assert.ok(fs.existsSync(outputPath));
  });
});

describe('createArchiveWithProgressSync', () => {
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

  it('invokes the callback exactly once per entry with (path, total, current, bytesWritten)', async () => {
    const calls = [];
    const report = createArchiveWithProgressSync(outputPath, [sourceDir], null, (err, arg) => {
      calls.push(arg);
      assertProgressCallShape(err, arg);
    });

    assert.ok(report.filesAdded >= 2);
    assert.ok(fs.existsSync(outputPath));

    // The ThreadsafeFunction is dispatched via NonBlocking mode, so queued
    // calls are only flushed on later event loop turns even though this
    // *Sync call has already returned. Same fixture as the async variant:
    // the source directory plus its 2 files means 3 calls.
    await waitUntil(() => calls.length >= 3);
    assert.strictEqual(calls.length, 3, 'expected exactly one callback per created entry');

    const currents = calls.map(([, , current]) => current);
    assert.deepStrictEqual(currents, [1, 2, 3]);
  });

  it('creates the archive normally when progress is null', () => {
    const report = createArchiveWithProgressSync(outputPath, [sourceDir], null, null);

    assert.ok(report.filesAdded >= 2);
    assert.ok(fs.existsSync(outputPath));
  });

  it('creates the archive normally when progress is undefined', () => {
    const report = createArchiveWithProgressSync(outputPath, [sourceDir]);

    assert.ok(report.filesAdded >= 2);
    assert.ok(fs.existsSync(outputPath));
  });
});

describe('createArchiveWithProgress bytesWritten staleness (parity with exarch-python #285)', () => {
  let tempDir;

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('reports bytesWritten === 0 at entry start even after a large preceding entry', async () => {
    // Regression test for exarch-python#285, ported to exarch-node: the
    // Python PyProgressAdapter used to pass a stale bytesWritten (accumulated
    // from all previously written entries) at on_entry_start. The fix resets
    // the running per-entry byte counter to 0 before dispatching that event.
    // NodeProgressAdapter has the identical current_entry_bytes reset logic
    // (crates/exarch-node/src/lib.rs) and nothing previously guarded it here.
    tempDir = createTempDir();
    const sourceDir = path.join(tempDir, 'source');
    fs.mkdirSync(sourceDir);
    fs.writeFileSync(path.join(sourceDir, 'small.txt'), 'x'.repeat(1024));
    fs.writeFileSync(path.join(sourceDir, 'large.txt'), 'y'.repeat(100 * 1024));
    const outputPath = path.join(tempDir, 'two_files.tar.gz');

    // entryStartBytes[name] = bytesWritten received at that entry's first callback.
    const entryStartBytes = {};
    await createArchiveWithProgress(
      outputPath,
      [sourceDir],
      null,
      (_err, [entryPath, , , bytesWritten]) => {
        const name = entryPath.split('/').pop();
        if (!(name in entryStartBytes)) {
          entryStartBytes[name] = bytesWritten;
        }
      }
    );

    assert.ok('small.txt' in entryStartBytes, 'callback never fired for small.txt');
    assert.ok('large.txt' in entryStartBytes, 'callback never fired for large.txt');

    assert.strictEqual(
      entryStartBytes['small.txt'],
      0,
      'small.txt: expected bytesWritten=0 at entry start'
    );
    assert.strictEqual(
      entryStartBytes['large.txt'],
      0,
      'large.txt: expected bytesWritten=0 at entry start (stale value would indicate the #285-class bug)'
    );
  });
});
