/**
 * Tests for extractArchiveWithProgress, including the #465 regression:
 * a throwing progress callback must reject the returned promise instead of
 * crashing the process via an uncatchable `uncaughtException`.
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const {
  extractArchiveWithProgress,
  createArchiveSync,
  SecurityConfig,
} = require('../index.js');

function createTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-progress-test-'));
}

function createValidArchive(archivePath, tempDir) {
  const sourceDir = path.join(tempDir, 'source');
  fs.mkdirSync(sourceDir);
  fs.writeFileSync(path.join(sourceDir, 'hello.txt'), 'Hello, World!');
  fs.writeFileSync(path.join(sourceDir, 'world.txt'), 'Another file');
  createArchiveSync(archivePath, [sourceDir]);
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
    createValidArchive(archivePath, tempDir);
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('reports progress for each entry and resolves with the report', async () => {
    const calls = [];
    const report = await extractArchiveWithProgress(
      archivePath,
      outputDir,
      null,
      null,
      (err, arg) => {
        calls.push([err, arg]);
      },
    );

    assert.strictEqual(report.filesExtracted, 2);
    assert.strictEqual(calls.length, 2);
    for (const [err, [entryPath, , , bytesWritten]] of calls) {
      assert.strictEqual(err, null);
      assert.ok(typeof entryPath === 'string' && entryPath.length > 0);
      assert.strictEqual(bytesWritten, 0);
    }
  });

  it('extracts successfully when no progress callback is passed', async () => {
    const report = await extractArchiveWithProgress(archivePath, outputDir);
    assert.strictEqual(report.filesExtracted, 2);
  });

  // Regression test for #465: a throwing progress callback must reject the
  // promise instead of crashing the process uncatchably.
  it('rejects the promise instead of throwing when the callback throws', async () => {
    await assert.rejects(
      () =>
        extractArchiveWithProgress(archivePath, outputDir, null, null, () => {
          throw new Error('boom from progress callback');
        }),
      (err) => {
        assert.strictEqual(err.cause.message, 'boom from progress callback');
        return true;
      },
    );
  });

  // Regression test for the #465 follow-up: when the callback throws but
  // extraction succeeded, the report must not be silently discarded — files
  // really were written to disk and the caller may need to clean them up.
  it('preserves the extraction report when the callback throws', async () => {
    await assert.rejects(
      () =>
        extractArchiveWithProgress(archivePath, outputDir, null, null, () => {
          throw new Error('boom from progress callback');
        }),
      (err) => {
        assert.ok(
          err.message.startsWith('PROGRESS_CALLBACK_ERROR:'),
          `expected PROGRESS_CALLBACK_ERROR prefix, got: ${err.message}`,
        );
        assert.match(err.message, /filesExtracted=2/);
        assert.match(err.message, /bytesWritten=\d+/);
        // The throw's own text and stack must stay out of the parseable
        // message — `cause` is the only channel for the callback's detail.
        assert.ok(!err.message.includes('boom from progress callback'));
        assert.strictEqual(err.cause.message, 'boom from progress callback');
        return true;
      },
    );
    assert.ok(fs.existsSync(path.join(outputDir, 'hello.txt')));
  });

  // Regression test for the #465 follow-up: a throwing progress callback must
  // not mask a core error. Callers grep the error-code prefix to detect
  // security violations, so the core error stays primary and the callback
  // throw is reported alongside it.
  it('surfaces the core error when the callback also throws', async () => {
    const config = new SecurityConfig().setMaxFileCount(1);

    await assert.rejects(
      () =>
        extractArchiveWithProgress(archivePath, outputDir, config, null, () => {
          throw new Error('boom from progress callback');
        }),
      (err) => {
        assert.ok(
          err.message.startsWith('QUOTA_EXCEEDED:'),
          `core error code must stay primary, got: ${err.message}`,
        );
        assert.match(err.message, /file count/);
        assert.ok(err.message.endsWith(' | progressCallbackError: see cause'));
        assert.ok(!err.message.includes('boom from progress callback'));
        assert.strictEqual(err.cause.message, 'boom from progress callback');
        return true;
      },
    );
  });

  // Regression test for #465, pinning the actual process-level behavior: run
  // in a child process so a crash (uncaughtException, non-zero exit) can be
  // distinguished from a clean rejection without taking down this test run.
  it('does not crash the host process when the callback throws (child process)', () => {
    const script = `
      const exarch = require(${JSON.stringify(path.join(__dirname, '..', 'index.js'))});
      exarch.extractArchiveWithProgress(
        ${JSON.stringify(archivePath)},
        ${JSON.stringify(outputDir)},
        null,
        null,
        () => { throw new Error('boom from progress callback'); },
      ).then(
        () => { console.log('UNEXPECTED_RESOLVE'); process.exit(2); },
        (err) => { console.log('REJECTED:' + err.cause.message); },
      );
    `;

    const result = spawnSync(process.execPath, ['-e', script], {
      encoding: 'utf8',
    });

    assert.strictEqual(
      result.status,
      0,
      `expected clean exit, got status=${result.status}, stderr=${result.stderr}`,
    );
    assert.ok(
      result.stdout.includes('REJECTED:boom from progress callback'),
      `expected rejection to be observed, got stdout=${result.stdout}`,
    );
    assert.ok(
      !result.stderr.includes('Uncaught'),
      `expected no uncaught exception, got stderr=${result.stderr}`,
    );
  });

  // KNOWN LIMITATION (not a passing "this works" test): throwing a primitive
  // (string/number/boolean) from the progress callback still crashes the host
  // process uncatchably, so #465 is only fixed for non-primitive throws.
  //
  // Upstream bug in napi-rs 3.12.0 (threadsafe_function.rs:864): the dispatcher
  // in `call_async_catch` overwrites its status with the result of
  // `napi_create_reference()`, which returns `napi_invalid_arg` for a primitive
  // exception value (a weak ref to a primitive is not possible). It correctly
  // falls back to `maybe_ref: None` and still delivers `Err` to the channel,
  // but the non-ok status then reaches `napi_fatal_exception`. The wasm branch
  // of the same function already resets `status = napi_ok`.
  //
  // This test pins the CURRENT behavior. A napi-rs upgrade that fixes the bug
  // will make it fail — that is the intended signal: flip the assertions to
  // match the clean-rejection case above and drop the caveat from the
  // `extractArchiveWithProgress` docs.
  it('KNOWN LIMITATION: crashes the host process when the callback throws a primitive (child process)', () => {
    const script = `
      const exarch = require(${JSON.stringify(path.join(__dirname, '..', 'index.js'))});
      exarch.extractArchiveWithProgress(
        ${JSON.stringify(archivePath)},
        ${JSON.stringify(outputDir)},
        null,
        null,
        () => { throw 'oops'; },
      ).then(
        () => { console.log('UNEXPECTED_RESOLVE'); },
        () => { console.log('UNEXPECTED_REJECT'); },
      );
    `;

    const result = spawnSync(process.execPath, ['-e', script], {
      encoding: 'utf8',
    });

    assert.notStrictEqual(
      result.status,
      0,
      'primitive throws are expected to still crash the process; if this now ' +
        'exits cleanly, the upstream napi-rs bug is fixed — update this test ' +
        'and the extractArchiveWithProgress docs',
    );
    assert.match(result.stderr, /Call JavaScript callback failed/);
    // The promise never settles, so neither handler runs.
    assert.strictEqual(result.stdout.trim(), '');
  });
});
