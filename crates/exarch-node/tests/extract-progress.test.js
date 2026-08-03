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
const { extractArchiveWithProgress, createArchiveSync, SecurityConfig } = require('../index.js');

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
      }
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
      }
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
          `expected PROGRESS_CALLBACK_ERROR prefix, got: ${err.message}`
        );
        assert.match(err.message, /filesExtracted=2/);
        assert.match(err.message, /bytesWritten=\d+/);
        // The throw's own text and stack must stay out of the parseable
        // message — `cause` is the only channel for the callback's detail.
        assert.ok(!err.message.includes('boom from progress callback'));
        assert.strictEqual(err.cause.message, 'boom from progress callback');
        return true;
      }
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
          `core error code must stay primary, got: ${err.message}`
        );
        assert.match(err.message, /file count/);
        assert.ok(err.message.endsWith(' | progressCallbackError: see cause'));
        assert.ok(!err.message.includes('boom from progress callback'));
        assert.strictEqual(err.cause.message, 'boom from progress callback');
        return true;
      }
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
      `expected clean exit, got status=${result.status}, stderr=${result.stderr}`
    );
    assert.ok(
      result.stdout.includes('REJECTED:boom from progress callback'),
      `expected rejection to be observed, got stdout=${result.stdout}`
    );
    assert.ok(
      !result.stderr.includes('Uncaught'),
      `expected no uncaught exception, got stderr=${result.stderr}`
    );
  });

  // Regression test for #473: throwing a bare primitive (string/number/
  // boolean) from the progress callback must also reject the promise
  // instead of crashing the process uncatchably. Run in a child process so a
  // crash (uncaughtException, non-zero exit) can be distinguished from a
  // clean rejection without taking down this test run.
  //
  // Fixed by wrapping the callback in a small JS shim (see
  // `WRAP_PROGRESS_CALLBACK_JS` in lib.rs) before it is ever handed to
  // napi-rs's threadsafe function dispatcher: the shim catches any
  // synchronous throw and, unless the thrown value is already an object or
  // function, re-throws a new `Error` carrying the original value as
  // `cause`. This sidesteps a napi-rs 3.12.0 upstream defect where
  // `call_async_catch` crashes the process when the JS value crossing the
  // callback boundary is a primitive (`napi_create_reference()` cannot
  // create a weak reference to one).
  for (const [label, thrown, thrownRepr] of [
    ['string', "'oops'", 'oops'],
    ['number', '42', '42'],
    ['boolean', 'true', 'true'],
  ]) {
    it(`rejects the promise instead of crashing when the callback throws a ${label} (child process)`, () => {
      const script = `
        const exarch = require(${JSON.stringify(path.join(__dirname, '..', 'index.js'))});
        exarch.extractArchiveWithProgress(
          ${JSON.stringify(archivePath)},
          ${JSON.stringify(outputDir)},
          null,
          null,
          () => { throw ${thrown}; },
        ).then(
          () => { console.log('UNEXPECTED_RESOLVE'); process.exit(2); },
          (err) => { console.log('REJECTED:' + err.cause.message + ':' + err.cause.cause); },
        );
      `;

      const result = spawnSync(process.execPath, ['-e', script], {
        encoding: 'utf8',
      });

      assert.strictEqual(
        result.status,
        0,
        `expected clean exit, got status=${result.status}, stderr=${result.stderr}`
      );
      assert.ok(
        result.stdout.includes(
          `REJECTED:progress callback threw a non-object value: ${thrownRepr}:${thrownRepr}`
        ),
        `expected rejection to be observed, got stdout=${result.stdout}`
      );
      assert.ok(
        !result.stderr.includes('Uncaught') &&
          !result.stderr.includes('Call JavaScript callback failed'),
        `expected no crash/uncaught exception, got stderr=${result.stderr}`
      );
    });
  }

  // Regression test for #473, in-process: a callback throwing a primitive no
  // longer crashes the host, so this can be asserted directly like the
  // `Error`-throw case above instead of needing a child process.
  it('preserves the extraction report when the callback throws a primitive', async () => {
    await assert.rejects(
      () =>
        extractArchiveWithProgress(archivePath, outputDir, null, null, () => {
          throw 'oops';
        }),
      (err) => {
        assert.ok(
          err.message.startsWith('PROGRESS_CALLBACK_ERROR:'),
          `expected PROGRESS_CALLBACK_ERROR prefix, got: ${err.message}`
        );
        assert.match(err.message, /filesExtracted=2/);
        assert.strictEqual(
          err.cause.message,
          'progress callback threw a non-object value: oops'
        );
        assert.strictEqual(err.cause.cause, 'oops');
        return true;
      }
    );
    assert.ok(fs.existsSync(path.join(outputDir, 'hello.txt')));
  });

  // Regression test for the #473 review: a non-function `progress` argument
  // must fail fast (before touching the archive), not run the whole
  // extraction and only fail when the shim's `callback(...)` call throws
  // `TypeError: callback is not a function`. Argument extraction happens
  // synchronously before the returned promise is even constructed, so the
  // invalid argument throws synchronously rather than rejecting.
  it('throws synchronously when progress is not a function, without extracting', () => {
    assert.throws(
      () => extractArchiveWithProgress(archivePath, outputDir, null, null, 42),
      (err) => {
        assert.match(err.message, /Function/);
        return true;
      }
    );
    assert.strictEqual(fs.readdirSync(outputDir).length, 0);
  });

  // Regression test for the #473 review: the shim must only rewrap values
  // `napi_create_reference()` genuinely cannot reference (primitives). A
  // plain object throw (or any non-Error object) must stay directly under
  // `cause`, not get demoted to `cause.cause` behind a synthesized wrapper.
  it('preserves a plain-object throw directly under cause, not cause.cause', async () => {
    await assert.rejects(
      () =>
        extractArchiveWithProgress(archivePath, outputDir, null, null, () => {
          throw { code: 'CUSTOM', detail: 'stuff' };
        }),
      (err) => {
        assert.deepStrictEqual(err.cause, { code: 'CUSTOM', detail: 'stuff' });
        return true;
      }
    );
  });

  // Regression test for the #473 re-critique: a thrown `Symbol` is a
  // primitive the shim's guard correctly rewraps (`typeof` is `"symbol"`,
  // not `"object"`/`"function"`), but assigning it to `wrapped.cause` as-is
  // relocates the crash rather than fixing it — napi-rs's own
  // `extract_error_cause` later coerces `.cause` to a string via
  // `napi_coerce_to_string`, which throws for a raw `Symbol` and, under
  // `--force-node-api-uncaught-exceptions-policy=true`, reproduces the exact
  // uncatchable crash this fix targets. The shim stringifies a `Symbol`
  // before attaching it as `cause` to avoid that.
  it('preserves a thrown Symbol as its string form under cause, without crashing', async () => {
    await assert.rejects(
      () =>
        extractArchiveWithProgress(archivePath, outputDir, null, null, () => {
          throw Symbol('boom');
        }),
      (err) => {
        assert.strictEqual(
          err.cause.message,
          'progress callback threw a non-object value: Symbol(boom)'
        );
        assert.strictEqual(err.cause.cause, 'Symbol(boom)');
        return true;
      }
    );
  });
});
