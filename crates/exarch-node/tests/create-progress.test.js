/**
 * Tests for createArchiveWithProgress / createArchiveWithProgressSync,
 * covering the #465 regression on the creation path: a throwing progress
 * callback must neither crash the process nor silently discard the result of
 * the creation that already ran.
 *
 * The create-side progress API landed in #469, after #465 was originally
 * scoped to extraction only.
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const { createArchiveWithProgress } = require('../index.js');

const INDEX_JS = JSON.stringify(path.join(__dirname, '..', 'index.js'));

// The unreadable-file fixture below relies on chmod actually denying reads,
// which is not true on Windows and not true for root.
const canDenyReads =
  process.platform !== 'win32' && typeof process.getuid === 'function' && process.getuid() !== 0;

function createTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-create-progress-test-'));
}

describe('createArchiveWithProgress', () => {
  let tempDir;
  let sourceDir;
  let outputPath;

  beforeEach(() => {
    tempDir = createTempDir();
    sourceDir = path.join(tempDir, 'source');
    fs.mkdirSync(sourceDir);
    fs.writeFileSync(path.join(sourceDir, 'hello.txt'), 'Hello, World!');
    fs.writeFileSync(path.join(sourceDir, 'world.txt'), 'Another file');
    outputPath = path.join(tempDir, 'output.tar.gz');
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  // Regression test for #465 on the creation path: a throwing progress
  // callback must reject the promise instead of crashing the process.
  it('rejects the promise instead of throwing when the callback throws', async () => {
    await assert.rejects(
      () =>
        createArchiveWithProgress(outputPath, [sourceDir], null, () => {
          throw new Error('boom from progress callback');
        }),
      (err) => {
        assert.strictEqual(err.cause.message, 'boom from progress callback');
        return true;
      }
    );
  });

  // Regression test for #465 on the creation path: before this fix the
  // captured callback error was dropped on the floor and the promise resolved
  // with the report, giving the caller no indication their callback threw.
  it('preserves the creation report when the callback throws', async () => {
    await assert.rejects(
      () =>
        createArchiveWithProgress(outputPath, [sourceDir], null, () => {
          throw new Error('boom from progress callback');
        }),
      (err) => {
        assert.ok(
          err.message.startsWith('PROGRESS_CALLBACK_ERROR:'),
          `expected PROGRESS_CALLBACK_ERROR prefix, got: ${err.message}`
        );
        assert.match(err.message, /filesAdded=2/);
        assert.match(err.message, /bytesWritten=\d+/);
        // The throw's own text and stack must stay out of the parseable
        // message — `cause` is the only channel for the callback's detail.
        assert.ok(!err.message.includes('boom from progress callback'));
        assert.strictEqual(err.cause.message, 'boom from progress callback');
        return true;
      }
    );
    // The archive really was written, which is why the report must survive.
    assert.ok(fs.existsSync(outputPath));
  });

  // A throwing progress callback must not mask a core error: callers grep the
  // error-code prefix, so the core error stays primary.
  it('surfaces the core error when the callback also throws', {
    skip: canDenyReads ? false : 'requires chmod-enforced read denial',
  }, async () => {
    // hello.txt is added first and fires the callback (which throws), then
    // the unreadable file fails the creation itself.
    const unreadable = path.join(sourceDir, 'zz-unreadable.txt');
    fs.writeFileSync(unreadable, 'secret');
    fs.chmodSync(unreadable, 0o000);

    await assert.rejects(
      () =>
        createArchiveWithProgress(outputPath, [sourceDir], null, () => {
          throw new Error('boom from progress callback');
        }),
      (err) => {
        assert.ok(
          err.message.startsWith('IO_ERROR:'),
          `core error code must stay primary, got: ${err.message}`
        );
        assert.ok(err.message.endsWith(' | progressCallbackError: see cause'));
        assert.ok(!err.message.includes('boom from progress callback'));
        assert.strictEqual(err.cause.message, 'boom from progress callback');
        return true;
      }
    );
  });

  // Run in a child process so a crash (uncaughtException, non-zero exit) can
  // be distinguished from a clean rejection without taking down this test run.
  it('does not crash the host process when the callback throws (child process)', () => {
    const script = `
      const exarch = require(${INDEX_JS});
      exarch.createArchiveWithProgress(
        ${JSON.stringify(outputPath)},
        [${JSON.stringify(sourceDir)}],
        null,
        () => { throw new Error('boom from progress callback'); },
      ).then(
        () => { console.log('UNEXPECTED_RESOLVE'); process.exit(2); },
        (err) => { console.log('REJECTED:' + err.cause.message); },
      );
    `;

    const result = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8' });

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

  // Regression test for #473, shared mechanism with extractArchiveWithProgress:
  // throwing a bare primitive (string/number/boolean) from the progress
  // callback must also reject the promise instead of crashing the process
  // uncatchably. Run in a child process so a crash (uncaughtException,
  // non-zero exit) can be distinguished from a clean rejection without
  // taking down this test run. See extract-progress.test.js for the
  // long-form explanation of the fix.
  for (const [label, thrown, thrownRepr] of [
    ['string', "'oops'", 'oops'],
    ['number', '42', '42'],
    ['boolean', 'true', 'true'],
  ]) {
    it(`rejects the promise instead of crashing when the callback throws a ${label} (child process)`, () => {
      const script = `
        const exarch = require(${INDEX_JS});
        exarch.createArchiveWithProgress(
          ${JSON.stringify(outputPath)},
          [${JSON.stringify(sourceDir)}],
          null,
          () => { throw ${thrown}; },
        ).then(
          () => { console.log('UNEXPECTED_RESOLVE'); process.exit(2); },
          (err) => { console.log('REJECTED:' + err.cause.message + ':' + err.cause.cause); },
        );
      `;

      const result = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8' });

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
  it('preserves the creation report when the callback throws a primitive', async () => {
    await assert.rejects(
      () =>
        createArchiveWithProgress(outputPath, [sourceDir], null, () => {
          throw 'oops';
        }),
      (err) => {
        assert.ok(
          err.message.startsWith('PROGRESS_CALLBACK_ERROR:'),
          `expected PROGRESS_CALLBACK_ERROR prefix, got: ${err.message}`
        );
        assert.match(err.message, /filesAdded=2/);
        assert.strictEqual(
          err.cause.message,
          'progress callback threw a non-object value: oops'
        );
        assert.strictEqual(err.cause.cause, 'oops');
        return true;
      }
    );
    assert.ok(fs.existsSync(outputPath));
  });

  // Regression test for the #473 review: a non-function `progress` argument
  // must fail fast (before touching the archive), not run the whole
  // creation and only fail when the shim's `callback(...)` call throws
  // `TypeError: callback is not a function`. Argument extraction happens
  // synchronously before the returned promise is even constructed, so the
  // invalid argument throws synchronously rather than rejecting.
  it('throws synchronously when progress is not a function, without creating', () => {
    assert.throws(
      () => createArchiveWithProgress(outputPath, [sourceDir], null, 42),
      (err) => {
        assert.match(err.message, /Function/);
        return true;
      }
    );
    assert.ok(!fs.existsSync(outputPath));
  });

  // Regression test for the #473 review: the shim must only rewrap values
  // `napi_create_reference()` genuinely cannot reference (primitives). A
  // plain object throw (or any non-Error object) must stay directly under
  // `cause`, not get demoted to `cause.cause` behind a synthesized wrapper.
  it('preserves a plain-object throw directly under cause, not cause.cause', async () => {
    await assert.rejects(
      () =>
        createArchiveWithProgress(outputPath, [sourceDir], null, () => {
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
        createArchiveWithProgress(outputPath, [sourceDir], null, () => {
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

describe('createArchiveWithProgressSync', () => {
  let tempDir;
  let sourceDir;
  let outputPath;

  beforeEach(() => {
    tempDir = createTempDir();
    sourceDir = path.join(tempDir, 'source');
    fs.mkdirSync(sourceDir);
    fs.writeFileSync(path.join(sourceDir, 'hello.txt'), 'Hello, World!');
    outputPath = path.join(tempDir, 'output.tar.gz');
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  // Every queued call is delivered only after this function has returned, so
  // there is no result left to merge a callback throw into. The throw takes
  // the ordinary deferred-callback route instead: an uncaughtException, which
  // the caller can observe — unlike the async variant, it is NOT reported as
  // a PROGRESS_CALLBACK_ERROR rejection.
  const syncThrowScript = (thrown) => `
    const exarch = require(${INDEX_JS});
    process.on('uncaughtException', (err) => {
      console.log('UNCAUGHT:' + (err && err.message ? err.message : String(err)));
      process.exit(0);
    });
    const report = exarch.createArchiveWithProgressSync(
      ${JSON.stringify(outputPath)},
      [${JSON.stringify(sourceDir)}],
      null,
      () => { throw ${thrown}; },
    );
    console.log('RETURNED:' + report.filesAdded);
  `;

  it('returns the report and reports a throwing callback as an uncaughtException (child process)', () => {
    const result = spawnSync(
      process.execPath,
      ['-e', syncThrowScript("new Error('boom from progress callback')")],
      { encoding: 'utf8' }
    );

    assert.strictEqual(
      result.status,
      0,
      `expected clean exit, got status=${result.status}, stderr=${result.stderr}`
    );
    // The report is returned normally: the callback had not run yet.
    assert.match(result.stdout, /RETURNED:1/);
    assert.ok(
      result.stdout.includes('UNCAUGHT:boom from progress callback'),
      `expected the throw to surface as uncaughtException, got stdout=${result.stdout}`
    );
  });

  // The primitive-throw crash that afflicts the async variants does NOT apply
  // here: the sync path cannot await its dispatch (the blocked event loop is
  // the only thing that can deliver it), so it never enters the napi-rs
  // `call_async_catch` code path that mishandles primitive exception values.
  it('reports a thrown primitive as an uncaughtException too, without crashing (child process)', () => {
    const result = spawnSync(process.execPath, ['-e', syncThrowScript("'oops'")], {
      encoding: 'utf8',
    });

    assert.strictEqual(
      result.status,
      0,
      `expected clean exit, got status=${result.status}, stderr=${result.stderr}`
    );
    assert.match(result.stdout, /RETURNED:1/);
    assert.ok(
      result.stdout.includes('UNCAUGHT:oops'),
      `expected the primitive throw to surface as uncaughtException, got stdout=${result.stdout}`
    );
    assert.ok(
      !result.stderr.includes('Call JavaScript callback failed'),
      `sync dispatch must not hit the call_async_catch primitive bug, got stderr=${result.stderr}`
    );
  });
});
