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
const { createArchiveWithProgress, createArchiveWithProgressSync } = require('../index.js');

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
      },
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
          `expected PROGRESS_CALLBACK_ERROR prefix, got: ${err.message}`,
        );
        assert.match(err.message, /filesAdded=2/);
        assert.match(err.message, /bytesWritten=\d+/);
        // The throw's own text and stack must stay out of the parseable
        // message — `cause` is the only channel for the callback's detail.
        assert.ok(!err.message.includes('boom from progress callback'));
        assert.strictEqual(err.cause.message, 'boom from progress callback');
        return true;
      },
    );
    // The archive really was written, which is why the report must survive.
    assert.ok(fs.existsSync(outputPath));
  });

  // A throwing progress callback must not mask a core error: callers grep the
  // error-code prefix, so the core error stays primary.
  it(
    'surfaces the core error when the callback also throws',
    { skip: canDenyReads ? false : 'requires chmod-enforced read denial' },
    async () => {
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
            `core error code must stay primary, got: ${err.message}`,
          );
          assert.ok(err.message.endsWith(' | progressCallbackError: see cause'));
          assert.ok(!err.message.includes('boom from progress callback'));
          assert.strictEqual(err.cause.message, 'boom from progress callback');
          return true;
        },
      );
    },
  );

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

  // KNOWN LIMITATION (not a passing "this works" test), shared with
  // extractArchiveWithProgress: both await the dispatch via `call_async_catch`,
  // whose napi-rs 3.12.0 defect turns a thrown primitive into an uncatchable
  // process abort. See the long-form explanation in extract-progress.test.js
  // and https://github.com/bug-ops/exarch/issues/473.
  //
  // This test pins the CURRENT behavior. A napi-rs upgrade that fixes the bug
  // will make it fail — that is the intended signal: flip the assertions to
  // match the clean-rejection case above and drop the caveat from the
  // createArchiveWithProgress docs.
  it('KNOWN LIMITATION: crashes the host process when the callback throws a primitive (child process)', () => {
    const script = `
      const exarch = require(${INDEX_JS});
      exarch.createArchiveWithProgress(
        ${JSON.stringify(outputPath)},
        [${JSON.stringify(sourceDir)}],
        null,
        () => { throw 'oops'; },
      ).then(
        () => { console.log('UNEXPECTED_RESOLVE'); },
        () => { console.log('UNEXPECTED_REJECT'); },
      );
    `;

    const result = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8' });

    assert.notStrictEqual(
      result.status,
      0,
      'primitive throws are expected to still crash the process; if this now ' +
        'exits cleanly, the upstream napi-rs bug is fixed — update this test ' +
        'and the createArchiveWithProgress docs',
    );
    assert.match(result.stderr, /Call JavaScript callback failed/);
    // The promise never settles, so neither handler runs.
    assert.strictEqual(result.stdout.trim(), '');
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
      { encoding: 'utf8' },
    );

    assert.strictEqual(
      result.status,
      0,
      `expected clean exit, got status=${result.status}, stderr=${result.stderr}`,
    );
    // The report is returned normally: the callback had not run yet.
    assert.match(result.stdout, /RETURNED:1/);
    assert.ok(
      result.stdout.includes('UNCAUGHT:boom from progress callback'),
      `expected the throw to surface as uncaughtException, got stdout=${result.stdout}`,
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
      `expected clean exit, got status=${result.status}, stderr=${result.stderr}`,
    );
    assert.match(result.stdout, /RETURNED:1/);
    assert.ok(
      result.stdout.includes('UNCAUGHT:oops'),
      `expected the primitive throw to surface as uncaughtException, got stdout=${result.stdout}`,
    );
    assert.ok(
      !result.stderr.includes('Call JavaScript callback failed'),
      `sync dispatch must not hit the call_async_catch primitive bug, got stderr=${result.stderr}`,
    );
  });
});
