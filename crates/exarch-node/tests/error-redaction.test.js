/**
 * End-to-end regression test for issue #464.
 *
 * Release builds redact `ArchiveError::Io` messages down to their
 * `std::io::ErrorKind` description, which collapses every `io::Error::other`
 * call site to the useless string "other error". Those call sites now wrap
 * their detail in `exarch_core::IoContext` so the actionable, path-free
 * context survives redaction while the dynamic detail does not.
 *
 * The redaction itself is unit-tested in `exarch-core`'s `error::redaction`
 * module, where it now lives; those tests are gated on `debug_assertions`, so
 * CI's debug `cargo nextest` run only covers the debug branch. This file is
 * where the release-mode behaviour is asserted against the compiled binding.
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { createArchiveSync } = require('../index.js');

// `IoContext::context` for the walkdir failure in `creation::walker`.
const WALK_CONTEXT = 'directory walk failed';

/**
 * Reports whether the compiled binding redacts host paths.
 *
 * Redaction is gated on `#[cfg(not(debug_assertions))]`, so it is active under
 * `npm run build` but not under `npm run build:debug`. Probed through the
 * public API via `SourceNotFound`, whose path is reduced to a bare filename
 * only when redaction is on.
 */
function redactionActive(tempDir) {
  let message = null;
  try {
    createArchiveSync(path.join(tempDir, 'probe.tar.gz'), [
      path.join(tempDir, 'probe-dir', 'missing.tar.gz'),
    ]);
  } catch (err) {
    message = err.message;
  }
  assert.ok(message !== null, 'expected createArchiveSync to reject a missing source');
  return !message.includes('probe-dir');
}

describe('IoContext error redaction', () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-redaction-test-'));
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('keeps the walk-failure context without leaking the source path or OS detail', (t) => {
    if (process.platform === 'win32') {
      return t.skip('POSIX permission bits do not gate directory reads');
    }

    const source = path.join(tempDir, 'confidential-source');
    fs.mkdirSync(source);
    fs.writeFileSync(path.join(source, 'payload.txt'), 'data');
    fs.chmodSync(source, 0o000);

    try {
      fs.readdirSync(source);
      return t.skip('mode 000 does not block reads for this user (running as root?)');
    } catch {
      // Expected: the directory is genuinely unreadable.
    }

    let message = null;
    try {
      createArchiveSync(path.join(tempDir, 'out.tar.gz'), [source]);
    } catch (err) {
      message = err.message;
    } finally {
      fs.chmodSync(source, 0o755);
    }

    assert.ok(message !== null, 'expected createArchiveSync to fail on an unreadable source');
    assert.ok(message.includes(WALK_CONTEXT), `lost IoContext context, got: ${message}`);

    if (redactionActive(tempDir)) {
      assert.ok(
        !message.includes('confidential-source'),
        `host path leaked in release build, got: ${message}`
      );
      assert.ok(
        !message.includes('Permission denied'),
        `raw OS detail leaked in release build, got: ${message}`
      );
    }
  });
});
