/**
 * Tests for the typed error contract: `code`, `relaxableBy`, `writes` and the
 * partial-extraction counters are properties, and `message` is the
 * description only (#758, #760).
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  extractArchive,
  extractArchiveSync,
  createArchive,
  createArchiveSync,
  listArchive,
  listArchiveSync,
  verifyArchive,
  verifyArchiveSync,
  SecurityConfig,
  ExtractionOptions,
  VerificationOptions,
} = require('../index.js');

const MESSAGE_GRAMMAR =
  /^[A-Z_]+: |\[relaxableBy=| \| writes=|filesExtracted=|progressCallbackError/;

function assertDescriptionOnly(err) {
  assert.doesNotMatch(err.message, MESSAGE_GRAMMAR, err.message);
}

describe('boundary errors keep their core code', () => {
  const nullPath = '/tmp/exarch\0malicious.tar';

  it('async functions reject with SECURITY_VIOLATION, not throw', async () => {
    const calls = [
      () => extractArchive(nullPath, '/tmp/out'),
      () => extractArchive('/tmp/a.tar', '/tmp/out\0x'),
      () => createArchive(nullPath, ['/tmp/src']),
      () => createArchive('/tmp/out.tar', ['/tmp/src\0x']),
      () => listArchive(nullPath),
      () => verifyArchive(nullPath),
    ];
    for (const call of calls) {
      let promise;
      assert.doesNotThrow(() => {
        promise = call();
      });
      await assert.rejects(promise, (err) => {
        assert.ok(err instanceof Error);
        assert.strictEqual(err.code, 'SECURITY_VIOLATION');
        assert.strictEqual(err.relaxableBy, undefined);
        assert.match(err.message, /null bytes/);
        assertDescriptionOnly(err);
        return true;
      });
    }
  });

  it('sync functions throw the same code', () => {
    const calls = [
      () => extractArchiveSync(nullPath, '/tmp/out'),
      () => createArchiveSync(nullPath, ['/tmp/src']),
      () => listArchiveSync(nullPath),
      () => verifyArchiveSync(nullPath),
    ];
    for (const call of calls) {
      assert.throws(call, (err) => {
        assert.ok(err instanceof Error);
        assert.strictEqual(err.code, 'SECURITY_VIOLATION');
        assertDescriptionOnly(err);
        return true;
      });
    }
  });
});

describe('setter errors', () => {
  it('core validation keeps INVALID_CONFIGURATION', () => {
    assert.throws(() => new SecurityConfig().addBannedComponent(''), {
      code: 'INVALID_CONFIGURATION',
    });
    assert.throws(() => new SecurityConfig().addAllowedExtension('a\0b'), {
      code: 'INVALID_CONFIGURATION',
    });
    assert.throws(
      () => new VerificationOptions().withIntegrityCheck(0),
      (err) => {
        assertDescriptionOnly(err);
        return typeof err.code === 'string' && err.code !== 'GenericFailure';
      }
    );
  });

  it('binding-native errors keep napi status and carry no typed properties', () => {
    assert.throws(
      () => new SecurityConfig().setMaxFileSize(-1),
      (err) => {
        assert.strictEqual(err.code, 'GenericFailure');
        assert.strictEqual(err.relaxableBy, undefined);
        assert.strictEqual(err.writes, undefined);
        return true;
      }
    );
  });
});

describe('extraction error properties', () => {
  let tempDir;
  let archivePath;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-test-'));
    archivePath = path.join(tempDir, 'two-files.tar.gz');
    const sourceDir = path.join(tempDir, 'source');
    fs.mkdirSync(sourceDir);
    fs.writeFileSync(path.join(sourceDir, 'a.txt'), 'a');
    fs.writeFileSync(path.join(sourceDir, 'b.txt'), 'b');
    createArchiveSync(archivePath, [sourceDir]);
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('a kept partial extraction carries typed counters and a warnings array', async () => {
    const config = new SecurityConfig().setMaxFileCount(1);
    await assert.rejects(extractArchive(archivePath, path.join(tempDir, 'out'), config), (err) => {
      assert.strictEqual(err.code, 'QUOTA_EXCEEDED');
      assert.strictEqual(err.writes, 'kept');
      assert.strictEqual(typeof err.filesExtracted, 'number');
      assert.strictEqual(typeof err.bytesWritten, 'number');
      assert.strictEqual(typeof err.filesSkipped, 'number');
      assert.ok(Array.isArray(err.warnings));
      assertDescriptionOnly(err);
      return true;
    });
  });

  it('a rolled-back atomic extraction reports writes without counters', async () => {
    const config = new SecurityConfig().setMaxFileCount(1);
    const options = new ExtractionOptions().withAtomic(true);
    await assert.rejects(
      extractArchive(archivePath, path.join(tempDir, 'atomic-out'), config, options),
      (err) => {
        assert.strictEqual(err.code, 'QUOTA_EXCEEDED');
        assert.strictEqual(err.writes, 'rolled_back');
        assert.strictEqual(err.filesExtracted, undefined);
        assert.strictEqual(err.bytesWritten, undefined);
        assert.strictEqual(err.warnings, undefined);
        assertDescriptionOnly(err);
        return true;
      }
    );
  });

  it('a failure before any write has no writes property', async () => {
    await assert.rejects(listArchive(path.join(tempDir, 'missing.tar')), (err) => {
      assert.strictEqual(err.code, 'IO_ERROR');
      assert.strictEqual(err.writes, undefined);
      assertDescriptionOnly(err);
      return true;
    });
  });
});
