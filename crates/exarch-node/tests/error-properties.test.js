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
      () => new SecurityConfig().setMaxFileSize('not a number'),
      (err) => {
        assert.strictEqual(err.code, 'NumberExpected');
        assert.strictEqual(err.setting, undefined);
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
      assert.strictEqual(err.subCode, 'FILE_COUNT');
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

describe('subCode', () => {
  const zlib = require('node:zlib');
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-subcode-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function tarBytes(sizeField) {
    const header = Buffer.alloc(512);
    header.write('a.txt', 0);
    header.write('0000644\0', 100);
    header.write('0000000\0', 108);
    header.write('0000000\0', 116);
    header.write(sizeField, 124, 'latin1');
    header.write('00000000000\0', 136);
    header.write('0', 156);
    header.write('ustar\0', 257);
    header.write('00', 263);
    header.fill(0x20, 148, 156);
    const sum = header.reduce((acc, byte) => acc + byte, 0);
    header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
    const data = Buffer.alloc(512);
    data.write('alpha');
    return Buffer.concat([header, data, Buffer.alloc(1024)]);
  }

  const cleanTar = () => tarBytes('00000000005\0');

  function write(name, bytes) {
    const file = path.join(tempDir, name);
    fs.writeFileSync(file, bytes);
    return file;
  }

  async function failureOf(file) {
    try {
      await extractArchive(file, path.join(tempDir, 'out'));
    } catch (err) {
      return err;
    }
    return assert.fail('extraction unexpectedly succeeded');
  }

  it('a non-canonical TAR header is INVALID_ARCHIVE / TAR_AMBIGUITY', async () => {
    const err = await failureOf(write('a.tar', tarBytes('+0000000005\0')));
    assert.strictEqual(err.code, 'INVALID_ARCHIVE');
    assert.strictEqual(err.subCode, 'TAR_AMBIGUITY');
  });

  it('junk after the gzip member is INVALID_ARCHIVE / TAR_TRAILER', async () => {
    const gz = Buffer.concat([zlib.gzipSync(cleanTar()), Buffer.from('\0\0\0garbage')]);
    const err = await failureOf(write('a.tar.gz', gz));
    assert.strictEqual(err.code, 'INVALID_ARCHIVE');
    assert.strictEqual(err.subCode, 'TAR_TRAILER');
  });

  it('an over-cap tail is SECURITY_VIOLATION / TAR_TRAILER and names its setting', async () => {
    const gz = Buffer.concat([
      zlib.gzipSync(cleanTar()),
      zlib.gzipSync(Buffer.alloc(5 * 1024 * 1024)),
    ]);
    const err = await failureOf(write('big.tar.gz', gz));
    assert.strictEqual(err.code, 'SECURITY_VIOLATION');
    assert.strictEqual(err.subCode, 'TAR_TRAILER');
    assert.strictEqual(err.relaxableBy, 'max_tar_metadata_bytes');
  });

  it('a corrupt TAR header is TAR_READER', async () => {
    const err = await failureOf(write('junk.tar', Buffer.alloc(2048, 0x41)));
    assert.strictEqual(err.subCode, 'TAR_READER');
  });

  it('every core SECURITY_VIOLATION carries a subCode', async () => {
    const violation = await extractArchive('/tmp/a\0.tar', '/tmp/out').catch((e) => e);
    assert.strictEqual(violation.code, 'SECURITY_VIOLATION');
    assert.strictEqual(violation.subCode, 'PATH_NAME');
  });
});

describe('ioKind', () => {
  it('an IO_ERROR keeps the kind core reported', async () => {
    const missing = path.join(os.tmpdir(), 'exarch-node-missing', 'a.tar');
    const err = await listArchive(missing).catch((e) => e);
    assert.strictEqual(err.code, 'IO_ERROR');
    assert.strictEqual(err.ioKind, 'NotFound');
  });

  it('an error that is not an IO_ERROR carries no ioKind', async () => {
    const err = await extractArchive('/tmp/a\0.tar', '/tmp/out').catch((e) => e);
    assert.strictEqual(err.ioKind, undefined);
  });
});
