/**
 * Tests for the old GNU sparse TAR policy (tarSparse)
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  SecurityConfig,
  extractArchive,
  extractArchiveSync,
  listArchiveSync,
  verifyArchiveSync,
} = require('../index.js');

const BLOCK = 512;

const octal = (value) => Buffer.from(`${value.toString(8).padStart(11, '0')}\0`);

function header(name, typeflag, size) {
  const block = Buffer.alloc(BLOCK);
  block.write(name, 0, 'latin1');
  block.write('0000644\0', 100, 'latin1');
  block.write('0000000\x000000000\0', 108, 'latin1');
  octal(size).copy(block, 124);
  octal(0).copy(block, 136);
  block[156] = typeflag.charCodeAt(0);
  block.write('ustar  \0', 257, 'latin1');
  return block;
}

function seal(block) {
  block.fill(' ', 148, 156);
  const sum = block.reduce((total, byte) => total + byte, 0);
  block.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
  return block;
}

function padded(bytes) {
  const out = Buffer.alloc(Math.ceil(bytes.length / BLOCK) * BLOCK);
  bytes.copy(out);
  return out;
}

/** A sparse `hole.bin` (5 stored bytes, real size 1000) and a regular `after.txt`. */
function sparseTar({ slotAfterEnd = false } = {}) {
  const sparse = header('hole.bin', 'S', 5);
  octal(0).copy(sparse, 386);
  octal(5).copy(sparse, 398);
  const holeAt = slotAfterEnd ? 434 : 410;
  octal(1000).copy(sparse, holeAt);
  octal(0).copy(sparse, holeAt + 12);
  octal(1000).copy(sparse, 483);
  const after = header('after.txt', '0', 5);
  return Buffer.concat([
    seal(sparse),
    padded(Buffer.from('hello')),
    seal(after),
    padded(Buffer.from('after')),
    Buffer.alloc(2 * BLOCK),
  ]);
}

describe('SecurityConfig tarSparse', () => {
  it('defaults to refuse, also for permissive', () => {
    assert.strictEqual(new SecurityConfig().tarSparse, 'refuse');
    assert.strictEqual(SecurityConfig.permissive().tarSparse, 'refuse');
  });

  it('round-trips through the setter', () => {
    const config = new SecurityConfig();
    config.withTarSparse('expand');
    assert.strictEqual(config.tarSparse, 'expand');
    config.withTarSparse('refuse');
    assert.strictEqual(config.tarSparse, 'refuse');
  });

  it('rejects unknown values', () => {
    assert.throws(() => new SecurityConfig().withTarSparse('off'));
  });
});

describe('old GNU sparse TAR entries', () => {
  let tempDir;
  let archive;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-test-'));
    archive = path.join(tempDir, 'sparse.tar');
    fs.writeFileSync(archive, sparseTar());
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function expanding() {
    const config = new SecurityConfig();
    config.withTarSparse('expand');
    return config;
  }

  it('are refused by default in extract, list and verify', async () => {
    const out = path.join(tempDir, 'out');
    await assert.rejects(extractArchive(archive, out), {
      code: 'INVALID_ARCHIVE',
      subCode: 'TAR_AMBIGUITY',
    });
    assert.strictEqual(fs.existsSync(path.join(out, 'hole.bin')), false);
    assert.throws(() => listArchiveSync(archive), { code: 'INVALID_ARCHIVE' });
    assert.throws(() => verifyArchiveSync(archive), { code: 'INVALID_ARCHIVE' });
  });

  it('expand to their real size under expand', () => {
    const out = path.join(tempDir, 'out');
    extractArchiveSync(archive, out, expanding());

    const content = fs.readFileSync(path.join(out, 'hole.bin'));
    assert.strictEqual(content.length, 1000);
    assert.strictEqual(content.subarray(0, 5).toString(), 'hello');
    assert.ok(content.subarray(5).every((byte) => byte === 0));
    assert.strictEqual(fs.readFileSync(path.join(out, 'after.txt'), 'utf8'), 'after');

    const hole = listArchiveSync(archive, expanding()).entries.find((e) => e.path === 'hole.bin');
    assert.strictEqual(hole.size, 1000);
    assert.strictEqual(verifyArchiveSync(archive, expanding()).status, 'PASS');
  });

  it('count their real size against the file limit', () => {
    const config = expanding();
    config.withMaxFileSize(999);
    assert.throws(() => extractArchiveSync(archive, path.join(tempDir, 'out'), config), {
      code: 'QUOTA_EXCEEDED',
    });
  });

  it('stay refused under expand when the map is ambiguous', () => {
    fs.writeFileSync(archive, sparseTar({ slotAfterEnd: true }));
    assert.throws(() => listArchiveSync(archive, expanding()), {
      code: 'INVALID_ARCHIVE',
      subCode: 'TAR_AMBIGUITY',
    });
  });
});
