/**
 * `subCode` of the typed INVALID_ARCHIVE families and the `setting` of
 * INVALID_CONFIGURATION (#887, #870).
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const zlib = require('node:zlib');
const {
  extractArchive,
  verifyArchive,
  SecurityConfig,
  ExtractionOptions,
  VerificationOptions,
} = require('../index.js');

function tarEntry({ name, type = '0', data = Buffer.alloc(0), linkname = '' }) {
  const header = Buffer.alloc(512);
  header.write(name, 0);
  header.write('0000644\0', 100);
  header.write('0000000\0', 108);
  header.write('0000000\0', 116);
  header.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  header.write('00000000000\0', 136);
  header.write(type, 156);
  header.write(linkname, 157);
  header.write('ustar\0', 257);
  header.write('00', 263);
  header.fill(0x20, 148, 156);
  const sum = header.reduce((acc, byte) => acc + byte, 0);
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
  const padded = Buffer.alloc(Math.ceil(data.length / 512) * 512);
  data.copy(padded);
  return Buffer.concat([header, padded]);
}

const tarOf = (...entries) => Buffer.concat([...entries.map(tarEntry), Buffer.alloc(1024)]);

function gzipWithBadSecondBlock(data, split) {
  const parts = [Buffer.from([0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff])];
  [data.subarray(0, split), data.subarray(split)].forEach((block, index) => {
    const head = Buffer.alloc(5);
    head.writeUInt8(index === 1 ? 1 : 0, 0);
    head.writeUInt16LE(block.length, 1);
    head.writeUInt16LE(index === 1 ? block.length : ~block.length & 0xffff, 3);
    parts.push(head, block);
  });
  const tail = Buffer.alloc(8);
  tail.writeUInt32LE(zlib.crc32(data), 0);
  tail.writeUInt32LE(data.length, 4);
  parts.push(tail);
  return Buffer.concat(parts);
}

function zipWithForgedCompressedSize() {
  const name = Buffer.from('a.txt');
  const body = Buffer.from('hello');
  const forged = 0x7ffffff0;
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt32LE(zlib.crc32(body), 14);
  local.writeUInt32LE(forged, 18);
  local.writeUInt32LE(body.length, 22);
  local.writeUInt16LE(name.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt32LE(zlib.crc32(body), 16);
  central.writeUInt32LE(forged, 20);
  central.writeUInt32LE(body.length, 24);
  central.writeUInt16LE(name.length, 28);
  const centralOffset = local.length + name.length + body.length;
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(central.length + name.length, 12);
  end.writeUInt32LE(centralOffset, 16);
  return Buffer.concat([local, name, body, central, name, end]);
}

describe('InvalidArchive families', () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-families-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  async function extractFailure(name, bytes, config, options) {
    const file = path.join(tempDir, name);
    fs.writeFileSync(file, bytes);
    try {
      await extractArchive(file, path.join(tempDir, 'out'), config, options);
    } catch (err) {
      return err;
    }
    return assert.fail('extraction unexpectedly succeeded');
  }

  it('a hardlink to a missing target is LINK_TARGET', async () => {
    const bytes = tarOf({ name: 'h', type: '1', linkname: 'nothere' });
    const config = new SecurityConfig().withAllowHardlinks(true);
    const err = await extractFailure('absent.tar', bytes, config);
    assert.strictEqual(err.code, 'INVALID_ARCHIVE');
    assert.strictEqual(err.subCode, 'LINK_TARGET');
  });

  it('a symlink without a target is LINK_TARGET', async () => {
    const bytes = tarOf({ name: 's', type: '2' });
    const config = new SecurityConfig().withAllowSymlinks(true);
    const err = await extractFailure('nolink.tar', bytes, config);
    assert.strictEqual(err.code, 'INVALID_ARCHIVE');
    assert.strictEqual(err.subCode, 'LINK_TARGET');
  });

  it('a hardlink over an existing path is an OUTPUT_EXISTS refusal', async () => {
    const bytes = tarOf(
      { name: 't', data: Buffer.from('x') },
      { name: 'h', type: '1', linkname: 't' },
      { name: 'h', type: '1', linkname: 't' }
    );
    const config = new SecurityConfig().withAllowHardlinks(true);
    const options = new ExtractionOptions().withExistingFiles('overwrite');
    const err = await extractFailure('dup.tar', bytes, config, options);
    assert.strictEqual(err.code, 'OUTPUT_EXISTS');
    assert.deepStrictEqual(err.conflicts, ['h']);
    assert.ok(['existing', 'archive'].includes(err.by), String(err.by));
  });

  it('a forged ZIP compressed size is DECLARED_SIZE', async () => {
    const err = await extractFailure('forged.zip', zipWithForgedCompressedSize());
    assert.strictEqual(err.code, 'INVALID_ARCHIVE');
    assert.strictEqual(err.subCode, 'DECLARED_SIZE');
  });

  it('a ZIP without an end record is ZIP_READER', async () => {
    const bytes = Buffer.concat([Buffer.from('PK\x03\x04', 'latin1'), Buffer.alloc(60)]);
    const err = await extractFailure('no_eocd.zip', bytes);
    assert.strictEqual(err.code, 'INVALID_ARCHIVE');
    assert.strictEqual(err.subCode, 'ZIP_READER');
  });

  it('an invalid deflate block under an integrity check is INTEGRITY', async () => {
    const tar = tarOf({ name: 'a', data: Buffer.alloc(30000, 0x71) });
    const file = path.join(tempDir, 'bad.tar.gz');
    fs.writeFileSync(file, gzipWithBadSecondBlock(tar, 10000));
    const options = new VerificationOptions().withIntegrityCheck();
    const err = await verifyArchive(file, undefined, options).then(
      () => assert.fail('verification unexpectedly succeeded'),
      (e) => e
    );
    assert.strictEqual(err.code, 'INVALID_ARCHIVE');
    assert.strictEqual(err.subCode, 'INTEGRITY');
  });
});

describe('INVALID_CONFIGURATION setting', () => {
  const refused = [
    ['withMaxFileCount', 0, 'max_file_count'],
    ['withMaxPathDepth', 0, 'max_path_depth'],
    ['withMaxFileSize', 0, 'max_file_size'],
    ['withMaxFileSize', -1, 'max_file_size'],
    ['withMaxTotalSize', 0, 'max_total_size'],
    ['withMaxSolidBlockMemory', 0, 'max_solid_block_memory'],
    ['withMaxCompressionRatio', 0, 'max_compression_ratio'],
    ['withMaxCompressionRatio', NaN, 'max_compression_ratio'],
    ['withMaxCompressionRatio', Infinity, 'max_compression_ratio'],
  ];

  for (const [method, value, setting] of refused) {
    it(`${method}(${value}) names ${setting}`, () => {
      assert.throws(
        () => new SecurityConfig()[method](value),
        (err) => {
          assert.strictEqual(err.code, 'INVALID_CONFIGURATION');
          assert.strictEqual(err.setting, setting);
          return true;
        }
      );
    });
  }
});
