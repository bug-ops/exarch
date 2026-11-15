/**
 * Contract of the shared archive builders of #1234 (tests/helpers/archives.js)
 * and of the rule that no test file keeps its own copy.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const testsDir = __dirname;
const { tarEntry, tarArchive, zipArchive, crc32 } = require('./helpers/archives.js');

function checksumOk(block) {
  const stored = parseInt(block.subarray(148, 154).toString('latin1'), 8);
  let sum = 0;
  for (let i = 0; i < 512; i++) {
    sum += i >= 148 && i < 156 ? 32 : block[i];
  }
  return stored === sum;
}

describe('shared archive builders (#1234)', () => {
  it('crc32 matches the standard check value', () => {
    assert.strictEqual(crc32(Buffer.from('123456789')), 0xcbf43926);
    assert.strictEqual(crc32(Buffer.alloc(0)), 0);
  });

  it('tarEntry builds a header block with a valid checksum and padded data', () => {
    const entry = tarEntry({ name: 'a.txt', data: Buffer.from('hello') });
    assert.strictEqual(entry.length, 1024);
    assert.strictEqual(entry.subarray(0, 5).toString(), 'a.txt');
    assert.ok(checksumOk(entry.subarray(0, 512)));
    assert.strictEqual(entry.subarray(512, 517).toString(), 'hello');
  });

  it('tarEntry defaults to a regular file and encodes a type and a link target', () => {
    const file = tarEntry({ name: 'f' });
    assert.strictEqual(String.fromCharCode(file[156]), '0');
    const link = tarEntry({ name: 'l', type: '2', link: 'target' });
    assert.strictEqual(String.fromCharCode(link[156]), '2');
    assert.strictEqual(link.subarray(157, 163).toString(), 'target');
    assert.ok(checksumOk(link.subarray(0, 512)));
  });

  it('tarArchive concatenates entries and ends with the zero trailer', () => {
    const entries = [tarEntry({ name: 'a', data: Buffer.from('1') }), tarEntry({ name: 'b' })];
    const archive = tarArchive(entries);
    assert.strictEqual(archive.length, entries[0].length + entries[1].length + 1024);
    assert.ok(archive.subarray(archive.length - 1024).every((byte) => byte === 0));
  });

  it('zipArchive stores entries with their crc32 and ends with an end-of-central-directory record', () => {
    const data = Buffer.from('payload');
    const archive = zipArchive([{ name: 'p.txt', data }, { name: 'd/', data: Buffer.alloc(0), dir: true }]);
    assert.strictEqual(archive.readUInt32LE(0), 0x04034b50);
    assert.strictEqual(archive.readUInt32LE(14), crc32(data));
    assert.strictEqual(archive.readUInt32LE(archive.length - 22), 0x06054b50);
    assert.strictEqual(archive.readUInt16LE(archive.length - 22 + 10), 2);
  });

  it('no other test file defines its own tarEntry, tarArchive, zipArchive or crc32', () => {
    const copies = [];
    for (const file of fs.readdirSync(testsDir).filter((name) => name.endsWith('.js'))) {
      const source = fs.readFileSync(path.join(testsDir, file), 'utf8');
      const pattern = /^(?:async\s+)?function\s+(tarEntry|tarArchive|zipArchive|crc32)\b/gm;
      for (const match of source.matchAll(pattern)) {
        copies.push(`${file}: ${match[1]}`);
      }
    }
    assert.deepStrictEqual(copies, []);
  });
});
