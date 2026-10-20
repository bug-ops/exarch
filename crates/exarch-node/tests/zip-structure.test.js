/**
 * Tests for ZIP structure findings and link-target limits through the Node API
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  SecurityConfig,
  extractArchiveSync,
  listArchiveSync,
  verifyArchiveSync,
} = require('../index.js');

const u16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n);
  return b;
};
const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
};

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function localRecord({ name, data, localExtra = Buffer.alloc(0) }) {
  const nameBytes = Buffer.from(name);
  return Buffer.concat([
    Buffer.from('PK\x03\x04', 'latin1'),
    u16(20),
    u16(0),
    u16(0),
    u16(0),
    u16(0x21),
    u32(crc32(data)),
    u32(data.length),
    u32(data.length),
    u16(nameBytes.length),
    u16(localExtra.length),
    nameBytes,
    localExtra,
    data,
  ]);
}

function centralRecord({ name, data, mode }, offset) {
  const nameBytes = Buffer.from(name);
  return Buffer.concat([
    Buffer.from('PK\x01\x02', 'latin1'),
    u16(0x031e),
    u16(20),
    u16(0),
    u16(0),
    u16(0),
    u16(0x21),
    u32(crc32(data)),
    u32(data.length),
    u32(data.length),
    u16(nameBytes.length),
    u16(0),
    u16(0),
    u16(0),
    u16(0),
    u32((mode << 16) >>> 0),
    u32(offset),
    nameBytes,
  ]);
}

/**
 * Builds a ZIP of stored entries. `beforeDirectory` is raw bytes between the
 * last entry and the directory; `endCount` overrides the end record's count.
 */
function buildZip(entries, { beforeDirectory = Buffer.alloc(0), endCount } = {}) {
  const locals = [];
  const offsets = [];
  let position = 0;
  for (const entry of entries) {
    const record = localRecord(entry);
    offsets.push(position);
    position += record.length;
    locals.push(record);
  }
  position += beforeDirectory.length;
  const directory = Buffer.concat(
    entries.map((entry, i) => centralRecord({ mode: 0o100644, ...entry }, offsets[i]))
  );
  const count = endCount ?? entries.length;
  return Buffer.concat([
    ...locals,
    beforeDirectory,
    directory,
    Buffer.from('PK\x05\x06', 'latin1'),
    u16(0),
    u16(0),
    u16(count),
    u16(count),
    u32(directory.length),
    u32(position),
    u16(0),
  ]);
}

describe('ZIP structure through the Node API', () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-test-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function write(name, bytes) {
    const file = path.join(tempDir, name);
    fs.writeFileSync(file, bytes);
    return file;
  }

  function ignoring() {
    const config = new SecurityConfig();
    config.setZipConsistency('ignore');
    return config;
  }

  const categories = (report) => new Set(report.issues.map((issue) => issue.category));

  it('reports duplicate names and counts every record', () => {
    const file = write(
      'dup.zip',
      buildZip([
        { name: 'a.txt', data: Buffer.from('first') },
        { name: 'a.txt', data: Buffer.from('EVIL') },
      ])
    );
    const report = verifyArchiveSync(file);
    assert.strictEqual(report.status, 'FAIL');
    assert.strictEqual(report.totalEntries, 2);
    assert.ok(categories(report).has('Duplicate Entry'));
    assert.strictEqual(verifyArchiveSync(file, ignoring()).status, 'PASS');
    assert.throws(() => listArchiveSync(file), /ZIP_INCONSISTENCY/);
  });

  it('reports central directory records past the end count and hidden headers', () => {
    const file = write(
      'count.zip',
      buildZip(
        [
          { name: 'benign.txt', data: Buffer.from('hello') },
          { name: 'hidden.sh', data: Buffer.from('echo pwned\n') },
        ],
        { endCount: 1 }
      )
    );
    const report = verifyArchiveSync(file);
    assert.strictEqual(report.totalEntries, 2);
    assert.ok(categories(report).has('Hidden Entry'));
    assert.ok(report.suspiciousEntries <= report.totalEntries);
    assert.strictEqual(listArchiveSync(file, ignoring()).totalEntries, 1);
  });

  it('finds a local header behind padding', () => {
    const hidden = localRecord({ name: 'evil.sh', data: Buffer.from('echo pwned\n') });
    const file = write(
      'padded.zip',
      buildZip([{ name: 'a.txt', data: Buffer.from('hello') }], {
        beforeDirectory: Buffer.concat([Buffer.from([0]), hidden]),
      })
    );
    assert.ok(categories(verifyArchiveSync(file)).has('Hidden Entry'));
    assert.strictEqual(verifyArchiveSync(file, ignoring()).status, 'PASS');
  });

  it('rejects an unparseable local header under enforce and extracts under ignore', () => {
    const badTimestamp = Buffer.concat([u16(0x5455), u16(9), Buffer.from([0x07]), Buffer.alloc(8)]);
    const file = write(
      'ut.zip',
      buildZip([{ name: 'a.txt', data: Buffer.from('hello'), localExtra: badTimestamp }])
    );
    const out = path.join(tempDir, 'out');
    assert.throws(() => extractArchiveSync(file, out), /ZIP_INCONSISTENCY/);
    assert.strictEqual(fs.existsSync(out), false);
    extractArchiveSync(file, out, ignoring());
    assert.strictEqual(fs.readFileSync(path.join(out, 'a.txt'), 'utf8'), 'hello');
  });

  it('reports a name collision only on case-insensitive hosts', {
    skip: !['darwin', 'win32'].includes(process.platform),
  }, () => {
    const file = write(
      'case.zip',
      buildZip([
        { name: 'a.txt', data: Buffer.from('one') },
        { name: 'A.txt', data: Buffer.from('two') },
      ])
    );
    assert.ok(categories(verifyArchiveSync(file)).has('Name Collision'));
  });

  it('reports an oversized symlink target instead of failing verify', () => {
    const target = Buffer.alloc(5000, 'a');
    const file = write('link.zip', buildZip([{ name: 'link', data: target, mode: 0o120777 }]));
    const config = new SecurityConfig();
    config.setAllowSymlinks(true);
    const report = verifyArchiveSync(file, config);
    assert.strictEqual(report.status, 'FAIL');
    assert.ok(categories(report).has('Invalid Archive'));
    assert.throws(() => listArchiveSync(file, config));
  });
});
