/**
 * Tests for the opt-in payload integrity check of verifyArchive (#623)
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  verifyArchive,
  verifyArchiveSync,
  SecurityConfig,
  VerificationOptions,
} = require('../index.js');

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/** Builds a one-entry stored ZIP whose CRC field is `crc`. */
function storedZip(name, data, crc) {
  const nameBytes = Buffer.from(name);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(nameBytes.length, 26);
  const localPart = Buffer.concat([local, nameBytes, data]);

  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(nameBytes.length, 28);
  const centralPart = Buffer.concat([central, nameBytes]);

  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(centralPart.length, 12);
  end.writeUInt32LE(localPart.length, 16);
  return Buffer.concat([localPart, centralPart, end]);
}

describe('verifyArchive integrity check', () => {
  let tempDir;
  const payload = Buffer.from('MARKER-PAYLOAD-BYTES');

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-integrity-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function writeZip(name, crc) {
    const file = path.join(tempDir, name);
    fs.writeFileSync(file, storedZip('data.txt', payload, crc));
    return file;
  }

  it('VerificationOptions defaults to no integrity check', () => {
    const options = new VerificationOptions();
    assert.strictEqual(options.integrityCheck, false);
    assert.strictEqual(options.decompressionBudget, null);
  });

  it('withIntegrityCheck defaults the budget to 500 MiB', () => {
    const options = new VerificationOptions().withIntegrityCheck();
    assert.strictEqual(options.integrityCheck, true);
    assert.strictEqual(options.decompressionBudget, 500 * 1024 * 1024);
  });

  it('withIntegrityCheck rejects a zero or negative budget', () => {
    assert.throws(() => new VerificationOptions().withIntegrityCheck(0));
    assert.throws(() => new VerificationOptions().withIntegrityCheck(-1));
  });

  it('default verify leaves integrity SKIPPED', async () => {
    const file = writeZip('bad.zip', 0xdeadbeef);
    const report = await verifyArchive(file);
    assert.strictEqual(report.integrityStatus, 'SKIPPED');
  });

  it('reports OK for a clean archive', async () => {
    const file = writeZip('ok.zip', crc32(payload));
    const options = new VerificationOptions().withIntegrityCheck();
    const report = await verifyArchive(file, null, options);
    assert.strictEqual(report.integrityStatus, 'OK');
    assert.strictEqual(report.status, 'PASS');
  });

  it('reports FAILED for a CRC mismatch', async () => {
    const file = writeZip('bad.zip', 0xdeadbeef);
    const options = new VerificationOptions().withIntegrityCheck();
    const report = await verifyArchive(file, null, options);
    assert.strictEqual(report.integrityStatus, 'FAILED');
    assert.strictEqual(report.status, 'FAIL');
    assert.ok(report.issues.some((i) => i.category === 'Corrupt Data'));
  });

  it('reports INCOMPLETE when the budget is exhausted (sync)', () => {
    const file = writeZip('ok.zip', crc32(payload));
    const options = new VerificationOptions().withIntegrityCheck(1);
    const report = verifyArchiveSync(file, null, options);
    assert.strictEqual(report.integrityStatus, 'INCOMPLETE');
    assert.strictEqual(report.status, 'WARNING');
    assert.ok(report.issues.some((i) => i.category === 'Integrity Incomplete'));
  });

  it('reports INCOMPLETE for a solid 7z until solid archives are allowed', async () => {
    const solid = path.join(__dirname, '..', '..', '..', 'tests', 'fixtures', 'solid.7z');
    const options = new VerificationOptions().withIntegrityCheck();

    const report = await verifyArchive(solid, null, options);
    assert.strictEqual(report.integrityStatus, 'INCOMPLETE');
    assert.strictEqual(report.status, 'WARNING');

    const config = new SecurityConfig().setAllowSolidArchives(true);
    const allowed = await verifyArchive(solid, config, options);
    assert.strictEqual(allowed.integrityStatus, 'OK');
  });
});
