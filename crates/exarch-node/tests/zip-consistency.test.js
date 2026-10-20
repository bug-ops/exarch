/**
 * Tests for the ZIP structure policy (zipConsistency)
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  SecurityConfig,
  createArchiveSync,
  extractArchive,
  extractArchiveSync,
  listArchiveSync,
  verifyArchiveSync,
} = require('../index.js');

/** Creates a ZIP whose local header names the entry `tample.txt`, central `sample.txt`. */
function createCloakedZip(tempDir) {
  const source = path.join(tempDir, 'sample.txt');
  fs.writeFileSync(source, 'payload');
  const archive = path.join(tempDir, 'cloaked.zip');
  createArchiveSync(archive, [source]);

  const bytes = fs.readFileSync(archive);
  const firstName = bytes.indexOf('sample.txt');
  bytes[firstName] = 't'.charCodeAt(0);
  fs.writeFileSync(archive, bytes);
  return archive;
}

describe('SecurityConfig zipConsistency', () => {
  it('defaults to enforce, also for permissive', () => {
    assert.strictEqual(new SecurityConfig().zipConsistency, 'enforce');
    assert.strictEqual(SecurityConfig.permissive().zipConsistency, 'enforce');
  });

  it('round-trips through the setter', () => {
    const config = new SecurityConfig();
    config.setZipConsistency('ignore');
    assert.strictEqual(config.zipConsistency, 'ignore');
    config.setZipConsistency('enforce');
    assert.strictEqual(config.zipConsistency, 'enforce');
  });

  it('rejects unknown values', () => {
    assert.throws(() => new SecurityConfig().setZipConsistency('off'));
  });
});

describe('ZIP structure policy', () => {
  let tempDir;
  let archive;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-test-'));
    archive = createCloakedZip(tempDir);
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('extract rejects a cloaked zip before writing anything', async () => {
    const out = path.join(tempDir, 'out');
    await assert.rejects(extractArchive(archive, out), /ZIP_INCONSISTENCY/);
    assert.strictEqual(fs.existsSync(out), false);
  });

  it('extract with ignore keeps the central directory name', () => {
    const out = path.join(tempDir, 'out');
    const config = new SecurityConfig();
    config.setZipConsistency('ignore');
    extractArchiveSync(archive, out, config);
    assert.ok(fs.existsSync(path.join(out, 'sample.txt')));
  });

  it('list rejects under enforce and succeeds under ignore', () => {
    assert.throws(() => listArchiveSync(archive), /ZIP_INCONSISTENCY/);
    const config = new SecurityConfig();
    config.setZipConsistency('ignore');
    assert.strictEqual(listArchiveSync(archive, config).totalEntries, 1);
  });

  it('verify reports a header mismatch under enforce only', () => {
    const report = verifyArchiveSync(archive);
    assert.strictEqual(report.status, 'FAIL');
    assert.ok(report.issues.some((issue) => issue.category === 'Header Mismatch'));

    const config = new SecurityConfig();
    config.setZipConsistency('ignore');
    assert.strictEqual(verifyArchiveSync(archive, config).status, 'PASS');
  });
});
