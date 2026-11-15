/**
 * The typed refusal of a directory, file or symlink occupant (#1183): each
 * `conflicts` element names its occupant, and `by` is set on an
 * `EXISTING_SYMLINK` refusal.
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { extractArchiveSync, SecurityConfig, ExtractionOptions } = require('../index.js');
const { tarEntry, tarArchive } = require('./helpers/archives.js');

describe('typed occupant refusal', () => {
  let tempDir;
  let out;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-occupant-'));
    out = path.join(tempDir, 'out');
    fs.mkdirSync(out);
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function extractFailure(entries, config = null, options = null) {
    const archive = path.join(tempDir, 'a.tar');
    fs.writeFileSync(archive, tarArchive(entries.map(tarEntry)));
    try {
      extractArchiveSync(archive, out, config, options);
    } catch (err) {
      return err;
    }
    return assert.fail('extraction unexpectedly succeeded');
  }

  it('a file over a directory names a directory occupant', () => {
    fs.mkdirSync(path.join(out, 'd'));
    const options = new ExtractionOptions().withExistingFiles('overwrite');
    const err = extractFailure([{ name: 'd', data: Buffer.from('x') }], null, options);
    assert.strictEqual(err.code, 'OUTPUT_EXISTS');
    assert.deepStrictEqual(err.conflicts, [{ path: 'd', occupant: 'directory' }]);
    assert.strictEqual(err.by, 'existing');
  });

  it('a directory over a file names a file occupant under every policy', () => {
    fs.writeFileSync(path.join(out, 'f'), 'old');
    for (const policy of ['skip', 'overwrite', 'refuse']) {
      const options = new ExtractionOptions().withExistingFiles(policy);
      const err = extractFailure([{ name: 'f/', type: '5' }], null, options);
      assert.strictEqual(err.code, 'OUTPUT_EXISTS', policy);
      assert.deepStrictEqual(err.conflicts, [{ path: 'f', occupant: 'file' }], policy);
    }
  });

  it('an atomic refusal names the caller destination, not a staging path', () => {
    fs.writeFileSync(path.join(out, 'f'), 'old');
    const options = new ExtractionOptions().withStaging('atomic');
    const err = extractFailure([{ name: 'f/', type: '5' }], null, options);
    assert.strictEqual(err.code, 'OUTPUT_EXISTS');
    assert.strictEqual(path.basename(err.path), 'out');
    assert.ok(!err.message.includes('.exarch'), err.message);
  });

  it('a directory over a symlink names who made it in by', (t) => {
    if (process.platform === 'win32') {
      return t.skip('symlink creation needs privileges on Windows');
    }
    fs.writeFileSync(path.join(out, 't'), 'target');
    fs.symlinkSync('t', path.join(out, 'l'));
    const config = new SecurityConfig().withAllowSymlinks(true);
    const err = extractFailure([{ name: 'l/', type: '5' }], config);
    assert.strictEqual(err.code, 'SECURITY_VIOLATION');
    assert.strictEqual(err.subCode, 'EXISTING_SYMLINK');
    assert.strictEqual(err.by, 'existing');
  });

  it('other refusals carry no by', () => {
    const err = extractFailure([{ name: '../escape', data: Buffer.from('x') }]);
    assert.strictEqual(err.code, 'PATH_TRAVERSAL');
    assert.strictEqual(err.by, undefined);
  });
});
