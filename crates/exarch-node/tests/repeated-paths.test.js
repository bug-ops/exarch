/**
 * Repeated paths (#1201): `SecurityConfig.repeatedPaths` refuses an archive
 * that names a landing twice in extract, list and verify alike; the default
 * keeps the first copy.
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
const { tarEntry, tarArchive } = require('./helpers/archives.js');

describe('repeated paths', () => {
  let tempDir;
  let repeatedFile;
  let directories;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-repeated-'));
    repeatedFile = path.join(tempDir, 's07.tar');
    fs.writeFileSync(
      repeatedFile,
      tarArchive([
        tarEntry({ name: 'a', data: Buffer.from('first\n') }),
        tarEntry({ name: 'a', data: Buffer.from('last\n') }),
      ]),
    );
    directories = path.join(tempDir, 'dirs.tar');
    fs.writeFileSync(
      directories,
      tarArchive([
        tarEntry({ name: 'd', type: '5' }),
        tarEntry({ name: 'd', type: '5' }),
        tarEntry({ name: 'd/f', data: Buffer.from('x') }),
      ]),
    );
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('defaults to keep_first, also for permissive', () => {
    assert.strictEqual(new SecurityConfig().repeatedPaths, 'keep_first');
    assert.strictEqual(SecurityConfig.permissive().repeatedPaths, 'keep_first');
  });

  it('round-trips through the setter and rejects unknown values', () => {
    const config = new SecurityConfig();
    config.withRepeatedPaths('refuse');
    assert.strictEqual(config.repeatedPaths, 'refuse');
    config.withRepeatedPaths('keep_first');
    assert.strictEqual(config.repeatedPaths, 'keep_first');
    assert.throws(() => new SecurityConfig().withRepeatedPaths('last_wins'));
  });

  it('keeps the first copy by default', () => {
    const out = path.join(tempDir, 'out');
    extractArchiveSync(repeatedFile, out);
    assert.strictEqual(fs.readFileSync(path.join(out, 'a'), 'utf8'), 'first\n');
  });

  it('refuse raises a typed security violation with a relax hint', () => {
    const config = new SecurityConfig().withRepeatedPaths('refuse');
    assert.throws(
      () => extractArchiveSync(repeatedFile, path.join(tempDir, 'out'), config),
      (err) => {
        assert.strictEqual(err.code, 'SECURITY_VIOLATION');
        assert.strictEqual(err.subCode, 'REPEATED_PATH');
        assert.strictEqual(err.relaxableBy, 'repeated_paths');
        return true;
      },
    );
  });

  it('refuse leaves a directory repeated over a directory alone', () => {
    const out = path.join(tempDir, 'out');
    extractArchiveSync(directories, out, new SecurityConfig().withRepeatedPaths('refuse'));
    assert.strictEqual(fs.readFileSync(path.join(out, 'd', 'f'), 'utf8'), 'x');
  });

  it('list marks the repeat as refused only under refuse', () => {
    const kept = listArchiveSync(repeatedFile).dispositions.map((d) => d.action);
    const refused = listArchiveSync(
      repeatedFile,
      new SecurityConfig().withRepeatedPaths('refuse'),
    ).dispositions.map((d) => d.action);
    assert.deepStrictEqual(kept, ['extract', 'skip']);
    assert.deepStrictEqual(refused, ['extract', 'refuse']);
  });

  it('verify reports the repeat only under refuse', () => {
    const named = (report) => report.issues.some((issue) => issue.message.includes('named twice'));
    assert.strictEqual(named(verifyArchiveSync(repeatedFile)), false);
    const strict = verifyArchiveSync(
      repeatedFile,
      new SecurityConfig().withRepeatedPaths('refuse'),
    );
    assert.strictEqual(named(strict), true);
  });
});
