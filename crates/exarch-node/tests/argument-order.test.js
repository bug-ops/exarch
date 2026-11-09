/**
 * One argument order across the in-memory list functions (#1102): `config`,
 * then `options`, then `format`. Distinct values in each position make a swap
 * fail.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const {
  ListOptions,
  SecurityConfig,
  listArchiveBytes,
  listArchiveBytesSync,
  listArchiveBytesWithProgress,
  listArchiveBytesWithProgressSync,
} = require('../index.js');

const SYMLINK_7Z = fs.readFileSync(
  path.join(__dirname, '..', '..', '..', 'tests', 'fixtures', 'symlink-mode.7z')
);

const config = () => new SecurityConfig();
const read = () => new ListOptions().withStoredTargets('read');
const symlinkState = (manifest) =>
  manifest.entries.find((e) => e.entryType === 'Symlink').target.state;

describe('list functions take config, options, format', () => {
  it('listArchiveBytesSync', () => {
    assert.strictEqual(
      symlinkState(listArchiveBytesSync(SYMLINK_7Z, config(), read(), 'SevenZ')),
      'recorded'
    );
    assert.strictEqual(
      symlinkState(listArchiveBytesSync(SYMLINK_7Z, config(), null, 'SevenZ')),
      'unread'
    );
    assert.throws(() => listArchiveBytesSync(SYMLINK_7Z, read(), config(), 'SevenZ'));
  });

  it('listArchiveBytes', async () => {
    const manifest = await listArchiveBytes(SYMLINK_7Z, config(), read(), 'SevenZ', null);
    assert.strictEqual(symlinkState(manifest), 'recorded');
    assert.throws(() => listArchiveBytes(SYMLINK_7Z, read(), config(), 'SevenZ', null));
  });

  it('listArchiveBytesWithProgress', async () => {
    let calls = 0;
    const manifest = await listArchiveBytesWithProgress(
      SYMLINK_7Z,
      config(),
      read(),
      'SevenZ',
      () => {
        calls += 1;
      },
      null
    );
    assert.strictEqual(symlinkState(manifest), 'recorded');
    assert.ok(calls > 0);
    assert.throws(() =>
      listArchiveBytesWithProgress(SYMLINK_7Z, read(), config(), 'SevenZ', null, null)
    );
  });

  it('listArchiveBytesWithProgressSync', () => {
    const manifest = listArchiveBytesWithProgressSync(SYMLINK_7Z, config(), read(), 'SevenZ', null);
    assert.strictEqual(symlinkState(manifest), 'recorded');
    assert.throws(() =>
      listArchiveBytesWithProgressSync(SYMLINK_7Z, read(), config(), 'SevenZ', null)
    );
  });
});
