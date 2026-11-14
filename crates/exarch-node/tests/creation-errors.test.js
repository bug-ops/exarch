/**
 * Unreadable and missing creation sources (#956).
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { createArchive, createArchiveSync } = require('../index.js');

describe('creation source errors', () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-creation-errors-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('an unreadable source is SOURCE_NOT_ACCESSIBLE and names the path', async (t) => {
    if (process.platform === 'win32') {
      return t.skip('POSIX permission bits');
    }
    const tree = path.join(tempDir, 'bad');
    fs.mkdirSync(tree);
    fs.writeFileSync(path.join(tree, 'ok.txt'), 'x');
    const unreadable = path.join(tree, 'unread.txt');
    fs.writeFileSync(unreadable, 'y');
    fs.chmodSync(unreadable, 0o000);
    try {
      fs.readFileSync(unreadable);
      return t.skip('mode 000 does not block reads for this user (running as root?)');
    } catch {
      // Expected: the file is genuinely unreadable.
    }
    const out = path.join(tempDir, 'o.tar.gz');

    await assert.rejects(createArchive(out, [tree]), (err) => {
      assert.strictEqual(err.code, 'SOURCE_NOT_ACCESSIBLE');
      assert.ok(err.message.includes('unread.txt'), err.message);
      assert.strictEqual(typeof err.errno, 'number');
      assert.strictEqual(typeof err.strerror, 'string');
      assert.ok(err.path.endsWith('unread.txt'), err.path);
      return true;
    });
    assert.throws(() => createArchiveSync(out, [tree]), { code: 'SOURCE_NOT_ACCESSIBLE' });
    assert.ok(!fs.existsSync(out));
  });

  it('a FIFO in the source is skipped as special_file, not read', (t) => {
    if (process.platform === 'win32') {
      return t.skip('needs mkfifo');
    }
    const tree = path.join(tempDir, 'tree');
    fs.mkdirSync(tree);
    fs.writeFileSync(path.join(tree, 'a.txt'), 'x');
    require('node:child_process').execFileSync('mkfifo', [path.join(tree, 'pipe')]);

    const report = createArchiveSync(path.join(tempDir, 'o.tar.gz'), [tree]);

    assert.strictEqual(report.filesAdded, 1);
    assert.deepStrictEqual(
      report.skipped.counts.filter((c) => c.kind === 'special_file'),
      [{ kind: 'special_file', count: 1 }],
    );
  });

  it('a missing source carries no OS failure properties', () => {
    assert.throws(
      () => createArchiveSync(path.join(tempDir, 'o.tar'), [path.join(tempDir, 'missing')]),
      (err) => {
        assert.strictEqual(err.code, 'SOURCE_NOT_FOUND');
        assert.strictEqual(err.errno, undefined);
        assert.strictEqual(err.strerror, undefined);
        return true;
      }
    );
  });

  it('two sources with one entry name are INVALID_CONFIGURATION naming both', () => {
    const one = path.join(tempDir, 'one');
    const two = path.join(tempDir, 'two');
    fs.mkdirSync(one);
    fs.mkdirSync(two);
    fs.writeFileSync(path.join(one, 'a.txt'), '1');
    fs.writeFileSync(path.join(two, 'a.txt'), '2');
    const out = path.join(tempDir, 'o.tar');
    assert.throws(
      () => createArchiveSync(out, [path.join(one, 'a.txt'), path.join(two, 'a.txt')]),
      (err) => {
        assert.strictEqual(err.code, 'INVALID_CONFIGURATION');
        assert.strictEqual(err.setting, 'source_paths');
        assert.strictEqual(err.collision.name, 'a.txt');
        assert.ok(err.collision.first.endsWith('a.txt'), err.collision.first);
        assert.ok(err.collision.second.endsWith('a.txt'), err.collision.second);
        return true;
      }
    );
    assert.ok(!fs.existsSync(out));
  });

  it('a missing source stays SOURCE_NOT_FOUND', () => {
    assert.throws(
      () => createArchiveSync(path.join(tempDir, 'o.tar'), [path.join(tempDir, 'missing')]),
      { code: 'SOURCE_NOT_FOUND' }
    );
  });
});
