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
      return true;
    });
    assert.throws(() => createArchiveSync(out, [tree]), { code: 'SOURCE_NOT_ACCESSIBLE' });
    assert.ok(!fs.existsSync(out));
  });

  it('a missing source stays SOURCE_NOT_FOUND', () => {
    assert.throws(
      () => createArchiveSync(path.join(tempDir, 'o.tar'), [path.join(tempDir, 'missing')]),
      { code: 'SOURCE_NOT_FOUND' }
    );
  });
});
