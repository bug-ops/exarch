/**
 * Passwords for in-memory and callback extraction, the `encrypted` entry
 * marker and the `unusable_password` reason (#1241, #1242, #1246). The fixtures
 * are the ones of `encrypted-archives.test.js`.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  extractArchiveToMemory,
  extractArchiveToMemorySync,
  extractArchiveToMemoryWithProgress,
  extractArchiveToMemoryWithProgressSync,
  extractArchiveToCallback,
  extractArchiveToCallbackSync,
  listArchiveSync,
} = require('../index.js');

const NAMES = ['encrypted-aes256.zip', 'encrypted-header.7z'];
const fixture = (name) => path.join(__dirname, 'fixtures', name);
const data = (name) => fs.readFileSync(fixture(name));
const password = () => Buffer.from('correct-horse');
const HELLO = 'hello encrypted\n';

const fileText = (entries, wanted) => {
  const entry = entries.find((e) => e.kind === 'file' && e.path === wanted);
  return entry && Buffer.from(entry.data).toString('utf8');
};

describe('passwords for in-memory extraction', () => {
  for (const name of NAMES) {
    it(`${name}: extractArchiveToMemory decrypts with the password`, async () => {
      const { entries } = await extractArchiveToMemory(
        data(name),
        null,
        null,
        null,
        null,
        null,
        null,
        password()
      );

      assert.strictEqual(fileText(entries, 'hello.txt'), HELLO);
    });

    it(`${name}: extractArchiveToMemorySync decrypts with the password`, () => {
      const { entries } = extractArchiveToMemorySync(
        data(name),
        null,
        null,
        null,
        null,
        null,
        password()
      );

      assert.strictEqual(fileText(entries, 'hello.txt'), HELLO);
    });

    it(`${name}: the progress variants take the password`, async () => {
      const asyncResult = await extractArchiveToMemoryWithProgress(
        data(name),
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        password()
      );
      const syncResult = extractArchiveToMemoryWithProgressSync(
        data(name),
        null,
        null,
        null,
        null,
        null,
        null,
        password()
      );

      assert.strictEqual(fileText(asyncResult.entries, 'hello.txt'), HELLO);
      assert.strictEqual(fileText(syncResult.entries, 'hello.txt'), HELLO);
    });

    it(`${name}: no password is password_required`, () => {
      assert.throws(
        () => extractArchiveToMemorySync(data(name)),
        (error) => error.subCode === 'ENCRYPTED' && error.reason === 'password_required'
      );
    });
  }

  it('refuses a string and an empty password', () => {
    assert.throws(() =>
      extractArchiveToMemorySync(data(NAMES[0]), null, null, null, null, null, 'correct-horse')
    );
    assert.throws(
      () =>
        extractArchiveToMemorySync(data(NAMES[0]), null, null, null, null, null, Buffer.alloc(0)),
      (error) => error.code === 'InvalidArg'
    );
  });
});

describe('passwords for callback extraction', () => {
  for (const name of NAMES) {
    it(`${name}: extractArchiveToCallback delivers decrypted files`, async () => {
      const delivered = [];

      await extractArchiveToCallback(
        data(name),
        (entry) => {
          delivered.push(entry);
        },
        null,
        null,
        null,
        null,
        null,
        password()
      );

      assert.strictEqual(fileText(delivered, 'hello.txt'), HELLO);
    });

    it(`${name}: extractArchiveToCallbackSync delivers decrypted files`, () => {
      const delivered = [];

      extractArchiveToCallbackSync(
        data(name),
        (entry) => {
          delivered.push(entry);
        },
        null,
        null,
        null,
        null,
        password()
      );

      assert.strictEqual(fileText(delivered, 'hello.txt'), HELLO);
    });
  }

  it('refuses a string password', () => {
    assert.throws(() =>
      extractArchiveToCallbackSync(
        data(NAMES[0]),
        () => {},
        null,
        null,
        null,
        null,
        'correct-horse'
      )
    );
  });
});

describe('unusable_password', () => {
  it('a non-UTF-8 password for a 7z is refused with that reason', () => {
    assert.throws(
      () =>
        extractArchiveToMemorySync(
          data('encrypted-header.7z'),
          null,
          null,
          null,
          null,
          null,
          Buffer.from([0xff, 0xfe, 0x2d, 0x78])
        ),
      (error) => error.subCode === 'ENCRYPTED' && error.reason === 'unusable_password'
    );
  });
});

describe('the encrypted entry marker', () => {
  for (const name of NAMES) {
    it(`${name}: listed files are encrypted`, () => {
      const manifest = listArchiveSync(fixture(name), null, null, null, password());

      const files = manifest.entries.filter((e) => e.entryType === 'File');
      assert.ok(files.length > 0);
      assert.ok(files.every((e) => e.encrypted === true));
    });
  }

  it('entries of a plain archive are not encrypted', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-plain-'));
    try {
      const { createArchiveSync } = require('../index.js');
      fs.writeFileSync(path.join(dir, 'a.txt'), 'x');
      const archive = path.join(dir, 'a.tar');
      createArchiveSync(archive, [path.join(dir, 'a.txt')]);

      const manifest = listArchiveSync(archive);

      assert.ok(manifest.entries.length > 0);
      assert.ok(manifest.entries.every((e) => e.encrypted === false));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
