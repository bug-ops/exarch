/**
 * Password-protected ZIP and 7z archives (#1023). The fixtures are WinZip
 * AES-256 and a non-solid 7z with an encrypted header, both protected with
 * `correct-horse`.
 */
const { describe, it, afterEach, beforeEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  SecurityConfig,
  extractArchiveSync,
  extractArchive,
  listArchiveSync,
  verifyArchiveSync,
} = require('../index.js');

const ARCHIVES = ['encrypted-aes256.zip', 'encrypted-header.7z'].map((name) =>
  path.join(__dirname, 'fixtures', name)
);
const WRONG_REASON = {
  'encrypted-aes256.zip': 'wrong_password',
  'encrypted-header.7z': 'wrong_password_or_corrupt',
};
const password = () => Buffer.from('correct-horse');

describe('encrypted archives', () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-encrypted-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  for (const archive of ARCHIVES) {
    const name = path.basename(archive);

    it(`${name}: extracts with the password`, () => {
      const out = path.join(tempDir, 'out');

      const report = extractArchiveSync(archive, out, null, null, password());

      assert.strictEqual(report.filesExtracted, 2);
      assert.strictEqual(fs.readFileSync(path.join(out, 'hello.txt'), 'utf8'), 'hello encrypted\n');
    });

    it(`${name}: async extract takes the password too`, async () => {
      const out = path.join(tempDir, 'out');

      const report = await extractArchive(archive, out, null, null, password());

      assert.strictEqual(report.filesExtracted, 2);
    });

    it(`${name}: without a password is a typed security violation`, () => {
      assert.throws(
        () => extractArchiveSync(archive, path.join(tempDir, 'out')),
        (err) =>
          err.code === 'SECURITY_VIOLATION' &&
          err.subCode === 'ENCRYPTED' &&
          err.reason === 'password_required'
      );
      assert.ok(!fs.existsSync(path.join(tempDir, 'out', 'hello.txt')));
    });

    it(`${name}: a wrong password is refused and never quoted`, () => {
      assert.throws(
        () =>
          extractArchiveSync(
            archive,
            path.join(tempDir, 'out'),
            null,
            null,
            Buffer.from('s3cr3t-wrong')
          ),
        (err) =>
          err.subCode === 'ENCRYPTED' &&
          err.reason === WRONG_REASON[name] &&
          !`${err.message}${JSON.stringify(err)}`.includes('s3cr3t')
      );
    });

    it(`${name}: list and verify take the password`, () => {
      const manifest = listArchiveSync(archive, null, null, null, password());
      const report = verifyArchiveSync(archive, null, null, password());

      assert.ok(manifest.entries.some((entry) => entry.path.endsWith('inner.txt')));
      assert.deepStrictEqual(report.issues, []);
    });
  }

  it('refuses a string password', () => {
    assert.throws(() =>
      extractArchiveSync(ARCHIVES[0], path.join(tempDir, 'out'), null, null, 'correct-horse')
    );
  });

  it('refuses an empty password', () => {
    assert.throws(() =>
      extractArchiveSync(ARCHIVES[0], path.join(tempDir, 'out'), null, null, Buffer.alloc(0))
    );
  });

  it('keeps max_kdf_work a config setting and the password out of it', () => {
    const config = new SecurityConfig();

    assert.strictEqual(config.maxKdfWork, 1 << 27);
    assert.ok(!JSON.stringify(config).toLowerCase().includes('password'));
  });
});
