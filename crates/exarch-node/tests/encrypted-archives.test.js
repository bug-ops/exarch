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
  listArchiveBytes,
  listArchiveBytesSync,
  listArchiveBytesWithProgress,
  listArchiveBytesWithProgressSync,
  verifyArchiveBytes,
  verifyArchiveBytesSync,
  verifyArchiveBytesWithProgress,
  verifyArchiveBytesWithProgressSync,
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

  for (const archive of ARCHIVES) {
    const name = path.basename(archive);

    it(`${name}: the bytes forms of list and verify take the password`, async () => {
      const data = fs.readFileSync(archive);
      const manifests = [
        listArchiveBytesSync(data, null, null, null, password()),
        listArchiveBytesWithProgressSync(data, null, null, null, null, password()),
        await listArchiveBytes(data, null, null, null, null, password()),
        await listArchiveBytesWithProgress(data, null, null, null, null, null, password()),
      ];
      const reports = [
        verifyArchiveBytesSync(data, null, null, null, password()),
        verifyArchiveBytesWithProgressSync(data, null, null, null, null, password()),
        await verifyArchiveBytes(data, null, null, null, null, password()),
        await verifyArchiveBytesWithProgress(data, null, null, null, null, null, password()),
      ];

      for (const manifest of manifests) {
        assert.ok(manifest.entries.some((entry) => entry.path.endsWith('inner.txt')));
      }
      for (const report of reports) {
        assert.deepStrictEqual(report.issues, []);
      }
    });
  }

  it('an encrypted header: the bytes forms without a password are a typed security violation', () => {
    const data = fs.readFileSync(ARCHIVES[1]);

    for (const call of [listArchiveBytesSync, verifyArchiveBytesSync]) {
      assert.throws(
        () => call(data),
        (err) =>
          err.code === 'SECURITY_VIOLATION' &&
          err.subCode === 'ENCRYPTED' &&
          err.reason === 'password_required'
      );
    }
  });

  it('the bytes forms refuse a string and an empty password before reading', () => {
    const data = fs.readFileSync(ARCHIVES[0]);

    assert.throws(() => listArchiveBytesSync(data, null, null, null, 'correct-horse'));
    assert.throws(() => verifyArchiveBytesSync(data, null, null, null, Buffer.alloc(0)));
    assert.throws(() => listArchiveBytes(data, null, null, null, null, Buffer.alloc(0)));
  });

  it('concurrent 7z operations with different passwords each succeed (#1352)', async () => {
    const fixtures = path.join(__dirname, 'fixtures');
    const jobs = [
      [path.join(fixtures, 'encrypted-header.7z'), 'correct-horse'],
      [path.join(fixtures, 'encrypted-content-plain-header.7z'), 'exarch'],
    ];
    // The encrypted-header archive adds a fixed header reserve of 2**24 to the budget.
    const config = new SecurityConfig().withMaxKdfWork(2 ** 24 + 2 ** 21);

    const reports = await Promise.all(
      [...Array(80).keys()].map((i) => {
        const [archive, secret] = jobs[i % 2];
        const out = path.join(tempDir, `out-${i}`);
        return extractArchive(archive, out, config, null, Buffer.from(secret));
      })
    );

    assert.ok(reports.every((report) => report.filesExtracted === 2));
  });

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
