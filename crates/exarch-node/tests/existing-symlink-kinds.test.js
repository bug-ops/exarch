/**
 * The typed kind of an entry over an existing symlink that points outside the
 * destination (#1204, #1221): the same `code`, `subCode` and `by` for a file,
 * a directory and a nested entry across tar, zip and 7z, and nothing is
 * written outside the destination.
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { extractArchiveSync, SecurityConfig, ExtractionOptions } = require('../index.js');
const { tarEntry, tarArchive, zipArchive } = require('./helpers/archives.js');

const FIXTURES = path.join(__dirname, '..', '..', 'exarch-core', 'tests', 'fixtures');

const POLICIES = ['refuse', 'overwrite'];

describe('entry over an escaping existing symlink', () => {
  let tempDir;
  let out;
  let outside;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-symlink-kinds-'));
    out = path.join(tempDir, 'out');
    outside = path.join(tempDir, 'outside');
    fs.mkdirSync(out);
    fs.mkdirSync(outside);
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function plantLink(rel) {
    fs.mkdirSync(path.dirname(path.join(out, rel)), { recursive: true });
    fs.symlinkSync(outside, path.join(out, rel));
  }

  // The Rust matrix blocks a nested entry with a symlink to a file inside the tree.
  function plantInsideFileLink(rel) {
    fs.writeFileSync(path.join(out, 't'), 'old');
    fs.symlinkSync('t', path.join(out, rel));
  }

  function extractFailure(archive, policy) {
    const config = new SecurityConfig().withAllowSymlinks(true);
    const options = new ExtractionOptions().withExistingFiles(policy);
    try {
      extractArchiveSync(archive, out, config, options);
    } catch (err) {
      return err;
    }
    return assert.fail('extraction unexpectedly succeeded');
  }

  function assertExistingSymlink(err, label) {
    assert.strictEqual(err.code, 'SECURITY_VIOLATION', label);
    assert.strictEqual(err.subCode, 'EXISTING_SYMLINK', label);
    assert.strictEqual(err.by, 'existing', label);
    assert.deepStrictEqual(fs.readdirSync(outside), [], label);
  }

  function assertFileOverLink(err, policy, rel, label) {
    if (policy === 'refuse') {
      assert.strictEqual(err.code, 'OUTPUT_EXISTS', label);
      assert.deepStrictEqual(err.conflicts, [{ path: rel, occupant: 'symlink' }], label);
      assert.strictEqual(err.by, 'existing', label);
      assert.deepStrictEqual(fs.readdirSync(outside), [], label);
    } else {
      assertExistingSymlink(err, label);
    }
  }

  function archives(files) {
    const write = (name, bytes) => {
      const file = path.join(tempDir, name);
      fs.writeFileSync(file, bytes);
      return file;
    };
    return {
      tar: write(
        'a.tar',
        tarArchive(
          files.map((f) => tarEntry({ ...f, type: f.name.endsWith('/') ? '5' : '0' }))
        )
      ),
      zip: write('a.zip', zipArchive(files)),
    };
  }

  const FILE_ENTRY = [{ name: 'l', data: Buffer.from('new') }];
  const DIR_ENTRY = [{ name: 'x/' }, { name: 'x/a', data: Buffer.from('ok') }];
  const NESTED_ENTRY = [{ name: 'd/e/f', data: Buffer.from('ok') }];

  for (const policy of POLICIES) {
    it(`a file over the link is the occupant kind in tar and zip (${policy})`, (t) => {
      if (process.platform === 'win32') {
        return t.skip('symlink creation needs privileges on Windows');
      }
      for (const [format, archive] of Object.entries(archives(FILE_ENTRY))) {
        fs.rmSync(out, { recursive: true, force: true });
        fs.mkdirSync(out);
        plantLink('l');
        assertFileOverLink(extractFailure(archive, policy), policy, 'l', `${format} ${policy}`);
      }
    });

    it(`a directory over the link is an existing-symlink refusal in tar and zip (${policy})`, (t) => {
      if (process.platform === 'win32') {
        return t.skip('symlink creation needs privileges on Windows');
      }
      for (const [format, archive] of Object.entries(archives(DIR_ENTRY))) {
        fs.rmSync(out, { recursive: true, force: true });
        fs.mkdirSync(out);
        plantLink('x');
        assertExistingSymlink(extractFailure(archive, policy), `${format} ${policy}`);
      }
    });

    it(`a nested entry below the link is an existing-symlink refusal in tar and zip (${policy})`, (t) => {
      if (process.platform === 'win32') {
        return t.skip('symlink creation needs privileges on Windows');
      }
      for (const [format, archive] of Object.entries(archives(NESTED_ENTRY))) {
        fs.rmSync(out, { recursive: true, force: true });
        fs.mkdirSync(out);
        plantInsideFileLink('d');
        assertExistingSymlink(extractFailure(archive, policy), `${format} ${policy}`);
      }
    });

    it(`7z: a file, a directory and a nested entry over the link (${policy})`, (t) => {
      if (process.platform === 'win32') {
        return t.skip('symlink creation needs privileges on Windows');
      }
      const simple = path.join(FIXTURES, 'simple.7z');
      const nested = path.join(FIXTURES, 'nested-dirs.7z');

      plantLink('simple/file1.txt');
      assertFileOverLink(
        extractFailure(simple, policy),
        policy,
        'simple/file1.txt',
        `7z file ${policy}`
      );

      fs.rmSync(out, { recursive: true, force: true });
      fs.mkdirSync(out);
      plantLink('nested/subdir1/subdir2');
      assertExistingSymlink(extractFailure(nested, policy), `7z directory ${policy}`);

      fs.rmSync(out, { recursive: true, force: true });
      fs.mkdirSync(out);
      plantInsideFileLink('simple');
      assertExistingSymlink(extractFailure(simple, policy), `7z nested ${policy}`);
    });
  }
});
