/**
 * 7z symlink targets stay unread by listArchive, and links count against
 * maxFileCount in extractArchive (issues #718, #719); directories count too
 * (#1038).
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  extractArchiveSync,
  listArchiveSync,
  verifyArchiveSync,
  SecurityConfig,
} = require('../index.js');

// Written with sevenz-rust2: `a.txt` and a Unix-mode symlink `link` -> `a.txt`.
const SYMLINK_7Z = path.join(__dirname, '..', '..', '..', 'tests', 'fixtures', 'symlink-mode.7z');

/** A tar of `count` empty members named `<prefix>0..N` of the given type flag. */
function tarOfEmptyMembers(count, prefix, typeflag, linkname) {
  const blocks = [];
  for (let i = 0; i < count; i++) {
    const header = Buffer.alloc(512);
    header.write(`${prefix}${i}`, 0, 100, 'ascii');
    header.write('0000777\0', 100, 8, 'ascii');
    header.write('0000000\0', 108, 8, 'ascii');
    header.write('0000000\0', 116, 8, 'ascii');
    header.write('00000000000\0', 124, 12, 'ascii');
    header.write('00000000000\0', 136, 12, 'ascii');
    header.write('        ', 148, 8, 'ascii');
    header.write(typeflag, 156, 1, 'ascii');
    header.write(linkname, 157, 100, 'ascii');
    header.write('ustar\0', 257, 6, 'ascii');
    header.write('00', 263, 2, 'ascii');
    const sum = header.reduce((total, byte) => total + byte, 0);
    header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
    blocks.push(header);
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

/** A tar holding `count` symlinks named link0..linkN that point at `target`. */
function tarWithSymlinks(count) {
  return tarOfEmptyMembers(count, 'link', '2', 'target');
}

/** A tar holding `count` directories named dir0/..dirN/. */
function tarWithDirectories(count) {
  return tarOfEmptyMembers(count, 'dir', '5', '');
}

describe('7z symlink targets and link counting', () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-test-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('listArchive leaves a 7z symlink target unread', () => {
    const manifest = listArchiveSync(SYMLINK_7Z);

    const link = manifest.entries.find((entry) => entry.entryType === 'Symlink');
    assert.strictEqual(link.path, 'link');
    assert.deepStrictEqual(link.target, { state: 'unread' });
    assert.strictEqual(link.size, undefined);
  });

  it('listArchive reports a recorded target and keeps size to files', () => {
    const archive = path.join(tempDir, 'one.tar');
    fs.writeFileSync(archive, tarWithSymlinks(1));
    const [link] = listArchiveSync(archive).entries;

    assert.strictEqual(link.entryType, 'Symlink');
    assert.deepStrictEqual(link.target, { state: 'recorded', path: 'target' });
    assert.strictEqual(link.size, undefined);
  });

  it('listArchive refuses a non-UTF-8 entry name instead of rendering it lossily', () => {
    const archive = path.join(tempDir, 'bytes.tar');
    const tar = tarWithSymlinks(1);
    tar.write('ÿ', 0, 'latin1');
    const sum = tar
      .subarray(0, 512)
      .reduce((total, byte, i) => total + (i >= 148 && i < 156 ? 32 : byte), 0);
    tar.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
    fs.writeFileSync(archive, tar);

    assert.throws(() => listArchiveSync(archive), {
      code: 'INVALID_ARCHIVE',
      subCode: 'ENTRY_NAME',
      nonUtf8EntryPath: '\\xFFink0',
    });
  });

  it('verifyArchive reports the typed refusal behind a finding', () => {
    const archive = path.join(tempDir, 'verify.tar');
    fs.writeFileSync(archive, tarWithSymlinks(1));
    const report = verifyArchiveSync(archive);

    const issue = report.issues.find((i) => i.code !== undefined);
    assert.ok(issue, JSON.stringify(report.issues));
    assert.strictEqual(issue.code, 'SECURITY_VIOLATION');
    assert.strictEqual(issue.subCode, 'LINK_POLICY');
    assert.strictEqual(issue.relaxableBy, 'symlinks');
    assert.strictEqual('context' in issue, false);
  });

  it('extractArchive counts symlinks against maxFileCount', () => {
    const archive = path.join(tempDir, 'links.tar');
    fs.writeFileSync(archive, tarWithSymlinks(3));
    const config = new SecurityConfig().withAllowSymlinks(true).withMaxFileCount(2);

    assert.throws(() => extractArchiveSync(archive, path.join(tempDir, 'out'), config));
  });

  it('extractArchive counts directories against maxFileCount', () => {
    const archive = path.join(tempDir, 'dirs.tar');
    fs.writeFileSync(archive, tarWithDirectories(3));

    assert.throws(() =>
      extractArchiveSync(
        archive,
        path.join(tempDir, 'out'),
        new SecurityConfig().withMaxFileCount(2),
      ),
    );

    extractArchiveSync(
      archive,
      path.join(tempDir, 'out'),
      new SecurityConfig().withMaxFileCount(3),
    );
    assert.deepStrictEqual(fs.readdirSync(path.join(tempDir, 'out')).sort(), [
      'dir0',
      'dir1',
      'dir2',
    ]);
  });

  it('extractArchive accepts symlinks at maxFileCount', () => {
    const archive = path.join(tempDir, 'links.tar');
    fs.writeFileSync(archive, tarWithSymlinks(2));
    const config = new SecurityConfig().withAllowSymlinks(true).withMaxFileCount(2);

    extractArchiveSync(archive, path.join(tempDir, 'out'), config);

    assert.deepStrictEqual(fs.readdirSync(path.join(tempDir, 'out')).sort(), ['link0', 'link1']);
  });
});
