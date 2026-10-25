/**
 * 7z symlink targets stay unread by listArchive, and links count against
 * maxFileCount in extractArchive (issues #718, #719).
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { extractArchiveSync, listArchiveSync, SecurityConfig } = require('../index.js');

// Written with sevenz-rust2: `a.txt` and a Unix-mode symlink `link` -> `a.txt`.
const SYMLINK_7Z = path.join(__dirname, '..', '..', '..', 'tests', 'fixtures', 'symlink-mode.7z');

/** A tar holding `count` symlinks named link0..linkN that point at `target`. */
function tarWithSymlinks(count) {
  const blocks = [];
  for (let i = 0; i < count; i++) {
    const header = Buffer.alloc(512);
    header.write(`link${i}`, 0, 100, 'ascii');
    header.write('0000777\0', 100, 8, 'ascii');
    header.write('0000000\0', 108, 8, 'ascii');
    header.write('0000000\0', 116, 8, 'ascii');
    header.write('00000000000\0', 124, 12, 'ascii');
    header.write('00000000000\0', 136, 12, 'ascii');
    header.write('        ', 148, 8, 'ascii');
    header.write('2', 156, 1, 'ascii');
    header.write('target', 157, 100, 'ascii');
    header.write('ustar\0', 257, 6, 'ascii');
    header.write('00', 263, 2, 'ascii');
    const sum = header.reduce((total, byte) => total + byte, 0);
    header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
    blocks.push(header);
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

describe('7z symlink targets and link counting', () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-test-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('listArchive leaves a 7z symlink target unset', () => {
    const manifest = listArchiveSync(SYMLINK_7Z);

    const link = manifest.entries.find((entry) => entry.entryType === 'Symlink');
    assert.strictEqual(link.path, 'link');
    assert.strictEqual(link.symlinkTarget ?? null, null);
  });

  it('extractArchive counts symlinks against maxFileCount', () => {
    const archive = path.join(tempDir, 'links.tar');
    fs.writeFileSync(archive, tarWithSymlinks(3));
    const config = new SecurityConfig().setAllowSymlinks(true).setMaxFileCount(2);

    assert.throws(() => extractArchiveSync(archive, path.join(tempDir, 'out'), config));
  });

  it('extractArchive accepts symlinks at maxFileCount', () => {
    const archive = path.join(tempDir, 'links.tar');
    fs.writeFileSync(archive, tarWithSymlinks(2));
    const config = new SecurityConfig().setAllowSymlinks(true).setMaxFileCount(2);

    extractArchiveSync(archive, path.join(tempDir, 'out'), config);

    assert.deepStrictEqual(fs.readdirSync(path.join(tempDir, 'out')).sort(), ['link0', 'link1']);
  });
});
