/**
 * Paths that are rendered as text (verification issues, progress callbacks)
 * never render two distinct entries alike: a backslash is `\x5C` and an
 * invalid byte is `\xNN`.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');
const { verifyArchiveBytes, verifyArchiveBytesWithProgress } = require('../index.js');

function emptyFile(nameBytes) {
  const header = Buffer.alloc(512);
  nameBytes.copy(header, 0);
  header.write('0000644\0', 100, 8, 'ascii');
  header.write('0000000\0', 108, 8, 'ascii');
  header.write('0000000\0', 116, 8, 'ascii');
  header.write('00000000000\0', 124, 12, 'ascii');
  header.write('00000000000\0', 136, 12, 'ascii');
  header.write('        ', 148, 8, 'ascii');
  header.write('0', 156, 1, 'ascii');
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  const sum = header.reduce((total, byte) => total + byte, 0);
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
  return header;
}

// One entry named with the raw byte 0xFF, one literally named `a\xFFb`.
const RAW = Buffer.from([0x61, 0xff, 0x62]);
const LITERAL = Buffer.from('a\\xFFb', 'ascii');
const ARCHIVE = Buffer.concat([emptyFile(RAW), emptyFile(LITERAL), Buffer.alloc(1024)]);

describe('rendered entry paths are injective', () => {
  it('progress callbacks render the two names differently', async () => {
    const seen = [];
    await verifyArchiveBytesWithProgress(ARCHIVE, null, null, null, (_err, [entryPath]) => {
      seen.push(entryPath);
    });
    assert.deepStrictEqual(seen.sort(), ['a\\x5CxFFb', 'a\\xFFb']);
  });

  it('verification issues name the invalid-byte entry unambiguously', async () => {
    const report = await verifyArchiveBytes(ARCHIVE);
    const paths = report.issues.map((issue) => issue.entryPath).filter((p) => p !== undefined);
    assert.ok(paths.includes('a\\xFFb'), JSON.stringify(paths));
    const flagged = report.issues.filter((issue) => issue.entryPath === 'a\\xFFb');
    assert.ok(flagged.length >= 1);
  });
});
