/**
 * Tests for createArchiveToBytes / createArchiveToBytesSync (#784) and
 * extractArchiveToMemoryWithProgress (#783).
 */
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  createArchiveToBytes,
  createArchiveToBytesSync,
  extractArchiveToMemory,
  extractArchiveToMemoryWithProgress,
  listArchiveBytesWithProgress,
  verifyArchiveBytesWithProgress,
} = require('../index.js');

const FORMATS = ['Tar', 'TarGz', 'TarBz2', 'TarXz', 'TarZst', 'Zip'];

describe('createArchiveToBytes', () => {
  let tempDir;
  let source;

  before(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-create-bytes-'));
    source = path.join(tempDir, 'source');
    fs.mkdirSync(path.join(source, 'd'), { recursive: true });
    fs.writeFileSync(path.join(source, 'a.txt'), 'alpha');
    fs.writeFileSync(path.join(source, 'd', 'b.txt'), 'bravo'.repeat(100));
  });

  after(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  const fileContents = (result) =>
    Object.fromEntries(
      result.entries
        .filter((entry) => entry.kind === 'file')
        .map((entry) => [path.basename(entry.path), Buffer.from(entry.data).toString()])
    );

  for (const format of FORMATS) {
    it(`round-trips ${format} (async)`, async () => {
      const created = await createArchiveToBytes([source], format);

      assert.ok(created.data instanceof Uint8Array);
      assert.strictEqual(created.report.filesAdded, 2);
      assert.strictEqual(created.report.bytesCompressed, created.data.length);
      const result = await extractArchiveToMemory(created.data, null, null, null, null, format);
      assert.deepStrictEqual(fileContents(result), {
        'a.txt': 'alpha',
        'b.txt': 'bravo'.repeat(100),
      });
    });

    it(`round-trips ${format} (sync)`, async () => {
      const created = createArchiveToBytesSync([source], format);

      const result = await extractArchiveToMemory(created.data);
      assert.deepStrictEqual(fileContents(result), {
        'a.txt': 'alpha',
        'b.txt': 'bravo'.repeat(100),
      });
    });
  }

  it('refuses SevenZ at the boundary: it is not a creatable format', async () => {
    const expected = { code: 'InvalidArg', message: /SevenZ.*CreatableFormat/ };
    assert.throws(() => createArchiveToBytesSync([source], 'SevenZ'), expected);
    assert.throws(() => createArchiveToBytes([source], 'SevenZ'), expected);
  });

  it('rejects a missing source', async () => {
    await assert.rejects(createArchiveToBytes([path.join(tempDir, 'missing')], 'Tar'));
  });

  it('rejects a source with a null byte', async () => {
    await assert.rejects(createArchiveToBytes(['a\0b'], 'Tar'));
  });
});

describe('extractArchiveToMemoryWithProgress', () => {
  let archive;
  let zipArchive;

  before(() => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-memory-progress-'));
    fs.writeFileSync(path.join(tempDir, 'a.txt'), 'alpha');
    fs.writeFileSync(path.join(tempDir, 'b.txt'), 'bravo');
    archive = createArchiveToBytesSync([tempDir], 'TarGz').data;
    zipArchive = createArchiveToBytesSync([tempDir], 'Zip').data;
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('reports every entry', async () => {
    const calls = [];

    const result = await extractArchiveToMemoryWithProgress(
      archive,
      null,
      null,
      null,
      null,
      null,
      (err, [entryPath, total, current]) => {
        assert.strictEqual(err, null);
        calls.push([entryPath, total, current]);
      }
    );

    const plain = await extractArchiveToMemory(archive);
    assert.strictEqual(calls.length, plain.entries.length);
    assert.deepStrictEqual(
      calls.map(([, total, current]) => [total, current]),
      [
        [null, 1],
        [null, 2],
      ]
    );
    assert.deepStrictEqual(
      result.entries.map((entry) => entry.path),
      plain.entries.map((entry) => entry.path)
    );
  });

  it('works without a callback', async () => {
    const result = await extractArchiveToMemoryWithProgress(archive);

    assert.strictEqual(result.report.filesExtracted, 2);
  });

  it('forwards maxBytes', async () => {
    await assert.rejects(
      extractArchiveToMemoryWithProgress(archive, null, null, 10, null, null, null),
      {
        code: 'QUOTA_EXCEEDED',
      }
    );
  });

  it('rejects with the counters when the callback throws after success', async () => {
    const boom = new Error('boom from progress callback');

    await assert.rejects(
      extractArchiveToMemoryWithProgress(archive, null, null, null, null, null, () => {
        throw boom;
      }),
      (err) => {
        assert.strictEqual(err.code, 'PROGRESS_CALLBACK_ERROR');
        assert.strictEqual(err.cause, boom);
        assert.strictEqual(err.writes, 'discarded');
        assert.strictEqual(err.filesExtracted, undefined);
        assert.strictEqual(err.entries, undefined);
        return true;
      }
    );
  });

  it('keeps the core error primary when the callback also throws', async () => {
    const boom = new Error('boom from progress callback');

    await assert.rejects(
      extractArchiveToMemoryWithProgress(archive, null, null, 10, null, null, () => {
        throw boom;
      }),
      (err) => {
        assert.strictEqual(err.code, 'QUOTA_EXCEEDED');
        assert.strictEqual(err.cause, boom);
        return true;
      }
    );
  });

  for (const [name, call, errorMessage] of [
    [
      'listArchiveBytesWithProgress',
      (progress, data = archive) => listArchiveBytesWithProgress(data, null, null, null, progress),
      'listing',
    ],
    [
      'verifyArchiveBytesWithProgress',
      (progress, data = archive) =>
        verifyArchiveBytesWithProgress(data, null, null, null, progress),
      'verification',
    ],
  ]) {
    it(`${name} reports every entry`, async () => {
      const calls = [];

      await call((err, [entryPath, total, current]) => {
        assert.strictEqual(err, null);
        calls.push([entryPath, total, current]);
      });

      assert.deepStrictEqual(
        calls.map(([, total, current]) => [total, current]),
        [
          [null, 1],
          [null, 2],
        ]
      );
    });

    it(`${name} reports the entry count as total for ZIP`, async () => {
      const calls = [];

      await call((err, [entryPath, total, current]) => {
        assert.strictEqual(err, null);
        calls.push([entryPath, total, current]);
      }, zipArchive);

      assert.deepStrictEqual(
        calls.map(([, total, current]) => [total, current]),
        [
          [2, 1],
          [2, 2],
        ]
      );
    });

    it(`${name} works without a callback`, async () => {
      assert.ok(await call(null));
    });

    it(`${name} rejects with PROGRESS_CALLBACK_ERROR when the callback throws`, async () => {
      const boom = new Error('boom from progress callback');

      await assert.rejects(
        call(() => {
          throw boom;
        }),
        (err) => {
          assert.strictEqual(err.code, 'PROGRESS_CALLBACK_ERROR');
          assert.strictEqual(err.cause, boom);
          assert.ok(err.message.includes(errorMessage));
          return true;
        }
      );
    });
  }

  it('listArchiveBytesWithProgress keeps the core error primary', async () => {
    const boom = new Error('boom from progress callback');

    await assert.rejects(
      listArchiveBytesWithProgress(Buffer.from('not an archive'), null, null, null, () => {
        throw boom;
      }),
      (err) => {
        assert.notStrictEqual(err.code, 'PROGRESS_CALLBACK_ERROR');
        return true;
      }
    );
  });
});
