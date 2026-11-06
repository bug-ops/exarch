/**
 * Tests for extractArchiveToMemory (archives held in memory, extracted into memory)
 */
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  extractArchiveToMemory,
  extractArchiveToMemorySync,
  createArchiveSync,
  SecurityConfig,
  ExtractionOptions,
  SinkOptions,
} = require('../index.js');

const FIXTURES = path.join(__dirname, '..', '..', '..', 'tests', 'fixtures');

function rawTar(nameBytes, content) {
  const header = Buffer.alloc(512);
  nameBytes.copy(header, 0);
  header.write('0000644\0', 100, 'ascii');
  header.write('0000000\0', 108, 'ascii');
  header.write('0000000\0', 116, 'ascii');
  header.write(`${content.length.toString(8).padStart(11, '0')}\0`, 124, 'ascii');
  header.write('00000000000\0', 136, 'ascii');
  header.write('        ', 148, 'ascii');
  header.write('0', 156, 'ascii');
  header.write('ustar\0' + '00', 257, 'ascii');
  const sum = header.reduce((total, byte) => total + byte, 0);
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii');
  const padded = Buffer.alloc(Math.ceil(content.length / 512) * 512);
  content.copy(padded);
  return Buffer.concat([header, padded, Buffer.alloc(1024)]);
}

describe('extractArchiveToMemory', () => {
  let tempDir;
  let tarGz;
  let zip;

  before(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-memory-'));
    const source = path.join(tempDir, 'source');
    fs.mkdirSync(path.join(source, 'd'), { recursive: true });
    fs.writeFileSync(path.join(source, 'a.txt'), 'alpha');
    fs.writeFileSync(path.join(source, 'd', 'b.txt'), 'bravo');
    const tarPath = path.join(tempDir, 'archive.tar.gz');
    const zipPath = path.join(tempDir, 'archive.zip');
    createArchiveSync(tarPath, [source]);
    createArchiveSync(zipPath, [source]);
    tarGz = fs.readFileSync(tarPath);
    zip = fs.readFileSync(zipPath);
  });

  after(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  const byName = (result) =>
    Object.fromEntries(result.entries.map((entry) => [path.basename(entry.path), entry]));

  it('extracts files into buffers', async () => {
    for (const bytes of [tarGz, zip]) {
      const result = await extractArchiveToMemory(bytes);
      const entries = byName(result);
      assert.strictEqual(result.report.filesExtracted, 2);
      assert.strictEqual(entries['a.txt'].kind, 'file');
      assert.ok(entries['a.txt'].data instanceof Uint8Array);
      assert.strictEqual(Buffer.from(entries['a.txt'].data).toString(), 'alpha');
      assert.strictEqual(Buffer.from(entries['b.txt'].data).toString(), 'bravo');
    }
  });

  it('has a sync form', () => {
    const result = extractArchiveToMemorySync(tarGz);
    assert.strictEqual(Buffer.from(byName(result)['a.txt'].data).toString(), 'alpha');
  });

  it('keeps nothing but files and directories without link support', async () => {
    const result = await extractArchiveToMemory(zip);
    for (const entry of result.entries) {
      assert.ok(['file', 'directory'].includes(entry.kind), entry.kind);
      if (entry.kind === 'directory') {
        assert.strictEqual(entry.data, undefined);
      }
    }
  });

  it('caps the payload with maxBytes', async () => {
    const config = new SecurityConfig();
    assert.strictEqual(
      (await extractArchiveToMemory(tarGz, config, null, 1000)).entries.length > 0,
      true
    );
    await assert.rejects(extractArchiveToMemory(tarGz, config, null, 6), {
      code: 'QUOTA_EXCEEDED',
    });
  });

  it('reports the sink capacity when maxBytes is exceeded', async () => {
    await assert.rejects(extractArchiveToMemory(tarGz, null, null, 6), {
      code: 'QUOTA_EXCEEDED',
      message: /sink capacity/,
    });
    assert.throws(() => extractArchiveToMemorySync(tarGz, null, null, 6), {
      code: 'QUOTA_EXCEEDED',
      message: /sink capacity/,
    });
  });

  it('extracts a 7z archive', async () => {
    const bytes = fs.readFileSync(path.join(FIXTURES, 'solid.7z'));
    const config = new SecurityConfig().setAllowSolidArchives(true);
    const result = await extractArchiveToMemory(bytes, config);
    assert.ok(result.report.filesExtracted > 0);
    assert.ok(result.entries.some((entry) => entry.kind === 'file' && entry.data.length > 0));
  });

  it('rejects entry names that are not valid UTF-8 instead of merging them', async () => {
    const bytes = rawTar(Buffer.from([0x62, 0x61, 0x64, 0xff]), Buffer.from('x'));
    await assert.rejects(extractArchiveToMemory(bytes));
  });

  it('defaults the cap to maxTotalSize', async () => {
    const config = new SecurityConfig().setMaxTotalSize(6);
    await assert.rejects(extractArchiveToMemory(tarGz, config), { code: 'QUOTA_EXCEEDED' });
  });

  it('rejects a maxBytes that is not a positive whole number', async () => {
    for (const bad of [0, -1, 1.5, Number.NaN]) {
      await assert.rejects(extractArchiveToMemory(tarGz, null, null, bad), {
        code: 'INVALID_CONFIGURATION',
      });
    }
  });

  it('rejects an unknown pathModel at the argument boundary', () => {
    assert.throws(() => extractArchiveToMemory(tarGz, null, null, null, 'windows'), {
      code: 'InvalidArg',
    });
  });

  it('accepts both path models', async () => {
    for (const model of ['host', 'portable']) {
      const result = await extractArchiveToMemory(tarGz, null, null, null, model);
      assert.strictEqual(result.report.filesExtracted, 2);
    }
  });

  it('does not accept path extraction options, so atomic cannot be requested', () => {
    const options = new ExtractionOptions().withAtomic(true);
    assert.throws(() => extractArchiveToMemory(tarGz, null, options), {
      code: 'InvalidArg',
    });
  });

  it('accepts SinkOptions and exposes only the existing-files policy', async () => {
    const options = new SinkOptions();
    assert.strictEqual(options.existingFiles, 'skip');
    assert.strictEqual(options.setExistingFiles('refuse'), options);
    assert.strictEqual(options.existingFiles, 'refuse');
    assert.strictEqual(options.setExistingFiles('overwrite'), options);
    assert.strictEqual(options.existingFiles, 'overwrite');
    assert.throws(() => options.setExistingFiles('replace'), { code: 'InvalidArg' });
    assert.strictEqual(options.existingFiles, 'overwrite');
    assert.strictEqual('skipDuplicates' in options, false);
    assert.strictEqual('atomic' in options, false);
    const result = await extractArchiveToMemory(tarGz, null, options);
    assert.strictEqual(result.report.filesExtracted, 2);
  });

  it('reports discarded writes when it fails after delivering entries', async () => {
    const first = rawTar(Buffer.from('a'), Buffer.from('x')).subarray(0, 1024);
    const second = rawTar(Buffer.from('../b'), Buffer.from('y'));
    await assert.rejects(extractArchiveToMemory(Buffer.concat([first, second])), (err) => {
      assert.strictEqual(err.code, 'PATH_TRAVERSAL');
      assert.strictEqual(err.writes, 'discarded');
      assert.strictEqual(err.filesExtracted, undefined);
      assert.strictEqual(err.bytesWritten, undefined);
      return true;
    });
  });

  it('rejects undetectable bytes as UNKNOWN_FORMAT', async () => {
    await assert.rejects(extractArchiveToMemory(Buffer.from('not an archive')), {
      code: 'UNKNOWN_FORMAT',
    });
  });
});
