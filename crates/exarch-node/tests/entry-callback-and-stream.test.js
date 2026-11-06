/**
 * Tests for extractArchiveToCallback (+ Sync), AsyncIterable archive input and
 * the sync WithProgress variants (#823).
 */
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Readable } = require('node:stream');
const {
  extractArchiveToCallback,
  extractArchiveToCallbackSync,
  extractArchiveToMemory,
  extractArchiveToMemorySync,
  extractArchiveToMemoryWithProgress,
  extractArchiveToMemoryWithProgressSync,
  listArchiveBytes,
  listArchiveBytesWithProgressSync,
  verifyArchiveBytes,
  verifyArchiveBytesWithProgressSync,
  createArchiveSync,
  SecurityConfig,
  ExtractionOptions,
  SinkOptions,
} = require('../index.js');

function tarEntry(name, { type = '0', data = Buffer.alloc(0), link = '' } = {}) {
  const header = Buffer.alloc(512);
  header.write(name, 0, 'utf8');
  header.write('0000644\0', 100, 'ascii');
  header.write('0000000\0', 108, 'ascii');
  header.write('0000000\0', 116, 'ascii');
  header.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124, 'ascii');
  header.write('00000000000\0', 136, 'ascii');
  header.write('        ', 148, 'ascii');
  header.write(type, 156, 'ascii');
  header.write(link, 157, 'utf8');
  header.write('ustar\0' + '00', 257, 'ascii');
  const sum = header.reduce((total, byte) => total + byte, 0);
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii');
  const padded = Buffer.alloc(Math.ceil(data.length / 512) * 512);
  data.copy(padded);
  return Buffer.concat([header, padded]);
}

function tar(entries) {
  return Buffer.concat([...entries, Buffer.alloc(1024)]);
}

const file = (name, text) => tarEntry(name, { data: Buffer.from(text) });
const linksConfig = () => new SecurityConfig().setAllowSymlinks(true).setAllowHardlinks(true);

async function* chunked(buffer, size = 700) {
  for (let at = 0; at < buffer.length; at += size) {
    yield buffer.subarray(at, at + size);
  }
}

const PRIMITIVES = [
  ['a string', 'oops'],
  ['a number', 42],
  ['undefined', undefined],
  ['null', null],
  ['a symbol', Symbol('boom')],
];

function assertWrapped(err, value) {
  assert.strictEqual(err.code, 'ENTRY_CALLBACK_ERROR');
  assert.ok(err.cause instanceof Error, 'cause must be an Error');
  assert.strictEqual(
    err.cause.cause,
    typeof value === 'symbol' ? String(value) : value,
    'the primitive is kept as the wrapper cause'
  );
  return true;
}

describe('extractArchiveToCallback', () => {
  const archive = tar([
    tarEntry('d/', { type: '5' }),
    file('d/a.txt', 'alpha'),
    tarEntry('s', { type: '2', link: 'd/a.txt' }),
    tarEntry('h', { type: '1', link: 'd/a.txt' }),
  ]);

  it('delivers every kind, with the hardlink last and by reference', async () => {
    const seen = [];
    const report = await extractArchiveToCallback(
      archive,
      (entry) => seen.push(entry),
      linksConfig()
    );

    assert.deepStrictEqual(
      seen.map((e) => [e.path, e.kind]),
      [
        ['d', 'directory'],
        ['d/a.txt', 'file'],
        ['s', 'symlink'],
        ['h', 'hardlink'],
      ]
    );
    assert.strictEqual(Buffer.from(seen[1].data).toString(), 'alpha');
    assert.strictEqual(seen[2].target, 'd/a.txt');
    assert.strictEqual(seen[3].target, 'd/a.txt');
    assert.strictEqual(seen[3].data, undefined);
    assert.ok(report.filesExtracted >= 1);
  });

  it('waits for the promise of each call before reading on', async () => {
    let running = 0;
    let maxRunning = 0;
    const order = [];
    await extractArchiveToCallback(
      tar([file('a', '1'), file('b', '2'), file('c', '3')]),
      async (entry) => {
        running += 1;
        maxRunning = Math.max(maxRunning, running);
        await new Promise((resolve) => setTimeout(resolve, 15));
        order.push(entry.path);
        running -= 1;
      }
    );
    assert.strictEqual(maxRunning, 1);
    assert.deepStrictEqual(order, ['a', 'b', 'c']);
  });

  it('rejects with ENTRY_CALLBACK_ERROR and the thrown Error as cause, and stops', async () => {
    const boom = new Error('boom');
    const seen = [];
    await assert.rejects(
      extractArchiveToCallback(tar([file('a', '1'), file('b', '2')]), (entry) => {
        seen.push(entry.path);
        throw boom;
      }),
      (err) => {
        assert.strictEqual(err.code, 'ENTRY_CALLBACK_ERROR');
        assert.strictEqual(err.cause, boom);
        return true;
      }
    );
    assert.deepStrictEqual(seen, ['a']);
  });

  for (const [label, value] of PRIMITIVES) {
    it(`wraps ${label} thrown by onEntry`, async () => {
      await assert.rejects(
        extractArchiveToCallback(tar([file('a', '1')]), () => {
          throw value;
        }),
        (err) => assertWrapped(err, value)
      );
    });

    it(`wraps ${label} rejected by an async onEntry`, async () => {
      await assert.rejects(
        extractArchiveToCallback(tar([file('a', '1')]), async () => {
          throw value;
        }),
        (err) => assertWrapped(err, value)
      );
    });
  }

  it('rejects a non-function onEntry', async () => {
    await assert.rejects(async () => extractArchiveToCallback(tar([file('a', '1')]), 'nope'));
  });

  it('keeps the security checks', async () => {
    const seen = [];
    await assert.rejects(
      extractArchiveToCallback(tar([file('../escape', 'x')]), (entry) => seen.push(entry)),
      { code: 'PATH_TRAVERSAL' }
    );
    assert.deepStrictEqual(seen, []);
  });

  it('does not accept path extraction options, so atomic cannot be requested', () => {
    assert.throws(
      () =>
        extractArchiveToCallback(
          tar([file('a', '1')]),
          () => {},
          null,
          new ExtractionOptions().withAtomic(true)
        ),
      { code: 'InvalidArg' }
    );
  });

  it('accepts SinkOptions', async () => {
    const seen = [];
    await extractArchiveToCallback(
      tar([file('a', '1')]),
      (entry) => seen.push(entry.path),
      null,
      new SinkOptions().withExistingFiles('overwrite')
    );
    assert.deepStrictEqual(seen, ['a']);
  });
});

describe('extractArchiveToCallbackSync', () => {
  const archive = tar([file('d/a.txt', 'alpha'), tarEntry('h', { type: '1', link: 'd/a.txt' })]);
  let unhandled;
  const onUnhandled = (reason) => unhandled.push(reason);

  before(() => process.on('unhandledRejection', onUnhandled));
  after(() => process.off('unhandledRejection', onUnhandled));

  it('delivers entries and returns the report', () => {
    const seen = [];
    const report = extractArchiveToCallbackSync(
      archive,
      (entry) => seen.push(entry.kind),
      linksConfig()
    );
    assert.deepStrictEqual(seen, ['file', 'hardlink']);
    assert.ok(report.filesExtracted >= 1);
  });

  it('throws ENTRY_CALLBACK_ERROR with the thrown Error as cause', () => {
    const boom = new Error('boom');
    assert.throws(
      () =>
        extractArchiveToCallbackSync(
          archive,
          () => {
            throw boom;
          },
          linksConfig()
        ),
      (err) => err.code === 'ENTRY_CALLBACK_ERROR' && err.cause === boom
    );
  });

  for (const [label, value] of PRIMITIVES) {
    it(`wraps ${label} thrown by onEntry`, () => {
      assert.throws(
        () =>
          extractArchiveToCallbackSync(
            archive,
            () => {
              throw value;
            },
            linksConfig()
          ),
        (err) => assertWrapped(err, value)
      );
    });
  }

  it('refuses a callback that returns a promise, without an unhandled rejection', async () => {
    unhandled = [];
    assert.throws(
      () =>
        extractArchiveToCallbackSync(
          archive,
          async () => Promise.reject(new Error('late')),
          linksConfig()
        ),
      (err) => {
        assert.strictEqual(err.code, 'ENTRY_CALLBACK_ERROR');
        assert.ok(err.cause instanceof TypeError);
        assert.match(err.cause.message, /extractArchiveToCallback/);
        return true;
      }
    );
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepStrictEqual(unhandled, []);
  });

  it('normalizes a throwing then getter', () => {
    const evil = {
      // biome-ignore lint/suspicious/noThenProperty: the test needs a thenable
      get then() {
        throw 'getter';
      },
    };
    assert.throws(
      () => extractArchiveToCallbackSync(archive, () => evil, linksConfig()),
      (err) => assertWrapped(err, 'getter')
    );
  });

  it('rejects a stream for the sync function', () => {
    assert.throws(() => extractArchiveToCallbackSync(chunked(archive), () => {}));
  });

  describe('input aliasing', () => {
    const COUNT = 300;
    const SIZE = 1024;
    const big = tar(
      Array.from({ length: COUNT }, (_, i) =>
        tarEntry(`f${i}.bin`, { data: Buffer.alloc(SIZE, 0x42) })
      )
    );

    const intact = (seen) =>
      seen.length === COUNT && seen.every((entry) => entry.data.every((byte) => byte === 0x42));

    it('is not affected by a callback that detaches the input buffer', (t) => {
      if (typeof ArrayBuffer.prototype.transfer !== 'function') {
        t.skip('ArrayBuffer.prototype.transfer is not available');
        return;
      }
      const data = new Uint8Array(big);
      const seen = [];
      const keep = [];
      extractArchiveToCallbackSync(data, (entry) => {
        seen.push(entry);
        if (seen.length === 1) {
          data.buffer.transfer(16);
          for (let i = 0; i < 64; i += 1) {
            keep.push(Buffer.alloc(big.length, 0x41));
          }
        }
      });
      assert.strictEqual(data.buffer.detached, true);
      assert.ok(intact(seen));
    });

    it('is not affected by a callback that overwrites the next members', () => {
      const data = new Uint8Array(big);
      const seen = [];
      extractArchiveToCallbackSync(data, (entry) => {
        seen.push(entry);
        if (seen.length === 1) {
          data.fill(0x41, 2048);
        }
      });
      assert.ok(intact(seen));
    });
  });

  it('delivers a hardlink chain link by link', () => {
    const chain = tar([
      file('a', 'x'),
      tarEntry('b', { type: '1', link: 'a' }),
      tarEntry('c', { type: '1', link: 'b' }),
    ]);
    const links = [];
    extractArchiveToCallbackSync(
      chain,
      (entry) => {
        if (entry.kind === 'hardlink') links.push([entry.path, entry.target]);
      },
      linksConfig()
    );
    assert.deepStrictEqual(links, [
      ['b', 'a'],
      ['c', 'b'],
    ]);
  });
});

describe('AsyncIterable input', () => {
  const archive = tar([
    file('a.txt', 'alpha'),
    tarEntry('d/', { type: '5' }),
    file('d/b.txt', 'bravo'),
  ]);

  it('extracts, lists and verifies from a stream', async () => {
    const { entries, report } = await extractArchiveToMemory(chunked(archive));
    assert.strictEqual(report.filesExtracted, 2);
    assert.deepStrictEqual(entries.map((e) => e.path).sort(), ['a.txt', 'd', 'd/b.txt']);

    const manifest = await listArchiveBytes(chunked(archive));
    assert.strictEqual(manifest.entries.length, 3);

    const verified = await verifyArchiveBytes(chunked(archive));
    assert.strictEqual(verified.status, 'PASS');
  });

  it('accepts Readable.from chunks, including Buffers', async () => {
    const result = await extractArchiveToMemory(
      Readable.from([archive.subarray(0, 100), archive.subarray(100)])
    );
    assert.strictEqual(result.report.filesExtracted, 2);
  });

  it('feeds extractArchiveToCallback and WithProgress from a stream', async () => {
    const seen = [];
    await extractArchiveToCallback(chunked(archive), (entry) => seen.push(entry.path));
    assert.strictEqual(seen.length, 3);

    const events = [];
    await extractArchiveToMemoryWithProgress(
      chunked(archive),
      null,
      null,
      null,
      null,
      null,
      (_err, [name]) => events.push(name)
    );
    assert.ok(events.length >= 3);
  });

  it('refuses a ZIP stream and closes it', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-stream-'));
    try {
      fs.writeFileSync(path.join(dir, 'a.txt'), 'x');
      const zipPath = path.join(dir, 'a.zip');
      createArchiveSync(zipPath, [path.join(dir, 'a.txt')]);
      const zip = fs.readFileSync(zipPath);
      let closed = false;
      const source = {
        async *[Symbol.asyncIterator]() {
          try {
            yield* chunked(zip);
          } finally {
            closed = true;
          }
        },
      };
      await assert.rejects(extractArchiveToMemory(source), (err) => {
        assert.notStrictEqual(err.code, 'STREAM_ERROR');
        assert.match(err.message, /seek|stream|format/i);
        return true;
      });
      assert.strictEqual(closed, true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('destroys a file stream after a refused archive', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-stream-'));
    try {
      const refused = path.join(dir, 'evil.tar');
      fs.writeFileSync(refused, tar([file('../escape', 'x')]));
      const stream = fs.createReadStream(refused);
      await assert.rejects(extractArchiveToMemory(stream), { code: 'PATH_TRAVERSAL' });
      assert.strictEqual(stream.destroyed, true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('closes the iterator when the archive ends early', async () => {
    let closed = false;
    async function* early() {
      try {
        yield archive;
        yield Buffer.alloc(4096);
        yield Buffer.alloc(4096);
      } finally {
        closed = true;
      }
    }
    await extractArchiveToMemory(early());
    assert.strictEqual(closed, true);
  });

  it('closes the iterator when onEntry throws', async () => {
    let closed = false;
    async function* source() {
      try {
        yield* chunked(archive);
      } finally {
        closed = true;
      }
    }
    await assert.rejects(
      extractArchiveToCallback(source(), () => {
        throw new Error('stop');
      }),
      { code: 'ENTRY_CALLBACK_ERROR' }
    );
    assert.strictEqual(closed, true);
  });

  it('reports the onEntry error, not a later stream error, when the callback fails first', async () => {
    const boom = new Error('callback first');
    let pulls = 0;
    async function* source() {
      yield archive.subarray(0, 1100);
      pulls += 1;
      throw new Error('stream later');
    }
    await assert.rejects(
      extractArchiveToCallback(source(), () => {
        throw boom;
      }),
      (err) => {
        assert.strictEqual(err.code, 'ENTRY_CALLBACK_ERROR');
        assert.strictEqual(err.cause, boom);
        return true;
      }
    );
    assert.strictEqual(pulls, 0, 'the stream must not be read on after the callback failed');
  });

  it('reports the stream error, not an onEntry error, when the stream fails first', async () => {
    const boom = new Error('stream first');
    let calls = 0;
    async function* source() {
      yield archive.subarray(0, 515);
      throw boom;
    }
    await assert.rejects(
      extractArchiveToCallback(source(), () => {
        calls += 1;
        throw new Error('callback later');
      }),
      (err) => {
        assert.strictEqual(err.code, 'STREAM_ERROR');
        assert.strictEqual(err.cause, boom);
        return true;
      }
    );
    assert.strictEqual(calls, 0);
  });

  it('closes a stream that was never read', async () => {
    let closed = false;
    const source = {
      [Symbol.asyncIterator]: () => ({
        next: async () => ({ done: true, value: undefined }),
        return: async () => {
          closed = true;
          return { done: true, value: undefined };
        },
      }),
    };
    await assert.rejects(extractArchiveToMemory(source, null, null, 0), {
      code: 'INVALID_CONFIGURATION',
    });
    assert.strictEqual(closed, true);
  });

  it('rejects with STREAM_ERROR when the stream throws', async () => {
    const boom = new Error('disk gone');
    async function* failing() {
      yield archive.subarray(0, 600);
      throw boom;
    }
    await assert.rejects(extractArchiveToMemory(failing()), (err) => {
      assert.strictEqual(err.code, 'STREAM_ERROR');
      assert.strictEqual(err.cause, boom);
      return true;
    });
  });

  for (const [label, value] of PRIMITIVES) {
    it(`wraps ${label} thrown by the stream`, async () => {
      async function* failing() {
        yield archive.subarray(0, 600);
        throw value;
      }
      await assert.rejects(extractArchiveToMemory(failing()), (err) => {
        assert.strictEqual(err.code, 'STREAM_ERROR');
        assert.ok(err.cause instanceof Error);
        assert.strictEqual(err.cause.cause, typeof value === 'symbol' ? String(value) : value);
        return true;
      });
    });
  }

  it('rejects chunks that are not Uint8Array', async () => {
    async function* wrong() {
      yield 'text';
    }
    await assert.rejects(extractArchiveToMemory(wrong()), { code: 'STREAM_ERROR' });
  });

  it('rejects data that is neither bytes nor an async iterable', async () => {
    await assert.rejects(async () => extractArchiveToMemory({}));
    await assert.rejects(async () => extractArchiveToMemory(42));
  });

  it('rejects a stream for the sync functions', () => {
    assert.throws(() => extractArchiveToMemorySync(chunked(archive)));
  });
});

describe('sync WithProgress variants', () => {
  const archive = tar([file('a.txt', 'alpha'), file('b.txt', 'bravo')]);

  it('deliver the progress events after the call returns', async () => {
    for (const run of [
      (progress) =>
        extractArchiveToMemoryWithProgressSync(archive, null, null, null, null, null, progress),
      (progress) => listArchiveBytesWithProgressSync(archive, null, null, progress),
      (progress) => verifyArchiveBytesWithProgressSync(archive, null, null, null, progress),
    ]) {
      const events = [];
      const result = run((_err, [name]) => events.push(name));
      assert.ok(result);
      assert.deepStrictEqual(events, [], 'nothing is delivered while the call blocks');
      await new Promise((resolve) => setImmediate(resolve));
      await new Promise((resolve) => setImmediate(resolve));
      assert.deepStrictEqual(events, ['a.txt', 'b.txt']);
    }
  });

  it('work without a progress callback', () => {
    assert.strictEqual(extractArchiveToMemoryWithProgressSync(archive).entries.length, 2);
    assert.strictEqual(listArchiveBytesWithProgressSync(archive).entries.length, 2);
    assert.strictEqual(verifyArchiveBytesWithProgressSync(archive).status, 'PASS');
  });
});
