/**
 * Tests for the optional `signal` argument of the async in-memory functions
 * (#840).
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const {
  extractArchiveToCallback,
  extractArchiveToMemory,
  extractArchiveToMemoryWithProgress,
  listArchiveBytes,
  listArchiveBytesWithProgress,
  verifyArchiveBytes,
  verifyArchiveBytesWithProgress,
} = require('../index.js');

function tarEntry(name, data) {
  const header = Buffer.alloc(512);
  header.write(name, 0, 'utf8');
  header.write('0000644\0', 100, 'ascii');
  header.write('0000000\0', 108, 'ascii');
  header.write('0000000\0', 116, 'ascii');
  header.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124, 'ascii');
  header.write('00000000000\0', 136, 'ascii');
  header.write('        ', 148, 'ascii');
  header.write('0', 156, 'ascii');
  header.write('ustar\0' + '00', 257, 'ascii');
  const sum = header.reduce((total, byte) => total + byte, 0);
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii');
  const padded = Buffer.alloc(Math.ceil(data.length / 512) * 512);
  data.copy(padded);
  return Buffer.concat([header, padded]);
}

const ARCHIVE = Buffer.concat([
  tarEntry('a.txt', Buffer.from('alpha')),
  tarEntry('b.txt', Buffer.from('beta')),
  Buffer.alloc(1024),
]);

const NEVER = () => new Promise(() => {});

/** Rejects if `promise` does not settle in time: a hang must fail the test. */
function settles(promise, ms = 5000) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('operation hung')), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function assertAborted(err, reasonMessage) {
  assert.strictEqual(err.code, 'ABORT_ERR');
  assert.strictEqual(err.name, 'AbortError');
  if (reasonMessage !== undefined) {
    assert.ok(err.cause instanceof Error, 'cause must carry the signal reason');
    assert.strictEqual(err.cause.message, reasonMessage);
  }
  return true;
}

/** An async iterable that never yields; records how it was closed. */
function stalledIterable() {
  const state = { pulled: 0, returned: false };
  return {
    state,
    [Symbol.asyncIterator]() {
      return {
        next() {
          state.pulled += 1;
          return NEVER();
        },
        return() {
          state.returned = true;
          return Promise.resolve({ done: true, value: undefined });
        },
      };
    },
  };
}

async function eventually(predicate, ms = 2000) {
  const deadline = Date.now() + ms;
  while (!predicate()) {
    if (Date.now() > deadline) {
      assert.fail('condition not met in time');
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

/** A duck-typed signal that is not an `AbortSignal` instance. */
function fakeSignal() {
  const listeners = new Set();
  const signal = {
    aborted: false,
    reason: undefined,
    listeners,
    removed: 0,
    addEventListener(type, listener) {
      assert.strictEqual(type, 'abort');
      listeners.add(listener);
    },
    removeEventListener(...args) {
      const listener = args[1];
      signal.removed += 1;
      listeners.delete(listener);
    },
    abort(reason) {
      signal.aborted = true;
      signal.reason = reason;
      for (const listener of [...listeners]) {
        listener();
      }
    },
  };
  return signal;
}

const CALLS = [
  ['listArchiveBytes', (data, signal) => listArchiveBytes(data, null, null, signal)],
  ['verifyArchiveBytes', (data, signal) => verifyArchiveBytes(data, null, null, null, signal)],
  [
    'extractArchiveToMemory',
    (data, signal) => extractArchiveToMemory(data, null, null, null, null, null, signal),
  ],
  [
    'extractArchiveToCallback',
    (data, signal) => extractArchiveToCallback(data, () => {}, null, null, null, null, signal),
  ],
  [
    'listArchiveBytesWithProgress',
    (data, signal) => listArchiveBytesWithProgress(data, null, null, null, signal),
  ],
  [
    'verifyArchiveBytesWithProgress',
    (data, signal) => verifyArchiveBytesWithProgress(data, null, null, null, null, signal),
  ],
  [
    'extractArchiveToMemoryWithProgress',
    (data, signal) =>
      extractArchiveToMemoryWithProgress(data, null, null, null, null, null, null, signal),
  ],
];

describe('signal argument', () => {
  for (const [name, call] of CALLS) {
    it(`${name} throws a TypeError synchronously for a non-signal`, () => {
      for (const bad of [{}, 'abort', 42, () => {}, { aborted: false }]) {
        assert.throws(() => call(ARCHIVE, bad), TypeError);
      }
    });

    it(`${name} accepts null and undefined as no signal`, async () => {
      await settles(call(ARCHIVE, undefined));
      await settles(call(ARCHIVE, null));
    });

    it(`${name} rejects with ABORT_ERR for a signal aborted before the call`, async () => {
      const reason = new Error('stop now');
      await assert.rejects(settles(call(ARCHIVE, AbortSignal.abort(reason))), (err) =>
        assertAborted(err, 'stop now')
      );
    });

    it(`${name} does not open an AsyncIterable for a pre-aborted signal`, async () => {
      const source = stalledIterable();
      await assert.rejects(settles(call(source, AbortSignal.abort())), (err) => assertAborted(err));
      await eventually(() => source.state.returned);
      assert.strictEqual(source.state.pulled, 0);
    });

    it(`${name} unsubscribes from the signal when it resolves`, async () => {
      const signal = fakeSignal();
      await settles(call(ARCHIVE, signal));
      assert.strictEqual(signal.removed, 1);
      assert.strictEqual(signal.listeners.size, 0);
    });

    it(`${name} unsubscribes from the signal when it rejects`, async () => {
      const signal = fakeSignal();
      await assert.rejects(settles(call(Buffer.from('not an archive'), signal)));
      assert.strictEqual(signal.removed, 1);
    });
  }
});

describe('duck-typed signals', () => {
  it('accepts a plain object, as a signal from another realm would be', async () => {
    const signal = fakeSignal();
    const source = stalledIterable();
    const pending = listArchiveBytes(source, null, null, signal);
    await eventually(() => source.state.pulled === 1);
    signal.abort(new Error('foreign'));
    await assert.rejects(settles(pending), (err) => assertAborted(err, 'foreign'));
    await eventually(() => source.state.returned);
  });

  it('carries a non-Error reason as the cause', async () => {
    const signal = fakeSignal();
    const pending = listArchiveBytes(stalledIterable(), null, null, signal);
    signal.abort('plain reason');
    await assert.rejects(settles(pending), (err) => {
      assertAborted(err);
      assert.strictEqual(err.cause, 'plain reason');
      return true;
    });
  });
});

describe('closing the iterable after an abort', () => {
  // The abort is raised from inside the operation at a known point, never by
  // a timer, so these tests do not depend on scheduling.
  const manyEntries = Buffer.concat([
    ...Array.from({ length: 50 }, (_, i) => tarEntry(`dir/file-${i}.txt`, Buffer.from('x'))),
    Buffer.alloc(1024),
  ]);

  /** Yields the whole archive in one chunk; `closed` flips when `finally` runs. */
  function oneChunkGenerator(state) {
    return (async function* () {
      try {
        yield new Uint8Array(manyEntries);
      } finally {
        state.closed = true;
      }
    })();
  }

  it('runs return() when the abort fires inside a progress callback', async () => {
    const state = { closed: false };
    const controller = new AbortController();
    const pending = extractArchiveToMemoryWithProgress(
      oneChunkGenerator(state),
      null,
      null,
      null,
      null,
      null,
      () => controller.abort(),
      controller.signal
    );
    await assert.rejects(settles(pending), (err) => assertAborted(err));
    await eventually(() => state.closed);
  });

  it('runs return() when the abort fires inside onEntry', async () => {
    const state = { closed: false };
    const controller = new AbortController();
    const pending = extractArchiveToCallback(
      oneChunkGenerator(state),
      () => controller.abort(),
      null,
      null,
      null,
      null,
      controller.signal
    );
    await assert.rejects(settles(pending), (err) => assertAborted(err));
    await eventually(() => state.closed);
  });

  it('runs return() of an abandoned job whose signal already fired', async () => {
    const source = stalledIterable();
    const pending = extractArchiveToMemory(source, null, null, 0, null, null, AbortSignal.abort());
    // The invalid request is refused before the archive is opened, so its own
    // error stays primary over the abort.
    await assert.rejects(settles(pending), (err) => err.code === 'INVALID_CONFIGURATION');
    await eventually(() => source.state.returned);
    assert.strictEqual(source.state.pulled, 0);
  });

  it('runs return() of an abandoned job when the signal never fires', async () => {
    const source = stalledIterable();
    const controller = new AbortController();
    const pending = extractArchiveToMemory(source, null, null, 0, null, null, controller.signal);
    await assert.rejects(settles(pending), (err) => err.code === 'INVALID_CONFIGURATION');
    await eventually(() => source.state.returned);
  });
});

describe('abort while waiting for JavaScript', () => {
  it('frees a worker stalled on the next chunk', async () => {
    const controller = new AbortController();
    const source = stalledIterable();
    const pending = extractArchiveToMemory(source, null, null, null, null, null, controller.signal);
    await eventually(() => source.state.pulled === 1);
    controller.abort(new Error('enough'));
    await assert.rejects(settles(pending), (err) => assertAborted(err, 'enough'));
    await eventually(() => source.state.returned);
  });

  it('queues the close behind a generator that is still pending', async () => {
    async function* hung() {
      yield ARCHIVE.subarray(0, 512);
      await NEVER();
    }
    const controller = new AbortController();
    const pending = listArchiveBytes(hung(), null, null, controller.signal);
    setTimeout(() => controller.abort(), 50);
    await assert.rejects(settles(pending), (err) => assertAborted(err));
  });

  it('frees a worker stalled on an onEntry promise', async () => {
    const controller = new AbortController();
    let entered = false;
    const pending = extractArchiveToCallback(
      ARCHIVE,
      () => {
        entered = true;
        return NEVER();
      },
      null,
      null,
      null,
      null,
      controller.signal
    );
    await eventually(() => entered);
    controller.abort(new Error('callback stuck'));
    await assert.rejects(settles(pending), (err) => assertAborted(err, 'callback stuck'));
  });

  it('rejects with the abort when the signal fires before onEntry fails', async () => {
    const controller = new AbortController();
    let entered = false;
    const pending = extractArchiveToCallback(
      ARCHIVE,
      () => {
        entered = true;
        return new Promise((_, reject) => setTimeout(() => reject(new Error('too late')), 300));
      },
      null,
      null,
      null,
      null,
      controller.signal
    );
    await eventually(() => entered);
    controller.abort(new Error('first'));
    await assert.rejects(settles(pending), (err) => assertAborted(err, 'first'));
  });

  it('rejects with the onEntry error when it fails before any abort', async () => {
    const controller = new AbortController();
    const boom = new Error('callback first');
    await assert.rejects(
      settles(
        extractArchiveToCallback(
          ARCHIVE,
          () => {
            throw boom;
          },
          null,
          null,
          null,
          null,
          controller.signal
        )
      ),
      (err) => {
        assert.strictEqual(err.code, 'ENTRY_CALLBACK_ERROR');
        assert.strictEqual(err.cause, boom);
        return true;
      }
    );
  });

  it('frees a worker stalled closing the iterable after a complete read', async () => {
    const closing = { started: false };
    const source = {
      [Symbol.asyncIterator]() {
        let sent = false;
        return {
          next: async () => {
            if (sent) {
              return { done: true, value: undefined };
            }
            sent = true;
            return { done: false, value: new Uint8Array(ARCHIVE) };
          },
          return: () => {
            closing.started = true;
            return NEVER();
          },
        };
      },
    };
    const controller = new AbortController();
    const pending = listArchiveBytes(source, null, null, controller.signal);
    await eventually(() => closing.started);
    controller.abort();
    await assert.rejects(settles(pending), (err) => assertAborted(err));
  });

  it('settles when the abort races the completion', async () => {
    for (let round = 0; round < 25; round += 1) {
      const controller = new AbortController();
      const pending = listArchiveBytes(
        (async function* () {
          yield new Uint8Array(ARCHIVE);
        })(),
        null,
        null,
        controller.signal
      );
      if (round % 2 === 0) {
        controller.abort();
      } else {
        setImmediate(() => controller.abort());
      }
      await settles(pending).then(
        (manifest) => assert.ok(manifest.totalEntries >= 0),
        (err) => assertAborted(err)
      );
    }
  });

  it('does not affect an operation that finishes before the abort', async () => {
    const controller = new AbortController();
    const manifest = await settles(listArchiveBytes(ARCHIVE, null, null, controller.signal));
    controller.abort();
    assert.strictEqual(manifest.totalEntries, 2);
  });
});

describe('abort of an in-memory Uint8Array call', () => {
  const manyEntries = Buffer.concat([
    ...Array.from({ length: 30 }, (_, i) => tarEntry(`dir/file-${i}.txt`, Buffer.from('x'))),
    Buffer.alloc(1024),
  ]);

  const PROGRESS_CALLS = [
    [
      'listArchiveBytesWithProgress',
      (progress, signal) => listArchiveBytesWithProgress(manyEntries, null, null, progress, signal),
    ],
    [
      'verifyArchiveBytesWithProgress',
      (progress, signal) =>
        verifyArchiveBytesWithProgress(manyEntries, null, null, null, progress, signal),
    ],
    [
      'extractArchiveToMemoryWithProgress',
      (progress, signal) =>
        extractArchiveToMemoryWithProgress(
          manyEntries,
          null,
          null,
          null,
          null,
          null,
          progress,
          signal
        ),
    ],
  ];

  for (const [name, call] of PROGRESS_CALLS) {
    it(`${name} stops after the progress callback that aborted`, async () => {
      const controller = new AbortController();
      const reason = new Error('from progress');
      let calls = 0;
      const pending = call(() => {
        calls += 1;
        controller.abort(reason);
      }, controller.signal);
      await assert.rejects(settles(pending), (err) => assertAborted(err, 'from progress'));
      assert.strictEqual(calls, 1);
    });
  }
});

describe('ABORT_ERR in the ErrorCode declarations', () => {
  const declared = () => {
    const dts = fs.readFileSync(path.join(__dirname, '..', 'index.d.ts'), 'utf8');
    const line = dts.split('\n').find((l) => l.startsWith('export type ErrorCode = '));
    assert.ok(line, 'index.d.ts declares ErrorCode');
    return line
      .slice('export type ErrorCode = '.length)
      .split('|')
      .map((s) => s.trim().replace(/'/g, ''));
  };

  it('is a member of the ErrorCode union', () => {
    assert.ok(declared().includes('ABORT_ERR'));
  });

  it('is the code an aborted call actually rejects with', async () => {
    await assert.rejects(
      settles(listArchiveBytes(ARCHIVE, null, null, AbortSignal.abort())),
      (err) => {
        assert.ok(declared().includes(err.code));
        return true;
      }
    );
  });
});
