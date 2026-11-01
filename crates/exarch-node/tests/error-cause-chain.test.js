/**
 * A progress callback can throw an error whose `cause` chain is cyclic or very
 * deep. Building the rejection must neither recurse without bound nor abort
 * the host process; each case runs in a child so a crash is observable.
 */
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const { createArchiveSync } = require('../index.js');

const INDEX_JS = JSON.stringify(path.join(__dirname, '..', 'index.js'));
const THROWERS = {
  cyclic: "() => { const e = new Error('x'); e.cause = e; throw e; }",
  deep: "() => { let e = new Error('leaf'); for (let i = 0; i < 5000; i++) { const n = new Error('n' + i); n.cause = e; e = n; } throw e; }",
};

describe('hostile cause chains from a throwing progress callback', () => {
  let tempDir;
  let sourceDir;
  let archivePath;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-test-'));
    sourceDir = path.join(tempDir, 'source');
    fs.mkdirSync(sourceDir);
    fs.writeFileSync(path.join(sourceDir, 'a.txt'), 'a');
    archivePath = path.join(tempDir, 'a.tar.gz');
    createArchiveSync(archivePath, [sourceDir]);
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function runChild(call, thrower) {
    const script = `
      const exarch = require(${INDEX_JS});
      const thrower = ${thrower};
      ${call}.then(
        () => { console.log('UNEXPECTED_RESOLVE'); process.exit(2); },
        (err) => { console.log('REJECTED:' + err.code + ':' + (err.cause instanceof Error)); },
      );
    `;
    return spawnSync(process.execPath, ['-e', script], { encoding: 'utf8' });
  }

  for (const [kind, thrower] of Object.entries(THROWERS)) {
    it(`extract rejects normally on a ${kind} cause`, () => {
      const out = path.join(tempDir, `out-${kind}`);
      const result = runChild(
        `exarch.extractArchiveWithProgress(${JSON.stringify(archivePath)}, ${JSON.stringify(out)}, null, null, thrower)`,
        thrower
      );
      assert.strictEqual(result.status, 0, `status=${result.status} stderr=${result.stderr}`);
      assert.match(result.stdout, /REJECTED:PROGRESS_CALLBACK_ERROR:true/);
    });

    it(`create rejects normally on a ${kind} cause`, () => {
      const out = path.join(tempDir, `new-${kind}.tar.gz`);
      const result = runChild(
        `exarch.createArchiveWithProgress(${JSON.stringify(out)}, [${JSON.stringify(sourceDir)}], null, thrower)`,
        thrower
      );
      assert.strictEqual(result.status, 0, `status=${result.status} stderr=${result.stderr}`);
      assert.match(result.stdout, /REJECTED:PROGRESS_CALLBACK_ERROR:true/);
    });
  }
});
