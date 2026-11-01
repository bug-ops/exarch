/**
 * Type-checks a small consumer of the generated `ExarchError` contract with
 * `tsc --strict`, so the hand-written d.ts header cannot drift into a union
 * whose property accesses fail to compile.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const LOCAL_TSC = path.join(ROOT, 'node_modules', '.bin', 'tsc');

function findTsc() {
  if (fs.existsSync(LOCAL_TSC)) {
    return LOCAL_TSC;
  }
  const probe = spawnSync('tsc', ['--version'], { encoding: 'utf8' });
  return probe.status === 0 ? 'tsc' : null;
}

describe('ExarchError declarations', () => {
  const tsc = findTsc();

  it('type-check under tsc --strict', { skip: tsc ? false : 'tsc is not installed' }, () => {
    const result = spawnSync(
      tsc,
      [
        '--noEmit',
        '--strict',
        '--target',
        'es2022',
        '--module',
        'commonjs',
        '--moduleResolution',
        'node',
        path.join(__dirname, 'types', 'error-usage.ts'),
      ],
      { encoding: 'utf8', cwd: ROOT }
    );
    assert.strictEqual(result.status, 0, `${result.stdout}${result.stderr}`);
  });
});
