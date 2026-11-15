/**
 * Package gate contract of #1233: the packed package.json must equal the
 * committed one on every field that decides what `require('exarch-rs')` loads
 * or what runs at install, whatever the key order.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.join(__dirname, '..');
const committed = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const loader = fs.readFileSync(path.join(root, 'index.js'), 'utf8');

function sortedKeys(value) {
  if (Array.isArray(value)) {
    return value.map(sortedKeys);
  }
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .reverse()
        .map((key) => [key, sortedKeys(value[key])])
    );
  }
  return value;
}

/** Runs the gate on a tarball whose packed package.json is `mutate(copy of the committed one)`. */
function gateOn(mutate, packedText) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-fields-'));
  try {
    fs.mkdirSync(path.join(dir, 'scripts'));
    fs.copyFileSync(path.join(root, 'package.json'), path.join(dir, 'package.json'));
    fs.copyFileSync(path.join(root, 'index.js'), path.join(dir, 'index.js'));
    fs.copyFileSync(
      path.join(root, 'scripts', 'check-package.mjs'),
      path.join(dir, 'scripts', 'check-package.mjs')
    );
    const stage = path.join(dir, 'stage', 'package');
    fs.mkdirSync(stage, { recursive: true });
    const copy = structuredClone(committed);
    const packed = mutate(copy) ?? copy;
    fs.writeFileSync(
      path.join(stage, 'package.json'),
      packedText === undefined ? JSON.stringify(packed, null, 2) : packedText
    );
    fs.writeFileSync(path.join(stage, 'index.js'), loader);
    fs.writeFileSync(path.join(stage, 'README.md'), 'readme\n');
    for (const file of loader.match(/\.\/exarch-rs\.[\w.-]+\.node/g)) {
      fs.writeFileSync(path.join(stage, file), '');
    }
    const tarball = path.join(dir, 'pkg.tgz');
    const made = spawnSync('tar', ['-czf', tarball, '-C', path.join(dir, 'stage'), 'package']);
    assert.strictEqual(made.status, 0, String(made.stderr));
    return spawnSync(process.execPath, ['scripts/check-package.mjs', tarball], {
      cwd: dir,
      encoding: 'utf8',
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe('package gate: packed package.json fields (#1233)', () => {
  it('accepts a packed package.json equal to the committed one', () => {
    const result = gateOn((pkg) => pkg);
    assert.strictEqual(result.status, 0, result.stderr);
  });

  it('accepts the same fields in a different key order', () => {
    const result = gateOn((pkg) => sortedKeys(pkg));
    assert.strictEqual(result.status, 0, result.stderr);
  });

  const mutations = {
    'an exports redirect to a packed file': [
      'exports',
      (pkg) => {
        pkg.exports = './README.md';
      },
    ],
    'an added imports map': [
      'imports',
      (pkg) => {
        pkg.imports = { '#x': './README.md' };
      },
    ],
    'an added bin': [
      'bin',
      (pkg) => {
        pkg.bin = { exarch: './README.md' };
      },
    ],
    'an added browser field': [
      'browser',
      (pkg) => {
        pkg.browser = './README.md';
      },
    ],
    'an added module field': [
      'module',
      (pkg) => {
        pkg.module = './README.md';
      },
    ],
    'a changed types entry': [
      'types',
      (pkg) => {
        pkg.types = './README.md';
      },
    ],
    'a changed module type': [
      'type',
      (pkg) => {
        pkg.type = pkg.type === 'module' ? 'commonjs' : 'module';
      },
    ],
    'an added postinstall script': [
      'postinstall',
      (pkg) => {
        pkg.scripts = { ...pkg.scripts, postinstall: 'node ./README.md' };
      },
    ],
    'an added preinstall script': [
      'preinstall',
      (pkg) => {
        pkg.scripts = { ...pkg.scripts, preinstall: 'node ./README.md' };
      },
    ],
    'an added prepare script': [
      'prepare',
      (pkg) => {
        pkg.scripts = { ...pkg.scripts, prepare: 'node ./README.md' };
      },
    ],
    'an added dependency': [
      'dependencies',
      (pkg) => {
        pkg.dependencies = { ...pkg.dependencies, evil: '1.0.0' };
      },
    ],
    'an added optional dependency': [
      'optionalDependencies',
      (pkg) => {
        pkg.optionalDependencies = { ...pkg.optionalDependencies, evil: '1.0.0' };
      },
    ],
  };

  for (const [name, [field, mutate]] of Object.entries(mutations)) {
    it(`rejects ${name} and names the field`, () => {
      const result = gateOn(mutate);
      assert.notStrictEqual(result.status, 0, 'the gate accepted the mutated package.json');
      assert.ok(result.stderr.includes(field), `stderr must name ${field}: ${result.stderr}`);
    });
  }

  it('rejects a packed main that differs from the committed one', () => {
    const result = gateOn((pkg) => {
      pkg.main = 'README.md';
    });
    assert.notStrictEqual(result.status, 0);
    assert.ok(result.stderr.includes('main'), result.stderr);
  });

  it('rejects a packed package.json that is not valid JSON', () => {
    const result = gateOn((pkg) => pkg, '{ not json');
    assert.notStrictEqual(result.status, 0);
  });
});
