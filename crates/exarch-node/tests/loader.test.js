/**
 * Loader contract of the published package (#1200, #1208): index.js is
 * committed, loads only the addons the package ships through literal
 * requires, and rejects any other platform without resolving a package name.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const loaderPath = path.join(root, 'index.js');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

function requireArguments(source) {
  return [...source.matchAll(/\brequire\s*\(\s*([^)]*?)\s*\)/g)].map((m) => m[1]);
}

const LITERAL = /^(['"])([^'"`$\\]*)\1$/;

describe('npm loader (#1200)', () => {
  it('index.js is part of the package and is the main entry', () => {
    assert.ok(fs.existsSync(loaderPath), 'index.js must be committed');
    assert.strictEqual(pkg.main, 'index.js');
    assert.ok(pkg.files.includes('index.js'));
  });

  it('every require argument is a single string literal', () => {
    const source = fs.readFileSync(loaderPath, 'utf8');
    for (const argument of requireArguments(source)) {
      assert.match(argument, LITERAL, `non-literal require(${argument})`);
    }
  });

  it('requires only node builtins and packed relative addon files', () => {
    const source = fs.readFileSync(loaderPath, 'utf8');
    for (const argument of requireArguments(source)) {
      const [, , name] = argument.match(LITERAL);
      const allowed = name.startsWith('node:') || /^\.\/exarch-rs\.[\w.-]+\.node$/.test(name);
      assert.ok(allowed, `require('${name}') resolves outside the package`);
    }
  });

  it('never names an exarch-rs-<platform> package', () => {
    const source = fs.readFileSync(loaderPath, 'utf8');
    assert.doesNotMatch(source, /exarch-rs-[a-z0-9]/);
    assert.doesNotMatch(source, /wasm32-wasi/);
  });

  it('bundles one literal addon require per napi target', () => {
    const source = fs.readFileSync(loaderPath, 'utf8');
    const addons = new Set(
      requireArguments(source)
        .map((argument) => argument.match(LITERAL)?.[2])
        .filter((name) => name?.endsWith('.node')),
    );
    assert.strictEqual(addons.size, pkg.napi.targets.length);
  });

  it('rejects an unsupported platform with an Error naming it', () => {
    const script = `
      Object.defineProperty(process, 'platform', { value: 'freebsd' });
      try { require('./index.js'); console.log('LOADED'); }
      catch (e) { console.log(JSON.stringify({ error: e instanceof Error, message: String(e.message) })); }
    `;
    const out = execFileSync(process.execPath, ['-e', script], { cwd: root, encoding: 'utf8' });
    const result = JSON.parse(out.trim());
    assert.strictEqual(result.error, true);
    assert.match(result.message, /freebsd/);
  });

  it('the build scripts do not regenerate the committed loader', () => {
    assert.match(pkg.scripts.build, /--no-js-binding/);
    assert.match(pkg.scripts['build:debug'], /--no-js-binding/);
  });

  it('the package gate script exists', () => {
    assert.ok(fs.existsSync(path.join(root, 'scripts', 'check-package.mjs')));
  });
});
