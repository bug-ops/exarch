/**
 * Loader contract of the published package (#1200, #1208): index.js is
 * committed, loads only the addons the package ships through literal
 * requires, and rejects any other platform without resolving a package name.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');
const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
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
        .filter((name) => name?.endsWith('.node'))
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

  it('treats Linux as musl only when the runtime report lacks glibc', () => {
    const probe = (report) => {
      const script = `
        Object.defineProperty(process, 'platform', { value: 'linux' });
        Object.defineProperty(process, 'arch', { value: 'x64' });
        Object.defineProperty(process, 'report', { value: ${report} });
        try { require('./index.js'); console.log('LOADED'); }
        catch (e) { console.log(e.message); }
      `;
      return execFileSync(process.execPath, ['-e', script], { cwd: root, encoding: 'utf8' });
    };
    const notMusl = (out) => assert.doesNotMatch(out, /musl/);
    notMusl(probe('undefined'));
    notMusl(probe('{ getReport: () => ({ header: { glibcVersionRuntime: "2.39" } }) }'));
    notMusl(probe('{ getReport: () => { throw new Error("NotCapable"); } }'));
    assert.match(probe('{ getReport: () => ({ header: {} }) }'), /musl/);
  });

  it('the build scripts do not regenerate the committed loader', () => {
    assert.match(pkg.scripts.build, /--no-js\b/);
    assert.match(pkg.scripts['build:debug'], /--no-js\b/);
  });

  it('assigns every export explicitly so ESM named imports resolve', () => {
    const source = fs.readFileSync(loaderPath, 'utf8');
    const names = [...source.matchAll(/^module\.exports\.(\w+) =\s+addon\.\1;$/gm)].map(
      (m) => m[1]
    );
    assert.ok(names.length > 0);
    assert.strictEqual(new Set(names).size, names.length, 'duplicate export assignment');

    const declarations = fs.readFileSync(path.join(root, 'index.d.ts'), 'utf8');
    for (const name of names) {
      assert.match(declarations, new RegExp(`(?:function|class|type|interface) ${name}\\b`));
    }

    const addonFile = fs.readdirSync(root).find((file) => /^exarch-rs\..+\.node$/.test(file));
    if (addonFile !== undefined) {
      const actual = Object.keys(require(path.join(root, addonFile))).sort();
      assert.deepStrictEqual([...names].sort(), actual, 'loader exports differ from the addon');
      const imported = `import { ${names.join(', ')} } from ${JSON.stringify(loaderPath)};`;
      execFileSync(process.execPath, ['--input-type=module', '-e', imported], { cwd: root });
    }
  });

  it('names the supported platforms when rejecting an unsupported one (#1222)', () => {
    const script = `
      Object.defineProperty(process, 'platform', { value: 'freebsd' });
      Object.defineProperty(process, 'arch', { value: 'arm64' });
      try { require('./index.js'); } catch (e) { console.log(e.message); }
    `;
    const message = execFileSync(process.execPath, ['-e', script], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.match(message, /freebsd-arm64/);
    for (const key of ['darwin-x64', 'darwin-arm64', 'win32-x64', 'linux-x64', 'linux-arm64']) {
      assert.ok(message.includes(key), `${key} missing from: ${message}`);
    }
  });

  describe('package gate (#1225)', () => {
    function withPackage(mutateLoader, body) {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exarch-pack-'));
      try {
        fs.mkdirSync(path.join(dir, 'scripts'));
        fs.copyFileSync(path.join(root, 'package.json'), path.join(dir, 'package.json'));
        const source = fs.readFileSync(loaderPath, 'utf8');
        fs.writeFileSync(path.join(dir, 'index.js'), mutateLoader(source));
        fs.copyFileSync(
          path.join(root, 'scripts', 'check-package.mjs'),
          path.join(dir, 'scripts', 'check-package.mjs')
        );
        const addons = source.match(/\.\/exarch-rs\.[\w.-]+\.node/g).map((f) => path.join(dir, f));
        for (const addon of addons) {
          fs.writeFileSync(addon, '');
        }
        const gate = () =>
          spawnSync(process.execPath, ['scripts/check-package.mjs'], {
            cwd: dir,
            encoding: 'utf8',
          });
        body({ gate, addons, dir });
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    }

    it('accepts a full addon set and rejects a missing one', () => {
      withPackage(
        (source) => source,
        ({ gate, addons }) => {
          assert.strictEqual(gate().status, 0);
          fs.rmSync(addons[0]);
          const failed = gate();
          assert.notStrictEqual(failed.status, 0);
          assert.match(failed.stderr, /\.node/);
        }
      );
    });

    it('rejects an addon with an unexpected file name', () => {
      withPackage(
        (source) => source,
        ({ gate, addons }) => {
          fs.renameSync(addons[0], path.join(path.dirname(addons[0]), 'exarch-rs.other.node'));
          assert.notStrictEqual(gate().status, 0);
        }
      );
    });

    const MUSL_THROW =
      'throw new Error(`exarch-rs: unsupported platform $' +
      '{key}-musl; only glibc Linux is bundled`);';

    const appended = [
      'const r = require; r("evil");',
      'module["req" + "uire"]("evil");',
      'import("evil");',
      'process.dlopen({}, "/evil");',
      'require("./exarch-rs.darwin-x64.node");',
      "module.exports.helper = () => require('evil');",
      "if (typeof Bun !== 'undefined') { require('evil'); }",
      "if (globalThis.process && process.versions) { require('evil'); }",
      "if (process.env && process.env.CI) { require('evil'); }",
      "// note\rif (process.versions) { require('evil'); }",
      "// note if (process.versions) { require('evil'); }",
      "let addons = () => 0; addons = addons['con' + 'structor'];",
      "req/**/uire('evil');",
      "require/* split */('evil');",
      'function f() { return arguments; } f();',
    ];
    for (const extra of appended) {
      it(`rejects a loader with appended code ${JSON.stringify(extra)}`, () => {
        withPackage(
          (source) => `${source}\n${extra}\n`,
          ({ gate }) => {
            const failed = gate();
            assert.notStrictEqual(failed.status, 0, failed.stdout);
            assert.match(failed.stderr, /generated/);
          }
        );
      });
    }

    it('rejects a loader that differs by a single trailing space', () => {
      withPackage(
        (source) => source.replace('const addon = loadAddon();', 'const addon = loadAddon(); '),
        ({ gate }) => assert.notStrictEqual(gate().status, 0)
      );
    });

    it('rejects a loader whose musl branch requires a package', () => {
      withPackage(
        (source) => {
          assert.ok(source.includes(MUSL_THROW), 'musl branch moved; update this test');
          return source.replace(MUSL_THROW, "return require('evil-musl');");
        },
        ({ gate }) => assert.notStrictEqual(gate().status, 0)
      );
    });

    it('rejects a loader whose musl branch loads a bundled addon', () => {
      withPackage(
        (source) => source.replace(MUSL_THROW, 'return key;'),
        ({ gate }) => {
          const failed = gate();
          assert.notStrictEqual(failed.status, 0);
          assert.match(failed.stderr, /musl/);
        }
      );
    });

    it('--write-loader reproduces the committed loader byte for byte', () => {
      withPackage(
        (source) => source,
        ({ dir }) => {
          const before = fs.readFileSync(path.join(dir, 'index.js'), 'utf8');
          execFileSync(process.execPath, ['scripts/check-package.mjs', '--write-loader'], {
            cwd: dir,
          });
          assert.strictEqual(fs.readFileSync(path.join(dir, 'index.js'), 'utf8'), before);
        }
      );
    });

    it('rejects a loader that resolves a package name', () => {
      withPackage(
        (source) => source.replace("require('./exarch-rs.linux-x64-gnu.node')", "require('evil')"),
        ({ gate }) => {
          const failed = gate();
          assert.notStrictEqual(failed.status, 0);
          assert.match(failed.stderr, /linux-x64/);
        }
      );
    });
  });
});
