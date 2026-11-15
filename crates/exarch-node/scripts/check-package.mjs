#!/usr/bin/env node
// Release gate for the npm tarball (#1200, #1208): inspects the files `npm pack`
// would publish and fails when the loader could resolve code outside the package
// or the package cannot load. Run from crates/exarch-node.

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const packageDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(join(packageDir, 'package.json'), 'utf8'));

const SCRIPT_FILE = /\.(?:[cm]?js)$/;
const CALL = /\b(require|import)\s*\(\s*([^)]*?)\s*\)/g;
const LITERAL = /^(['"])([^'"`$\\]*)\1$/;

function packedFiles() {
  const out = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: packageDir,
    encoding: 'utf8',
  });
  const [entry] = JSON.parse(out);
  return entry.files.map((file) => normalize(file.path));
}

function checkCalls(file, files, errors) {
  const source = readFileSync(join(packageDir, file), 'utf8');
  for (const [, callee, argument] of source.matchAll(CALL)) {
    const literal = argument.match(LITERAL);
    if (literal === null) {
      errors.push(`${file}: ${callee}(${argument}) is not a single string literal`);
      continue;
    }
    const target = literal[2];
    if (target.startsWith('node:')) {
      continue;
    }
    const packed = files.includes(normalize(join(dirname(file), target)));
    if (!target.startsWith('./') || !packed) {
      errors.push(`${file}: ${callee}('${target}') is neither node:* nor a packed relative file`);
    }
  }
}

function check() {
  const errors = [];
  const files = packedFiles();

  if (typeof pkg.main !== 'string' || !files.includes(normalize(pkg.main))) {
    errors.push(`main ${JSON.stringify(pkg.main)} is not in the packed files`);
  }

  for (const file of files.filter((name) => SCRIPT_FILE.test(name))) {
    checkCalls(file, files, errors);
  }

  const addons = files.filter((name) => name.endsWith('.node')).length;
  const expected = pkg.napi.targets.length;
  if (addons !== expected) {
    errors.push(`${addons} .node addons packed, napi.targets declares ${expected}`);
  }
  return errors;
}

const errors = check();
if (errors.length > 0) {
  console.error(errors.map((error) => `check-package: ${error}`).join('\n'));
  process.exit(1);
}
console.log('check-package: ok');
