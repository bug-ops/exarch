---
tags:
  - sdd
  - delta
created: 2026-11-15
status: merged
related:
  - "[[007-node-bindings/spec]]"
---

# Delta: Node surface of the #1230 batch

## ADDED

### FR-133

The security options SHALL accept `repeatedPaths: 'keep_first' | 'refuse'` and `maxKdfWork`; the extract, list and verify options SHALL accept `password?: Buffer` (a string is refused with a typed error); `index.d.ts` is regenerated. Core owns every check (#1201, #1023).

### FR-134

An entry below an existing escaping symlink SHALL surface as `SYMLINK_ESCAPE` in every format (#1230).

### FR-135

`scripts/check-package.mjs` SHALL compare the packed `package.json` with the committed one by whole-object, key-order-insensitive deep equality, with a field allowlist recorded in a constant together with the measurement of what `pnpm pack` rewrites (empty if nothing changes); a difference, including a key present in only one, is an error naming the field. Mutation tests in `loader.test.js` cover an exports redirect, `bin`, an added postinstall, a changed `main` and an added dependency (#1233). The tar and zip test builders live once in `tests/helpers/archives.js` (#1234).

Parallelism stays unexposed in the Node binding (#1027).
