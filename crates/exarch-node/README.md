# exarch

[![npm](https://img.shields.io/npm/v/exarch)](https://www.npmjs.com/package/exarch)
[![Node](https://img.shields.io/node/v/exarch)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)](https://www.typescriptlang.org/)
[![CI](https://img.shields.io/github/actions/workflow/status/bug-ops/exarch/ci.yml?branch=main)](https://github.com/bug-ops/exarch/actions)
[![License](https://img.shields.io/npm/l/exarch)](LICENSE-MIT)

Memory-safe archive extraction library for Node.js.

> [!IMPORTANT]
> **exarch** is designed as a secure replacement for vulnerable archive libraries like `tar-fs`, which has known CVEs with CVSS scores up to 9.4.

This package provides Node.js bindings for [exarch-core](../exarch-core), a Rust library with built-in protection against common archive vulnerabilities.

## Installation

```bash
# npm
npm install exarch

# yarn
yarn add exarch

# pnpm
pnpm add exarch

# bun
bun add exarch
```

> [!NOTE]
> This package includes TypeScript definitions. No need for separate `@types` package.

## Requirements

- Node.js >= 18.0.0

## Quick Start

```javascript
const exarch = require('exarch');

const result = exarch.extractArchive('archive.tar.gz', '/output/path');
console.log(`Extracted ${result.filesExtracted} files`);
```

## Usage

### CommonJS

```javascript
const { extractArchive } = require('exarch');

const result = extractArchive('archive.tar.gz', '/output/path');

console.log(`Files extracted: ${result.filesExtracted}`);
console.log(`Bytes written: ${result.bytesWritten}`);
console.log(`Duration: ${result.durationMs}ms`);
```

### ES Modules

```javascript
import { extractArchive } from 'exarch';

const result = extractArchive('archive.tar.gz', '/output/path');
console.log(`Extracted ${result.filesExtracted} files`);
```

### TypeScript

```typescript
import { extractArchive, ExtractionReport } from 'exarch';

const result: ExtractionReport = extractArchive('archive.tar.gz', '/output/path');
console.log(`Extracted ${result.filesExtracted} files`);
```

### Error Handling

```javascript
const { extractArchive } = require('exarch');

try {
  const result = extractArchive('archive.tar.gz', '/output');
  console.log(`Success: ${result.filesExtracted} files`);
} catch (error) {
  console.error(`Extraction failed: ${error.message}`);
}
```

## API

### `extractArchive(archivePath, outputDir)`

Extract an archive to the specified directory with security validation.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `archivePath` | `string` | Path to the archive file |
| `outputDir` | `string` | Directory where files will be extracted |

**Returns:** `ExtractionReport`

```typescript
interface ExtractionReport {
  filesExtracted: number;  // Number of files extracted
  bytesWritten: number;    // Total bytes written
  durationMs: number;      // Extraction duration in milliseconds
}
```

**Throws:**

- `Error` - If extraction fails due to security violations or I/O errors

## Security Features

The library provides built-in protection against:

| Protection | Description |
|------------|-------------|
| Path traversal | Blocks `../` and absolute paths |
| Symlink attacks | Prevents symlinks escaping extraction directory |
| Hardlink attacks | Validates hardlink targets |
| Zip bombs | Detects high compression ratios |
| Permission sanitization | Strips setuid/setgid bits |
| Size limits | Enforces file and total size limits |

> [!CAUTION]
> Unlike many Node.js archive libraries, exarch applies security validation by default. This may cause some archives to fail extraction if they contain potentially malicious content.

## Supported Formats

- TAR (`.tar`)
- TAR+GZIP (`.tar.gz`, `.tgz`)
- TAR+BZIP2 (`.tar.bz2`)
- TAR+XZ (`.tar.xz`, `.txz`)
- ZIP (`.zip`)

## Comparison with tar-fs

```javascript
// UNSAFE - tar-fs has known vulnerabilities
const tar = require('tar-fs');
const fs = require('fs');
fs.createReadStream('archive.tar')
  .pipe(tar.extract('/output'));  // May extract outside target directory!

// SAFE - exarch validates all paths
const { extractArchive } = require('exarch');
extractArchive('archive.tar', '/output');  // Protected by default
```

## Development

This package is built using [napi-rs](https://napi.rs/).

```bash
# Clone repository
git clone https://github.com/bug-ops/exarch
cd exarch/crates/exarch-node

# Install dependencies
npm install

# Build native module
npm run build

# Run tests
npm test
```

## Related Packages

- [exarch-core](../exarch-core) - Core Rust library
- [exarch (PyPI)](../exarch-python) - Python bindings

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](../../LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
