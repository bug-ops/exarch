# exarch

[![npm](https://img.shields.io/npm/v/exarch)](https://www.npmjs.com/package/exarch)
[![Node](https://img.shields.io/node/v/exarch)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)](https://www.typescriptlang.org/)
[![CI](https://img.shields.io/github/actions/workflow/status/rabax/exarch/ci.yml?branch=main)](https://github.com/rabax/exarch/actions)
[![License](https://img.shields.io/npm/l/exarch)](../../LICENSE-MIT)

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

- Node.js >= 14

## Quick Start

```javascript
const { extractArchive } = require('exarch');

// Async (recommended)
const result = await extractArchive('archive.tar.gz', '/output/path');
console.log(`Extracted ${result.filesExtracted} files`);
```

## Usage

### Async API (Recommended)

```javascript
const { extractArchive } = require('exarch');

const result = await extractArchive('archive.tar.gz', '/output/path');

console.log(`Files extracted: ${result.filesExtracted}`);
console.log(`Bytes written: ${result.bytesWritten}`);
console.log(`Duration: ${result.durationMs}ms`);
```

### Sync API

```javascript
const { extractArchiveSync } = require('exarch');

const result = extractArchiveSync('archive.tar.gz', '/output/path');
console.log(`Extracted ${result.filesExtracted} files`);
```

> [!TIP]
> Prefer the async API to avoid blocking the event loop during extraction.

### ES Modules

```javascript
import { extractArchive } from 'exarch';

const result = await extractArchive('archive.tar.gz', '/output/path');
```

### TypeScript

```typescript
import { extractArchive, SecurityConfig, ExtractionReport } from 'exarch';

const result: ExtractionReport = await extractArchive('archive.tar.gz', '/output/path');
console.log(`Extracted ${result.filesExtracted} files`);
```

### Custom Security Configuration

```typescript
import { extractArchive, SecurityConfig } from 'exarch';

const config = new SecurityConfig()
  .maxFileSize(100 * 1024 * 1024)   // 100 MB per file
  .maxTotalSize(1024 * 1024 * 1024) // 1 GB total
  .maxFileCount(10_000);             // Max 10k files

const result = await extractArchive('archive.tar.gz', '/output', config);
```

### Error Handling

```javascript
const { extractArchive } = require('exarch');

try {
  const result = await extractArchive('archive.tar.gz', '/output');
  console.log(`Success: ${result.filesExtracted} files`);
} catch (error) {
  // Error codes: PATH_TRAVERSAL, SYMLINK_ESCAPE, ZIP_BOMB, QUOTA_EXCEEDED, etc.
  console.error(`Extraction failed: ${error.message}`);
}
```

## API

### `extractArchive(archivePath, outputDir, config?)`

Extract an archive asynchronously with security validation.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `archivePath` | `string` | Path to the archive file |
| `outputDir` | `string` | Directory where files will be extracted |
| `config` | `SecurityConfig` | Optional security configuration |

**Returns:** `Promise<ExtractionReport>`

### `extractArchiveSync(archivePath, outputDir, config?)`

Synchronous version. Blocks the event loop until extraction completes.

**Returns:** `ExtractionReport`

### `ExtractionReport`

```typescript
interface ExtractionReport {
  filesExtracted: number;  // Number of files extracted
  bytesWritten: number;    // Total bytes written
  durationMs: number;      // Extraction duration in milliseconds
}
```

### `SecurityConfig`

Builder-style security configuration.

```typescript
const config = new SecurityConfig()
  .maxFileSize(bytes)       // Max size per file
  .maxTotalSize(bytes)      // Max total extraction size
  .maxFileCount(count)      // Max number of files
  .maxCompressionRatio(n);  // Max compression ratio (zip bomb detection)
```

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
> Unlike many Node.js archive libraries, exarch applies security validation by default.

## Supported Formats

| Format | Extensions |
|--------|------------|
| TAR | `.tar` |
| TAR+GZIP | `.tar.gz`, `.tgz` |
| TAR+BZIP2 | `.tar.bz2`, `.tbz2` |
| TAR+XZ | `.tar.xz`, `.txz` |
| TAR+ZSTD | `.tar.zst`, `.tzst` |
| ZIP | `.zip` |

## Comparison with tar-fs

```javascript
// UNSAFE - tar-fs has known vulnerabilities
const tar = require('tar-fs');
const fs = require('fs');
fs.createReadStream('archive.tar')
  .pipe(tar.extract('/output'));  // May extract outside target directory!

// SAFE - exarch validates all paths
const { extractArchive } = require('exarch');
await extractArchive('archive.tar', '/output');  // Protected by default
```

## Development

This package is built using [napi-rs](https://napi.rs/).

```bash
# Clone repository
git clone https://github.com/rabax/exarch
cd exarch/crates/exarch-node

# Install dependencies
npm install

# Build native module
npm run build

# Run tests
npm test
```

## Related Packages

- [exarch-core](../exarch-core) — Core Rust library
- [exarch (PyPI)](../exarch-python) — Python bindings

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT License ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
