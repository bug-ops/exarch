# Exarch

Memory-safe archive extraction library with Python and Node.js bindings.

## Features

- **Security-First Design**: Built-in protection against common vulnerabilities
  - Path traversal prevention
  - Zip bomb detection
  - Symlink/hardlink validation
  - Configurable quotas and limits
- **Multiple Formats**: Support for tar, tar.gz, tar.bz2, tar.xz, and zip
- **Language Bindings**: Native Python and Node.js support
- **Zero Unsafe Code**: Core library is 100% safe Rust (Edition 2024)
- **Production Ready**: Comprehensive testing and security validation

## Quick Start

### Rust

```rust
use exarch_core::{extract_archive, SecurityConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecurityConfig::default();
    let report = extract_archive("archive.tar.gz", "/output/dir", &config)?;
    println!("Extracted {} files", report.files_extracted);
    Ok(())
}
```

### Python

```python
import exarch

report = exarch.extract_archive("archive.tar.gz", "/output/dir")
print(f"Extracted {report['files_extracted']} files")
```

### Node.js

```javascript
const exarch = require('exarch');

const report = exarch.extractArchive("archive.tar.gz", "/output/dir");
console.log(`Extracted ${report.files_extracted} files`);
```

## Installation

### Rust

```toml
[dependencies]
exarch-core = "0.1"
```

### Python

```bash
pip install exarch
```

### Node.js

```bash
npm install exarch
```

## Security Configuration

```rust
use exarch_core::SecurityConfig;

let config = SecurityConfig {
    max_file_size: 100 * 1024 * 1024,  // 100 MB
    max_total_size: 1024 * 1024 * 1024, // 1 GB
    allow_symlinks: false,
    allow_hardlinks: false,
    ..Default::default()
};
```

## Development

### Requirements

- Rust 1.85.0 or later (Edition 2024)
- Python 3.8+ (for Python bindings)
- Node.js 14+ (for Node.js bindings)

### Build

```bash
cargo build --workspace
```

### Test

```bash
cargo test --workspace
```

### Format

```bash
cargo +nightly fmt
```

### Lint

```bash
cargo clippy --workspace -- -D warnings
```

## Project Structure

```
exarch/
├── crates/
│   ├── exarch-core/     # Core Rust library
│   ├── exarch-python/   # Python bindings
│   └── exarch-node/     # Node.js bindings
├── benches/             # Benchmarks
├── examples/            # Usage examples
├── tests/               # Integration tests
└── docs/                # Documentation
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.
