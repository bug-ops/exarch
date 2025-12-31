# exarch

[![Crates.io](https://img.shields.io/crates/v/exarch-cli)](https://crates.io/crates/exarch-cli)
[![CI](https://img.shields.io/github/actions/workflow/status/bug-ops/exarch/ci.yml?branch=main)](https://github.com/bug-ops/exarch/actions)
[![codecov](https://codecov.io/gh/bug-ops/exarch/graph/badge.svg?flag=exarch-cli)](https://codecov.io/gh/bug-ops/exarch)
[![License](https://img.shields.io/crates/l/exarch-cli)](LICENSE)

Command-line utility for secure archive extraction and creation. Built on [exarch-core](../exarch-core/), providing memory-safe archive handling with built-in protection against path traversal, zip bombs, and symlink escape attacks.

## Features

- **Secure by default** - All security checks enabled out of the box
- **Path traversal protection** - Blocks `../` escape attempts
- **Zip bomb detection** - Configurable compression ratio limits
- **Symlink/hardlink validation** - Prevents symlink escape attacks
- **Quota enforcement** - File count, total size, and per-file limits
- **Multiple formats** - TAR (gz, bz2, xz, zstd) and ZIP support
- **Multiple output modes** - Human-readable and JSON output

## Installation

### From crates.io

```bash
cargo install exarch-cli
```

### From source

```bash
git clone https://github.com/bug-ops/exarch
cd exarch
cargo install --path crates/exarch-cli
```

> [!TIP]
> Use `cargo binstall exarch-cli` for faster installation without compilation.

<details>
<summary>Pre-built binaries</summary>

Download from [GitHub Releases](https://github.com/bug-ops/exarch/releases/latest):

| Platform | Architecture | Download |
|----------|--------------|----------|
| Linux | x86_64 | [exarch-x86_64-unknown-linux-gnu.tar.gz](https://github.com/bug-ops/exarch/releases/latest) |
| Linux | aarch64 | [exarch-aarch64-unknown-linux-gnu.tar.gz](https://github.com/bug-ops/exarch/releases/latest) |
| macOS | x86_64 | [exarch-x86_64-apple-darwin.tar.gz](https://github.com/bug-ops/exarch/releases/latest) |
| macOS | aarch64 | [exarch-aarch64-apple-darwin.tar.gz](https://github.com/bug-ops/exarch/releases/latest) |
| Windows | x86_64 | [exarch-x86_64-pc-windows-msvc.zip](https://github.com/bug-ops/exarch/releases/latest) |

After downloading:

```bash
# Linux/macOS
tar -xzf exarch-*.tar.gz
chmod +x exarch
sudo mv exarch /usr/local/bin/

# Windows - extract zip and add to PATH
```

</details>

> [!IMPORTANT]
> Requires Rust 1.89.0 or later for building from source.

## Usage

```bash
exarch [OPTIONS] <COMMAND>
```

### Commands

| Command | Description | Status |
|---------|-------------|--------|
| `extract` | Extract archive contents | Available |
| `create` | Create a new archive | Available |
| `list` | List archive contents | Coming soon |
| `verify` | Verify archive integrity | Coming soon |

### Global Options

| Option | Short | Description |
|--------|-------|-------------|
| `--verbose` | `-v` | Enable verbose output |
| `--quiet` | `-q` | Suppress non-error output |
| `--json` | `-j` | Output results in JSON format |
| `--help` | `-h` | Print help |
| `--version` | `-V` | Print version |

## Extract Command

```bash
exarch extract [OPTIONS] <ARCHIVE> [OUTPUT_DIR]
```

### Examples

```bash
# Extract archive to current directory
exarch extract archive.tar.gz

# Extract to specific directory
exarch extract archive.zip /tmp/output

# Extract with JSON output for scripting
exarch extract --json archive.tar.xz | jq '.data.files_extracted'

# Extract with verbose output
exarch extract --verbose archive.tar.gz

# Increase security limits for large archives
exarch extract --max-files 50000 --max-total-size 50G large-archive.tar.gz

# Allow symlinks for trusted archives
exarch extract --allow-symlinks trusted-source.tar
```

### Security Options

| Option | Default | Description |
|--------|---------|-------------|
| `--max-files` | 10000 | Maximum number of files to extract |
| `--max-total-size` | - | Maximum total extracted size (supports K/M/G/T suffixes) |
| `--max-file-size` | - | Maximum single file size |
| `--max-compression-ratio` | 100 | Maximum compression ratio (zip bomb protection) |
| `--allow-symlinks` | false | Allow symlinks (within extraction directory) |
| `--allow-hardlinks` | false | Allow hardlinks (within extraction directory) |
| `--preserve-permissions` | false | Preserve file permissions from archive |
| `--force` | false | Overwrite existing files |

> [!CAUTION]
> Only use `--allow-symlinks` and `--allow-hardlinks` with archives from trusted sources. These options can be exploited by malicious archives.

## Create Command

Create archives from files and directories:

```bash
exarch create [OPTIONS] <OUTPUT> <SOURCES>...
```

### Examples

```bash
# Create tar.gz from directory
exarch create backup.tar.gz ./src

# Create from multiple sources
exarch create project.tar.gz src/ Cargo.toml README.md

# Create ZIP with maximum compression
exarch create -l 9 archive.zip ./data

# Exclude patterns
exarch create backup.tar.gz ./project --exclude "*.log" --exclude "target/"

# Include hidden files
exarch create backup.tar.gz ./project --include-hidden

# Overwrite existing archive
exarch create -f backup.tar.gz ./src
```

### Create Options

| Option | Short | Description |
|--------|-------|-------------|
| `--compression-level` | `-l` | Compression level (1-9, default: 6) |
| `--follow-symlinks` | | Follow symbolic links |
| `--include-hidden` | | Include hidden files |
| `--exclude` | `-x` | Exclude pattern (repeatable) |
| `--strip-prefix` | | Strip path prefix |
| `--force` | `-f` | Overwrite existing file |
| `--quiet` | `-q` | Suppress output |
| `--json` | | Output JSON format |

> [!TIP]
> Archive format is detected from the output file extension. Supported formats: `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`, `.zip`

## Output Modes

### Human-readable (default)

```
Extraction complete
  Files extracted: 1,523
  Directories: 87
  Total size: 42.3 MB
```

### JSON output (`--json`)

```json
{
  "operation": "extract",
  "status": "success",
  "data": {
    "files_extracted": 1523,
    "directories_created": 87,
    "symlinks_created": 0,
    "bytes_written": 44396032
  }
}
```

> [!TIP]
> Use JSON output with `jq` for scripting: `exarch extract --json archive.tar.gz | jq '.data.files_extracted'`

## Security

exarch is designed with security as a primary concern, protecting against common archive vulnerabilities:

| Vulnerability | Protection |
|--------------|------------|
| **Path traversal** (CVE-2025-4517) | Blocks `../` and absolute paths by default |
| **Symlink escape** (CVE-2024-12905) | Validates symlink targets stay within extraction dir |
| **Hardlink attacks** (CVE-2025-48387) | Validates hardlink targets |
| **Zip bombs** (42.zip) | Configurable compression ratio limit (default: 100:1) |
| **Resource exhaustion** | File count and size quotas |
| **Permission escalation** | Permission sanitization by default |

> [!NOTE]
> All security checks are enabled by default. Use `--allow-*` flags only for trusted archives.

## Supported Formats

| Format | Extension | Extraction | Creation |
|--------|-----------|------------|----------|
| TAR | `.tar` | Yes | Yes |
| TAR + gzip | `.tar.gz`, `.tgz` | Yes | Yes |
| TAR + bzip2 | `.tar.bz2`, `.tbz2` | Yes | Yes |
| TAR + xz | `.tar.xz`, `.txz` | Yes | Yes |
| TAR + zstd | `.tar.zst`, `.tzst` | Yes | Yes |
| ZIP | `.zip` | Yes | Yes |

## Development

```bash
# Build
cargo build -p exarch-cli

# Run tests
cargo nextest run -p exarch-cli

# Run CLI directly
cargo run -p exarch-cli -- extract tests/fixtures/sample.tar.gz

# Check formatting and lints
cargo +nightly fmt --all -- --check
cargo clippy -p exarch-cli -- -D warnings
```

## Roadmap

- [x] **Phase 1**: Foundation - CLI parsing, error handling, output formatting
- [ ] **Phase 2**: Archive creation functionality
- [ ] **Phase 3**: List and verify commands
- [ ] **Phase 4**: Progress bars, shell completions
- [ ] **Phase 5**: Distribution (Homebrew, apt, releases)

## Related Crates

- [exarch-core](../exarch-core/) - Core extraction library
- [exarch-python](../exarch-python/) - Python bindings
- [exarch-node](../exarch-node/) - Node.js bindings

## License

Licensed under MIT OR Apache-2.0 - see [LICENSE-MIT](../../LICENSE-MIT) or [LICENSE-APACHE](../../LICENSE-APACHE).
