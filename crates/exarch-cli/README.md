# exarch-cli

Command-line utility for secure archive extraction and creation.

## Features (Phase 1)

- CLI argument parsing with `clap` v4.5
- Extract command with security validation
- Human-readable and JSON output modes
- Error conversion from `exarch-core`

## Installation

```bash
cargo build --release -p exarch-cli
```

## Usage

```bash
# Extract archive with default security settings
exarch extract archive.tar.gz

# Extract with custom output directory
exarch extract archive.zip /tmp/output

# Extract with JSON output
exarch extract --json archive.tar.xz

# Extract with verbose output
exarch extract --verbose archive.tar.gz

# Increase security limits
exarch extract --max-files 50000 --max-total-size 50G archive.tar.gz

# Allow symlinks (trusted sources only)
exarch extract --allow-symlinks trusted.tar
```

## Development Status

**Phase 1 (Current):** Foundation - CLI parsing, error handling, output formatting
**Phase 2:** Archive creation functionality
**Phase 3:** List and verify commands, progress bars
**Phase 4:** Testing and polish
**Phase 5:** Distribution setup

## Testing

```bash
# Run integration tests
cargo test -p exarch-cli

# Run CLI manually
cargo run -p exarch-cli -- extract tests/fixtures/sample.tar.gz
```
