# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

- **DO NOT** open a public GitHub issue for security vulnerabilities
- Email security reports to the maintainers (check repository for contact details)
- Provide detailed information about the vulnerability and steps to reproduce

We will acknowledge receipt of your report within 48 hours and provide a timeline for resolution.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

Pre-1.0 versions are under active development. Breaking changes may occur between minor versions.

## Security Considerations

This library implements archive extraction with security as a primary design goal:

### Path Security

- **Path Traversal Prevention**: Validates all paths to prevent extraction outside the destination directory
- **Symlink Escape Prevention**: Validates symlink targets to ensure they stay within bounds
- **Hardlink Escape Prevention**: Validates hardlink targets (when enabled)
- **Null Byte Injection Prevention**: Rejects paths containing null bytes

### Resource Protection

- **Zip Bomb Detection**: Monitors compression ratios to detect decompression bombs
- **File Size Limits**: Configurable limits on individual file and total extraction sizes
- **File Count Limits**: Prevents DoS via excessive file creation
- **Path Depth Limits**: Prevents deep directory nesting attacks

### Component Filtering

- **Banned Components**: Default deny-list for sensitive directories (`.git`, `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `.env`)
- **Case-Insensitive Matching**: Prevents bypass on case-insensitive filesystems
- **Extension Filtering**: Optional allowlist for file extensions

### Configuration

The default `SecurityConfig` implements a defense-in-depth strategy:

```rust
use exarch_core::SecurityConfig;

// Use secure defaults
let config = SecurityConfig::default();

// Or customize for trusted sources (use with caution)
let permissive = SecurityConfig::permissive();
```

### Known Limitations

1. **TOCTOU Conditions**: Time-of-check-time-of-use race conditions exist in filesystem validation. While mitigated through canonicalization, full elimination requires platform-specific `openat()` usage.

2. **Symlink Resolution**: Circular symlinks are not explicitly detected but won't cause infinite loops during validation.

3. **Platform Differences**: Some security checks are platform-specific (e.g., permission validation on Unix vs Windows).

## Best Practices

When using this library:

1. **Never** extract untrusted archives with `SecurityConfig::permissive()`
2. **Always** use the default configuration or more restrictive settings for untrusted input
3. **Validate** the extraction destination directory is properly isolated
4. **Monitor** resource usage during extraction of large archives
5. **Review** security configuration for your specific use case

## Security Audit History

- **2025-12-30**: Phase 1 security audit completed
  - 0 BLOCKING issues
  - 8 HIGH priority issues (all fixed)
  - 16 MEDIUM priority issues (all fixed)
  - 12 LOW priority issues (all fixed)

## Disclosure Policy

We follow responsible disclosure practices:

1. Security issues are fixed before public disclosure
2. Security advisories published after patches are available
3. Credit given to reporters who follow responsible disclosure

## Contact

For security concerns, please contact the maintainers through the repository's designated security channels.
