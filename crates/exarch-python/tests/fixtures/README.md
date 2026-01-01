# CVE Test Fixtures

This directory contains malicious test archives used to verify that exarch correctly blocks known CVE attack vectors. These files are intentionally crafted to trigger security violations.

## Files

### cve-2025-4517-traversal.tar.gz

**CVE:** [CVE-2025-4517](https://nvd.nist.gov/vuln/detail/CVE-2025-4517) - Python tarfile path traversal

**Attack Vector:** Path traversal using `../` sequences

**Contents:** TAR.GZ archive with a single entry named `../../../etc/passwd`

**Expected Behavior:** exarch raises `PathTraversalError`

**Test:** `test_cve_path_traversal()`

---

### cve-2024-12905-symlink-escape.tar

**CVE:** [CVE-2024-12905](https://nvd.nist.gov/vuln/detail/CVE-2024-12905) - Node.js tar-fs symlink escape

**Attack Vector:** Symlink pointing to absolute path outside extraction directory

**Contents:** TAR archive with a symlink named `evil_link` pointing to `/etc/passwd`

**Expected Behavior:**
- Default config (symlinks disabled): `SecurityViolationError`
- With symlinks enabled: `SymlinkEscapeError`

**Test:** `test_cve_symlink_escape()`

---

### cve-2025-48387-hardlink.tar

**CVE:** [CVE-2025-48387](https://nvd.nist.gov/vuln/detail/CVE-2025-48387) - Node.js tar-fs hardlink traversal

**Attack Vector:** Hardlink pointing to absolute path outside extraction directory

**Contents:** TAR archive with a hardlink named `evil_hardlink` pointing to `/etc/passwd`

**Expected Behavior:**
- Default config (hardlinks disabled): `SecurityViolationError`
- With hardlinks enabled: `HardlinkEscapeError`

**Test:** `test_hardlink_escape()`

---

## Regenerating Fixtures

To regenerate these test archives, run:

```bash
cd tests/fixtures
python3 generate_fixtures.py
```

## Security Notes

These files are **intentionally malicious** for testing purposes. They should:

1. Never be extracted without proper security validation
2. Be kept in version control for reproducible testing
3. Only be used in test environments
4. Demonstrate real-world attack vectors from CVE reports

## Archive Structure

### Path Traversal Archive

```
cve-2025-4517-traversal.tar.gz
└── ../../../etc/passwd  (17 bytes: "malicious content")
```

### Symlink Escape Archive

```
cve-2024-12905-symlink-escape.tar
└── evil_link -> /etc/passwd  (symlink)
```

### Hardlink Escape Archive

```
cve-2025-48387-hardlink.tar
└── evil_hardlink -> /etc/passwd  (hardlink)
```

## Test Coverage

These fixtures ensure that exarch:

1. **Blocks path traversal** - Rejects any entry with `..` or absolute paths
2. **Blocks symlink escapes** - Verifies symlink targets stay within extraction directory
3. **Blocks hardlink escapes** - Verifies hardlink targets exist within extraction directory
4. **Provides defense in depth** - Default config blocks symlinks/hardlinks entirely

## References

- [CVE-2025-4517](https://nvd.nist.gov/vuln/detail/CVE-2025-4517) - Python tarfile path traversal (CVSS 9.4)
- [CVE-2024-12905](https://nvd.nist.gov/vuln/detail/CVE-2024-12905) - Node.js tar-fs symlink escape
- [CVE-2025-48387](https://nvd.nist.gov/vuln/detail/CVE-2025-48387) - Node.js tar-fs hardlink traversal
- [CWE-22](https://cwe.mitre.org/data/definitions/22.html) - Path Traversal
- [CWE-59](https://cwe.mitre.org/data/definitions/59.html) - Improper Link Resolution Before File Access
