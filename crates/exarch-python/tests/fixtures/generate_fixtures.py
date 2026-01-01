#!/usr/bin/env python3
"""Generate malicious CVE test fixtures.

This script creates malicious test archives that demonstrate known CVE attack vectors.
These archives are used in CVE regression tests to verify exarch blocks these attacks.
"""

import io
import tarfile
from pathlib import Path


def create_path_traversal_archive():
    """Create CVE-2025-4517 path traversal test archive."""
    archive_path = Path(__file__).parent / "cve-2025-4517-traversal.tar.gz"

    with tarfile.open(archive_path, "w:gz") as tar:
        data = b"malicious content"
        info = tarfile.TarInfo(name="../../../etc/passwd")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    print(f"Created: {archive_path}")


def create_symlink_escape_archive():
    """Create CVE-2024-12905 symlink escape test archive."""
    archive_path = Path(__file__).parent / "cve-2024-12905-symlink-escape.tar"

    with tarfile.open(archive_path, "w") as tar:
        info = tarfile.TarInfo(name="evil_link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)

    print(f"Created: {archive_path}")


def create_hardlink_escape_archive():
    """Create CVE-2025-48387 hardlink traversal test archive."""
    archive_path = Path(__file__).parent / "cve-2025-48387-hardlink.tar"

    with tarfile.open(archive_path, "w") as tar:
        info = tarfile.TarInfo(name="evil_hardlink")
        info.type = tarfile.LNKTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)

    print(f"Created: {archive_path}")


if __name__ == "__main__":
    create_path_traversal_archive()
    create_symlink_escape_archive()
    create_hardlink_escape_archive()
    print("\nAll CVE test fixtures created successfully.")
