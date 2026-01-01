"""CVE regression tests for exarch-python.

These tests verify that exarch correctly blocks known CVE attack vectors.
"""

from pathlib import Path

import pytest

import exarch


def test_cve_path_traversal(malicious_traversal_tar, temp_dir):
    """
    Test CVE-2025-4517: Python tarfile path traversal.

    Verify that archives with path traversal attempts (../) are blocked.
    """
    output_dir = temp_dir / "output"
    output_dir.mkdir()

    # Default security config should block path traversal
    with pytest.raises(exarch.PathTraversalError):
        exarch.extract_archive(malicious_traversal_tar, output_dir)

    # Verify no files were created outside output_dir
    assert not (temp_dir / "etc" / "passwd").exists()


def test_cve_symlink_escape(malicious_symlink_escape, temp_dir):
    """
    Test CVE-2024-12905: Node.js tar-fs symlink escape.

    Verify that symlinks pointing outside extraction directory are blocked.
    """
    output_dir = temp_dir / "output"
    output_dir.mkdir()

    # Default security config blocks ALL symlinks (SecurityViolationError)
    with pytest.raises(exarch.SecurityViolationError):
        exarch.extract_archive(malicious_symlink_escape, output_dir)

    # Verify no symlinks were created
    evil_link = output_dir / "evil_link"
    assert not evil_link.exists()

    # Test that even with symlinks enabled, escape is detected
    output_dir2 = temp_dir / "output2"
    output_dir2.mkdir()
    config = exarch.SecurityConfig().allow_symlinks(True)

    with pytest.raises(exarch.SymlinkEscapeError):
        exarch.extract_archive(malicious_symlink_escape, output_dir2, config)

    # Verify no symlinks were created
    evil_link2 = output_dir2 / "evil_link"
    assert not evil_link2.exists()


def test_path_traversal_with_permissive_config(malicious_traversal_tar, temp_dir):
    """
    Test that path traversal is still blocked even with permissive config.

    Path traversal should NEVER be allowed, regardless of config.
    """
    output_dir = temp_dir / "output"
    output_dir.mkdir()

    # Even permissive config should block path traversal
    config = exarch.SecurityConfig.permissive()

    with pytest.raises(exarch.PathTraversalError):
        exarch.extract_archive(malicious_traversal_tar, output_dir, config)


def test_symlink_allowed_within_directory(temp_dir):
    """
    Test that symlinks within the extraction directory are allowed when configured.
    """
    import io
    import tarfile

    # Create archive with safe symlink (points to file within archive)
    archive_path = temp_dir / "safe_symlink.tar"

    with tarfile.open(archive_path, "w") as tar:
        # Add a regular file
        file_data = b"target content"
        file_info = tarfile.TarInfo(name="target.txt")
        file_info.size = len(file_data)
        tar.addfile(file_info, io.BytesIO(file_data))

        # Add a symlink pointing to the file above
        link_info = tarfile.TarInfo(name="link.txt")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "target.txt"
        tar.addfile(link_info)

    output_dir = temp_dir / "output"
    output_dir.mkdir()

    # Allow symlinks within extraction directory
    config = exarch.SecurityConfig().allow_symlinks(True)

    report = exarch.extract_archive(archive_path, output_dir, config)

    assert report.files_extracted == 1  # target.txt
    assert report.symlinks_created == 1  # link.txt
    assert (output_dir / "target.txt").exists()
    assert (output_dir / "link.txt").is_symlink()


def test_absolute_path_blocked(temp_dir):
    """
    Test that absolute paths in archives are blocked.
    """
    import io
    import tarfile

    # Create archive with absolute path
    archive_path = temp_dir / "absolute_path.tar"

    with tarfile.open(archive_path, "w") as tar:
        file_data = b"absolute path content"
        file_info = tarfile.TarInfo(name="/tmp/malicious.txt")
        file_info.size = len(file_data)
        tar.addfile(file_info, io.BytesIO(file_data))

    output_dir = temp_dir / "output"
    output_dir.mkdir()

    # Default config should block absolute paths
    with pytest.raises(exarch.PathTraversalError):
        exarch.extract_archive(archive_path, output_dir)

    # Verify file was not created at absolute path
    assert not Path("/tmp/malicious.txt").exists()


def test_zip_bomb_detection(temp_dir):
    """
    Test that zip bombs are detected via compression ratio check.

    Creates a small archive with high compression ratio to simulate zip bomb.
    1 MB of zeros compresses to ~1 KB (ratio ~1000x), exceeding default limit of 100x.
    """
    import zipfile

    archive_path = temp_dir / "zipbomb.zip"

    # Create a zip with high compression ratio
    # 1 MB of zeros compresses to ~1 KB (ratio ~1000x)
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.txt", b"\x00" * (1024 * 1024))  # 1 MB of zeros

    output_dir = temp_dir / "output"
    output_dir.mkdir()

    # Default max_compression_ratio is 100.0, so this should fail
    with pytest.raises(exarch.ZipBombError):
        exarch.extract_archive(archive_path, output_dir)

    # Verify no files were extracted
    assert not (output_dir / "bomb.txt").exists()


def test_hardlink_escape(malicious_hardlink_escape, temp_dir):
    """
    Test CVE-2025-48387: Node.js tar-fs hardlink traversal.

    Verify that hardlinks pointing outside extraction directory are blocked.
    """
    output_dir = temp_dir / "output"
    output_dir.mkdir()

    # Default config blocks ALL hardlinks (SecurityViolationError)
    with pytest.raises(exarch.SecurityViolationError):
        exarch.extract_archive(malicious_hardlink_escape, output_dir)

    # Verify no hardlinks were created
    assert not (output_dir / "evil_hardlink").exists()

    # Test that even with hardlinks enabled, escape is detected
    output_dir2 = temp_dir / "output2"
    output_dir2.mkdir()

    config = exarch.SecurityConfig().allow_hardlinks(True)
    with pytest.raises(exarch.HardlinkEscapeError):
        exarch.extract_archive(malicious_hardlink_escape, output_dir2, config)

    # Verify no hardlinks were created
    assert not (output_dir2 / "evil_hardlink").exists()
