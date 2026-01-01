"""CVE regression tests for exarch-python.

NOTE: These tests are skipped until exarch-core extract_archive API is fully implemented.
The current implementation is a placeholder (see exarch-core/src/api.rs).
"""

from pathlib import Path

import pytest

import exarch

# Skip reason for all extraction-dependent tests
EXTRACT_NOT_IMPLEMENTED = "extract_archive is a placeholder - enable when core API is implemented"


@pytest.mark.skip(reason=EXTRACT_NOT_IMPLEMENTED)
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


@pytest.mark.skip(reason=EXTRACT_NOT_IMPLEMENTED)
def test_cve_symlink_escape(malicious_symlink_escape, temp_dir):
    """
    Test CVE-2024-12905: Node.js tar-fs symlink escape.

    Verify that symlinks pointing outside extraction directory are blocked.
    """
    output_dir = temp_dir / "output"
    output_dir.mkdir()

    # Default security config should block symlink escape
    with pytest.raises(exarch.SymlinkEscapeError):
        exarch.extract_archive(malicious_symlink_escape, output_dir)

    # Verify no symlinks were created
    evil_link = output_dir / "evil_link"
    assert not evil_link.exists()


@pytest.mark.skip(reason=EXTRACT_NOT_IMPLEMENTED)
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


@pytest.mark.skip(reason=EXTRACT_NOT_IMPLEMENTED)
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


@pytest.mark.skip(reason=EXTRACT_NOT_IMPLEMENTED)
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


@pytest.mark.skip(reason="Zip bomb test requires specialized test archive (42.zip)")
def test_zip_bomb_detection(temp_dir):
    """
    Test that zip bombs are detected via compression ratio check.

    Note: This test requires a specially crafted archive or we skip it.
    """
    pass


@pytest.mark.skip(reason=EXTRACT_NOT_IMPLEMENTED)
def test_hardlink_escape(temp_dir):
    """
    Test CVE-2025-48387: Node.js tar-fs hardlink traversal.

    Verify that hardlinks pointing outside extraction directory are blocked.
    """
    import tarfile

    # Create archive with hardlink escape attempt
    archive_path = temp_dir / "hardlink_escape.tar"

    with tarfile.open(archive_path, "w") as tar:
        # Add a hardlink pointing to /etc/passwd
        link_info = tarfile.TarInfo(name="evil_hardlink")
        link_info.type = tarfile.LNKTYPE
        link_info.linkname = "/etc/passwd"
        tar.addfile(link_info)

    output_dir = temp_dir / "output"
    output_dir.mkdir()

    # Default config should block hardlink escape
    with pytest.raises(exarch.HardlinkEscapeError):
        exarch.extract_archive(archive_path, output_dir)
