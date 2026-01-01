"""Pytest configuration for exarch-python integration tests."""

import io
import tarfile
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test outputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_tar_gz(temp_dir):
    """Create a sample TAR.GZ archive for testing."""
    archive_path = temp_dir / "sample.tar.gz"

    with tarfile.open(archive_path, "w:gz") as tar:
        # Add a simple text file
        file_data = b"Hello, World!"
        tarinfo = tarfile.TarInfo(name="hello.txt")
        tarinfo.size = len(file_data)
        tar.addfile(tarinfo, io.BytesIO(file_data))

        # Add a directory
        dirinfo = tarfile.TarInfo(name="subdir")
        dirinfo.type = tarfile.DIRTYPE
        tar.addfile(dirinfo)

        # Add a file in the subdirectory
        nested_data = b"Nested file content"
        nested_info = tarfile.TarInfo(name="subdir/nested.txt")
        nested_info.size = len(nested_data)
        tar.addfile(nested_info, io.BytesIO(nested_data))

    return archive_path


@pytest.fixture
def malicious_traversal_tar(temp_dir):
    """Create an archive with path traversal attempt."""
    archive_path = temp_dir / "traversal.tar"

    with tarfile.open(archive_path, "w") as tar:
        # Add a file with path traversal (../../../etc/passwd)
        malicious_data = b"malicious content"
        tarinfo = tarfile.TarInfo(name="../../../etc/passwd")
        tarinfo.size = len(malicious_data)
        tar.addfile(tarinfo, io.BytesIO(malicious_data))

    return archive_path


@pytest.fixture
def malicious_symlink_escape(temp_dir):
    """Create an archive with symlink escape attempt."""
    archive_path = temp_dir / "symlink_escape.tar"

    with tarfile.open(archive_path, "w") as tar:
        # Add a symlink pointing outside extraction directory
        linkinfo = tarfile.TarInfo(name="evil_link")
        linkinfo.type = tarfile.SYMTYPE
        linkinfo.linkname = "/etc/passwd"
        tar.addfile(linkinfo)

    return archive_path


@pytest.fixture
def corrupted_archive(temp_dir):
    """Create a corrupted archive file."""
    archive_path = temp_dir / "corrupted.tar.gz"

    # Write garbage data to simulate corruption
    with open(archive_path, "wb") as f:
        f.write(b"\x1f\x8b\x08\x00" + b"corrupted data that is not a valid gzip stream" * 100)

    return archive_path
