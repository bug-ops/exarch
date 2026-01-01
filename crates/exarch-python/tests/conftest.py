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


@pytest.fixture(scope="session")
def fixtures_dir():
    """Return fixtures directory path (session-scoped)."""
    path = Path(__file__).parent / "fixtures"
    if not path.exists():
        pytest.fail(f"Fixtures directory missing: {path}")
    return path


@pytest.fixture
def malicious_traversal_tar(fixtures_dir):
    """Return path to CVE-2025-4517 path traversal test archive."""
    path = fixtures_dir / "cve-2025-4517-traversal.tar.gz"
    if not path.exists():
        pytest.fail(
            f"Test fixture missing: {path}. Run: python tests/fixtures/generate_fixtures.py"
        )
    return path


@pytest.fixture
def malicious_symlink_escape(fixtures_dir):
    """Return path to CVE-2024-12905 symlink escape test archive."""
    path = fixtures_dir / "cve-2024-12905-symlink-escape.tar"
    if not path.exists():
        pytest.fail(
            f"Test fixture missing: {path}. Run: python tests/fixtures/generate_fixtures.py"
        )
    return path


@pytest.fixture
def malicious_hardlink_escape(fixtures_dir):
    """Return path to CVE-2025-48387 hardlink escape test archive."""
    path = fixtures_dir / "cve-2025-48387-hardlink.tar"
    if not path.exists():
        pytest.fail(
            f"Test fixture missing: {path}. Run: python tests/fixtures/generate_fixtures.py"
        )
    return path


@pytest.fixture
def corrupted_archive(temp_dir):
    """Create a corrupted archive file."""
    archive_path = temp_dir / "corrupted.tar.gz"

    # Write garbage data to simulate corruption
    with open(archive_path, "wb") as f:
        f.write(b"\x1f\x8b\x08\x00" + b"corrupted data that is not a valid gzip stream" * 100)

    return archive_path
