"""Integration tests for extract_archive function."""

import pytest
from pathlib import Path

# TODO: Import exarch module once the extension is built
# from exarch import extract_archive, SecurityConfig


class TestExtractArchive:
    """Test extract_archive function."""

    def test_path_validation_null_bytes(self):
        """Test path validation rejects null bytes."""
        pytest.skip("Requires compiled Python extension module and test fixtures")
        # with pytest.raises(ValueError, match="null bytes"):
        #     extract_archive("test\x00.tar.gz", "/tmp/output")

    def test_path_validation_too_long(self):
        """Test path validation rejects overly long paths."""
        pytest.skip("Requires compiled Python extension module")
        # long_path = "x" * 5000
        # with pytest.raises(ValueError, match="maximum length"):
        #     extract_archive(long_path, "/tmp/output")

    def test_pathlib_support(self, temp_dir):
        """Test extraction with pathlib.Path objects."""
        pytest.skip("Requires compiled Python extension module and test fixtures")
        # archive = Path("tests/fixtures/test.tar.gz")
        # output = temp_dir / "output"
        # output.mkdir()
        #
        # report = extract_archive(archive, output)
        # assert report.files_extracted > 0

    def test_string_path_support(self, temp_dir):
        """Test extraction with string paths."""
        pytest.skip("Requires compiled Python extension module and test fixtures")
        # archive = "tests/fixtures/test.tar.gz"
        # output = str(temp_dir / "output")
        #
        # report = extract_archive(archive, output)
        # assert report.files_extracted > 0

    def test_custom_config(self, temp_dir):
        """Test extraction with custom configuration."""
        pytest.skip("Requires compiled Python extension module and test fixtures")
        # config = SecurityConfig().max_file_size(100 * 1024 * 1024)
        # archive = "tests/fixtures/test.tar.gz"
        # output = str(temp_dir / "output")
        #
        # report = extract_archive(archive, output, config)
        # assert report.files_extracted > 0
