"""Integration tests for extract_archive function."""

import pytest

pytest.importorskip("exarch")
from exarch import SecurityConfig, SecurityViolationError, extract_archive  # noqa: E402


class TestExtractArchive:
    """Test extract_archive function."""

    def test_path_validation_null_bytes(self):
        """Test path validation rejects null bytes."""
        with pytest.raises(SecurityViolationError, match="null bytes"):
            extract_archive("test\x00.tar.gz", "/tmp/output")

    def test_path_validation_too_long(self):
        """Test path validation rejects overly long paths."""
        long_path = "x" * 5000
        with pytest.raises(SecurityViolationError, match="maximum length"):
            extract_archive(long_path, "/tmp/output")

    def test_pathlib_support(self, sample_tar_gz, temp_dir):
        """Test extraction with pathlib.Path objects."""
        output = temp_dir / "output"
        output.mkdir()

        report = extract_archive(sample_tar_gz, output)
        assert report.files_extracted > 0

    def test_string_path_support(self, sample_tar_gz, temp_dir):
        """Test extraction with string paths."""
        archive = str(sample_tar_gz)
        output_dir = temp_dir / "output"
        output_dir.mkdir()
        output = str(output_dir)

        report = extract_archive(archive, output)
        assert report.files_extracted > 0

    def test_custom_config(self, sample_tar_gz, temp_dir):
        """Test extraction with custom configuration."""
        config = SecurityConfig().with_max_file_size(100 * 1024 * 1024)
        output_dir = temp_dir / "output"
        output_dir.mkdir()
        output = str(output_dir)

        report = extract_archive(sample_tar_gz, output, config)
        assert report.files_extracted > 0
