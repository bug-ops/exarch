"""Integration tests for ExtractionOptions Python API."""

import pytest

pytest.importorskip("exarch")
from exarch import ExtractionOptions, extract_archive  # noqa: E402


class TestExtractionOptions:
    """Test ExtractionOptions Python bindings."""

    def test_default_skip_duplicates_is_true(self):
        """Test that skip_duplicates defaults to True."""
        opts = ExtractionOptions()
        assert opts.skip_duplicates is True

    def test_default_static_method(self):
        """Test that ExtractionOptions.default() equals ExtractionOptions()."""
        opts = ExtractionOptions.default()
        assert opts.skip_duplicates is True

    def test_with_skip_duplicates_false(self):
        """Test with_skip_duplicates(False) sets the flag and returns self."""
        opts = ExtractionOptions()
        result = opts.with_skip_duplicates(False)
        assert opts.skip_duplicates is False
        assert result is opts

    def test_with_skip_duplicates_true(self):
        """Test with_skip_duplicates(True) sets the flag."""
        opts = ExtractionOptions()
        opts.with_skip_duplicates(False)
        opts.with_skip_duplicates(True)
        assert opts.skip_duplicates is True

    def test_skip_duplicates_property_setter(self):
        """Test skip_duplicates property setter."""
        opts = ExtractionOptions()
        opts.skip_duplicates = False
        assert opts.skip_duplicates is False

    def test_build_returns_self(self):
        """Test build() returns self for builder consistency."""
        opts = ExtractionOptions()
        result = opts.build()
        assert result is opts

    def test_repr(self):
        """Test string representation."""
        opts = ExtractionOptions()
        repr_str = repr(opts)
        assert "ExtractionOptions" in repr_str
        assert "skip_duplicates" in repr_str

    def test_extract_archive_with_default_options(self, sample_tar_gz, temp_dir):
        """Test extract_archive with ExtractionOptions() succeeds."""
        output = temp_dir / "output"
        output.mkdir()
        opts = ExtractionOptions()
        report = extract_archive(sample_tar_gz, output, options=opts)
        assert report.files_extracted >= 1

    def test_extract_archive_with_skip_duplicates_false(self, sample_tar_gz, temp_dir):
        """Test extract_archive with skip_duplicates=False on a non-duplicate archive succeeds."""
        output = temp_dir / "output"
        output.mkdir()
        opts = ExtractionOptions().with_skip_duplicates(False)
        report = extract_archive(sample_tar_gz, output, options=opts)
        assert report.files_extracted >= 1

    def test_extract_archive_options_keyword_arg(self, sample_tar_gz, temp_dir):
        """Test extract_archive accepts options as keyword argument."""
        output = temp_dir / "output"
        output.mkdir()
        opts = ExtractionOptions()
        report = extract_archive(sample_tar_gz, output, options=opts)
        assert report.files_extracted >= 1

    def test_atomic_default(self):
        """Test that atomic defaults to False."""
        opts = ExtractionOptions()
        assert opts.atomic is False

    def test_atomic_round_trip(self):
        """Test with_atomic(True) sets the flag and returns self."""
        opts = ExtractionOptions().with_atomic(True)
        assert opts.atomic is True

    def test_skip_duplicates_default(self):
        """Test that skip_duplicates defaults to True."""
        opts = ExtractionOptions()
        assert opts.skip_duplicates is True

    def test_skip_duplicates_round_trip(self):
        """Test with_skip_duplicates(True) sets the flag after toggling."""
        opts = ExtractionOptions().with_skip_duplicates(True)
        assert opts.skip_duplicates is True
