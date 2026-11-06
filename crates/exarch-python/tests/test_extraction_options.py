"""Integration tests for ExtractionOptions Python API."""

import pytest

pytest.importorskip("exarch")
from exarch import (  # noqa: E402
    ExtractionOptions,
    InvalidConfigurationError,
    OutputExistsError,
    extract_archive,
)


class TestExtractionOptions:
    """Test ExtractionOptions Python bindings."""

    def test_default_existing_files_is_skip(self):
        """Existing files are skipped unless the caller says otherwise."""
        assert ExtractionOptions().existing_files == "skip"

    def test_default_static_method(self):
        """Test that ExtractionOptions.default() equals ExtractionOptions()."""
        assert ExtractionOptions.default().existing_files == "skip"

    @pytest.mark.parametrize("value", ["skip", "overwrite", "refuse"])
    def test_with_existing_files_sets_the_value_and_returns_self(self, value):
        opts = ExtractionOptions()
        result = opts.with_existing_files(value)
        assert opts.existing_files == value
        assert result is opts

    def test_existing_files_property_setter(self):
        opts = ExtractionOptions()
        opts.existing_files = "refuse"
        assert opts.existing_files == "refuse"

    @pytest.mark.parametrize("value", ["", "Skip", "replace", "true"])
    def test_unknown_existing_files_value_is_refused(self, value):
        opts = ExtractionOptions()
        with pytest.raises(InvalidConfigurationError) as info:
            opts.with_existing_files(value)
        assert info.value.setting == "existing_files"
        with pytest.raises(InvalidConfigurationError):
            opts.existing_files = value
        assert opts.existing_files == "skip"

    def test_skip_duplicates_is_gone(self):
        opts = ExtractionOptions()
        assert not hasattr(opts, "skip_duplicates")
        assert not hasattr(opts, "with_skip_duplicates")

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
        assert "existing_files='skip'" in repr_str.replace('"', "'")

    def test_extract_archive_with_default_options(self, sample_tar_gz, temp_dir):
        """Test extract_archive with ExtractionOptions() succeeds."""
        output = temp_dir / "output"
        output.mkdir()
        opts = ExtractionOptions()
        report = extract_archive(sample_tar_gz, output, options=opts)
        assert report.files_extracted >= 1

    @pytest.mark.parametrize("value", ["skip", "overwrite", "refuse"])
    def test_extract_archive_into_an_empty_destination_under_every_value(
        self, sample_tar_gz, temp_dir, value
    ):
        output = temp_dir / "output"
        output.mkdir()
        opts = ExtractionOptions().with_existing_files(value)
        report = extract_archive(sample_tar_gz, output, options=opts)
        assert report.files_extracted >= 1

    def test_refuse_never_overwrites_an_existing_file(self, sample_tar_gz, temp_dir):
        first = temp_dir / "first"
        first.mkdir()
        extract_archive(sample_tar_gz, first)
        planted = next(path for path in sorted(first.rglob("*")) if path.is_file())
        planted.write_text("planted")

        opts = ExtractionOptions().with_existing_files("refuse")
        with pytest.raises(OutputExistsError) as info:
            extract_archive(sample_tar_gz, first, options=opts)

        assert planted.read_text() == "planted"
        assert info.value.code == "OUTPUT_EXISTS"
        assert info.value.conflicts

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
