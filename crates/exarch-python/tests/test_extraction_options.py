"""Integration tests for ExtractionOptions Python API."""

import io
import tarfile

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

    @pytest.mark.parametrize(
        ("value", "survivor"),
        [("skip", b"first"), ("overwrite", b"second"), ("refuse", b"first")],
    )
    def test_in_archive_duplicate_follows_the_policy(self, temp_dir, value, survivor):
        archive = temp_dir / "dup.tar"
        with tarfile.open(archive, "w") as tar:
            for body in (b"first", b"second"):
                info = tarfile.TarInfo("a.txt")
                info.size = len(body)
                tar.addfile(info, io.BytesIO(body))
        output = temp_dir / "out"
        output.mkdir()
        opts = ExtractionOptions().with_existing_files(value)

        report = extract_archive(archive, output, options=opts)

        assert (output / "a.txt").read_bytes() == survivor
        assert report.skipped.count("duplicate") == (0 if value == "overwrite" else 1)

    def test_extract_archive_options_keyword_arg(self, sample_tar_gz, temp_dir):
        """Test extract_archive accepts options as keyword argument."""
        output = temp_dir / "output"
        output.mkdir()
        opts = ExtractionOptions()
        report = extract_archive(sample_tar_gz, output, options=opts)
        assert report.files_extracted >= 1

    def test_staging_default_is_in_place(self):
        assert ExtractionOptions().staging == "in_place"

    @pytest.mark.parametrize("value", ["in_place", "atomic", "atomic_replace"])
    def test_with_staging_round_trip(self, value):
        opts = ExtractionOptions()
        assert opts.with_staging(value) is opts
        assert opts.staging == value
        opts.staging = "in_place"
        opts.staging = value
        assert opts.staging == value

    @pytest.mark.parametrize("value", ["", "Atomic", "replace", "true"])
    def test_unknown_staging_is_refused(self, value):
        opts = ExtractionOptions()
        with pytest.raises(InvalidConfigurationError) as info:
            opts.with_staging(value)
        assert info.value.setting == "staging"
        with pytest.raises(InvalidConfigurationError):
            opts.staging = value
        assert opts.staging == "in_place"

    def test_atomic_flag_is_gone(self):
        opts = ExtractionOptions()
        assert not hasattr(opts, "atomic")
        assert not hasattr(opts, "with_atomic")


def _one_file_tar(path):
    data = b"hello"
    with tarfile.open(path, "w") as tar:
        info = tarfile.TarInfo("hello.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return path


class TestMarkPropagation:
    """The download-origin mark policy and what the report says about it."""

    def test_default_is_never(self):
        assert ExtractionOptions().mark_propagation == "never"
        assert ExtractionOptions.default().mark_propagation == "never"

    @pytest.mark.parametrize("value", ["never", "when_marked"])
    def test_with_mark_propagation_sets_the_value_and_returns_self(self, value):
        opts = ExtractionOptions()
        assert opts.with_mark_propagation(value) is opts
        assert opts.mark_propagation == value

    def test_property_setter(self):
        opts = ExtractionOptions()
        opts.mark_propagation = "when_marked"
        assert opts.mark_propagation == "when_marked"

    @pytest.mark.parametrize("value", ["", "When_Marked", "when-marked", "always"])
    def test_unknown_value_is_refused(self, value):
        opts = ExtractionOptions()
        with pytest.raises(InvalidConfigurationError) as info:
            opts.with_mark_propagation(value)
        assert info.value.setting == "mark_propagation"
        with pytest.raises(InvalidConfigurationError):
            opts.mark_propagation = value
        assert opts.mark_propagation == "never"

    def test_repr_names_the_policy(self):
        assert "mark_propagation=" in repr(ExtractionOptions())

    def test_report_says_not_requested_by_default(self, tmp_path):
        archive = _one_file_tar(tmp_path / "a.tar")
        report = extract_archive(str(archive), str(tmp_path / "out"))
        assert report.mark_propagation == "not_requested"
        assert report.marks_written == 0
        assert report.marks_failed == 0

    def test_report_states_an_unmarked_archive_or_an_unsupported_platform(self, tmp_path):
        archive = _one_file_tar(tmp_path / "a.tar")
        opts = ExtractionOptions().with_mark_propagation("when_marked")
        report = extract_archive(str(archive), str(tmp_path / "out"), options=opts)
        assert report.mark_propagation in {"unmarked", "unsupported_platform"}
        assert report.marks_written == 0
        assert report.marks_failed == 0
