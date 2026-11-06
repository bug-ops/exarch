"""Error attributes that core derives once (#1010) and the parity fields (#1011)."""

import pytest

import exarch


def test_an_io_error_always_carries_the_replace_attributes(sample_tar_gz, temp_dir):
    blocker = temp_dir / "afile"
    blocker.write_text("x")

    with pytest.raises(OSError) as info:
        exarch.extract_archive(sample_tar_gz, blocker / "sub")

    err = info.value
    assert err.code == "IO_ERROR"
    assert err.restore is None
    assert err.backup_path is None
    assert err.leftover_path is None


def test_leftover_path_defaults_to_none_on_every_archive_error(temp_dir):
    with pytest.raises(exarch.SourceNotFoundError) as info:
        exarch.extract_archive(temp_dir / "missing.tar", temp_dir / "out")

    assert info.value.leftover_path is None
    assert exarch.ArchiveError.leftover_path is None


def test_unmatched_include_names_the_patterns_as_unmatched_patterns(sample_tar_gz, temp_dir):
    config = exarch.SecurityConfig().add_include_pattern("nope")

    with pytest.raises(exarch.InvalidConfigurationError) as info:
        exarch.extract_archive(sample_tar_gz, temp_dir / "out", config)

    assert info.value.unmatched_patterns == ["nope"]
    assert not hasattr(info.value, "patterns")


def test_a_verification_report_exposes_the_suspicious_count_and_the_format(sample_tar_gz):
    report = exarch.verify_archive(sample_tar_gz)

    assert report.suspicious_entries == 0
    assert report.format == "TarGz"


def test_create_archive_accepts_durability_none_as_the_default(temp_dir):
    source = temp_dir / "a.txt"
    source.write_text("a")

    report = exarch.create_archive(temp_dir / "out.tar", [source], durability=None)

    assert report.files_added == 1
