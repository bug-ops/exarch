"""Typed skips on reports, unknown progress totals and exclude pattern refusals."""

import pytest

import exarch


@pytest.fixture
def source(tmp_path):
    src = tmp_path / "src"
    (src / "build").mkdir(parents=True)
    (src / "keep.txt").write_text("keep")
    (src / "drop.tmp").write_text("drop")
    (src / "build" / "out.bin").write_text("bin")
    (src / ".hidden").write_text("h")
    return src


def test_creation_report_counts_skips_per_kind(tmp_path, source):
    config = exarch.CreationConfig().with_exclude_patterns(["*.tmp", "build"])

    report = exarch.create_archive(tmp_path / "o.tar", [source], config)

    assert report.skipped.count("excluded") == report.skipped.total - report.skipped.count("hidden")
    assert report.skipped.counts["excluded"] >= 2
    assert report.files_skipped == report.skipped.total == len(report.skipped)
    assert {skip.kind for skip in report.skipped.sample} <= set(report.skipped.counts)
    assert all(isinstance(skip.path, str) for skip in report.skipped.sample)


def test_hidden_entries_are_counted(tmp_path, source):
    report = exarch.create_archive(tmp_path / "o.tar", [source])

    assert report.skipped.count("hidden") == 1
    hidden = [skip for skip in report.skipped.sample if skip.kind == "hidden"]
    assert len(hidden) == 1
    assert hidden[0].path.endswith(".hidden")
    assert hidden[0].io_kind is None


def test_unknown_kind_is_a_value_error(tmp_path, source):
    report = exarch.create_archive(tmp_path / "o.tar", [source])

    with pytest.raises(exarch.InvalidConfigurationError, match="not one of the allowed values"):
        report.skipped.count("nope")


def test_extraction_report_carries_skipped(tmp_path, source):
    archive = tmp_path / "o.tar"
    exarch.create_archive(archive, [source])
    out = tmp_path / "out"
    out.mkdir()
    config = exarch.SecurityConfig().add_allowed_extension("txt")

    report = exarch.extract_archive(archive, out, config)

    assert report.skipped.count("extension_not_allowed") == report.files_skipped > 0


def test_tar_progress_total_is_none_and_zip_total_is_known(tmp_path, source):
    for format, expected in (("TarGz", None), ("Zip", 3)):
        out = tmp_path / f"o-{format}"
        exarch.create_archive(out, [source], format=format)
        calls = []

        exarch.extract_archive_with_progress(
            out, tmp_path / f"x-{format}", None, lambda *args: calls.append(args)
        )

        assert calls
        if expected is None:
            assert all(total is None for _, total, _, _ in calls)
        else:
            assert all(isinstance(total, int) and total >= len(calls) for _, total, _, _ in calls)


@pytest.mark.parametrize(
    "pattern",
    [
        "",
        ".",
        "..",
        "/abs",
        "*",
        "a*b",
        "**x",
        "build/*",
        "?.txt",
        "[a",
        "{a,b}",
        "!a.txt",
        " .env",
        "a,b",
    ],
)
def test_unsupported_exclude_patterns_are_refused(pattern):
    with pytest.raises(exarch.InvalidConfigurationError) as info:
        exarch.CreationConfig().with_exclude_patterns([pattern])

    assert info.value.setting == "exclude_pattern"
    with pytest.raises(exarch.InvalidConfigurationError):
        exarch.CreationConfig().exclude_patterns = [pattern]


def test_supported_exclude_patterns_round_trip():
    config = exarch.CreationConfig().with_exclude_patterns(["*.tmp", "tmp*", "docs/build", "x"])

    assert sorted(config.exclude_patterns) == sorted(["*.tmp", "tmp*", "docs/build", "x"])
