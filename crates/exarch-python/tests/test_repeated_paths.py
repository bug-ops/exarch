"""Repeated paths (#1201): ``SecurityConfig.repeated_paths`` refuses an archive
that names a landing twice, in extract, list and verify alike; the default
keeps the first copy.
"""

import io
import tarfile

import pytest

import exarch


def _repeated_file_tar(temp_dir):
    archive = temp_dir / "s07.tar"
    with tarfile.open(archive, "w") as tar:
        for payload in (b"first\n", b"last\n"):
            info = tarfile.TarInfo("a")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
    return archive


def _nested_directories_tar(temp_dir):
    archive = temp_dir / "dirs.tar"
    with tarfile.open(archive, "w") as tar:
        for name in ("d", "d"):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            tar.addfile(info)
        info = tarfile.TarInfo("d/f")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
    return archive


def test_default_keeps_the_first_copy_and_succeeds(temp_dir):
    archive = _repeated_file_tar(temp_dir)
    out = temp_dir / "out"

    report = exarch.extract_archive(archive, out)

    assert (out / "a").read_bytes() == b"first\n"
    assert report.skipped.count("duplicate") == 1
    assert exarch.SecurityConfig().repeated_paths == "keep_first"


def test_the_setter_and_the_builder_round_trip_and_reject_unknown_values():
    config = exarch.SecurityConfig().with_repeated_paths("refuse")
    assert config.repeated_paths == "refuse"
    config.repeated_paths = "keep_first"
    assert config.repeated_paths == "keep_first"

    with pytest.raises(exarch.InvalidConfigurationError):
        exarch.SecurityConfig().with_repeated_paths("last_wins")


def test_refuse_raises_a_typed_security_violation_with_a_relax_hint(temp_dir):
    archive = _repeated_file_tar(temp_dir)
    config = exarch.SecurityConfig().with_repeated_paths("refuse")

    with pytest.raises(exarch.SecurityViolationError) as caught:
        exarch.extract_archive(archive, temp_dir / "out", config)

    assert caught.value.sub_code == "REPEATED_PATH"
    assert caught.value.relaxable_by == "repeated_paths"


def test_refuse_leaves_a_directory_repeated_over_a_directory_alone(temp_dir):
    archive = _nested_directories_tar(temp_dir)
    out = temp_dir / "out"
    config = exarch.SecurityConfig().with_repeated_paths("refuse")

    exarch.extract_archive(archive, out, config)

    assert (out / "d" / "f").read_bytes() == b"x"


def test_list_marks_the_repeat_as_refused_only_under_refuse(temp_dir):
    archive = _repeated_file_tar(temp_dir)

    kept = exarch.list_archive(archive).dispositions
    refused = exarch.list_archive(
        archive, exarch.SecurityConfig().with_repeated_paths("refuse")
    ).dispositions

    assert [d.action for d in kept] == ["extract", "skip"]
    assert [d.action for d in refused] == ["extract", "refuse"]


def test_verify_reports_the_repeat_only_under_refuse(temp_dir):
    archive = _repeated_file_tar(temp_dir)

    plain = exarch.verify_archive(archive)
    strict = exarch.verify_archive(archive, exarch.SecurityConfig().with_repeated_paths("refuse"))

    assert not any("named twice" in issue.message for issue in plain.issues)
    assert any("named twice" in issue.message for issue in strict.issues)


def test_extract_to_memory_refuses_a_repeat_like_extract(temp_dir):
    archive = _repeated_file_tar(temp_dir)
    config = exarch.SecurityConfig().with_repeated_paths("refuse")

    with pytest.raises(exarch.SecurityViolationError) as caught:
        exarch.extract_archive_to_memory(archive.read_bytes(), config)

    assert caught.value.sub_code == "REPEATED_PATH"
