"""create_archive stages its output, can refuse an existing one and takes a format."""

import os
import tarfile
import zipfile

import pytest

import exarch


@pytest.fixture
def source(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("alpha")
    return src


def test_overwrite_false_refuses_an_existing_output(tmp_path, source):
    out = tmp_path / "out.tar"
    out.write_bytes(b"keep me")

    with pytest.raises(exarch.OutputExistsError) as info:
        exarch.create_archive(out, [source], overwrite=False)

    assert info.value.code == "OUTPUT_EXISTS"
    assert isinstance(info.value, FileExistsError)
    assert out.read_bytes() == b"keep me"


def test_overwrite_false_creates_when_absent(tmp_path, source):
    out = tmp_path / "out.tar"

    exarch.create_archive(out, [source], overwrite=False)

    assert tarfile.open(out).getnames() == ["a.txt"]


def test_default_replaces_and_keeps_the_mode(tmp_path, source):
    out = tmp_path / "out.tar"
    out.write_bytes(b"old")
    out.chmod(0o640)

    exarch.create_archive(out, [source])

    assert tarfile.is_tarfile(out)
    assert (out.stat().st_mode & 0o777) == 0o640


def test_failed_creation_leaves_the_output_untouched(tmp_path):
    out = tmp_path / "out.tar"
    out.write_bytes(b"old")

    with pytest.raises(exarch.SourceNotFoundError):
        exarch.create_archive(out, [tmp_path / "missing"])

    assert out.read_bytes() == b"old"
    assert sorted(os.listdir(tmp_path)) == ["out.tar"]


def test_directory_output_is_refused(tmp_path, source):
    target = tmp_path / "dir.tar"
    target.mkdir()

    with pytest.raises(exarch.InvalidConfigurationError) as info:
        exarch.create_archive(target, [source])

    assert info.value.setting == "output_path"


def test_output_inside_a_source_does_not_archive_itself(tmp_path, source):
    out = source / "out.tar"

    exarch.create_archive(out, [source])

    assert not any(name.endswith("out.tar") for name in tarfile.open(out).getnames())


def test_explicit_format_overrides_the_extension(tmp_path, source):
    out = tmp_path / "bundle.apk"

    exarch.create_archive(out, [source], format="Zip")

    assert zipfile.is_zipfile(out)


def test_unknown_format_is_a_value_error(tmp_path, source):
    with pytest.raises(exarch.InvalidConfigurationError, match="not one of the allowed values"):
        exarch.create_archive(tmp_path / "o.tar", [source], format="rar")


@pytest.mark.parametrize("error", [RuntimeError("boom"), KeyboardInterrupt()])
def test_raising_progress_callback_does_not_commit(tmp_path, source, error):
    out = tmp_path / "out.tar"
    out.write_bytes(b"previous archive")

    def progress(*args):
        raise error

    with pytest.raises(type(error)) as info:
        exarch.create_archive_with_progress(out, [source], None, progress)

    assert info.value is error
    assert info.value.progress_callback_error is True
    assert out.read_bytes() == b"previous archive"
    assert sorted(os.listdir(tmp_path)) == ["out.tar", "src"]


def test_working_progress_callback_still_commits(tmp_path, source):
    out = tmp_path / "out.tar"
    seen = []

    exarch.create_archive_with_progress(out, [source], None, lambda *args: seen.append(args))

    assert seen
    assert tarfile.is_tarfile(out)


@pytest.mark.parametrize("durability", ["synced", "unsynced"])
@pytest.mark.parametrize("create", ["create_archive", "create_archive_with_progress"])
def test_durability_is_accepted_by_both_creation_functions(tmp_path, source, durability, create):
    out = tmp_path / "out.tar"

    getattr(exarch, create)(out, [source], durability=durability)

    assert tarfile.open(out).getnames() == ["a.txt"]


def test_an_unknown_durability_raises_a_typed_error(tmp_path, source):
    out = tmp_path / "out.tar"

    with pytest.raises(exarch.InvalidConfigurationError) as info:
        exarch.create_archive(out, [source], durability="fsync")

    assert info.value.setting == "durability"
    assert "synced, unsynced" in str(info.value)
    assert not out.exists()
