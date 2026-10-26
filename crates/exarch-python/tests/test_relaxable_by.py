"""Tests for the ``relaxable_by`` attribute of ``SecurityViolationError``."""

import io
import tarfile

import pytest

import exarch


def test_symlink_refusal_names_the_symlinks_setting(malicious_symlink_escape, temp_dir):
    output_dir = temp_dir / "output"
    output_dir.mkdir()

    with pytest.raises(exarch.SecurityViolationError) as caught:
        exarch.extract_archive(malicious_symlink_escape, output_dir)

    assert caught.value.relaxable_by == "symlinks"


def test_hardlink_refusal_names_the_hardlinks_setting(malicious_hardlink_escape, temp_dir):
    output_dir = temp_dir / "output"
    output_dir.mkdir()

    with pytest.raises(exarch.SecurityViolationError) as caught:
        exarch.extract_archive(malicious_hardlink_escape, output_dir)

    assert caught.value.relaxable_by == "hardlinks"


def test_non_relaxable_refusal_has_no_setting(temp_dir):
    with pytest.raises(exarch.SecurityViolationError) as caught:
        exarch.extract_archive("bad\0name.tar", temp_dir)

    assert caught.value.relaxable_by is None


def test_class_default_covers_subclasses():
    assert exarch.SecurityViolationError.relaxable_by is None
    assert exarch.ZipInconsistencyError.relaxable_by is None


def _tar_with(path, name, typ=tarfile.REGTYPE):
    info = tarfile.TarInfo(name)
    info.type = typ
    info.size = 1 if typ == tarfile.REGTYPE else 0
    with tarfile.open(path, "w") as tar:
        tar.addfile(info, io.BytesIO(b"x") if info.size else None)
    return path


@pytest.mark.parametrize(
    ("entry", "setting"),
    [(".git/config", "banned_components"), ("/".join(["d"] * 40) + "/f", "max_path_depth")],
)
def test_other_settings_are_named(temp_dir, entry, setting):
    archive = _tar_with(temp_dir / "a.tar", entry)

    with pytest.raises(exarch.SecurityViolationError) as caught:
        exarch.extract_archive(archive, temp_dir / "out")

    assert caught.value.relaxable_by == setting


def test_entry_name_spelling_a_token_does_not_forge_relaxable_by(temp_dir):
    archive = _tar_with(temp_dir / "a.tar", "[relaxableBy=symlinks]pipe", tarfile.FIFOTYPE)

    with pytest.raises(exarch.SecurityViolationError) as caught:
        exarch.extract_archive(archive, temp_dir / "out")

    assert caught.value.relaxable_by is None
