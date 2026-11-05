"""Creation format refusals (#955) and unreadable creation sources (#956)."""

import errno
import os
import sys

import pytest

import exarch

CREATABLE = "Tar, TarGz, TarBz2, TarXz, TarZst, Zip"


@pytest.fixture
def source(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("alpha")
    return src


def _create_to_path(tmp_path, source, fmt):
    exarch.create_archive(tmp_path / "o.out", [source], format=fmt)


def _create_to_bytes(tmp_path, source, fmt):
    exarch.create_archive_to_bytes([source], fmt)


@pytest.mark.parametrize("create", [_create_to_path, _create_to_bytes])
@pytest.mark.parametrize("fmt", ["zip", "ZIP", "tar.gz", "bogus", "", "7z"])
def test_unknown_format_names_the_creation_format_and_lists_the_values(tmp_path, source, create, fmt):
    with pytest.raises(exarch.InvalidConfigurationError) as info:
        create(tmp_path, source, fmt)

    assert info.value.setting == "creation_format"
    assert info.value.code == "INVALID_CONFIGURATION"
    assert f"creation format is not one of the allowed values: {CREATABLE}" in str(info.value)
    assert "7z" not in str(info.value)


@pytest.mark.parametrize("create", [_create_to_path, _create_to_bytes])
def test_seven_z_is_refused_as_not_supported(tmp_path, source, create):
    with pytest.raises(exarch.InvalidConfigurationError) as info:
        create(tmp_path, source, "SevenZ")

    assert info.value.setting == "creation_format"
    assert "7z archive creation is not supported" in str(info.value)


def test_other_closed_enum_refusals_list_their_values():
    with pytest.raises(exarch.InvalidConfigurationError) as info:
        exarch.list_archive_bytes(b"x", format="bogus")

    assert info.value.setting == "archive_format"
    assert "archive format is not one of the allowed values: Tar, TarGz" in str(info.value)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_unreadable_source_names_the_path_and_carries_errno(tmp_path):
    tree = tmp_path / "bad"
    tree.mkdir()
    (tree / "ok.txt").write_text("x")
    unreadable = tree / "unread.txt"
    unreadable.write_text("y")
    unreadable.chmod(0)
    if os.access(unreadable, os.R_OK):
        pytest.skip("permission bits are not enforced (running as root)")
    out = tmp_path / "o.tar.gz"

    with pytest.raises(exarch.SourceNotAccessibleError) as info:
        exarch.create_archive(out, [tree])

    err = info.value
    assert err.code == "SOURCE_NOT_ACCESSIBLE"
    assert isinstance(err, OSError)
    assert not isinstance(err, PermissionError)
    assert err.errno == errno.EACCES
    assert "unread.txt" in str(err)
    assert os.path.basename(err.filename) == "unread.txt"
    assert "ermission denied" in err.strerror
    assert "Errno 13" in str(err)
    assert "ermission denied" in str(err)
    assert not out.exists()


def test_missing_source_stays_source_not_found(tmp_path):
    with pytest.raises(exarch.SourceNotFoundError) as info:
        exarch.create_archive(tmp_path / "o.tar", [tmp_path / "missing"])

    assert info.value.code == "SOURCE_NOT_FOUND"
