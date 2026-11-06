"""errno, filename and io_kind of the path-related errors (#962, #989, #992)."""

import errno
import os

import pytest

import exarch


def _basename(name):
    return os.path.basename(name)


def test_source_not_found_carries_errno_filename_and_strerror(temp_dir):
    with pytest.raises(FileNotFoundError) as info:
        exarch.create_archive(temp_dir / "out.tar", [temp_dir / "nothere"])

    err = info.value
    assert isinstance(err, exarch.SourceNotFoundError)
    assert err.errno == errno.ENOENT
    assert _basename(err.filename) == "nothere"
    assert err.strerror == os.strerror(errno.ENOENT)
    assert err.code == "SOURCE_NOT_FOUND"


def test_missing_archive_is_a_source_not_found_with_errno(temp_dir):
    with pytest.raises(FileNotFoundError) as info:
        exarch.extract_archive(temp_dir / "missing.tar", temp_dir / "out")

    err = info.value
    assert err.errno == errno.ENOENT
    assert _basename(err.filename) == "missing.tar"
    assert err.strerror


def test_output_exists_carries_errno_and_filename(temp_dir):
    existing = temp_dir / "ex.tar"
    existing.write_bytes(b"x")
    source = temp_dir / "a"
    source.write_bytes(b"a")

    with pytest.raises(FileExistsError) as info:
        exarch.create_archive(existing, [source], overwrite=False)

    err = info.value
    assert isinstance(err, exarch.OutputExistsError)
    assert err.errno == errno.EEXIST
    assert _basename(err.filename) == "ex.tar"
    assert err.strerror == os.strerror(errno.EEXIST)
    assert err.conflicts is None


def test_a_non_utf8_host_path_reaches_core_as_a_typed_error(temp_dir):
    bad = os.fsencode(str(temp_dir)) + b"/\xff.tar"

    for path in (bad, bad.decode("utf-8", "surrogateescape")):
        with pytest.raises(exarch.SourceNotFoundError) as info:
            exarch.extract_archive(path, temp_dir / "out")
        assert info.value.code == "SOURCE_NOT_FOUND"


def test_a_path_of_the_wrong_type_is_still_a_type_error(temp_dir):
    with pytest.raises(TypeError):
        exarch.extract_archive(12, temp_dir / "out")


def test_io_errors_carry_a_stable_io_kind_and_are_oserrors(temp_dir):
    archive = temp_dir / "dir-as-archive.tar"
    archive.mkdir()

    with pytest.raises(OSError) as info:
        exarch.extract_archive(archive, temp_dir / "out")

    assert info.value.code == "IO_ERROR"
    assert info.value.io_kind == "IsADirectory"


def test_compression_level_refusals_come_from_one_core_parser():
    config = exarch.CreationConfig()
    for level in (0, 10, -3, 2**40, 2**100):
        with pytest.raises(exarch.InvalidCompressionLevelError) as info:
            config.with_compression_level(level)
        assert info.value.code == "INVALID_COMPRESSION_LEVEL"
        assert isinstance(info.value, ValueError)
    with pytest.raises(exarch.InvalidCompressionLevelError, match="-3"):
        config.with_compression_level(-3)
