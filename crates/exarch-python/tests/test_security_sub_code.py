"""Tests for ``sub_code`` on core-raised ``SecurityViolationError``."""

import io
import tarfile

import pytest

import exarch


def _tar_with(member):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        member(archive)
    return buffer.getvalue()


def _file_member(name):
    def add(archive):
        info = tarfile.TarInfo(name)
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))

    return add


def _symlink_member(archive):
    info = tarfile.TarInfo("link")
    info.type = tarfile.SYMTYPE
    info.linkname = "target"
    archive.addfile(info)


def _violation(temp_dir, data):
    archive = temp_dir / "a.tar"
    archive.write_bytes(data)
    with pytest.raises(exarch.SecurityViolationError) as caught:
        exarch.extract_archive(archive, temp_dir / "out")
    return caught.value


def test_banned_component_is_path_name_and_relaxable(temp_dir):
    error = _violation(temp_dir, _tar_with(_file_member(".git/config")))

    assert error.sub_code == "PATH_NAME"
    assert error.relaxable_by == "banned_components"


def test_symlink_policy_is_link_policy(temp_dir):
    error = _violation(temp_dir, _tar_with(_symlink_member))

    assert error.sub_code == "LINK_POLICY"
    assert error.relaxable_by == "symlinks"


def test_boundary_nul_is_path_name_and_not_relaxable(temp_dir):
    with pytest.raises(exarch.SecurityViolationError) as caught:
        exarch.extract_archive("bad\0name.tar", temp_dir)

    assert caught.value.sub_code == "PATH_NAME"
    assert caught.value.relaxable_by is None
