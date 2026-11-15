"""`step` on destination errors and the typed destination failures of
#1197 and #1206, plus the existing-symlink error kinds of #1203/#1204."""

import errno
import io
import os
import sys
import tarfile

import pytest

import exarch

CORE_STEPS = {"resolve", "create", "open", "list", "write_access", "stage"}

needs_permissions = pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="permission bits are not enforced for this user",
)
needs_symlinks = pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")


def _tar(path, members):
    with tarfile.open(path, "w") as tar:
        for name, is_dir in members:
            info = tarfile.TarInfo(name)
            if is_dir:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.size = 2
                tar.addfile(info, io.BytesIO(b"n\n"))
    return path


@pytest.fixture
def archive(temp_dir):
    return _tar(temp_dir / "a.tar", [("f", False)])


def _atomic():
    return exarch.ExtractionOptions().with_staging("atomic")


def test_destination_step_values_are_the_core_names(archive, temp_dir):
    blocker = temp_dir / "afile"
    blocker.write_bytes(b"")

    with pytest.raises(NotADirectoryError) as info:
        exarch.extract_archive(archive, blocker / "s")

    assert info.value.step in CORE_STEPS
    assert info.value.step == "create"


def test_atomic_destination_below_a_file_is_not_a_directory_with_errno_20(archive, temp_dir):
    blocker = temp_dir / "afile"
    blocker.write_bytes(b"")

    with pytest.raises(NotADirectoryError) as info:
        exarch.extract_archive(archive, blocker / "s", None, _atomic())

    assert info.value.errno == errno.ENOTDIR
    assert info.value.step == "create"
    assert info.value.io_kind == "NotADirectory"


@needs_permissions
def test_unsearchable_destination_is_a_typed_write_access_failure(archive, temp_dir):
    dest = temp_dir / "ns"
    dest.mkdir()
    dest.chmod(0o600)
    try:
        with pytest.raises(PermissionError) as info:
            exarch.extract_archive(archive, dest)
    finally:
        dest.chmod(0o700)

    err = info.value
    assert err.errno == errno.EACCES
    assert err.filename is not None
    assert os.path.basename(err.filename) == "ns"
    assert err.step == "write_access"


@pytest.mark.skipif(sys.platform == "win32", reason="path length limits differ")
def test_atomic_too_long_leaf_carries_errno_filename_and_the_plain_step(archive, temp_dir):
    dest = temp_dir / "d" / ("n" * 300)

    with pytest.raises(OSError) as plain:
        exarch.extract_archive(archive, dest)
    with pytest.raises(OSError) as atomic:
        exarch.extract_archive(archive, dest, None, _atomic())

    assert atomic.value.errno is not None
    assert atomic.value.filename is not None
    assert atomic.value.step == plain.value.step
    assert atomic.value.errno == plain.value.errno


@needs_symlinks
def test_file_over_an_existing_symlink_is_output_exists_when_refusing(temp_dir):
    archive = _tar(temp_dir / "f.tar", [("x", False)])
    out = temp_dir / "out"
    out.mkdir()
    (out / "t").write_text("old")
    os.symlink("t", out / "x")
    options = exarch.ExtractionOptions().with_existing_files("refuse")

    with pytest.raises(exarch.OutputExistsError) as info:
        exarch.extract_archive(archive, out, None, options)

    assert [(c.path, c.occupant) for c in info.value.conflicts] == [("x", "symlink")]
    assert info.value.by == "existing"


@needs_symlinks
@pytest.mark.parametrize("mode", ["refuse", "overwrite"])
def test_directory_over_an_escaping_existing_symlink_is_existing_symlink(temp_dir, mode):
    archive = _tar(temp_dir / "d.tar", [("x", True), ("x/a", False)])
    out = temp_dir / "out"
    outside = temp_dir / "outside"
    out.mkdir()
    outside.mkdir()
    os.symlink("../outside", out / "x")
    options = exarch.ExtractionOptions().with_existing_files(mode)

    with pytest.raises(exarch.SecurityViolationError) as info:
        exarch.extract_archive(archive, out, None, options)

    assert info.value.sub_code == "EXISTING_SYMLINK"
    assert info.value.by == "existing"
    assert list(outside.iterdir()) == []


@needs_symlinks
def test_symlink_parent_carries_the_maker(temp_dir):
    archive = _tar(temp_dir / "a.tar", [("d/e/f", False)])
    out = temp_dir / "out"
    out.mkdir()
    (out / "t").write_text("old")
    os.symlink("t", out / "d")
    options = exarch.ExtractionOptions().with_existing_files("refuse")

    with pytest.raises(exarch.SecurityViolationError) as info:
        exarch.extract_archive(archive, out, None, options)

    assert info.value.sub_code == "EXISTING_SYMLINK"
    assert info.value.by == "existing"
    assert "d/e/f" in str(info.value)


@pytest.mark.parametrize("mode", ["skip", "refuse", "overwrite"])
def test_directory_over_a_file_of_the_run_names_the_archive_in_every_mode(temp_dir, mode):
    archive = _tar(temp_dir / "a.tar", [("x", False), ("x/a", False)])
    out = temp_dir / "out"
    out.mkdir()
    options = exarch.ExtractionOptions().with_existing_files(mode)

    with pytest.raises(exarch.OutputExistsError) as info:
        exarch.extract_archive(archive, out, None, options)

    assert info.value.by == "archive"
