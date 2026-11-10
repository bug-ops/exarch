"""str, errno and pickling of destination I/O errors (#1178)."""

import errno
import io
import os
import pickle
import sys
import tarfile

import pytest

import exarch

needs_permissions = pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="permission bits are not enforced for this user",
)


@pytest.fixture
def archive(temp_dir):
    source = temp_dir / "f.txt"
    source.write_text("hi")
    path = temp_dir / "a.tar"
    exarch.create_archive(path, [source])
    return path


def _assert_destination_error(err, exact, expected_errno, cause, name):
    assert type(err) is exact
    assert err.errno == expected_errno
    assert os.path.basename(err.filename) == name
    text = str(err)
    assert text.startswith(f"[Errno {expected_errno}] destination is not accessible: ")
    assert cause in text.lower()
    revived = pickle.loads(pickle.dumps(err))
    assert type(revived) is exact
    assert revived.errno == err.errno
    assert revived.filename == err.filename
    assert str(revived) == text


def test_extract_below_a_file_names_the_cause(archive, temp_dir):
    blocker = temp_dir / "afile"
    blocker.write_bytes(b"")

    with pytest.raises(NotADirectoryError) as info:
        exarch.extract_archive(archive, blocker / "s")

    _assert_destination_error(info.value, NotADirectoryError, errno.ENOTDIR, "not a directory", "s")
    assert info.value.io_kind == "NotADirectory"


def test_list_destination_below_a_file_names_the_cause(archive, temp_dir):
    blocker = temp_dir / "afile"
    blocker.write_bytes(b"")
    config = exarch.SecurityConfig().add_include_pattern("f.txt")

    with pytest.raises(NotADirectoryError) as info:
        exarch.list_archive(archive, config, destination=blocker / "s")

    _assert_destination_error(info.value, NotADirectoryError, errno.ENOTDIR, "not a directory", "s")


@needs_permissions
def test_extract_into_a_read_only_parent_names_the_cause(archive, temp_dir):
    ro = temp_dir / "ro"
    ro.mkdir()
    ro.chmod(0o555)
    try:
        with pytest.raises(PermissionError) as info:
            exarch.extract_archive(archive, ro / "sub")
    finally:
        ro.chmod(0o755)

    _assert_destination_error(info.value, PermissionError, errno.EACCES, "permission denied", "sub")
    assert info.value.io_kind == "PermissionDenied"


def test_destination_error_without_an_os_code_keeps_the_cause_and_filename(archive):
    with pytest.raises(FileNotFoundError) as info:
        exarch.extract_archive(archive, "")

    err = info.value
    assert type(err) is FileNotFoundError
    assert err.errno is None
    assert err.filename is not None
    assert "destination is not accessible: " in str(err)
    assert "resolving the path" in str(err)
    revived = pickle.loads(pickle.dumps(err))
    assert revived.errno is None
    assert str(revived) == str(err)


def test_extract_into_a_read_only_filesystem_is_a_plain_oserror(archive):
    probe = "/System/exarch-destination-probe"
    try:
        os.mkdir(probe)
    except OSError as refused:
        if refused.errno != errno.EROFS:
            pytest.skip("no read-only filesystem to probe")
    else:
        os.rmdir(probe)
        pytest.skip("no read-only filesystem to probe")

    with pytest.raises(OSError) as info:
        exarch.extract_archive(archive, probe)

    err = info.value
    assert type(err) is OSError
    assert err.errno == errno.EROFS
    assert err.io_kind == "ReadOnlyFilesystem"
    assert "destination is not accessible:" in str(err)


def _file_entry_archive(temp_dir, name):
    path = temp_dir / "entry.tar"
    with tarfile.open(path, "w") as tar:
        info = tarfile.TarInfo(name=name)
        info.size = 2
        tar.addfile(info, io.BytesIO(b"hi"))
    return path


def test_overwrite_over_a_directory_occupant_is_output_exists(temp_dir):
    archive = _file_entry_archive(temp_dir, "d")
    destination = temp_dir / "out"
    (destination / "d").mkdir(parents=True)
    options = exarch.ExtractionOptions().with_existing_files("overwrite")

    with pytest.raises(exarch.OutputExistsError) as info:
        exarch.extract_archive(archive, destination, options=options)

    assert info.value.conflicts == ["d"]
    assert info.value.by == "existing"
    assert (destination / "d").is_dir()


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_overwrite_over_a_symlink_occupant_is_an_existing_symlink_violation(temp_dir):
    archive = _file_entry_archive(temp_dir, "link_entry")
    destination = temp_dir / "out"
    destination.mkdir()
    target = temp_dir / "target.txt"
    target.write_text("keep")
    (destination / "link_entry").symlink_to(target)
    options = exarch.ExtractionOptions().with_existing_files("overwrite")

    with pytest.raises(exarch.SecurityViolationError) as info:
        exarch.extract_archive(archive, destination, options=options)

    assert info.value.sub_code == "EXISTING_SYMLINK"
    assert "existing symlink at link_entry" in str(info.value)
    assert target.read_text() == "keep"
    assert (destination / "link_entry").is_symlink()
