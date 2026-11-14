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

    assert [(c.path, c.occupant) for c in info.value.conflicts] == [("d", "directory")]
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
    assert info.value.by == "existing"
    assert "existing symlink at link_entry" in str(info.value)
    assert target.read_text() == "keep"
    assert (destination / "link_entry").is_symlink()


def test_conflict_is_a_frozen_typed_value(temp_dir):
    archive = _file_entry_archive(temp_dir, "d")
    destination = temp_dir / "out"
    (destination / "d").mkdir(parents=True)
    options = exarch.ExtractionOptions().with_existing_files("overwrite")

    with pytest.raises(exarch.OutputExistsError) as info:
        exarch.extract_archive(archive, destination, options=options)

    (conflict,) = info.value.conflicts
    assert isinstance(conflict, exarch.OccupiedPath)
    assert repr(conflict) == 'OccupiedPath(path="d", occupant="directory")'
    with pytest.raises(AttributeError):
        conflict.path = "other"


def test_other_security_violations_have_no_maker(temp_dir):
    entry = tarfile.TarInfo("../escape")
    entry.size = 1
    archive = temp_dir / "bad.tar"
    with tarfile.open(archive, "w") as tar:
        tar.addfile(entry, io.BytesIO(b"x"))

    with pytest.raises(exarch.ArchiveError) as info:
        exarch.extract_archive(archive, temp_dir / "out")

    assert getattr(info.value, "by", None) is None


def test_atomic_refusal_names_the_caller_destination(temp_dir):
    archive = _file_entry_archive(temp_dir, "d")
    destination = temp_dir / "out"
    (destination / "d").mkdir(parents=True)
    options = exarch.ExtractionOptions().with_existing_files("overwrite").with_staging("atomic")

    with pytest.raises(exarch.OutputExistsError) as info:
        exarch.extract_archive(archive, destination, options=options)

    assert os.path.basename(info.value.filename) == "out"
    assert ".exarch" not in str(info.value)


def _directory_entry_archive(temp_dir, name):
    path = temp_dir / "dir_entry.tar"
    with tarfile.open(path, "w") as tar:
        info = tarfile.TarInfo(name=name)
        info.type = tarfile.DIRTYPE
        tar.addfile(info)
    return path


@pytest.mark.parametrize("policy", ["skip", "overwrite", "refuse"])
def test_directory_over_a_file_is_output_exists_under_every_policy(temp_dir, policy):
    archive = _directory_entry_archive(temp_dir, "f/")
    destination = temp_dir / "out"
    destination.mkdir()
    (destination / "f").write_text("keep")
    options = exarch.ExtractionOptions().with_existing_files(policy)

    with pytest.raises(exarch.OutputExistsError) as info:
        exarch.extract_archive(archive, destination, options=options)

    assert type(info.value) is exarch.OutputExistsError
    assert [(c.path, c.occupant) for c in info.value.conflicts] == [("f", "file")]
    assert (destination / "f").read_text() == "keep"


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_directory_over_a_symlink_made_by_the_archive_names_the_archive(temp_dir):
    archive = temp_dir / "linked.tar"
    with tarfile.open(archive, "w") as tar:
        target = tarfile.TarInfo("t")
        target.size = 1
        tar.addfile(target, io.BytesIO(b"x"))
        link = tarfile.TarInfo("l")
        link.type = tarfile.SYMTYPE
        link.linkname = "t"
        tar.addfile(link)
        folder = tarfile.TarInfo("l/")
        folder.type = tarfile.DIRTYPE
        tar.addfile(folder)
    config = exarch.SecurityConfig().with_allow_symlinks()
    # Only `overwrite` and `refuse` keep the run record that proves the maker.
    options = exarch.ExtractionOptions().with_existing_files("refuse")

    with pytest.raises(exarch.SecurityViolationError) as info:
        exarch.extract_archive(archive, temp_dir / "out", config, options)

    assert info.value.sub_code == "EXISTING_SYMLINK"
    assert info.value.by == "archive"


def test_str_names_the_entry_and_its_kind_and_keeps_the_os_error_fields(temp_dir):
    archive = _file_entry_archive(temp_dir, "d")
    destination = temp_dir / "out"
    (destination / "d").mkdir(parents=True)
    options = exarch.ExtractionOptions().with_existing_files("overwrite")

    with pytest.raises(FileExistsError) as info:
        exarch.extract_archive(archive, destination, options=options)

    err = info.value
    assert isinstance(err, exarch.OutputExistsError)
    assert "existing directory at d" in str(err)
    assert err.errno == errno.EEXIST
    assert os.path.basename(err.filename) == "out"
    revived = pickle.loads(pickle.dumps(err))
    assert str(revived) == str(err)


def test_str_of_a_hand_built_error_falls_back_to_oserror():
    assert str(exarch.OutputExistsError()) == ""
    assert str(exarch.OutputExistsError(17, "msg")) == "[Errno 17] msg"


def test_str_counts_several_conflicts(temp_dir):
    path = temp_dir / "two.tar"
    with tarfile.open(path, "w") as tar:
        for name in ("a", "b"):
            entry = tarfile.TarInfo(name)
            entry.size = 1
            tar.addfile(entry, io.BytesIO(b"x"))
    destination = temp_dir / "out"
    destination.mkdir()
    (destination / "a").write_text("1")
    (destination / "b").write_text("2")
    options = exarch.ExtractionOptions().with_existing_files("refuse")

    with pytest.raises(exarch.OutputExistsError) as info:
        exarch.extract_archive(path, destination, options=options)

    message = str(info.value)
    assert "file at a" in message or "paths to extract" in message
    revived = pickle.loads(pickle.dumps(info.value))
    assert [(c.path, c.occupant) for c in revived.conflicts] == [
        (c.path, c.occupant) for c in info.value.conflicts
    ]
