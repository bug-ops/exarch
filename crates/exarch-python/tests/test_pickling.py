"""Every exarch exception survives pickle with its attributes (#1207)."""

import concurrent.futures
import io
import os
import pickle
import tarfile

import pytest

import exarch

PARTIAL_ATTRIBUTES = ("code", "writes", "leftover_path", "skipped")


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


def _refuse():
    return exarch.ExtractionOptions().with_existing_files("refuse")


def _roundtrip(err, attributes):
    revived = pickle.loads(pickle.dumps(err))
    assert type(revived) is type(err)
    assert str(revived) == str(err)
    for name in attributes:
        if hasattr(err, name):
            assert hasattr(revived, name), name
    return revived


def test_partial_extraction_error_pickles_and_keeps_the_partial_attributes(temp_dir):
    archive = _tar(temp_dir / "a.tar", [("x", False), ("x", True)])
    out = temp_dir / "out"
    out.mkdir()

    with pytest.raises(exarch.ArchiveError) as info:
        exarch.extract_archive(archive, out, None, _refuse())

    revived = _roundtrip(info.value, PARTIAL_ATTRIBUTES)
    assert revived.code == info.value.code
    assert revived.writes == info.value.writes
    assert revived.leftover_path == info.value.leftover_path


def test_security_violation_after_partial_writes_pickles(temp_dir):
    archive = _tar(temp_dir / "a.tar", [("ok", False), ("d/e/f", False)])
    out = temp_dir / "out"
    out.mkdir()
    (out / "t").write_text("old")
    os.symlink("t", out / "d")

    with pytest.raises(exarch.SecurityViolationError) as info:
        exarch.extract_archive(archive, out, None, _refuse())

    revived = _roundtrip(info.value, PARTIAL_ATTRIBUTES + ("sub_code", "by"))
    assert revived.sub_code == info.value.sub_code
    assert revived.by == info.value.by


def test_output_exists_error_revives_with_errno_filename_and_strerror(temp_dir):
    archive = _tar(temp_dir / "f.tar", [("x", False)])
    out = temp_dir / "out"
    (out / "x").mkdir(parents=True)
    options = exarch.ExtractionOptions().with_existing_files("overwrite")

    with pytest.raises(exarch.OutputExistsError) as info:
        exarch.extract_archive(archive, out, None, options)

    err = info.value
    revived = _roundtrip(err, ("conflicts", "by"))
    assert revived.errno == err.errno is not None
    assert revived.filename == err.filename is not None
    assert revived.strerror == err.strerror is not None
    assert isinstance(revived, FileExistsError)
    assert revived.by == err.by
    assert [(c.path, c.occupant) for c in revived.conflicts] == [
        (c.path, c.occupant) for c in err.conflicts
    ]


def test_destination_error_keeps_its_step_across_pickle(temp_dir):
    archive = _tar(temp_dir / "a.tar", [("f", False)])
    blocker = temp_dir / "afile"
    blocker.write_bytes(b"")

    with pytest.raises(NotADirectoryError) as info:
        exarch.extract_archive(archive, blocker / "s")

    revived = _roundtrip(info.value, ("step", "errno", "filename"))
    assert revived.step == info.value.step == "create"
    assert revived.errno == info.value.errno
    assert revived.filename == info.value.filename


def test_partial_error_crosses_a_process_pool(temp_dir):
    archive = _tar(temp_dir / "a.tar", [("x", False), ("x", True)])
    out = temp_dir / "out"
    out.mkdir()

    with concurrent.futures.ProcessPoolExecutor(1) as pool:
        future = pool.submit(exarch.extract_archive, str(archive), str(out), None, _refuse())
        with pytest.raises(exarch.ArchiveError):
            future.result(timeout=60)
