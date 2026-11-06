"""Integration tests for the *_with_progress functions.

Covers the dual-path `catch_unwind` wiring introduced for issue #395: both the
Python-callback branch and the `progress=None` branch of
`extract_archive_with_progress`, and the `progress=None` branch of
`create_archive_with_progress`. `create_archive_with_progress`'s callback
branch is already covered by
`test_cve_regression.py::test_progress_bytes_written_not_stale`.

Also covers a raising `progress` callback (issue #489): the exception must
propagate to the caller instead of being silently discarded, `progress` must
not be invoked again once it has raised, and the raised exception must carry
the `progress_callback_error` marker (not just `files_extracted`/
`files_added` and `bytes_written`) so callers can tell a callback failure
apart from a genuine partial extraction/creation.
"""

import io
import os
import sys
import tarfile
import threading

import pytest

import exarch


def test_extract_archive_with_progress_invokes_callback(sample_tar_gz, temp_dir):
    """extract_archive_with_progress calls back once per entry and extracts normally."""
    output = temp_dir / "output"
    output.mkdir()

    calls: list[tuple[str, int, int, int]] = []

    def callback(path: str, total: int, current: int, bytes_written: int) -> None:
        calls.append((path, total, current, bytes_written))

    report = exarch.extract_archive_with_progress(sample_tar_gz, output, None, callback)

    assert report.files_extracted >= 1
    assert calls, "progress callback was never invoked"


def test_extract_archive_with_progress_without_callback(sample_tar_gz, temp_dir):
    """extract_archive_with_progress(progress=None) still extracts normally."""
    output = temp_dir / "output"
    output.mkdir()

    report = exarch.extract_archive_with_progress(sample_tar_gz, output, None, None)

    assert report.files_extracted >= 1


def test_create_archive_with_progress_without_callback(temp_dir):
    """create_archive_with_progress(progress=None) still creates a valid archive."""
    src_dir = temp_dir / "src"
    src_dir.mkdir()
    (src_dir / "file.txt").write_bytes(b"content")

    archive = temp_dir / "output.tar.gz"

    report = exarch.create_archive_with_progress(archive, [src_dir], None, None)

    assert report.files_added >= 1
    assert archive.exists()


def test_extract_archive_with_progress_callback_error_propagates(sample_tar_gz, temp_dir):
    """A raising progress callback propagates instead of being swallowed (#489).

    `sample_tar_gz` has 3 entries (hello.txt, subdir, subdir/nested.txt), so a
    callback that raises on its first invocation and would otherwise be
    invoked again for the remaining two entries proves both that the
    exception reaches the caller and that dispatch stops after the raise.
    """
    output = temp_dir / "output"
    output.mkdir()

    calls: list[tuple[str, int, int, int]] = []

    def callback(path: str, total: int, current: int, bytes_written: int) -> None:
        calls.append((path, total, current, bytes_written))
        raise RuntimeError("callback aborted")

    with pytest.raises(RuntimeError, match="callback aborted") as exc_info:
        exarch.extract_archive_with_progress(sample_tar_gz, output, None, callback)

    assert len(calls) == 1, "progress must not be invoked again after it raised"

    err = exc_info.value
    assert err.files_extracted >= 1
    assert err.bytes_written >= 0
    assert err.progress_callback_error is True


def test_create_archive_with_progress_callback_error_propagates(temp_dir):
    """A raising progress callback propagates instead of being swallowed (#489)."""
    src_dir = temp_dir / "src"
    src_dir.mkdir()
    (src_dir / "a.txt").write_bytes(b"content a")
    (src_dir / "b.txt").write_bytes(b"content b")

    archive = temp_dir / "output.tar.gz"

    calls: list[tuple[str, int, int, int]] = []

    def callback(path: str, total: int, current: int, bytes_written: int) -> None:
        calls.append((path, total, current, bytes_written))
        raise ValueError("callback aborted")

    with pytest.raises(ValueError, match="callback aborted") as exc_info:
        exarch.create_archive_with_progress(archive, [src_dir], None, callback)

    assert len(calls) == 1, "progress must not be invoked again after it raised"

    err = exc_info.value
    assert err.progress_callback_error is True
    # The raising callback cancels creation: nothing is committed and no
    # counters describe a finished archive.
    assert not hasattr(err, "files_added")
    assert not archive.exists()


def _tar_gz_of(temp_dir, entries):
    archive = temp_dir / "entries.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name, data in entries:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return archive


def test_raising_callback_stops_extraction_before_the_next_entry(temp_dir):
    """A raise cancels the extraction instead of running to completion (#973)."""
    archive = _tar_gz_of(temp_dir, [("a.txt", b"a"), ("b.txt", b"b"), ("c.txt", b"c")])
    output = temp_dir / "output"
    output.mkdir()
    seen = []

    def callback(path, total, current, bytes_written):
        seen.append(path)
        if current == 2:
            raise RuntimeError("stop")

    with pytest.raises(RuntimeError, match="stop") as info:
        exarch.extract_archive_with_progress(archive, output, None, callback)

    assert seen == ["a.txt", "b.txt"]
    assert info.value.progress_callback_error is True
    assert info.value.writes == "kept"
    assert info.value.files_extracted == 2
    assert (output / "b.txt").exists()
    assert not (output / "c.txt").exists()


def test_raising_callback_under_atomic_rolls_the_output_back(temp_dir):
    archive = _tar_gz_of(temp_dir, [("a.txt", b"a"), ("b.txt", b"b"), ("c.txt", b"c")])
    output = temp_dir / "output"
    options = exarch.ExtractionOptions().with_staging("atomic")

    def callback(path, total, current, bytes_written):
        if current == 2:
            raise RuntimeError("stop")

    with pytest.raises(RuntimeError, match="stop") as info:
        exarch.extract_archive_with_progress(archive, output, None, callback, options)

    assert info.value.progress_callback_error is True
    assert info.value.writes == "rolled_back"
    assert not hasattr(info.value, "files_extracted")
    assert not output.exists()


def test_raising_callback_under_atomic_replace_keeps_the_original_destination(temp_dir):
    archive = _tar_gz_of(temp_dir, [("a.txt", b"a"), ("b.txt", b"b"), ("c.txt", b"c")])
    output = temp_dir / "output"
    output.mkdir()
    (output / "old.txt").write_text("old")
    options = exarch.ExtractionOptions().with_staging("atomic_replace")

    def callback(path, total, current, bytes_written):
        if current == 2:
            raise RuntimeError("stop")

    with pytest.raises(RuntimeError, match="stop") as info:
        exarch.extract_archive_with_progress(archive, output, None, callback, options)

    assert info.value.progress_callback_error is True
    assert info.value.writes == "rolled_back"
    assert [p.name for p in output.iterdir()] == ["old.txt"]
    assert (output / "old.txt").read_text() == "old"


def test_progress_variants_do_not_hold_a_borrow_of_the_config(temp_dir):
    """A config setter in another thread works while a progress run is under way (#987)."""
    archive = _tar_gz_of(temp_dir, [("a.txt", b"a"), ("b.txt", b"b")])
    config = exarch.SecurityConfig()
    errors = []

    def mutate():
        try:
            config.max_file_size = 1024
            config.allowed_extensions = ["txt"]
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def callback(path, total, current, bytes_written):
        worker = threading.Thread(target=mutate)
        worker.start()
        worker.join()

    output = temp_dir / "output"
    output.mkdir()
    exarch.extract_archive_with_progress(archive, output, config, callback)
    assert errors == []
    assert config.max_file_size == 1024

    errors.clear()
    with open(archive, "rb") as handle:
        exarch.extract_archive_to_memory_with_progress(handle.read(), config, callback)
    assert errors == []

    errors.clear()
    created = temp_dir / "created.tar.gz"
    source = temp_dir / "src"
    source.mkdir()
    (source / "f.txt").write_bytes(b"f")
    creation = exarch.CreationConfig()

    def mutate_creation():
        try:
            creation.compression_level = 3
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def creation_callback(path, total, current, bytes_written):
        worker = threading.Thread(target=mutate_creation)
        worker.start()
        worker.join()

    exarch.create_archive_with_progress(created, [source], creation, creation_callback)
    assert errors == []
    assert creation.compression_level == 3


def test_other_threads_run_while_a_progress_extraction_decodes(temp_dir):
    """The GIL is released between callbacks, as it is without a callback (#987).

    A thread is parked on a gate and released from the first callback. With the
    switch interval raised, the interpreter never forces the running thread to
    yield, so the thread can only run in the native stretch between two
    callbacks, and only if the GIL is released there.
    """
    archive = _tar_gz_of(temp_dir, [("big.bin", os.urandom(16 * 1024 * 1024)), ("after.txt", b"x")])
    output = temp_dir / "output"
    output.mkdir()
    gate = threading.Event()
    ran = threading.Event()
    seen = []

    def parked():
        gate.wait()
        ran.set()

    worker = threading.Thread(target=parked)

    def callback(path, total, current, bytes_written):
        if current == 1:
            worker.start()
            gate.set()
        else:
            seen.append(ran.is_set())

    config = exarch.SecurityConfig().with_max_file_size(32 * 1024 * 1024)
    interval = sys.getswitchinterval()
    sys.setswitchinterval(1000)
    try:
        exarch.extract_archive_with_progress(archive, output, config, callback)
    finally:
        sys.setswitchinterval(interval)
        gate.set()
        worker.join()

    assert seen == [True], "the thread could not run while the first entry was decoded: GIL held"


def test_a_callback_raising_after_a_finished_extraction_carries_the_whole_report(temp_dir):
    """The last entry's raise cannot cancel anything: the exception describes the run."""
    archive = temp_dir / "dup.tar"
    with tarfile.open(archive, "w") as tar:
        for body in (b"first", b"second"):
            info = tarfile.TarInfo("a.txt")
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
    output = temp_dir / "output"
    output.mkdir()

    def callback(path, total, current, bytes_written):
        if current == 2:
            raise RuntimeError("late")

    with pytest.raises(RuntimeError, match="late") as info:
        exarch.extract_archive_with_progress(archive, output, None, callback)

    err = info.value
    assert err.progress_callback_error is True
    assert err.writes == "kept"
    assert err.files_extracted == 1
    assert err.files_skipped == 1
    assert err.skipped.count("duplicate") == 1
    assert err.warnings == []
    assert (output / "a.txt").read_bytes() == b"first"
