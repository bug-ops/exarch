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
    assert err.files_added >= 1
    assert err.bytes_written >= 0
    assert err.progress_callback_error is True
    # Creation ran to completion despite the callback raising (no cancellation
    # signal exists in the progress-callback contract) — the archive exists.
    assert archive.exists()
