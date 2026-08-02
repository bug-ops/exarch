"""Integration tests for the *_with_progress functions.

Covers the dual-path `catch_unwind` wiring introduced for issue #395: both the
Python-callback branch and the `progress=None` branch of
`extract_archive_with_progress`, and the `progress=None` branch of
`create_archive_with_progress`. `create_archive_with_progress`'s callback
branch is already covered by
`test_cve_regression.py::test_progress_bytes_written_not_stale`.
"""

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
