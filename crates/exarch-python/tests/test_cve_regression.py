"""CVE regression tests for exarch-python.

These tests verify that exarch correctly blocks known CVE attack vectors.
"""

from pathlib import Path

import pytest

import exarch


def test_cve_path_traversal(malicious_traversal_tar, temp_dir):
    """
    Test CVE-2025-4517: Python tarfile path traversal.

    Verify that archives with path traversal attempts (../) are blocked.
    """
    output_dir = temp_dir / "output"
    output_dir.mkdir()

    # Default security config should block path traversal
    with pytest.raises(exarch.PathTraversalError):
        exarch.extract_archive(malicious_traversal_tar, output_dir)

    # Verify no files were created outside output_dir
    assert not (temp_dir / "etc" / "passwd").exists()


def test_cve_symlink_escape(malicious_symlink_escape, temp_dir):
    """
    Test CVE-2024-12905: Node.js tar-fs symlink escape.

    Verify that symlinks pointing outside extraction directory are blocked.
    """
    output_dir = temp_dir / "output"
    output_dir.mkdir()

    # Default security config blocks ALL symlinks (SecurityViolationError)
    with pytest.raises(exarch.SecurityViolationError):
        exarch.extract_archive(malicious_symlink_escape, output_dir)

    # Verify no symlinks were created
    evil_link = output_dir / "evil_link"
    assert not evil_link.exists()

    # Test that even with symlinks enabled, escape is detected
    output_dir2 = temp_dir / "output2"
    output_dir2.mkdir()
    config = exarch.SecurityConfig().allow_symlinks(True)

    with pytest.raises(exarch.SymlinkEscapeError):
        exarch.extract_archive(malicious_symlink_escape, output_dir2, config)

    # Verify no symlinks were created
    evil_link2 = output_dir2 / "evil_link"
    assert not evil_link2.exists()


def test_path_traversal_with_permissive_config(malicious_traversal_tar, temp_dir):
    """
    Test that path traversal is still blocked even with permissive config.

    Path traversal should NEVER be allowed, regardless of config.
    """
    output_dir = temp_dir / "output"
    output_dir.mkdir()

    # Even permissive config should block path traversal
    config = exarch.SecurityConfig.permissive()

    with pytest.raises(exarch.PathTraversalError):
        exarch.extract_archive(malicious_traversal_tar, output_dir, config)


def test_symlink_allowed_within_directory(temp_dir):
    """
    Test that symlinks within the extraction directory are allowed when configured.
    """
    import io
    import tarfile

    # Create archive with safe symlink (points to file within archive)
    archive_path = temp_dir / "safe_symlink.tar"

    with tarfile.open(archive_path, "w") as tar:
        # Add a regular file
        file_data = b"target content"
        file_info = tarfile.TarInfo(name="target.txt")
        file_info.size = len(file_data)
        tar.addfile(file_info, io.BytesIO(file_data))

        # Add a symlink pointing to the file above
        link_info = tarfile.TarInfo(name="link.txt")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "target.txt"
        tar.addfile(link_info)

    output_dir = temp_dir / "output"
    output_dir.mkdir()

    # Allow symlinks within extraction directory
    config = exarch.SecurityConfig().allow_symlinks(True)

    report = exarch.extract_archive(archive_path, output_dir, config)

    assert report.files_extracted == 1  # target.txt
    assert report.symlinks_created == 1  # link.txt
    assert (output_dir / "target.txt").exists()
    assert (output_dir / "link.txt").is_symlink()


def test_absolute_path_blocked(temp_dir):
    """
    Test that absolute paths in archives are blocked.
    """
    import io
    import tarfile

    # Create archive with absolute path
    archive_path = temp_dir / "absolute_path.tar"

    with tarfile.open(archive_path, "w") as tar:
        file_data = b"absolute path content"
        file_info = tarfile.TarInfo(name="/tmp/malicious.txt")
        file_info.size = len(file_data)
        tar.addfile(file_info, io.BytesIO(file_data))

    output_dir = temp_dir / "output"
    output_dir.mkdir()

    # Default config should block absolute paths
    with pytest.raises(exarch.PathTraversalError):
        exarch.extract_archive(archive_path, output_dir)

    # Verify file was not created at absolute path
    assert not Path("/tmp/malicious.txt").exists()


def test_zip_bomb_detection(temp_dir):
    """
    Test that zip bombs are detected via compression ratio check.

    Creates a small archive with high compression ratio to simulate zip bomb.
    1 MB of zeros compresses to ~1 KB (ratio ~1000x), exceeding default limit of 100x.
    """
    import zipfile

    archive_path = temp_dir / "zipbomb.zip"

    # Create a zip with high compression ratio
    # 1 MB of zeros compresses to ~1 KB (ratio ~1000x)
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.txt", b"\x00" * (1024 * 1024))  # 1 MB of zeros

    output_dir = temp_dir / "output"
    output_dir.mkdir()

    # Default max_compression_ratio is 100.0, so this should fail
    with pytest.raises(exarch.ZipBombError):
        exarch.extract_archive(archive_path, output_dir)

    # Verify no files were extracted
    assert not (output_dir / "bomb.txt").exists()


def test_hardlink_escape(malicious_hardlink_escape, temp_dir):
    """
    Test CVE-2025-48387: Node.js tar-fs hardlink traversal.

    Verify that hardlinks pointing outside extraction directory are blocked.
    """
    output_dir = temp_dir / "output"
    output_dir.mkdir()

    # Default config blocks ALL hardlinks (SecurityViolationError)
    with pytest.raises(exarch.SecurityViolationError):
        exarch.extract_archive(malicious_hardlink_escape, output_dir)

    # Verify no hardlinks were created
    assert not (output_dir / "evil_hardlink").exists()

    # Test that even with hardlinks enabled, escape is detected
    output_dir2 = temp_dir / "output2"
    output_dir2.mkdir()

    config = exarch.SecurityConfig().allow_hardlinks(True)
    with pytest.raises(exarch.HardlinkEscapeError):
        exarch.extract_archive(malicious_hardlink_escape, output_dir2, config)

    # Verify no hardlinks were created
    assert not (output_dir2 / "evil_hardlink").exists()


def _make_tar_gz(path, entries):
    """Build a .tar.gz at `path` from (TarInfo, data-or-None) entries."""
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for info, data in entries:
            if data is None:
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    path.write_bytes(buf.getvalue())


def test_partial_extraction_preserves_symlink_escape_type(temp_dir):
    """
    Regression test for #251.

    When a security error occurs after a regular file has already been written,
    the core wraps it in PartialExtraction. The binding must still raise the
    specific exception type (not a generic one) and expose the partial report
    via `files_extracted` / `bytes_written` attributes (the #210 capability).
    """
    import tarfile

    archive = temp_dir / "partial_symlink.tar.gz"
    regular = tarfile.TarInfo("dist/file.txt")
    regular.type = tarfile.REGTYPE
    link = tarfile.TarInfo("dist/link")
    link.type = tarfile.SYMTYPE
    link.linkname = "../../outside.txt"
    _make_tar_gz(archive, [(regular, b"ok"), (link, None)])

    output_dir = temp_dir / "out"
    output_dir.mkdir()
    config = exarch.SecurityConfig().allow_symlinks(True).allow_hardlinks(False)

    with pytest.raises(exarch.SymlinkEscapeError) as exc_info:
        exarch.extract_archive(archive, output_dir, config)

    # #210 report attributes are attached to the specific exception.
    err = exc_info.value
    assert getattr(err, "files_extracted", None) is not None
    assert err.files_extracted >= 1
    assert err.bytes_written >= len(b"ok")


def test_partial_extraction_preserves_hardlink_escape_type(temp_dir):
    """Regression test for #251 (hardlink variant)."""
    import tarfile

    archive = temp_dir / "partial_hardlink.tar.gz"
    regular = tarfile.TarInfo("dist/file.txt")
    regular.type = tarfile.REGTYPE
    hard = tarfile.TarInfo("dist/hard")
    hard.type = tarfile.LNKTYPE
    hard.linkname = "../../outside.txt"
    _make_tar_gz(archive, [(regular, b"ok"), (hard, None)])

    output_dir = temp_dir / "out"
    output_dir.mkdir()
    config = exarch.SecurityConfig().allow_hardlinks(True)

    with pytest.raises(exarch.HardlinkEscapeError) as exc_info:
        exarch.extract_archive(archive, output_dir, config)

    err = exc_info.value
    assert getattr(err, "files_extracted", None) is not None
    assert err.files_extracted >= 1


def test_progress_bytes_written_not_stale(temp_dir):
    """
    Regression test for #285.

    PyProgressAdapter was passing stale `bytes_written` (accumulated from all
    previous entries) to the Python callback at `on_entry_start`. The bug only
    manifests through `create_archive_with_progress` because `on_bytes_written`
    is only called during creation, not extraction.

    The fix resets `current_entry_bytes` to 0 at the start of each entry, so
    `bytes_written` at `on_entry_start` is always 0 regardless of how many
    bytes the preceding entries wrote.

    Failure signature of the original bug: file2's on_entry_start call would
    report bytes_written == len(SMALL) (stale from file1) instead of 0.
    """
    SMALL = b"x" * 1024          # 1 KB
    LARGE = b"y" * (100 * 1024)  # 100 KB

    src_dir = temp_dir / "src"
    src_dir.mkdir()
    (src_dir / "small.txt").write_bytes(SMALL)
    (src_dir / "large.txt").write_bytes(LARGE)

    archive = temp_dir / "two_files.tar.gz"

    # entry_start_bytes[name] = bytes_written received at on_entry_start
    entry_start_bytes: dict = {}

    def callback(path: str, total: int, current: int, bytes_written: int) -> None:
        name = path.split("/")[-1].split("\\")[-1]
        if name not in entry_start_bytes:
            entry_start_bytes[name] = bytes_written

    exarch.create_archive_with_progress(archive, [src_dir], None, callback)

    assert "small.txt" in entry_start_bytes, "callback never fired for small.txt"
    assert "large.txt" in entry_start_bytes, "callback never fired for large.txt"

    # Both entries must start with bytes_written == 0.
    # The original bug: large.txt received bytes_written == 1024 (stale from small.txt).
    assert entry_start_bytes["small.txt"] == 0, (
        f"small.txt: expected bytes_written=0 at entry start, got {entry_start_bytes['small.txt']}"
    )
    assert entry_start_bytes["large.txt"] == 0, (
        f"large.txt: expected bytes_written=0 at entry start, "
        f"got {entry_start_bytes['large.txt']} (stale value — original #285 bug)"
    )
