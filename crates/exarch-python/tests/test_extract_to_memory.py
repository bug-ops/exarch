"""extract_archive_to_memory on archives held in memory (#776)."""

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

import exarch

SOLID_7Z = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "solid.7z"


def _tar(entries, mode: str = "w") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as archive:
        for name, payload, kind, extra in entries:
            info = tarfile.TarInfo(name=name)
            info.type = kind
            info.mode = extra.get("mode", 0o644)
            if kind == tarfile.REGTYPE:
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            else:
                info.linkname = extra.get("linkname", "")
                archive.addfile(info)
    return buffer.getvalue()


def _file(name: str, payload: bytes, **extra):
    return (name, payload, tarfile.REGTYPE, extra)


def _by_path(result) -> dict:
    return {entry.path: entry for entry in result.entries}


def test_round_trips_files_and_directories():
    data = _tar(
        [
            ("d", b"", tarfile.DIRTYPE, {"mode": 0o755}),
            _file("d/a.txt", b"alpha"),
            _file("b.txt", b"bravo"),
        ]
    )

    result = exarch.extract_archive_to_memory(data)
    entries = _by_path(result)

    assert result.report.files_extracted == 2
    assert entries["d"].kind == "directory"
    assert entries["d"].data is None
    assert entries["d/a.txt"].kind == "file"
    assert entries["d/a.txt"].data == b"alpha"
    assert isinstance(entries["b.txt"].data, bytes)
    assert [entry.path for entry in result.entries] == sorted(entries)


def test_zip_and_compressed_tar_are_detected():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("z.txt", b"zip")
    tar_gz = _tar([_file("t.txt", b"tar")], "w:gz")

    assert _by_path(exarch.extract_archive_to_memory(buffer.getvalue()))["z.txt"].data == b"zip"
    assert _by_path(exarch.extract_archive_to_memory(tar_gz))["t.txt"].data == b"tar"


def test_seven_z_is_extracted_to_memory():
    config = exarch.SecurityConfig().with_allow_solid_archives(True)

    result = exarch.extract_archive_to_memory(SOLID_7Z.read_bytes(), config)

    assert result.report.files_extracted > 0
    assert any(entry.kind == "file" and entry.data for entry in result.entries)


def test_symlinks_need_the_config_to_allow_them():
    data = _tar(
        [
            _file("a.txt", b"alpha"),
            ("l", b"", tarfile.SYMTYPE, {"linkname": "a.txt"}),
        ]
    )

    with pytest.raises(exarch.SecurityViolationError):
        exarch.extract_archive_to_memory(data)

    config = exarch.SecurityConfig().with_allow_symlinks(True)
    link = _by_path(exarch.extract_archive_to_memory(data, config))["l"]

    assert link.kind == "symlink"
    assert link.target == "a.txt"
    assert link.data is None


def test_setuid_and_setgid_bits_are_stripped():
    data = _tar([_file("x", b"x", mode=0o6755)])
    config = exarch.SecurityConfig().with_preserve_permissions(True)

    mode = _by_path(exarch.extract_archive_to_memory(data, config))["x"].mode

    assert mode is not None
    assert mode & 0o6000 == 0


def test_max_bytes_caps_the_payload():
    data = _tar([_file("a", b"x" * 100), _file("b", b"x" * 100)])

    assert len(exarch.extract_archive_to_memory(data, max_bytes=1000).entries) == 2
    with pytest.raises(exarch.QuotaExceededError):
        exarch.extract_archive_to_memory(data, max_bytes=150)


def test_sink_capacity_is_a_quota_error_naming_the_sink():
    data = _tar([_file("a", b"x" * 100)])

    with pytest.raises(exarch.QuotaExceededError, match="sink capacity"):
        exarch.extract_archive_to_memory(data, max_bytes=10)


def test_default_cap_follows_max_total_size():
    data = _tar([_file("a", b"x" * 100)])
    config = exarch.SecurityConfig().with_max_total_size(50)

    with pytest.raises(exarch.QuotaExceededError):
        exarch.extract_archive_to_memory(data, config)


@pytest.mark.parametrize("max_bytes", [0, -1, -(2**70), 2**70])
def test_non_positive_or_oversized_max_bytes_is_a_value_error(max_bytes):
    with pytest.raises(ValueError, match="max_bytes"):
        exarch.extract_archive_to_memory(_tar([_file("a", b"x")]), max_bytes=max_bytes)


@pytest.mark.parametrize("name", ["", "Host", "windows"])
def test_unknown_path_model_is_a_value_error(name):
    with pytest.raises(ValueError, match="path_model must be one of"):
        exarch.extract_archive_to_memory(_tar([_file("a", b"x")]), path_model=name)


def test_portable_model_refuses_names_other_platforms_reject():
    data = _tar([_file("a\\b", b"x")])

    assert "a\\b" in _by_path(exarch.extract_archive_to_memory(data, path_model="host"))
    with pytest.raises(exarch.ArchiveError):
        exarch.extract_archive_to_memory(data, path_model="portable")


def test_non_utf8_entry_names_are_rejected_not_merged():
    data = _tar([_file("bad\udcff.txt", b"x"), _file("bad\udcfe.txt", b"y")])

    with pytest.raises(exarch.ArchiveError):
        exarch.extract_archive_to_memory(data)


def test_traversal_is_rejected_like_the_path_api():
    data = _tar([_file("../evil", b"x")])

    with pytest.raises(exarch.PathTraversalError):
        exarch.extract_archive_to_memory(data)


def test_unknown_format_name_and_undetectable_bytes():
    with pytest.raises(ValueError, match="format must be one of"):
        exarch.extract_archive_to_memory(b"", format="rar")
    with pytest.raises(exarch.UnknownFormatError):
        exarch.extract_archive_to_memory(b"not an archive")


def test_atomic_options_are_refused():
    options = exarch.ExtractionOptions().with_atomic(True)

    with pytest.raises(ValueError):
        exarch.extract_archive_to_memory(_tar([_file("a", b"x")]), options=options)
