"""list_archive_bytes and verify_archive_bytes on archives held in memory (#776)."""

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

import exarch

FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "fixtures"
FORMATS = ["Tar", "TarGz", "TarBz2", "TarXz", "TarZst", "Zip", "SevenZ"]


def _tar(mode: str = "w") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as archive:
        data = b"alpha"
        info = tarfile.TarInfo(name="a.txt")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("a.txt", b"alpha")
    return buffer.getvalue()


def _paths(manifest) -> list[str]:
    return [entry.path for entry in manifest.entries]


@pytest.mark.parametrize(
    ("data", "format_name"),
    [
        (_tar(), "Tar"),
        (_tar("w:gz"), "TarGz"),
        (_tar("w:bz2"), "TarBz2"),
        (_tar("w:xz"), "TarXz"),
        (_zip(), "Zip"),
        ((FIXTURES / "solid.7z").read_bytes(), "SevenZ"),
    ],
)
def test_list_detects_the_format(data, format_name):
    manifest = exarch.list_archive_bytes(data)

    assert manifest.format == format_name
    assert _paths(manifest)


def test_list_matches_the_path_api(tmp_path):
    data = _tar("w:gz")
    path = tmp_path / "a.tar.gz"
    path.write_bytes(data)

    assert _paths(exarch.list_archive_bytes(data)) == _paths(exarch.list_archive(path))


def test_explicit_format_skips_detection():
    data = _tar()

    assert exarch.list_archive_bytes(data, format="Tar").format == "Tar"


def test_explicit_format_must_match_the_bytes():
    with pytest.raises(exarch.ArchiveError):
        exarch.list_archive_bytes(_zip(), format="Tar")


def test_unknown_format_name_is_a_value_error():
    with pytest.raises(exarch.InvalidConfigurationError, match="not one of the allowed values"):
        exarch.list_archive_bytes(_tar(), format="tar.gz")


@pytest.mark.parametrize("data", [b"", b"not an archive", bytes(1024)])
def test_undetectable_bytes_raise_unknown_format(data):
    with pytest.raises(exarch.UnknownFormatError):
        exarch.list_archive_bytes(data)


def test_config_is_honored():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name in ("a.txt", "b.txt"):
            info = tarfile.TarInfo(name=name)
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
    config = exarch.SecurityConfig().with_max_file_count(1)

    with pytest.raises(exarch.QuotaExceededError):
        exarch.list_archive_bytes(buffer.getvalue(), config)


def test_bytearray_is_accepted():
    assert _paths(exarch.list_archive_bytes(bytearray(_tar()))) == ["a.txt"]


@pytest.mark.parametrize("data", [_tar(), _tar("w:gz"), _zip()])
def test_verify_passes_a_clean_archive(data):
    report = exarch.verify_archive_bytes(data)

    assert report.is_safe()
    assert report.integrity_status == "SKIPPED"


def test_verify_accepts_options_and_format():
    options = exarch.VerificationOptions().with_integrity_check()

    report = exarch.verify_archive_bytes(_zip(), None, options, "Zip")

    assert report.integrity_status == "OK"


def test_verify_rejects_an_unknown_format_name():
    with pytest.raises(exarch.InvalidConfigurationError, match="not one of the allowed values"):
        exarch.verify_archive_bytes(_zip(), format="rar")


def test_verify_rejects_a_traversal_entry_like_the_path_api(tmp_path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo(name="../evil.txt")
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))
    path = tmp_path / "evil.tar"
    path.write_bytes(buffer.getvalue())

    with pytest.raises(exarch.PathTraversalError):
        exarch.verify_archive(path)
    with pytest.raises(exarch.PathTraversalError):
        exarch.verify_archive_bytes(buffer.getvalue())
