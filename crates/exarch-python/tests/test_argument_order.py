"""One positional argument order across the binding functions (#1102).

Each call below passes every argument positionally with a distinct, valid value,
so swapping two neighbours in a signature fails the call or its outcome.
"""

import io
import tarfile

import pytest

import exarch


def _tar() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo(name="a.txt")
        info.size = 5
        archive.addfile(info, io.BytesIO(b"alpha"))
    return buffer.getvalue()


@pytest.fixture
def source(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "f.txt").write_bytes(b"content")
    return src


def test_list_archive_bytes_takes_config_options_format():
    manifest = exarch.list_archive_bytes(
        _tar(), exarch.SecurityConfig(), exarch.ListOptions(), "Tar"
    )
    assert manifest.format == "Tar"


def test_list_archive_bytes_with_progress_takes_options_format_progress():
    seen = []
    manifest = exarch.list_archive_bytes_with_progress(
        _tar(),
        exarch.SecurityConfig(),
        exarch.ListOptions(),
        "Tar",
        lambda *args: seen.append(args[0]),
    )
    assert manifest.format == "Tar"
    assert seen == ["a.txt"]


def test_verify_archive_bytes_with_progress_takes_options_format_progress():
    seen = []
    report = exarch.verify_archive_bytes_with_progress(
        _tar(),
        exarch.SecurityConfig(),
        exarch.VerificationOptions(),
        "Tar",
        lambda *args: seen.append(args[0]),
    )
    assert report.is_safe()
    assert seen == ["a.txt"]


def test_extract_archive_to_memory_with_progress_order():
    seen = []
    result = exarch.extract_archive_to_memory_with_progress(
        _tar(),
        exarch.SecurityConfig(),
        exarch.SinkOptions(),
        1 << 20,
        "portable",
        "Tar",
        lambda *args: seen.append(args[0]),
    )
    assert [entry.path for entry in result.entries] == ["a.txt"]
    assert seen == ["a.txt"]


def test_extract_archive_to_memory_with_progress_max_bytes_is_fourth():
    with pytest.raises(exarch.QuotaExceededError):
        exarch.extract_archive_to_memory_with_progress(
            _tar(), exarch.SecurityConfig(), exarch.SinkOptions(), 1, "host", "Tar", None
        )


def test_create_archive_positions(tmp_path, source):
    out = tmp_path / "o.zip"
    exarch.create_archive(out, [source], exarch.CreationConfig(), True, "unsynced", "Zip")
    assert out.read_bytes()[:2] == b"PK"

    with pytest.raises(exarch.OutputExistsError):
        exarch.create_archive(out, [source], None, False, "unsynced", "Zip")

    with pytest.raises(exarch.InvalidConfigurationError) as info:
        exarch.create_archive(out, [source], None, True, "bogus", "Zip")
    assert info.value.setting == "durability"


def test_create_archive_with_progress_positions(tmp_path, source):
    out = tmp_path / "o.zip"
    seen = []
    exarch.create_archive_with_progress(
        out,
        [source],
        exarch.CreationConfig(),
        True,
        "unsynced",
        "Zip",
        lambda *args: seen.append(args[0]),
    )
    assert out.read_bytes()[:2] == b"PK"
    assert seen

    with pytest.raises(exarch.OutputExistsError):
        exarch.create_archive_with_progress(out, [source], None, False, None, "Zip", None)


def test_extract_archive_with_progress_takes_options_before_progress(tmp_path):
    archive = tmp_path / "a.tar"
    archive.write_bytes(_tar())
    dest = tmp_path / "dest"
    seen = []
    exarch.extract_archive_with_progress(
        archive,
        dest,
        exarch.SecurityConfig(),
        exarch.ExtractionOptions().with_staging("atomic"),
        lambda *args: seen.append(args[0]),
    )
    assert (dest / "a.txt").read_bytes() == b"alpha"
    assert seen == ["a.txt"]
