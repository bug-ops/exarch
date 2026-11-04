"""create_archive_to_bytes (#784) and extract_archive_to_memory_with_progress (#783)."""

import io
import tarfile
import zipfile

import pytest

import exarch


@pytest.fixture
def source_tree(temp_dir):
    root = temp_dir / "src"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_bytes(b"alpha")
    (root / "sub" / "b.txt").write_bytes(b"bravo" * 100)
    return root


def _entries(result) -> dict:
    return {entry.path: entry for entry in result.entries}


@pytest.mark.parametrize("format", ["Tar", "TarGz", "TarBz2", "TarXz", "TarZst", "Zip"])
def test_created_bytes_round_trip(source_tree, format):
    created = exarch.create_archive_to_bytes([source_tree], format)

    assert isinstance(created.data, bytes)
    assert created.report.files_added == 2
    assert created.report.bytes_compressed == len(created.data)

    result = exarch.extract_archive_to_memory(created.data, format=format)
    files = {
        path.rsplit("/", 1)[-1]: e.data for path, e in _entries(result).items() if e.kind == "file"
    }
    assert files == {"a.txt": b"alpha", "b.txt": b"bravo" * 100}


def test_created_zip_is_readable_by_stdlib(source_tree):
    created = exarch.create_archive_to_bytes([str(source_tree)], "Zip")

    with zipfile.ZipFile(io.BytesIO(created.data)) as archive:
        assert archive.testzip() is None
        assert len(archive.namelist()) >= 2


def test_created_tar_gz_is_readable_by_stdlib(source_tree):
    created = exarch.create_archive_to_bytes([source_tree], "TarGz")

    with tarfile.open(fileobj=io.BytesIO(created.data), mode="r:gz") as archive:
        assert len(archive.getnames()) >= 2


def test_seven_z_cannot_be_created(source_tree):
    with pytest.raises(ValueError, match="7z archive creation is not supported"):
        exarch.create_archive_to_bytes([source_tree], "SevenZ")


def test_unknown_format_is_a_value_error(source_tree):
    with pytest.raises(exarch.InvalidConfigurationError, match="not one of the allowed values"):
        exarch.create_archive_to_bytes([source_tree], "Rar")


def test_missing_source_is_an_error(temp_dir):
    with pytest.raises(Exception):
        exarch.create_archive_to_bytes([temp_dir / "missing"], "Tar")


@pytest.fixture
def tar_gz_bytes(source_tree):
    return exarch.create_archive_to_bytes([source_tree], "TarGz").data


def _assert_numbered(calls, expected_total):
    """`expected_total` is None for a TAR stream, whose entry count is not known up front."""
    assert [current for _, _, current, _ in calls] == list(range(1, len(calls) + 1))
    assert {total for _, total, _, _ in calls} == {expected_total}


@pytest.mark.parametrize("format", ["TarGz", "Zip"])
def test_memory_progress_reports_every_entry(source_tree, format):
    data = exarch.create_archive_to_bytes([source_tree], format).data
    calls = []

    result = exarch.extract_archive_to_memory_with_progress(
        data, None, lambda *args: calls.append(args)
    )

    plain = exarch.extract_archive_to_memory(data)
    assert len(calls) == len(plain.entries)
    _assert_numbered(calls, None if format == "TarGz" else len(calls))
    assert {path.rstrip("/") for path, *_ in calls} == {entry.path for entry in result.entries}
    assert [entry.path for entry in result.entries] == [entry.path for entry in plain.entries]


def test_memory_progress_none_matches_plain(tar_gz_bytes):
    result = exarch.extract_archive_to_memory_with_progress(tar_gz_bytes)

    assert (
        result.report.files_extracted
        == exarch.extract_archive_to_memory(tar_gz_bytes).report.files_extracted
    )


def test_memory_progress_forwards_options(tar_gz_bytes):
    with pytest.raises(exarch.QuotaExceededError):
        exarch.extract_archive_to_memory_with_progress(tar_gz_bytes, max_bytes=10)


def test_raising_callback_surfaces_and_discards_entries(tar_gz_bytes):
    calls = []

    def boom(*args):
        calls.append(args)
        raise RuntimeError("callback failed")

    with pytest.raises(RuntimeError, match="callback failed") as info:
        exarch.extract_archive_to_memory_with_progress(tar_gz_bytes, None, boom)

    assert len(calls) == 1
    assert info.value.progress_callback_error is True
    assert info.value.writes == "discarded"
    assert not hasattr(info.value, "files_extracted")


def test_raising_callback_does_not_mask_core_error(tar_gz_bytes):
    def boom(*args):
        raise RuntimeError("callback failed")

    with pytest.raises(exarch.QuotaExceededError) as info:
        exarch.extract_archive_to_memory_with_progress(tar_gz_bytes, None, boom, max_bytes=10)

    assert isinstance(info.value.__cause__, RuntimeError)


@pytest.mark.parametrize(
    "call",
    [
        lambda data, progress: exarch.list_archive_bytes_with_progress(data, None, progress),
        lambda data, progress: exarch.verify_archive_bytes_with_progress(data, None, progress),
    ],
    ids=["list", "verify"],
)
class TestInspectionProgress:
    @pytest.mark.parametrize("format", ["TarGz", "Zip"])
    def test_reports_every_entry(self, source_tree, call, format):
        data = exarch.create_archive_to_bytes([source_tree], format).data
        calls = []

        call(data, lambda *args: calls.append(args))

        names = [entry.path for entry in exarch.list_archive_bytes(data).entries]
        _assert_numbered(calls, None if format == "TarGz" else len(names))
        assert len(calls) == len(names)
        assert sorted(path.rstrip("/") for path, *_ in calls) == sorted(
            n.rstrip("/") for n in names
        )

    def test_works_without_callback(self, tar_gz_bytes, call):
        assert call(tar_gz_bytes, None) is not None

    def test_raising_callback_surfaces(self, tar_gz_bytes, call):
        def boom(*args):
            raise RuntimeError("callback failed")

        with pytest.raises(RuntimeError, match="callback failed") as info:
            call(tar_gz_bytes, boom)

        assert info.value.progress_callback_error is True

    def test_core_error_stays_primary(self, call):
        def boom(*args):
            raise RuntimeError("callback failed")

        with pytest.raises(exarch.ArchiveError):
            call(b"definitely not an archive", boom)
