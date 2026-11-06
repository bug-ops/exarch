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
    assert isinstance(entries["d"], exarch.MemoryDirectory)
    assert not hasattr(entries["d"], "data")
    assert isinstance(entries["d/a.txt"], exarch.MemoryFile)
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
    assert any(isinstance(entry, exarch.MemoryFile) and entry.data for entry in result.entries)


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
    assert isinstance(link, exarch.MemorySymlink)
    assert link.target == "a.txt"
    assert not hasattr(link, "data")


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
    with pytest.raises(exarch.InvalidConfigurationError, match="not one of the allowed values"):
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


def test_failure_after_delivered_entries_reports_discarded_writes():
    data = _tar([_file("a", b"x"), _file("../b", b"y")])

    with pytest.raises(exarch.PathTraversalError) as info:
        exarch.extract_archive_to_memory(data)

    assert info.value.writes == "discarded"
    assert not hasattr(info.value, "files_extracted")
    assert not hasattr(info.value, "bytes_written")


def test_unknown_format_name_and_undetectable_bytes():
    with pytest.raises(exarch.InvalidConfigurationError, match="not one of the allowed values"):
        exarch.extract_archive_to_memory(b"", format="rar")
    with pytest.raises(exarch.UnknownFormatError):
        exarch.extract_archive_to_memory(b"not an archive")


def test_path_extraction_options_are_not_accepted():
    options = exarch.ExtractionOptions().with_atomic(True)

    with pytest.raises(TypeError):
        exarch.extract_archive_to_memory(_tar([_file("a", b"x")]), options=options)


def test_every_entry_class_derives_from_memory_entry():
    for cls in (
        exarch.MemoryFile,
        exarch.MemoryDirectory,
        exarch.MemorySymlink,
        exarch.MemoryHardlink,
    ):
        assert issubclass(cls, exarch.MemoryEntry)


def test_sink_options_default_and_getters():
    options = exarch.SinkOptions()

    assert options.existing_files == "skip"
    assert options.decode_reuse == "off"
    assert options.decode_reuse_limit is None


def test_sink_options_existing_files_selects_the_surviving_entry():
    data = _tar([_file("a", b"1"), _file("a", b"2")])

    kept = exarch.extract_archive_to_memory(data, options=exarch.SinkOptions())
    assert [(e.path, e.data) for e in kept.entries] == [("a", b"1")]

    replaced = exarch.extract_archive_to_memory(
        data, options=exarch.SinkOptions(existing_files="overwrite")
    )
    assert [(e.path, e.data) for e in replaced.entries] == [("a", b"2")]


def test_sink_options_existing_files_values_and_refusal():
    for value in ("skip", "overwrite", "refuse"):
        assert exarch.SinkOptions(existing_files=value).existing_files == value
    with pytest.raises(exarch.InvalidConfigurationError) as info:
        exarch.SinkOptions(existing_files="replace")
    assert info.value.setting == "existing_files"


def test_sink_options_refuse_fails_on_an_in_archive_duplicate():
    data = _tar([_file("a", b"1"), _file("a", b"2")])

    with pytest.raises(exarch.OutputExistsError):
        exarch.extract_archive_to_memory(data, options=exarch.SinkOptions(existing_files="refuse"))


def test_sink_options_decode_reuse_modes():
    assert exarch.SinkOptions(decode_reuse="memory").decode_reuse_limit == 32 * 1024 * 1024
    temp = exarch.SinkOptions(decode_reuse="temp_file", decode_reuse_limit=1024)
    assert (temp.decode_reuse, temp.decode_reuse_limit) == ("temp_file", 1024)
    huge = exarch.SinkOptions(decode_reuse="memory", decode_reuse_limit=2**40)
    assert huge.decode_reuse_limit == 256 * 1024 * 1024


@pytest.mark.parametrize(
    ("kwargs", "setting", "problem"),
    [
        ({"decode_reuse": "disk"}, "decode_reuse", "not one of the allowed values"),
        ({"decode_reuse_limit": 1024}, "decode_reuse_limit", "is not supported"),
        ({"decode_reuse": "memory", "decode_reuse_limit": 0}, "decode_reuse_limit", "zero"),
        ({"decode_reuse": "memory", "decode_reuse_limit": -1}, "decode_reuse_limit", "negative"),
        ({"decode_reuse": "memory", "decode_reuse_limit": 2**200}, "decode_reuse_limit", "exceed"),
    ],
)
def test_sink_options_refuse_invalid_combinations(kwargs, setting, problem):
    with pytest.raises(exarch.InvalidConfigurationError) as info:
        exarch.SinkOptions(**kwargs)

    assert info.value.setting == setting
    assert problem in str(info.value)


def test_sink_options_limit_refuses_bool():
    with pytest.raises(TypeError):
        exarch.SinkOptions(decode_reuse="memory", decode_reuse_limit=True)
