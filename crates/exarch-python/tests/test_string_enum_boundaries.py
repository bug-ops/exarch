"""Non-str, lone-surrogate and unknown values of the string-enum parameters (#1094)."""

from collections.abc import Callable
from pathlib import Path

import pytest

import exarch

Call = Callable[[Path, object], object]

LONE_SURROGATE = "\ud800"
UNKNOWN = "nope"


def _noop_entry(entry: object) -> None:
    return None


def _create(function: Callable[..., object], parameter: str) -> Call:
    def call(tmp_path: Path, value: object) -> object:
        source = tmp_path / "src.txt"
        source.write_bytes(b"x")
        return function(tmp_path / "out.tar", [source], **{parameter: value})

    return call


def _create_to_bytes(tmp_path: Path, value: object) -> object:
    source = tmp_path / "src.txt"
    source.write_bytes(b"x")
    return exarch.create_archive_to_bytes([source], value)


def _bytes_function(function: Callable[..., object], parameter: str) -> Call:
    return lambda _tmp_path, value: function(b"x", **{parameter: value})


def _callback(parameter: str) -> Call:
    return lambda _tmp_path, value: exarch.extract_archive_to_callback(
        b"x", _noop_entry, **{parameter: value}
    )


def _sink_options(parameter: str) -> Call:
    return lambda _tmp_path, value: exarch.SinkOptions(**{parameter: value})


CALLS: dict[str, Call] = {
    "create_archive.format": _create(exarch.create_archive, "format"),
    "create_archive.durability": _create(exarch.create_archive, "durability"),
    "create_archive_with_progress.format": _create(exarch.create_archive_with_progress, "format"),
    "create_archive_with_progress.durability": _create(
        exarch.create_archive_with_progress, "durability"
    ),
    "create_archive_to_bytes.format": _create_to_bytes,
    "SinkOptions.existing_files": _sink_options("existing_files"),
    "SinkOptions.decode_reuse": _sink_options("decode_reuse"),
    "extract_archive_to_memory.format": _bytes_function(exarch.extract_archive_to_memory, "format"),
    "extract_archive_to_memory.path_model": _bytes_function(
        exarch.extract_archive_to_memory, "path_model"
    ),
    "extract_archive_to_memory_with_progress.format": _bytes_function(
        exarch.extract_archive_to_memory_with_progress, "format"
    ),
    "extract_archive_to_memory_with_progress.path_model": _bytes_function(
        exarch.extract_archive_to_memory_with_progress, "path_model"
    ),
    "extract_archive_to_callback.format": _callback("format"),
    "extract_archive_to_callback.path_model": _callback("path_model"),
    "list_archive_bytes.format": _bytes_function(exarch.list_archive_bytes, "format"),
    "list_archive_bytes_with_progress.format": _bytes_function(
        exarch.list_archive_bytes_with_progress, "format"
    ),
    "verify_archive_bytes.format": _bytes_function(exarch.verify_archive_bytes, "format"),
    "verify_archive_bytes_with_progress.format": _bytes_function(
        exarch.verify_archive_bytes_with_progress, "format"
    ),
}

CREATION_FORMAT_CALLS = {
    "create_archive.format",
    "create_archive_with_progress.format",
    "create_archive_to_bytes.format",
}


def _setting(name: str) -> str:
    parameter = name.rsplit(".", 1)[1]
    if name in CREATION_FORMAT_CALLS:
        return "creation_format"
    return "archive_format" if parameter == "format" else parameter


CASES = [pytest.param(call, id=name) for name, call in CALLS.items()]
SETTING_CASES = [pytest.param(call, _setting(name), id=name) for name, call in CALLS.items()]


@pytest.mark.parametrize("call", CASES)
def test_bytes_value_is_a_type_error(call, tmp_path):
    with pytest.raises(TypeError):
        call(tmp_path, b"zip")


@pytest.mark.parametrize("call", CASES)
def test_lone_surrogate_is_a_unicode_encode_error(call, tmp_path):
    with pytest.raises(UnicodeEncodeError):
        call(tmp_path, LONE_SURROGATE)


@pytest.mark.parametrize(("call", "setting"), SETTING_CASES)
def test_unknown_value_is_an_invalid_configuration_error(call, setting, tmp_path):
    with pytest.raises(exarch.InvalidConfigurationError) as info:
        call(tmp_path, UNKNOWN)

    assert info.value.setting == setting
