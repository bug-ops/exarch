"""Passwords for in-memory and callback extraction, the ``encrypted`` entry marker
and the ``unusable_password`` reason (#1241, #1242, #1246)."""

import io
import tarfile
from pathlib import Path

import pytest

import exarch

FIXTURES = Path(__file__).parent / "fixtures"
ARCHIVES = ["encrypted-aes256.zip", "encrypted-header.7z"]
PASSWORD = b"correct-horse"


def _password():
    return bytearray(PASSWORD)


def _data(name):
    return (FIXTURES / name).read_bytes()


def _files(extraction):
    return {entry.path: entry.data for entry in extraction.entries if entry.kind == "file"}


@pytest.mark.parametrize("name", ARCHIVES)
def test_extract_to_memory_with_the_password_decrypts(name):
    result = exarch.extract_archive_to_memory(_data(name), password=_password())

    assert _files(result)["hello.txt"] == b"hello encrypted\n"


@pytest.mark.parametrize("name", ARCHIVES)
def test_extract_to_memory_with_progress_takes_the_password(name):
    seen = []

    result = exarch.extract_archive_to_memory_with_progress(
        _data(name), progress=lambda *args: seen.append(args), password=_password()
    )

    assert _files(result)["hello.txt"] == b"hello encrypted\n"
    assert seen


@pytest.mark.parametrize("name", ARCHIVES)
def test_extract_to_callback_with_the_password_delivers_decrypted_files(name):
    delivered = {}

    def on_entry(entry):
        if entry.kind == "file":
            delivered[entry.path] = entry.data

    exarch.extract_archive_to_callback(_data(name), on_entry, password=_password())

    assert delivered["hello.txt"] == b"hello encrypted\n"


@pytest.mark.parametrize("name", ARCHIVES)
def test_extract_to_memory_without_a_password_is_password_required(name):
    with pytest.raises(exarch.SecurityViolationError) as caught:
        exarch.extract_archive_to_memory(_data(name))

    assert caught.value.sub_code == "ENCRYPTED"
    assert caught.value.reason == "password_required"


@pytest.mark.parametrize("secret", [b"correct-horse", "correct-horse"])
def test_memory_and_callback_refuse_bytes_and_str_passwords(secret):
    data = _data("encrypted-aes256.zip")

    with pytest.raises(TypeError):
        exarch.extract_archive_to_memory(data, password=secret)
    with pytest.raises(TypeError):
        exarch.extract_archive_to_callback(data, lambda entry: None, password=secret)


def test_an_empty_password_is_a_value_error_for_memory_and_callback():
    data = _data("encrypted-aes256.zip")

    with pytest.raises(ValueError):
        exarch.extract_archive_to_memory(data, password=bytearray())
    with pytest.raises(ValueError):
        exarch.extract_archive_to_callback(data, lambda entry: None, password=bytearray())


def test_a_non_utf8_password_for_a_7z_is_unusable():
    with pytest.raises(exarch.SecurityViolationError) as caught:
        exarch.extract_archive_to_memory(
            _data("encrypted-header.7z"), password=bytearray(b"\xff\xfe-not-text")
        )

    assert caught.value.sub_code == "ENCRYPTED"
    assert caught.value.reason == "unusable_password"


@pytest.mark.parametrize("name", ARCHIVES)
def test_listed_files_of_an_encrypted_archive_are_marked_encrypted(name):
    listed = exarch.list_archive(FIXTURES / name, password=_password())

    files = [entry for entry in listed.entries if entry.entry_type == "File"]
    assert files
    assert all(entry.encrypted is True for entry in files)


def test_listed_entries_of_a_plain_archive_are_not_encrypted(tmp_path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo("a.txt")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
    path = tmp_path / "a.tar"
    path.write_bytes(buffer.getvalue())

    listed = exarch.list_archive(path)

    assert [entry.encrypted for entry in listed.entries] == [False]
